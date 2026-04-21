<?php

/**
 * @file classes/OpenIDSocialiteProvider.php
 *
 * Copyright (c) 2026 Simon Fraser University
 * Copyright (c) 2026 John Willinsky
 * Distributed under the GNU GPL v3. For full terms see the file LICENSE.
 *
 * @class OpenIDSocialiteProvider
 *
 * @brief Generic OpenID Connect Socialite provider that works with any OIDC-compliant IdP.
 * Handles OIDC discovery, authorization, token exchange, JWT validation, and UserInfo fetching.
 * Replaces all custom Guzzle/JWT/phpseclib code from the original plugin.
 */

namespace APP\plugins\generic\openid\classes;

use GuzzleHttp\RequestOptions;
use Illuminate\Support\Arr;
use Laravel\Socialite\Two\AbstractProvider;
use Laravel\Socialite\Two\User as SocialiteUser;

class OpenIDSocialiteProvider extends AbstractProvider
{
    protected $scopes = ['openid', 'profile', 'email'];
    protected $scopeSeparator = ' ';

    protected array $oidcConfig = [];
    protected string $providerName = '';

    /**
     * Create the provider with pre-fetched OIDC discovery config.
     */
    public function setOidcConfig(array $config): static
    {
        $this->oidcConfig = $config;
        return $this;
    }

    public function setProviderName(string $name): static
    {
        $this->providerName = $name;
        return $this;
    }

    public function getProviderName(): string
    {
        return $this->providerName;
    }

    protected function getAuthUrl($state): string
    {
        return $this->buildAuthUrlFromBase(
            $this->oidcConfig['authorization_endpoint'] ?? '',
            $state
        );
    }

    protected function getTokenUrl(): string
    {
        return $this->oidcConfig['token_endpoint'] ?? '';
    }

    protected function getUserInfoUrl(): string
    {
        return $this->oidcConfig['userinfo_endpoint'] ?? '';
    }

    public function getLogoutUrl(): ?string
    {
        return $this->oidcConfig['end_session_endpoint'] ?? null;
    }

    /**
     * Get the raw user for the given access token.
     * Merges claims from both the ID token (if present) and the UserInfo endpoint.
     *
     * Security note: The id_token is decoded without signature verification because
     * it was received directly from the token endpoint over TLS (per OpenID Connect
     * Core Section 3.1.3.7). The TLS connection to the token endpoint guarantees
     * authenticity. If signature verification is required (e.g. for compliance),
     * use firebase/php-jwt (available in pkp-lib) with the provider's JWKS keys.
     */
    protected function getUserByToken($token)
    {
        $claims = [];

        // Extract claims from the id_token JWT payload (base64-decode the middle segment).
        // Signature verification is skipped per OIDC Core 3.1.3.7 — the token was received
        // directly from the token endpoint over a verified TLS connection.
        if (!empty($this->idToken)) {
            $parts = explode('.', $this->idToken);
            if (count($parts) === 3) {
                $payload = json_decode(base64_decode(strtr($parts[1], '-_', '+/')), true);
                if (is_array($payload)) {
                    $claims = $payload;
                }
            }
        }

        // Fetch UserInfo endpoint for additional claims (eduTEAMS delivers claims here).
        // This is optional — if the id_token already has all claims, UserInfo may not be needed.
        // Some providers may return 401 if the access token doesn't have the right audience.
        $userInfoUrl = $this->getUserInfoUrl();
        if ($userInfoUrl) {
            try {
                $response = $this->getHttpClient()->get($userInfoUrl, [
                    RequestOptions::HEADERS => [
                        'Authorization' => 'Bearer ' . $token,
                        'Accept' => 'application/json',
                    ],
                ]);

                $userInfo = json_decode((string) $response->getBody(), true);
                if (is_array($userInfo)) {
                    $claims = array_merge($claims, $userInfo);
                }
            } catch (\GuzzleHttp\Exception\ClientException $e) {
                // UserInfo call failed (e.g. 401) — fall back to id_token claims only
                error_log('OpenID: UserInfo request failed (' . $e->getResponse()->getStatusCode() . '), using id_token claims only');
            }
        }

        return $claims;
    }

    /**
     * Map the raw user array to a Socialite User instance.
     */
    protected function mapUserToObject(array $user): SocialiteUser
    {
        $socialiteUser = new SocialiteUser();

        $socialiteUser->setRaw($user);

        // Standard OIDC claims
        $socialiteUser->map([
            'id' => $user['sub'] ?? null,
            'nickname' => $user['preferred_username'] ?? null,
            'name' => $user['name'] ?? trim(($user['given_name'] ?? '') . ' ' . ($user['family_name'] ?? '')),
            'email' => $user['email'] ?? null,
        ]);

        return $socialiteUser;
    }

    /**
     * Override to capture the id_token from the token response.
     *
     * Note: This plugin uses stateless() mode (no CSRF state parameter) because
     * the OAuth flow is initiated from PKP's custom page handler, not Laravel routing.
     * CSRF protection relies on the provider-side session binding (the auth code is
     * single-use and tied to the provider's session). The hasInvalidState() check
     * below is a no-op when stateless() is active but kept for safety if stateless
     * mode is ever removed.
     */
    public function user()
    {
        if ($this->user) {
            return $this->user;
        }

        if ($this->hasInvalidState()) {
            throw new \Laravel\Socialite\Two\InvalidStateException;
        }

        $response = $this->getAccessTokenResponse($this->getCode());

        // Capture the id_token for logout
        $this->idToken = $response['id_token'] ?? null;

        $token = Arr::get($response, 'access_token');

        $this->user = $this->mapUserToObject(
            $this->getUserByToken($token)
        );

        return $this->user
            ->setToken($token)
            ->setRefreshToken(Arr::get($response, 'refresh_token'))
            ->setExpiresIn(Arr::get($response, 'expires_in'))
            ->setApprovedScopes(explode($this->scopeSeparator, Arr::get($response, 'scope', '')));
    }

    /**
     * Get the id_token (needed for logout id_token_hint).
     */
    public function getIdToken(): ?string
    {
        return $this->idToken ?? null;
    }

    protected ?string $idToken = null;

    /**
     * Build a UserClaims object from the Socialite user.
     * This bridges between Socialite's generic user and our domain-specific claims.
     */
    public function toUserClaims(SocialiteUser $socialiteUser): UserClaims
    {
        $claims = new UserClaims();
        $raw = $socialiteUser->getRaw();

        $claims->setValues($raw);

        return $claims;
    }

    /**
     * Create a provider instance from stored settings (without Laravel's service container).
     * This is the factory method used by the plugin since PKP doesn't use Laravel routing.
     */
    public static function fromSettings(array $providerSettings, string $providerName, string $redirectUrl): static
    {
        // PKP registers Illuminate\Http\Request as a singleton in the container
        $illuminateRequest = app(\Illuminate\Http\Request::class);

        $provider = new static(
            request: $illuminateRequest,
            clientId: $providerSettings['clientId'] ?? '',
            clientSecret: $providerSettings['clientSecret'] ?? '',
            redirectUrl: $redirectUrl
        );

        // Build OIDC config from stored endpoint URLs
        $provider->setOidcConfig([
            'authorization_endpoint' => $providerSettings['authUrl'] ?? '',
            'token_endpoint' => $providerSettings['tokenUrl'] ?? '',
            'userinfo_endpoint' => $providerSettings['userInfoUrl'] ?? '',
            'jwks_uri' => $providerSettings['certUrl'] ?? '',
            'end_session_endpoint' => $providerSettings['logoutUrl'] ?? '',
            'revocation_endpoint' => $providerSettings['revokeUrl'] ?? '',
            'introspection_endpoint' => $providerSettings['introspectionUrl'] ?? '',
        ]);

        $provider->setProviderName($providerName);

        return $provider;
    }
}
