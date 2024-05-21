<?php

/**
 * @file handler/OpenIDHandler.php
 *
 * Copyright (c) 2020 Leibniz Institute for Psychology Information (https://leibniz-psychology.org/)
 * Copyright (c) 2023 Simon Fraser University
 * Copyright (c) 2023 John Willinsky
 * Distributed under the GNU GPL v3. For full terms see the file LICENSE.
 *
 * @class OpenIDHandler
 *
 * @ingroup plugins_generic_openid
 *
 * @brief Handler for OpenID workflow:
 *  - receive auth-code
 *  - perform auth-code -> token exchange
 *  - token validation via server certificate
 *  - extract user details
 *  - register new accounts
 *  - connect existing accounts
 */

namespace APP\plugins\generic\openid\handler;

use APP\core\Application;
use APP\core\Request;
use APP\handler\Handler;
use APP\plugins\generic\openid\enums\OpenIDProvider;
use APP\plugins\generic\openid\enums\SSOError;
use APP\plugins\generic\openid\forms\OpenIDStep2Form;
use APP\plugins\generic\openid\OpenIDPlugin;
use APP\template\TemplateManager;
use Exception;
use Firebase\JWT\JWT;
use GuzzleHttp\Exception\GuzzleException;
use phpseclib\Crypt\RSA;
use phpseclib\Math\BigInteger;
use PKP\config\Config;
use PKP\core\PKPApplication;
use APP\facades\Repo;
use PKP\security\Role;
use PKP\security\Validation;
use PKP\user\User;

class OpenIDHandler extends Handler
{
    public const USER_OPENID_IDENTIFIER_SETTING_BASE = 'openid::';
    public const USER_OPENID_LAST_PROVIDER_SETTING = self::USER_OPENID_IDENTIFIER_SETTING_BASE . 'lastProvider';

    /**
     * Constructor
     */
    public function __construct(protected OpenIDPlugin $plugin)
    {
    }

    /**
     * This function is called via OpenID provider redirect URL.
     * It receives the authentication code via the get parameter and uses $this->_getTokenViaAuthCode to exchange the code into a JWT
     * The JWT is validated with the public key of the server fetched by $this->_getOpenIDAuthenticationCert.
     * If the JWT and the key are successfully retrieved, the JWT is validated and extracted using $this->_validateAndExtractToken.
     *
     * If no user was found with the provided OpenID identifier a second step is called to connect a local account with the OpenID account, or to register a
     * new account. It is possible for a user to connect his/her account to more than one OpenID provider.
     *
     * If the account is disabled or in case of errors/exceptions the user is redirect to the sign in page and some errors will be displayed.
     *
     * @return bool|void|string
     */
    function doAuthentication(array $args, Request $request)
    {
        $providerStr = $request->getUserVar('provider');
        $selectedProvider = OpenIDProvider::tryFrom($providerStr);

        $context = $request->getContext();
        $contextId = $context ? $context->getId() : PKPApplication::CONTEXT_SITE;

        $error = $request->getUserVar('error');
        $errorDescription = $request->getUserVar('error_description');

        if ($error) {
            return $this->handleSSOError($request, $context, SSOError::API_RETURNED, "{$selectedProvider->value}: ($error) \"$errorDescription\"");
        }
        
        $settings = OpenIDHandler::getOpenIDSettings($this->plugin, $contextId);
        $token = $this->getTokenViaAuthCode($settings['provider'], $request->getUserVar('code'), $selectedProvider);
        $publicKey = $this->getOpenIDAuthenticationCert($settings['provider'], $selectedProvider);

        if (!$token || !$publicKey) {
            return $this->handleSSOError($request, $context, $publicKey ? SSOError::CONNECT_DATA : SSOError::CONNECT_KEY);
        }

        $claims = $this->validateAndExtractToken($token, $publicKey);

        if (!$claims || !is_array($claims)) {
            return $this->handleSSOError($request, $context, SSOError::CERTIFICATION);
        }

        $user = $this->getUserViaProviderId($claims['id'], $selectedProvider);

        if (!$user) {
            $regForm = new OpenIDStep2Form($this->plugin, $selectedProvider, $claims);
            $regForm->initData();
            return $regForm->fetch($request, null, true);
        }

        $reason = null;
        if ($user->getDisabled()) {
            $reason = $user->getDisabledReason();
            return $this->handleSSOError($request, $context, SSOError::USER_DISABLED, $reason);
        }

        Validation::registerUserSession($user, $reason);

        $request->getSession()->put('id_token', OpenIDHandler::encryptOrDecrypt($this->plugin, $contextId, $token['id_token']));

        self::updateUserDetails($this->plugin, $claims, $user, $request, $selectedProvider);

        $redirectUrl = $user->hasRole(
            [
                Role::ROLE_ID_SITE_ADMIN, 
                Role::ROLE_ID_MANAGER, 
                Role::ROLE_ID_SUB_EDITOR, 
                Role::ROLE_ID_AUTHOR, 
                Role::ROLE_ID_REVIEWER, 
                Role::ROLE_ID_ASSISTANT
            ],
            $contextId
        ) ? 'submissions' : 'user/profile';

        return $request->redirect($context->getPath(), $redirectUrl, null, $args);
    }

    /**
     * Step2 POST (Form submit) function.
     * OpenIDStep2Form is used to handle form initialization, validation and persistence.
     */
    function registerOrConnect(array $args, Request $request)
    {
        if (Validation::isLoggedIn()) {
            $this->setupTemplate($request);
            $templateMgr = TemplateManager::getManager($request);
            $templateMgr->assign('pageTitle', 'user.login.registrationComplete');
            $templateMgr->display('frontend/pages/userRegisterComplete.tpl');
            return;
        }

        if (!$request->isPost()) {
            return $request->redirect($request->getContext()->getPath(), 'login');
        }

        $regForm = new OpenIDStep2Form($this->plugin);
        $regForm->readInputData();
        if (!$regForm->validate()) {
            return $regForm->display($request);
        }

        if ($regForm->execute()) {
            return $request->redirect($request->getContext()->getPath(), 'openid', 'registerOrConnect');
        }

        $regForm->addError('', __('plugins.generic.openid.form.error.invalid'));
        $regForm->display($request);
    }

    public static function updateUserDetails(
        OpenIDPlugin $plugin, 
        ?array $claims, 
        User $user, 
        Request $request, 
        OpenIDProvider $selectedProvider, 
        bool $setProviderId = false
    )
    {
        $context = $request->getContext();
        $contextId = $context ? $context->getId() : PKPApplication::CONTEXT_SITE;

        $settings = OpenIDHandler::getOpenIDSettings($plugin, $contextId);

        if (($settings['providerSync'] ?? false) && isset($claims)) {
            $sitePrimaryLocale = $request->getSite()->getPrimaryLocale();

            $user->setGivenName($claims['given_name'] ?? '', $sitePrimaryLocale);
            $user->setFamilyName($claims['family_name'] ?? '', $sitePrimaryLocale);
            if (isset($claims['email']) && Repo::user()->getByEmail($claims['email']) == null) {
                $user->setEmail($claims['email']);
            }

            if ($selectedProvider == OpenIDProvider::ORCID && isset($claims['id'])) {
                $user->setOrcid($claims['id']);
            }
        }

        $user->setData(self::USER_OPENID_LAST_PROVIDER_SETTING, $selectedProvider->value);

        if ($setProviderId && isset($claims['id'])) {
            $user->setData(self::getOpenIDUserSetting($selectedProvider), $claims['id']);
            self::updateApiKey($plugin, $contextId, $user, $claims['id'], $settings, $selectedProvider);
        }

        Repo::user()->edit($user);
    }

    private static function updateApiKey(OpenIDPlugin $plugin, int $contextId, User $user, string $providerId, array $settings, OpenIDProvider $selectedProvider)
    {
        if (($settings['generateAPIKey'] ?? false) && $selectedProvider == OpenIDProvider::CUSTOM) {
            $secret = Config::getVar('security', 'api_key_secret');

            if (!$secret) {
                error_log($plugin->getName() . ' - api_key_secret not defined in configuration file');
                return;
            }

            $user->setData('apiKeyEnabled', true);
            $user->setData('apiKey', self::encryptOrDecrypt($plugin, $contextId, $providerId));
            Repo::user()->edit($user);
        }
    }

    /**
     * De-/Encrypt function to hide some important things.
     */
    public static function encryptOrDecrypt(OpenIDPlugin $plugin, int $contextId, ?string $string, bool $encrypt = true): ?string
    {
        if (!isset($string)) {
            return null;
        }
        
        $alg = 'AES-256-CBC';
        $settings = OpenIDHandler::getOpenIDSettings($plugin, $contextId);

        if (!isset($settings['hashSecret'])) {
            return $string;
        }

        $pwd = $settings['hashSecret'];
        $iv = substr($pwd, 0, 16);

        return $encrypt
            ? openssl_encrypt($string, $alg, $pwd, 0, $iv)
            : openssl_decrypt($string, $alg, $pwd, 0, $iv);
    }

    /**
     * Tries to find a user via OpenID credentials via user settings openid::{provider}
     * This is a very simple step, and it should be safe because the token is valid at this point.
     * If the token is invalid, the auth process stops before this function is called.
     */
    private function getUserViaProviderId(string $idClaim, OpenIDProvider $selectedProvider): ?User
    {
        $userIds = Repo::user()->getIdsBySetting(self::getOpenIDUserSetting($selectedProvider), $idClaim);
        if ($userIds->isNotEmpty()) {
            return Repo::user()->get($userIds->firstOrFail());
        }

        $userIds = Repo::user()->getIdsBySetting(self::getOpenIDUserSetting($selectedProvider), hash('sha256', $idClaim));
        if ($userIds->isNotEmpty()) {
            return Repo::user()->get($userIds->firstOrFail()->getId());
        }

        return null;
    }

    /**
     * This function swaps the Auth code into a JWT that contains the user_details and a signature.
     * An array with the access_token, id_token and/or refresh_token is returned on success, otherwise null.
     * The OpenID implementation differs a bit between the providers. Some use an id_token, others a refresh token.
     */
    private function getTokenViaAuthCode(array $providerList, string $authorizationCode, OpenIDProvider $selectedProvider): ?array
    {
        if (!isset($providerList[$selectedProvider->value])) {
            return null;
        }

        $settings = $providerList[$selectedProvider->value];
        $httpClient = Application::get()->getHttpClient();
        $params = [
            'code' => $authorizationCode,
            'grant_type' => 'authorization_code',
            'client_id' => $settings['clientId'],
            'client_secret' => $settings['clientSecret'],
            'redirect_uri' => Application::get()->getRequest()->url(
                null,
                'openid',
                'doAuthentication',
                null,
                ['provider' => $selectedProvider->value]
            ),
        ];

        try {
            $response = $httpClient->request(
                'POST',
                $settings['tokenUrl'],
                [
                    'headers' => ['Accept' => 'application/json'],
                    'form_params' => $params,
                ]
            );

            if ($response->getStatusCode() != 200) {
                error_log($this->plugin->getName() . ' - Guzzle Response != 200: ' . $response->getStatusCode());
                return null;
            }

            $result = $response->getBody()->getContents();
            $result = json_decode($result, true);

            if (isset($result['access_token'])) {
                return [
                    'access_token' => $result['access_token'],
                    'id_token' => $result['id_token'] ?? null,
                    'refresh_token' => $result['refresh_token'] ?? null,
                ];
            }
        } catch (GuzzleException $e) {
            error_log($this->plugin->getName() . ' - Guzzle Exception thrown: ' . $e->getMessage());
        }

        return null;
    }

    /**
     * This function uses the certs endpoint of the openid provider to get the server certificate.
     * There are provider-specific differences in case of the certificate.
     *
     * E.g.
     * - Keycloak uses x5c as certificate format which included the cert.
     * - Other vendors provide the cert modulus and exponent and the cert has to be created via phpseclib/RSA
     *
     * If no key is found, null is returned
     */
    private function getOpenIDAuthenticationCert(?array $providerList, OpenIDProvider $selectedProvider): ?array
    {
        if (!isset($providerList[$selectedProvider->value])) {
            return null;
        }

        $settings = $providerList[$selectedProvider->value];
        $httpClient = Application::get()->getHttpClient();
        $publicKeys = [];
        $beginCert = '-----BEGIN CERTIFICATE-----';
        $endCert = '-----END CERTIFICATE----- ';

        try {
            $response = $httpClient->request('GET', $settings['certUrl']);
            if ($response->getStatusCode() != 200) {
                error_log($this->plugin->getName() . ' - Guzzle Response != 200: ' . $response->getStatusCode());
                return null;
            }

            $result = $response->getBody()->getContents();
            $arr = json_decode($result, true);

            if (!isset($arr['keys'])) {
                return null;
            }

            foreach ($arr['keys'] as $key) {
                if (($key['alg'] ?? null) == 'RS256' || ($key['kty'] ?? null) == 'RSA') {
                    if (is_array($key['x5c'] ?? null)) {
                        foreach ($key['x5c'] as $n) {
                            if (!empty($n)) {
                                $publicKeys[] = $beginCert . PHP_EOL . $n . PHP_EOL . $endCert;
                            }
                        }
                    } elseif (isset($key['n'], $key['e'])) {
                        $rsa = new RSA();
                        $modulus = new BigInteger(JWT::urlsafeB64Decode($key['n']), 256);
                        $exponent = new BigInteger(JWT::urlsafeB64Decode($key['e']), 256);
                        $rsa->loadKey(['n' => $modulus, 'e' => $exponent]);
                        $publicKeys[] = $rsa->getPublicKey();
                    }
                }
            }
        } catch (GuzzleException $e) {
            error_log($this->plugin->getName() . ' - Guzzle Exception thrown: ' . $e->getMessage());
        }

        return $publicKeys;
    }

    /**
     * Validates the token via JWT and public key and returns the token claims data as array.
     * In case of an error null is returned
     */
    private function validateAndExtractToken(array $token, array $publicKeys): ?array
    {
        foreach ($publicKeys as $publicKey) {
            foreach ($token as $t) {
                try {
                    if ($t) {
                        $jwtPayload = JWT::decode($t, new \Firebase\JWT\Key($publicKey, 'RS256'));

                        if ($jwtPayload) {
                            return [
                                'id' => $jwtPayload->sub ?? null,
                                'email' => $jwtPayload->email ?? null,
                                'username' => $jwtPayload->preferred_username ?? null,
                                'given_name' => $jwtPayload->given_name ?? null,
                                'family_name' => $jwtPayload->family_name ?? null,
                                'email_verified' => $jwtPayload->email_verified ?? null,
                            ];
                        }
                    }
                } catch (Exception $e) {
                    continue;
                }
            }
        }

        return null;
    }

    /**
     * This function is unused at the moment.
     * It can be unsed to get the user details from an endpoint but usually all user data are provided in the JWT.
     */
    private function getClientDetails(array $token, array $settings): ?string
    {
        $httpClient = Application::get()->getHttpClient();

        try {
            $response = $httpClient->request(
                'GET',
                $settings['userInfoUrl'],
                [
                    'headers' => [
                        'Accept' => 'application/json',
                        'Authorization' => 'Bearer ' . $token['access_token'],
                    ],
                ]
            );

            if ($response->getStatusCode() != 200) {
                error_log($this->plugin->getName() . ' - Guzzle Response != 200: ' . $response->getStatusCode());
                return null;
            }

            return $response->getBody()->getContents();
        } catch (GuzzleException $e) {
            error_log($this->plugin->getName() . ' - Guzzle Exception thrown: ' . $e->getMessage());
            return null;
        }
    }

    public static function getOpenIDUserSetting(OpenIDProvider $provider): string
    {
        return self::USER_OPENID_IDENTIFIER_SETTING_BASE . $provider->value;
    }

    /**
     * Handle SSO errors
     */
    private function handleSSOError(Request $request, $context, SSOError $error, $errorMsg = null)
    {
        $ssoErrors = ['sso_error' => $error->value];

        if ($errorMsg) {
            $ssoErrors['sso_error_msg'] = $errorMsg;
        }

        return $request->redirect($context->getPath(), 'login', null, null, $ssoErrors);
    }

    public static function getOpenIDSettings(OpenIDPlugin $plugin, int $contextId): ?array
    {
        $settingsJson = $plugin->getSetting($contextId, 'openIDSettings');
        return $settingsJson ? json_decode($settingsJson, true) : null;
    }
}