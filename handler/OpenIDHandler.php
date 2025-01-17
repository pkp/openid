<?php

/**
 * @file handler/OpenIDHandler.php
 *
 * Copyright (c) 2020 Leibniz Institute for Psychology Information (https://leibniz-psychology.org/)
 * Copyright (c) 2024 Simon Fraser University
 * Copyright (c) 2024 John Willinsky
 * Distributed under the GNU GPL v3. For full terms see the file LICENSE.
 *
 * @class OpenIDHandler
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
use APP\plugins\generic\openid\classes\ContextData;
use APP\plugins\generic\openid\forms\OpenIDStep2Form;
use APP\plugins\generic\openid\OpenIDPlugin;
use APP\template\TemplateManager;
use Exception;
use Firebase\JWT\JWT;
use GuzzleHttp\Exception\GuzzleException;
use phpseclib\Crypt\RSA;
use phpseclib\Math\BigInteger;
use PKP\config\Config;
use APP\facades\Repo;
use PKP\security\Role;
use PKP\security\Validation;
use PKP\user\User;

class OpenIDHandler extends Handler
{
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
	 * new OJS account. It is possible for a user to connect his/her OJS account to more than one OpenID provider.
	 *
	 * If the OJS account is disabled or in case of errors/exceptions the user is redirect to the sign in page and some errors will be displayed.
	 *
	 * @param $args
	 * @param $request
	 * @return bool|void|string
	 */
	function doAuthentication($args, $request, $provider = null)
	{
		$selectedProvider = $request->getUserVar('provider');

		$contextData = OpenIDPlugin::getContextData($request);

		$contextId = $contextData->getId();
		$contextPath = $contextData ? $contextData->getPath() : null; 

		$error = $request->getUserVar('error');
		$errorDescription = $request->getUserVar('error_description');

		if ($error) {
			return $this->handleSSOError($request, $contextPath, OpenIDPlugin::SSO_ERROR_API_RETURNED, "{$selectedProvider}: ($error) \"$errorDescription\"");
		}
		
		$settings = OpenIDPlugin::getOpenIDSettings($this->plugin, $contextId);
		$token = $this->getTokenViaAuthCode($settings['provider'], $request->getUserVar('code'), $selectedProvider);
		$publicKey = $this->getOpenIDAuthenticationCert($settings['provider'], $selectedProvider);

		if (!$token || !$publicKey) {
			return $this->handleSSOError($request, $contextPath, $publicKey ? OpenIDPlugin::SSO_ERROR_CONNECT_DATA : OpenIDPlugin::SSO_ERROR_CONNECT_KEY);
		}

		$claims = $this->validateAndExtractToken($token, $publicKey);

		if (!$claims || !is_array($claims)) {
			return $this->handleSSOError($request, $contextPath, OpenIDPlugin::SSO_ERROR_CERTIFICATION);
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
			return $this->handleSSOError($request, $contextPath, OpenIDPlugin::SSO_ERROR_USER_DISABLED, $reason);
		}

		Validation::registerUserSession($user, $reason);

		$request->getSession()->setSessionVar('id_token', OpenIDPlugin::encryptOrDecrypt($this->plugin, $contextId, $token['id_token']));

		self::updateUserDetails($this->plugin, $claims, $user, $contextData, $selectedProvider);

		if ($user->hasRole(
			[
				Role::ROLE_ID_SITE_ADMIN, 
				Role::ROLE_ID_MANAGER, 
				Role::ROLE_ID_SUB_EDITOR, 
				Role::ROLE_ID_AUTHOR, 
				Role::ROLE_ID_REVIEWER, 
				Role::ROLE_ID_ASSISTANT
			],
			$contextId
		)) {
			return $request->redirect($contextPath, 'submissions', null, $args);
		} else {
			return $request->redirect($contextPath, 'user', 'profile', $args);
		}
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

		$contextData = $request->getContext();
		$contextPath = $contextData ? OpenIDPlugin::getContextData($request)->getPath() : null;

		if (!$request->isPost()) {
			return $request->redirect($contextPath, 'login');
		}

		$regForm = new OpenIDStep2Form($this->plugin);
		$regForm->readInputData();
		if (!$regForm->validate()) {
			return $regForm->display($request);
		}

		if ($regForm->execute()) {
			return $request->redirect($contextPath, 'openid', 'registerOrConnect');
		}

		$regForm->addError('', __('plugins.generic.openid.form.error.invalid'));
		$regForm->display($request);
	}

	public static function updateUserDetails(
		OpenIDPlugin $plugin,
		?array $claims,
		User $user,
		ContextData $contextData,
		string $selectedProvider,
		bool $setProviderId = false
	)
	{
		$contextId = $contextData->getId();

		$settings = OpenIDPlugin::getOpenIDSettings($plugin, $contextId);

		if (($settings['providerSync'] ?? false) && isset($claims)) {
			$sitePrimaryLocale = $contextData->getPrimaryLocale();

			if (!empty($claims['given_name'])) {
				$user->setGivenName($claims['given_name'] ?? '', $sitePrimaryLocale);
			}

			if (!empty($claims['family_name'])) {
				$user->setFamilyName($claims['family_name'] ?? '', $sitePrimaryLocale);
			}

			if (!empty($claims['email']) && Repo::user()->getByEmail($claims['email']) == null) {
				$user->setEmail($claims['email']);
			}

			if (!empty($claims['id']) && $selectedProvider == OpenIDPlugin::PROVIDER_ORCID) {
				$user->setOrcid($claims['id']);
			}
		}

		$user->setData(OpenIDPlugin::USER_OPENID_LAST_PROVIDER_SETTING, $selectedProvider);

		if ($setProviderId && isset($claims['id'])) {
			$user->setData(OpenIDPlugin::getOpenIDUserSetting($selectedProvider), $claims['id']);
			self::updateApiKey($plugin, $contextId, $user, $claims['id'], $settings, $selectedProvider);
		}

		Repo::user()->edit($user);
	}

	private static function updateApiKey(OpenIDPlugin $plugin, int $contextId, User $user, string $providerId, array $settings, string $selectedProvider)
	{
		if ($settings['generateAPIKey'] ?? false) {
			$secret = Config::getVar('security', 'api_key_secret');

			if (!$secret) {
				error_log($plugin->getName() . ' - api_key_secret not defined in configuration file');
				return;
			}

			$user->setData('apiKeyEnabled', true);
			$user->setData('apiKey', OpenIDPlugin::encryptOrDecrypt($plugin, $contextId, $providerId));
		}
	}

	/**
	 * Tries to find a user via OpenID credentials via user settings openid::{provider}
	 * This is a very simple step, and it should be safe because the token is valid at this point.
	 * If the token is invalid, the auth process stops before this function is called.
	 */
	private function getUserViaProviderId(string $idClaim, string $selectedProvider): ?User
	{
		$userIds = Repo::user()->getCollector()
			->filterBySettings([OpenIDPlugin::getOpenIDUserSetting($selectedProvider) => $idClaim])
			->getIds();
		
		if ($userIds->isNotEmpty()) {
			return Repo::user()->get($userIds->firstOrFail());
		}

		$userIds = Repo::user()->getCollector()
			->filterBySettings([OpenIDPlugin::getOpenIDUserSetting($selectedProvider), hash('sha256', $idClaim)])
			->getIds();

		if ($userIds->isNotEmpty()) {
			return Repo::user()->get($userIds->firstOrFail());
		}

		return null;
	}

	/**
	 * This function swaps the Auth code into a JWT that contains the user_details and a signature.
	 * An array with the access_token, id_token and/or refresh_token is returned on success, otherwise null.
	 * The OpenID implementation differs a bit between the providers. Some use an id_token, others a refresh token.
	 */
	private function getTokenViaAuthCode(array $providerList, string $authorizationCode, string $selectedProvider): ?array
	{
		if (!isset($providerList[$selectedProvider])) {
			return null;
		}

		$settings = $providerList[$selectedProvider];
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
				['provider' => $selectedProvider]
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
	private function getOpenIDAuthenticationCert(?array $providerList, string $selectedProvider): ?array
	{
		if (!isset($providerList[$selectedProvider])) {
			return null;
		}

		$settings = $providerList[$selectedProvider];
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

	/**
	 * Handle SSO errors
	 */
	private function handleSSOError(Request $request, ?string $contextPath, string $error, $errorMsg = null)
	{
		$ssoErrors = ['sso_error' => htmlspecialchars($error, ENT_QUOTES, 'UTF-8')];

		if ($errorMsg) {
			$ssoErrors['sso_error_msg'] = htmlspecialchars($errorMsg, ENT_QUOTES, 'UTF-8');
		}

		return $request->redirect($contextPath, 'login', null, null, $ssoErrors);
	}
}
