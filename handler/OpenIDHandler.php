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
use APP\plugins\generic\openid\classes\UserClaims;
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

	public function authorize($request, &$args, $roleAssignments)
	{
		$this->setEnforceRestrictedSite(false);
		return parent::authorize($request, $args, $roleAssignments);
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
		$contextPath = $contextData->getPath();

		$error = $request->getUserVar('error');
		$errorDescription = $request->getUserVar('error_description');

		if ($error) {
			return $this->handleSSOError($request, $contextPath, OpenIDPlugin::SSO_ERROR_API_RETURNED, "{$selectedProvider}: ($error) \"$errorDescription\"");
		}
		
		$settings = OpenIDPlugin::getOpenIDSettings($this->plugin, $contextId);

		if (!isset($settings['provider'][$selectedProvider])) {
			return $this->handleSSOError($request, $contextPath, OpenIDPlugin::SSO_ERROR_CONNECT_DATA);
		}

		$providerSettings = $settings['provider'][$selectedProvider];

		$token = $this->getTokenViaAuthCode($providerSettings, $request->getUserVar('code'), $selectedProvider);
		if (!$token) {
			return $this->handleSSOError($request, $contextPath, OpenIDPlugin::SSO_ERROR_CONNECT_KEY);
		}

		$userClaims = $this->getCompleteClaims($providerSettings, $token);

		if (!$userClaims || $userClaims->isEmpty()) {
			return $this->handleSSOError($request, $contextPath, OpenIDPlugin::SSO_ERROR_CERTIFICATION);
		}

		$user = $this->getUserViaProviderId($userClaims->id, $selectedProvider);

		if (!$user) {
			$regForm = new OpenIDStep2Form($this->plugin, $selectedProvider, $userClaims);
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

		self::updateUserDetails($this->plugin, $userClaims, $user, $contextData, $selectedProvider, true, true);

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

		$contextPath = OpenIDPlugin::getContextData($request)->getPath();

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
		?UserClaims $claims,
		User $user,
		ContextData $contextData,
		string $selectedProvider,
		bool $setProviderId = false,
		bool $considerDisabledFields = false
	): void 
	{
		$contextId = $contextData->getId();
		$settings = OpenIDPlugin::getOpenIDSettings($plugin, $contextId);

		$disabledFields = $considerDisabledFields ? ($settings['disableFields'] ?? []) : [];

		if (($settings['providerSync'] ?? false) && $claims !== null) {
			$sitePrimaryLocale = $contextData->getPrimaryLocale();

			if (!empty($claims->givenName) && !array_key_exists('givenName', $disabledFields)) {
				$user->setGivenName($claims->givenName, $sitePrimaryLocale);
			}

			if (!empty($claims->familyName) && !array_key_exists('familyName', $disabledFields)) {
				$user->setFamilyName($claims->familyName, $sitePrimaryLocale);
			}

			if (!empty($claims->email) && !array_key_exists('email', $disabledFields) && Repo::user()->getByEmail($claims->email) === null) {
				$user->setEmail($claims->email);
			}

			if (!empty($claims->id) && $selectedProvider === OpenIDPlugin::PROVIDER_ORCID) {
				$user->setOrcid($claims->id);
			}
		}

		$user->setData(OpenIDPlugin::USER_OPENID_LAST_PROVIDER_SETTING, $selectedProvider);

		if ($setProviderId && !empty($claims->id)) {
			$user->setData(OpenIDPlugin::getOpenIDUserSetting($selectedProvider), $claims->id);
			self::updateApiKey($plugin, $contextId, $user, $claims->id, $settings, $selectedProvider);
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
	private function getTokenViaAuthCode(array $providerSettings, string $authorizationCode, string $selectedProvider): ?array
	{
		$httpClient = Application::get()->getHttpClient();
		$params = [
			'code' => $authorizationCode,
			'grant_type' => 'authorization_code',
			'client_id' => $providerSettings['clientId'],
			'client_secret' => $providerSettings['clientSecret'],
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
				$providerSettings['tokenUrl'],
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
	private function getOpenIDAuthenticationCert(?array $providerSettings): ?array
	{
		$httpClient = Application::get()->getHttpClient();
		$publicKeys = [];
		$beginCert = '-----BEGIN CERTIFICATE-----';
		$endCert = '-----END CERTIFICATE----- ';

		try {
			$response = $httpClient->request('GET', $providerSettings['certUrl']);
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
	private function getClaimsFromJwt(array $token, array $publicKeys): ?UserClaims
	{
		foreach ($publicKeys as $publicKey) {
			foreach ($token as $t) {
				try {
					if ($t) {
						$jwtPayload = JWT::decode($t, new \Firebase\JWT\Key($publicKey, 'RS256'));

						if ($jwtPayload) {
							$claimsParams = (array)$jwtPayload;

							$claims = new UserClaims();
							$claims->setValues($claimsParams);

							return $claims;
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
	 * This function gets the user details from the UserInfo endpoint
	 */
	private function getClaimsFromUserInfo(array $providerSettings, array $token): ?UserClaims
	{
		$httpClient = Application::get()->getHttpClient();

		try {
			$response = $httpClient->request(
				'GET',
				$providerSettings['userInfoUrl'],
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

			$userInfo = json_decode($response->getBody()->getContents(), true);

			$claims = new UserClaims();
			$claims->setValues($userInfo);

			return $claims;
		} catch (GuzzleException $e) {
			error_log($this->plugin->getName() . ' - Guzzle Exception thrown: ' . $e->getMessage());
			return null;
		}
	}

	private function getCompleteClaims(array $providerSettings, array $token): ?UserClaims
	{
		$retUserClaims = new UserClaims();

		$publicKey = $this->getOpenIDAuthenticationCert($providerSettings);

		if (!$publicKey) {
			return null;
		}

		$jwtClaims = $this->getClaimsFromJwt($token, $publicKey);

		if ($jwtClaims != null) {
			$retUserClaims->merge($jwtClaims);
		}

		if (!$retUserClaims->isComplete()) {
			$userInfoClaims = $this->getClaimsFromUserInfo($providerSettings, $token);
			$retUserClaims->merge($userInfoClaims); // Merge UserInfo claims into JWT claims
		}

		return $retUserClaims;
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
