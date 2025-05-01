<?php

/**
 * @file handler/OpenIDLoginHandler.php
 *
 * Copyright (c) 2020 Leibniz Institute for Psychology Information (https://leibniz-psychology.org/)
 * Copyright (c) 2024 Simon Fraser University
 * Copyright (c) 2024 John Willinsky
 * Distributed under the GNU GPL v3. For full terms see the file LICENSE.
 *
 * @class OpenIDLoginHandler
 *
 * @brief Handler to overwrite default OJS/OMP/OPS login and registration
 */

use Illuminate\Support\Facades\Http;

import('classes.handler.Handler');
import('plugins.generic.openid.classes.ContextData');

class OpenIDLoginHandler extends Handler
{
	protected OpenIDPlugin $plugin;

	public function __construct()
	{
		$this->plugin =  PluginRegistry::getPlugin('generic', KEYCLOAK_PLUGIN_NAME);
	}

	// public function __construct(OpenIDPlugin $plugin)
	// {
	// 	$this->plugin = $plugin;
	// }
	/**
	 * This function overwrites the default login.
	 * There a 2 different workflows implemented:
	 * - If only one OpenID provider is configured and legacy login is disabled, the user is automatically redirected to the sign-in page of that provider.
	 * - If more than one provider is configured, a login page is shown within the OJS/OMP/OPS and the user can select his preferred OpenID provider for login/registration.
	 *
	 * In case of an error or incorrect configuration, a link to the default login page is provided to prevent a complete system lockout.
	 *
	 * @param $args
	 * @param $request
	 *
	 * @return false|void
	 */
	function index($args, $request)
	{
		$this->setupTemplate($request);

		if ($this->isSSLRequired($request)) {
			$request->redirectSSL();
		}

		$contextData = OpenIDPlugin::getContextData($request);

		if (Validation::isLoggedIn()) {
			$request->redirect($contextData->getPath(), 'index');
			return false;
		}
		
		$contextId = $contextData->getId();

		$settings = OpenIDPlugin::getOpenIDSettings($this->plugin, $contextId);

		$templateMgr = TemplateManager::getManager($request);

		if ($settings) {
			$providerList = $settings['provider'] ?? [];

			if ($this->handleSingleProviderLogin($providerList, $settings, $request)) {
				return false;
			}

			$linkList = $this->generateProviderLinks($providerList, $request);

			if ($settings['legacyRegister'] ?? false) {
				$linkList['legacyRegister'] = $request->getRouter()->url($request, null, "user", "registerUser");
			}

			if (!empty($linkList)) {
				$templateMgr->assign('linkList', $linkList);
				$this->handleErrors($templateMgr, $request, $contextData);
				$this->handleLegacyLogin($templateMgr, $request, $settings);

				return $templateMgr->display($this->plugin->getTemplateResource('openidLogin.tpl'));
			}
		}

		// Invalid Configuration
		$templateMgr->assign([
			'openidError' => true,
			'errorMsg' => 'plugins.generic.openid.settings.error'
		]);

		return $templateMgr->display($this->plugin->getTemplateResource('openidLogin.tpl'));
	}

	/**
	 * Used for legacy login in case of errors or other bad things.
	 */
	function legacyLogin(array $args, Request $request)
	{
		$templateMgr = TemplateManager::getManager($request);
		$this->_enableLegacyLogin($templateMgr, $request);
		$templateMgr->assign('disableUserReg', true);

		return $templateMgr->display('frontend/pages/userLogin.tpl');
	}

	/**
	 * Overwrites the default registration, because it is not needed anymore.
	 * User registration is done via OpenID provider.
	 */
	function register(array $args, Request $request)
	{
		$this->index($args, $request);
	}

	/**
	 * Overwrites default signOut.
	 * Performs logout and if logoutUrl is provided (e.g. Apple doesn't provide this url) it redirects to the oauth logout to delete session and tokens.
	 */
	function signOut(array $args, Request $request)
	{
		if (!Validation::isLoggedIn()) {
			$request->redirect(null, 'index');
			return;
		}

		$contextData = OpenIDPlugin::getContextData($request);

		$contextId = $contextData->getId();

		$settings = OpenIDPlugin::getOpenIDSettings($this->plugin, $contextId);

		$user = Application::get()->getRequest()->getUser();

		if ($user) {
			$lastProviderValue = $user->getData(OpenIDPlugin::USER_OPENID_LAST_PROVIDER_SETTING);

			if ($lastProviderValue) {
				$userSettingsDao = DAORegistry::getDAO('UserSettingsDAO');
				$userSettingsDao->deleteSetting($user->getId(), OpenIDPlugin::USER_OPENID_LAST_PROVIDER_SETTING);
			}
		}

		$tokenEncrypted = $request->getSession()->getSessionVar(OpenIDPlugin::ID_TOKEN_NAME);
		$token = OpenIDPlugin::encryptOrDecrypt($this->plugin, $contextId, $tokenEncrypted, false);

		Validation::logout();

		if ($settings && isset($lastProviderValue)) {
			$providerSettings = $settings['provider'][$lastProviderValue] ?? [];
			if (!empty($providerSettings['logoutUrl'])) {
				$this->redirectToProviderLogout($request, $providerSettings, $contextData->getPath(), $token);
				return;
			}
		}

		$request->redirect($contextData->getPath(), 'index');
	}

	/**
	 * Sets user friendly error messages, which are thrown during the OpenID auth process.
	 */
	private function _setSSOErrorMessages(string $ssoError, string $reason, TemplateManager $templateMgr, ContextData $contextData): void
	{
		$templateMgr->assign('openidError', true);
		
		$errorMessages = [
			OpenIDPlugin::SSO_ERROR_CONNECT_DATA => 'plugins.generic.openid.error.openid.connect.desc.data',
			OpenIDPlugin::SSO_ERROR_CONNECT_KEY => 'plugins.generic.openid.error.openid.connect.desc.key',
			OpenIDPlugin::SSO_ERROR_CERTIFICATION => 'plugins.generic.openid.error.openid.cert.desc',
			OpenIDPlugin::SSO_ERROR_USER_DISABLED => 'plugins.generic.openid.error.openid.disabled.' . (empty($reason) ? 'without' : 'with'),
			OpenIDPlugin::SSO_ERROR_API_RETURNED => 'plugins.generic.openid.error.openid.api.returned'
		];

		$templateMgr->assign('errorMsg', $errorMessages[$ssoError] ?? '');
		if (in_array($ssoError, [OpenIDPlugin::SSO_ERROR_USER_DISABLED, OpenIDPlugin::SSO_ERROR_API_RETURNED])) {
			$templateMgr->assign('reason', $reason);
			if ($ssoError == OpenIDPlugin::SSO_ERROR_USER_DISABLED) {
				$templateMgr->assign('accountDisabled', true);
			}
		}

		$templateMgr->assign('supportEmail', $contextData->getSupportEmail());
	}

	/**
	 * This function is used
	 *  - if the legacy login is activated via plugin settings,
	 *  - or an error occurred during the Auth process to ensure that the Journal Manager can log in.
	 */
	private function _enableLegacyLogin(TemplateManager $templateMgr, Request $request)
	{
		$loginUrl = $request->url(null, 'login', 'signIn');

		if (Config::getVar('security', 'force_login_ssl')) {
			$loginUrl = preg_replace('/^http:/', 'https:', $loginUrl);
		}

		// Apply htmlspecialchars to encode special characters
		$loginMessage = htmlspecialchars($request->getUserVar('loginMessage'), ENT_QUOTES, 'UTF-8');
		$username = htmlspecialchars($request->getSession()->getSessionVar('username'), ENT_QUOTES, 'UTF-8');
		$remember = htmlspecialchars($request->getUserVar('remember'), ENT_QUOTES, 'UTF-8');
		$source = htmlspecialchars($request->getUserVar('source'), ENT_QUOTES, 'UTF-8');

		$templateMgr->assign([
			'loginMessage' => $loginMessage,
			'username' => $username,
			'remember' => $remember,
			'source' => $source,
			'showRemember' => Config::getVar('general', 'session_lifetime') > 0,
			'legacyLogin' => true,
			'loginUrl' => $loginUrl,
		]);
	}

	private function isSSLRequired(Request $request): bool
	{
		return Config::getVar('security', 'force_login_ssl') && $request->getProtocol() != 'https';
	}

	private function handleSingleProviderLogin(array $providerList, array $settings, Request $request): bool
	{
		$legacyLogin = $settings['legacyLogin'] ?? false;
		$legacyRegister = $settings['legacyRegister'] ?? false;

		if (count($providerList) == 1 && !$legacyLogin && !$legacyRegister) {
			$providerSettings = $providerList[0];
			if (!empty($providerSettings['authUrl']) && !empty($providerSettings['clientId'])) {
				$this->redirectToProviderAuth($providerSettings, $request, key($providerList));
				return true;
			}
		}
		return false;
	}

	private function redirectToProviderAuth(array $providerSettings, Request $request, string $providerName): void
	{
		$router = $request->getRouter();
		$redirectUri = $router->url($request, null, 'openid', 'doAuthentication', null, ['provider' => $providerName]);

		if ($this->plugin->isEnabledSitewide()) {
			$redirectUri = $router->url($request, 'index', 'openid', 'doAuthentication', null, ['provider' => $providerName]);
		}

		$router = $request->getRouter();
		$redirectUrl = $providerSettings['authUrl'] .
			'?client_id=' . urlencode($providerSettings['clientId']) .
			'&response_type=code' .
			'&scope=openid' .
			'&redirect_uri=' . urlencode($redirectUri);

		$request->redirectUrl($redirectUrl);
	}

	private function redirectToProviderLogout(Request $request, array $providerSettings, ?string $contextPath, ?string $token = null): void
	{
		$router = $request->getRouter();
		$redirectUrl = $router->url($request, $contextPath, "index");

		if ($this->plugin->isEnabledSitewide()) {
			$redirectUrl = $request->url('index');
		}

		$logoutUrl = $providerSettings['logoutUrl']
			. '?client_id=' . urlencode($providerSettings['clientId'])
			. '&post_logout_redirect_uri=' . urlencode($redirectUrl);

		if (isset($token) && $this->isTokenValid($token, $providerSettings)) {
			$logoutUrl = $logoutUrl. '&id_token_hint=' . urlencode($token);
		}

		$request->redirectUrl($logoutUrl);
	}

	/**
	 * Validates an access token by calling the provider's introspection endpoint.
	 *
	 * Uses the configured client credentials and introspection URL to check whether the token is active.
	 * Returns true if the token is valid, false if it's inactive, and null if no introspection URL is defined.
	 *
	 * @param string $token The access token to validate.
	 * @param array $providerSettings An array of OpenID provider settings including 'clientId', 'clientSecret', and 'introspectionUrl'.
	 *
	 * @return bool|null True if the token is active, false if inactive, or null if the introspection URL is not set.
	*/
	private function isTokenValid(string $token, array $providerSettings): ?bool 
	{
		if (empty($providerSettings['introspectionUrl'])) {
			return null;
		}

		return $this->introspectToken(
			$providerSettings['introspectionUrl'],
			$token,
			$providerSettings['clientId'],
			$providerSettings['clientSecret']
		);
	}

	/**
	 * Perform token introspection against an OAuth2/OpenID Connect provider.
	 *
	 * Sends a POST request to the given introspection endpoint with the token
	 * and client credentials, and returns whether the token is active.
	 *
	 * @param string $introspectionUrl The URL of the token introspection endpoint.
	 * @param string $token The access token to introspect.
	 * @param string $clientId The client ID registered with the provider.
	 * @param string $clientSecret The client secret associated with the client ID.
	 *
	 * @return bool True if the token is active; false otherwise.
	*/
	private function introspectToken(string $introspectionUrl, string $token, string $clientId, string $clientSecret): bool
	{
		$httpClient = Application::get()->getHttpClient();
		$params = [
			'token' => $token,
			'client_id' => $clientId,
			'client_secret' => $clientSecret,
		];

		try {
			$response = $httpClient->request('POST', $introspectionUrl, [
				'headers' => ['Accept' => 'application/json'],
				'form_params' => $params,
			]);

			if ($response->getStatusCode() !== 200) {
				error_log('Token introspection failed with status code: ' . $response->getStatusCode());
				return false;
			}

			$data = json_decode($response->getBody()->getContents(), true);
			return isset($data['active']) && $data['active'];

		} catch (\GuzzleHttp\Exception\GuzzleException $e) {
			error_log('Token introspection Guzzle error: ' . $e->getMessage());
			return false;
		}
	}

	private function generateProviderLinks(array $providerList, Request $request): array
	{
		$router = $request->getRouter();
		$linkList = [];

		foreach ($providerList as $provider => $settings) {
			if (!empty($settings['authUrl']) && !empty($settings['clientId'])) {
				$redirectUri = $router->url($request, null, 'openid', 'doAuthentication', null, ['provider' => $provider]);

				if ($this->plugin->isEnabledSitewide()) {
					$redirectUri = $router->url($request, 'index', 'openid', 'doAuthentication', null, ['provider' => $provider]);
				}

				$baseLink = "{$settings['authUrl']}?client_id={$settings['clientId']}&response_type=code&scope=openid profile email";
				$linkList[$provider] = "{$baseLink}&redirect_uri=" . urlencode($redirectUri);
				$this->handleCustomProvider($provider, $settings, TemplateManager::getManager($request));
			}
		}
		return $linkList;
	}

	private function handleCustomProvider(string $provider, array $settings, TemplateManager $templateMgr): void
	{
		if ($provider == OpenIDPlugin::PROVIDER_CUSTOM) {
			$customBtnTxt = htmlspecialchars($settings['btnTxt'][AppLocale::getLocale()] ?? '', ENT_QUOTES, 'UTF-8');
			$templateMgr->assign([
				'customBtnImg' => $settings['btnImg'] ?? null,
				'customBtnTxt' => $customBtnTxt
			]);
		}
	}

	private function handleErrors(TemplateManager $templateMgr, Request $request, ContextData $contextData): void
	{
		$ssoError = $request->getUserVar('sso_error');
		$reason = htmlspecialchars($request->getUserVar('sso_error_msg') ?? '', ENT_QUOTES, 'UTF-8');

		if ($ssoError) {
			$this->_setSSOErrorMessages($ssoError, $reason, $templateMgr, $contextData);
		}
	}

	private function handleLegacyLogin(TemplateManager $templateMgr, Request $request, array $settings): void
	{
		if ($settings['legacyLogin'] ?? false) {
			$this->_enableLegacyLogin($templateMgr, $request);
		}
	}
}
