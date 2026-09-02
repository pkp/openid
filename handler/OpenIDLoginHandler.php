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

namespace APP\plugins\generic\openid\handler;

use APP\core\Request;
use APP\facades\Repo;
use APP\plugins\generic\openid\classes\ContextData;
use APP\plugins\generic\openid\OpenIDPlugin;
use APP\template\TemplateManager;
use Illuminate\Support\Facades\Http;
use PKP\config\Config;
use PKP\core\PKPApplication;
use PKP\core\PKPRequest;
use PKP\facades\Locale;
use PKP\orcid\OrcidManager;
use PKP\pages\login\LoginHandler;
use PKP\security\Validation;

class OpenIDLoginHandler extends LoginHandler
{
	public function __construct(protected OpenIDPlugin $plugin)
	{
		parent::__construct();
	}

	/**
	 * @see PKPHandler::index($args, $request)
	 */
	function index($args, $request)
	{
		$settings = OpenIDPlugin::getOpenIDSettings($this->plugin, OpenIDPlugin::getContextData($request)->getId());

		if ($settings && !Validation::isLoggedIn()
			&& $this->handleSingleProviderLogin($settings['provider'] ?? [], $settings, $request)) {
			return false;
		}

		return parent::index($args, $request);
	}

	function legacyLogin(array $args, Request $request)
	{
		$this->addRecaptchaScript($request);

		return parent::index($args, $request);
	}

	/**
	 * Registers the reCAPTCHA script for ops other than
	 * login/index and login/signIn, which core handles.
	 */
	private function addRecaptchaScript(PKPRequest $request): void
	{
		if (!Config::getVar('captcha', 'recaptcha') || !Config::getVar('captcha', 'captcha_on_login')) {
			return;
		}

		TemplateManager::getManager($request)->addJavaScript(
			'recaptcha',
			'https://www.recaptcha.net/recaptcha/api.js?hl=' . Locale::getLocale(),
			['contexts' => ['frontend-login-legacyLogin']]
		);
	}

	/**
	 * Overwrites default signOut.
	 * Performs logout and if logoutUrl is provided (e.g. Apple doesn't provide this url) it redirects to the oauth logout to delete session and tokens.
	 */
	function signOut($args, $request)
	{
		if (!Validation::isLoggedIn()) {
			$request->redirect(null, 'index');
			return;
		}

		$contextData = OpenIDPlugin::getContextData($request);

		$contextId = $contextData->getId();

		$settings = OpenIDPlugin::getOpenIDSettings($this->plugin, $contextId);

		$user = $request->getUser() ? Repo::user()->get($request->getUser()->getId()) : null;

		if ($user) {
			$lastProviderValue = $user->getData(OpenIDPlugin::USER_OPENID_LAST_PROVIDER_SETTING);

			if ($lastProviderValue) {
				$user->setData(OpenIDPlugin::USER_OPENID_LAST_PROVIDER_SETTING, null);
				Repo::user()->edit($user);
			}
		}

		$tokenEncrypted = $request->getSession()->get(OpenIDPlugin::ID_TOKEN_NAME);
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
	public static function setSSOErrorMessages(string $ssoError, string $reason, TemplateManager $templateMgr, ContextData $contextData): void
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


	private function handleSingleProviderLogin(array $providerList, array $settings, Request $request): bool
	{
		$legacyLogin = $settings['legacyLogin'] ?? false;
		$legacyRegister = $settings['legacyRegister'] ?? false;

		if (count($providerList) == 1 && !$legacyLogin && !$legacyRegister) {
			$providerSettings = reset($providerList);

			if (!empty($providerSettings['authUrl']) && !empty($providerSettings['clientId'])) {
				$this->redirectToProviderAuth($providerSettings, $request, (string) key($providerList));

				return true;
			}
		}

		return false;
	}

	private function redirectToProviderAuth(array $providerSettings, Request $request, string $providerName): void
	{
		$redirectUri = self::generateRedirectUri($this->plugin, $request, $providerName);
		$redirectUrl = self::generateAuthorizationUrl($providerSettings, $redirectUri, $providerName, $request);

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

	private function isTokenValid(string $token, array $providerSettings): ?bool 
	{
		$introspectionUrl = $providerSettings['introspectionUrl'];

		if (!isset($introspectionUrl)) {
			return null;
		}
		
		$clientId = $providerSettings['clientId'];
		$clientSecret = $providerSettings['clientSecret'];

		$response = Http::asForm()->post($introspectionUrl, [
			'token' => $token,
			'client_id' => $clientId,
			'client_secret' => $clientSecret,
		]);

		$data = $response->json();

		return isset($data['active']) && $data['active']; // Returns true if valid, false otherwise
	}

	public static function generateProviderLinks(
		OpenIDPlugin $plugin,
		array $providerList,
		PKPRequest $request,
		TemplateManager $templateMgr,
		bool $includeLegacyRegister = false
	): array {
		$router = $request->getRouter();
		$linkList = [];

		foreach ($providerList as $provider => $settings) {
			if (!empty($settings['authUrl']) && !empty($settings['clientId'])) {
				$redirectUri = self::generateRedirectUri($plugin, $request, (string) $provider);
				$linkList[$provider] = self::generateAuthorizationUrl($settings, $redirectUri, (string) $provider, $request);
				self::handleCustomProvider($provider, $settings, $templateMgr);
			}
		}

		if ($includeLegacyRegister && !empty($linkList)) {
			$linkList['legacyRegister'] = $router->url($request, null, 'user', 'registerUser');
		}

		return $linkList;
	}

	public static function generateRedirectUri(OpenIDPlugin $plugin, PKPRequest $request, string $providerName): string
	{
		return $request->getDispatcher()->url(
			$request,
			PKPApplication::ROUTE_PAGE,
			newContext: $plugin->isEnabledSitewide() ? 'index' : OpenIDPlugin::getContextData($request)->getPath(),
			handler: 'openid',
			op: 'doAuthentication',
			params: ['provider' => $providerName],
			urlLocaleForPage: '',
		);
	}

	public static function generateAuthorizationUrl(array $providerSettings, string $redirectUri, string $providerName, PKPRequest $request): string
	{
		$state = bin2hex(random_bytes(16));
		$nonce = bin2hex(random_bytes(16));
		$codeVerifier = self::base64UrlEncode(random_bytes(64));

		$session = $request->getSession();
		$pending = $session->get(OpenIDPlugin::SESSION_AUTH_REQUEST);
		$pending = is_array($pending) ? $pending : [];

		$pending[$providerName] = [
			'state' => $state,
			'nonce' => $nonce,
			'codeVerifier' => $codeVerifier,
			'redirectUri' => $redirectUri,
		];

		$session->put(OpenIDPlugin::SESSION_AUTH_REQUEST, $pending);

		return $providerSettings['authUrl'] . '?' . http_build_query([
			'client_id' => $providerSettings['clientId'],
			'response_type' => 'code',
			'scope' => self::generateScope($providerName),
			'redirect_uri' => $redirectUri,
			'state' => $state,
			'nonce' => $nonce,
			'code_challenge' => self::base64UrlEncode(hash('sha256', $codeVerifier, true)),
			'code_challenge_method' => 'S256',
		]);
	}

	private static function generateScope(string $providerName): string
	{
		$scope = 'openid profile email';

		if ($providerName === OpenIDPlugin::PROVIDER_ORCID) {
			$scope .= ' ' . OrcidManager::ORCID_API_SCOPE_PUBLIC;
		}

		return $scope;
	}

	private static function base64UrlEncode(string $bytes): string
	{
		return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
	}

	private static function handleCustomProvider(string $provider, array $settings, TemplateManager $templateMgr): void
	{
		if ($provider == OpenIDPlugin::PROVIDER_CUSTOM) {
			$customBtnTxt = htmlspecialchars($settings['btnTxt'][Locale::getLocale()] ?? '', ENT_QUOTES, 'UTF-8');
			$templateMgr->assign([
				'customBtnImg' => $settings['btnImg'] ?? null,
				'customBtnTxt' => $customBtnTxt
			]);
		}
	}

}
