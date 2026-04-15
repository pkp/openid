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
 * @brief Handler for OpenID workflow using Laravel Socialite:
 *  - receive auth-code via Socialite callback
 *  - Socialite handles token exchange, JWT extraction, UserInfo fetching
 *  - extract user details from Socialite User
 *  - register new accounts
 *  - connect existing accounts
 */

namespace APP\plugins\generic\openid\handler;

use APP\core\Request;
use APP\handler\Handler;
use APP\plugins\generic\openid\classes\ContextData;
use APP\plugins\generic\openid\classes\OpenIDSocialiteProvider;
use APP\plugins\generic\openid\classes\UserClaims;
use APP\plugins\generic\openid\forms\OpenIDStep2Form;
use APP\plugins\generic\openid\OpenIDPlugin;
use APP\template\TemplateManager;
use Exception;
use PKP\config\Config;
use APP\facades\Repo;
use PKP\security\Role;
use PKP\security\Validation;
use PKP\user\User;

class OpenIDHandler extends Handler
{
	public function __construct(protected OpenIDPlugin $plugin)
	{
	}

	public function authorize($request, &$args, $roleAssignments)
	{
		$this->setEnforceRestrictedSite(false);
		return parent::authorize($request, $args, $roleAssignments);
	}

	/**
	 * Callback handler for OpenID authentication.
	 * Uses Laravel Socialite to handle the entire OAuth2/OIDC protocol:
	 * - Token exchange (auth code → access token + id_token)
	 * - UserInfo fetching
	 * - Claim extraction
	 *
	 * Replaces the previous custom Guzzle/JWT/phpseclib implementation.
	 */
	function doAuthentication($args, $request)
	{
		$selectedProvider = $request->getUserVar('provider');

		$contextData = OpenIDPlugin::getContextData($request);
		$contextId = $contextData->getId();
		$contextPath = $contextData->getPath();

		// Handle OAuth errors from the provider
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

		// Build redirect URI — must match EXACTLY what was sent in the auth request.
		// Reconstruct from the current request URL by stripping query parameters.
		$currentUrl = $request->getCompleteUrl();
		$redirectUri = strtok($currentUrl, '?') . '?provider=' . urlencode($selectedProvider);

		try {
			// Create Socialite provider from stored settings
			$socialiteProvider = OpenIDSocialiteProvider::fromSettings($providerSettings, $selectedProvider, $redirectUri);

			// Socialite handles: token exchange, JWT parsing, UserInfo fetching
			$socialiteUser = $socialiteProvider->stateless()->user();

			// Convert Socialite user to our UserClaims
			$userClaims = $socialiteProvider->toUserClaims($socialiteUser);

			if ($userClaims->isEmpty()) {
				return $this->handleSSOError($request, $contextPath, OpenIDPlugin::SSO_ERROR_CERTIFICATION);
			}

			$idToken = $socialiteProvider->getIdToken();
		} catch (Exception $e) {
			error_log($this->plugin->getName() . ' - Socialite exception: ' . $e->getMessage());
			return $this->handleSSOError($request, $contextPath, OpenIDPlugin::SSO_ERROR_CONNECT_KEY);
		}

		$session = $request->getSession();

		$user = $this->getUserViaProviderId($userClaims->id, $selectedProvider);

		if (!$user) {
			$session->put(OpenIDPlugin::ID_TOKEN_NAME, OpenIDPlugin::encryptOrDecrypt($this->plugin, $contextId, $idToken));

			$regForm = new OpenIDStep2Form($this->plugin, $selectedProvider, $userClaims);
			$regForm->initData();
			return $regForm->fetch($request, null, true);
		}

		$reason = null;
		if ($user->getDisabled()) {
			$reason = $user->getDisabledReason();
			return $this->handleSSOError($request, $contextPath, OpenIDPlugin::SSO_ERROR_USER_DISABLED, $reason);
		}

		self::updateUserDetails($this->plugin, $userClaims, $user, $contextData, $selectedProvider, true, true);

		Validation::registerUserSession($user, $reason);



		$session->put(OpenIDPlugin::ID_TOKEN_NAME, OpenIDPlugin::encryptOrDecrypt($this->plugin, $contextId, $idToken));

		// Redirect to appropriate page after login.
		// When site-level: admins go to site admin, others go to profile.
		// When journal-level: editorial roles go to submissions, others to profile.
		if ($this->plugin->isEnabledSitewide() && $user->hasRole([Role::ROLE_ID_SITE_ADMIN], \APP\core\Application::SITE_CONTEXT_ID)) {
			return $request->redirect('index', 'admin');
		} elseif ($contextPath && $user->hasRole(
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
			return $request->redirect($contextPath ?? 'index', 'user', 'profile', $args);
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

		$disabledFields = $settings['disableFields'] ?? [];

		if (($settings['providerSync'] ?? false) && $claims !== null) {
			$sitePrimaryLocale = $contextData->getPrimaryLocale();

			if (!empty($disabledFields['givenName']) && !empty($claims->givenName)) {
				$user->setGivenName($claims->givenName, $sitePrimaryLocale);
			}

			if (!empty($disabledFields['familyName']) && !empty($claims->familyName)) {
				$user->setFamilyName($claims->familyName, $sitePrimaryLocale);
			}

			if (!empty($disabledFields['email']) && !empty($claims->email) && Repo::user()->getByEmail($claims->email) === null) {
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

		// Persist non-localized changes (email, orcid, openid:: settings)
		Repo::user()->edit($user);

	}

	private static function updateApiKey(OpenIDPlugin $plugin, ?int $contextId, User $user, string $providerId, array $settings, string $selectedProvider)
	{
		if ($settings['generateAPIKey'] ?? false) {
			$secret = Config::getVar('security', 'api_key_secret');

			if (!$secret) {
				error_log($plugin->getName() . ' - api_key_secret not defined in configuration file');
				return;
			}

			// Only generate if no API key exists yet
			if (!$user->getData('apiKey')) {
				$user->setData('apiKeyEnabled', true);
				$user->setData('apiKey', OpenIDPlugin::encryptOrDecrypt($plugin, $contextId, $providerId));
			}
		}
	}

	/**
	 * Tries to find a user via OpenID credentials via user settings openid::{provider}
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
