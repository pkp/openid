<?php

/**
 * @file OpenIDPlugin.php
 *
 * Copyright (c) 2020 Leibniz Institute for Psychology Information (https://leibniz-psychology.org/)
 * Copyright (c) 2024 Simon Fraser University
 * Copyright (c) 2024 John Willinsky
 * Distributed under the GNU GPL v3. For full terms see the file LICENSE.
 *
 * @class OpenIDPlugin
 *
 * @brief OpenIDPlugin class for plugin and handler registration
 */

use Illuminate\Support\Collection;

import('lib.pkp.classes.plugins.GenericPlugin');
import('plugins.generic.openid.classes.ContextData');
import('plugins.generic.openid.forms.OpenIDPluginSettingsForm');

class OpenIDPlugin extends GenericPlugin
{
	public const USER_OPENID_IDENTIFIER_SETTING_BASE = 'openid::';
	public const USER_OPENID_LAST_PROVIDER_SETTING = self::USER_OPENID_IDENTIFIER_SETTING_BASE . 'lastProvider';

	// OpenIDProviders
	public const PROVIDER_CUSTOM = 'custom';
	public const PROVIDER_ORCID = 'orcid';
	public const PROVIDER_GOOGLE = 'google';
	public const PROVIDER_MICROSOFT = 'microsoft';
	public const PROVIDER_APPLE = 'apple';

	// SSOErrors
	public const SSO_ERROR_CONNECT_DATA = 'connect_data';
	public const SSO_ERROR_CONNECT_KEY = 'connect_key';
	public const SSO_ERROR_CERTIFICATION = 'cert';
	public const SSO_ERROR_USER_DISABLED = 'disabled';
	public const SSO_ERROR_API_RETURNED = 'api_returned';

	// MicrosoftAudiences
	public const MICROSOFT_AUDIENCE_COMMON = 'common';
	public const MICROSOFT_AUDIENCE_CONSUMERS = 'consumers';
	public const MICROSOFT_AUDIENCE_ORGANIZATIONS = 'organizations';

	/**
	 * List of OpenID provider.
	 */
	public static Collection $publicOpenidProviders;

	public const ID_TOKEN_NAME = 'id_token';

	public function __construct() 
	{
		self::$publicOpenidProviders = collect([
			self::PROVIDER_CUSTOM => "",
			self::PROVIDER_ORCID => ["configUrl" => "https://orcid.org/.well-known/openid-configuration"],
			self::PROVIDER_GOOGLE => ["configUrl" => "https://accounts.google.com/.well-known/openid-configuration"],
			self::PROVIDER_MICROSOFT => ["configUrl" => "https://login.windows.net/{audience}/v2.0/.well-known/openid-configuration"],
			self::PROVIDER_APPLE => ["configUrl" => "https://appleid.apple.com/.well-known/openid-configuration"],
		]);
	}

	/**
	 * Replace the given provider's {$setting} placeholder in the configUrl with the provided value.
	 */
	public static function prepareMicrosoftConfigUrl(string $audience): string
	{
		return str_replace(
			'{audience}', 
			$audience, 
			self::$publicOpenidProviders->get(self::PROVIDER_MICROSOFT)['configUrl']
		);
	}

	function isSitePlugin()
	{
		return true;
	}
	/**
	 * Get the display name of this plugin
	 * @return string
	 */
	function getDisplayName()
	{
		return __('plugins.generic.openid.name');
	}

	/**
	 * Get the description of this plugin
	 * @return string
	 */
	function getDescription()
	{
		return __('plugins.generic.openid.description');
	}

	function getCanEnable()
	{
		// this plugin can't be enabled if it is already configured for the context == 0
		if ($this->getCurrentContextId() != 0 && $this->getSetting(0, 'enabled')) {
			return false;
		}
		return true;
	}

	/**
	 * @copydoc LazyLoadPlugin::getCanDisable()
	 */
	function getCanDisable()
	{
		// this plugin can't be disabled if it is already configured for the context == 0
		if ($this->getCurrentContextId() != 0 && $this->getSetting(0, 'enabled')) {
			return false;
		}

		return true;
	}

	/**
	 * We need to override the method to make sure that the plugin works as a sitewide and journal-scoped plugin
	 */
	function setEnabled($enabled)
	{
		$contextId = $this->getCurrentContextId();
		$this->updateSetting($contextId, 'enabled', $enabled, 'bool');
	}

	/**
	 * We need to override the method to make sure that the plugin works as a sitewide and journal-scoped plugin
	 */
	function getEnabled($contextId = null)
	{
		if ($contextId === null) {
			$contextId = $this->getCurrentContextId();
		}
		return $this->getSetting($contextId, 'enabled');
	}

		/**
	 * @copydoc Plugin::getSetting()
	 */
	function getSetting($contextId, $name)
	{
		if (parent::getSetting(0, 'enabled')) {
			return parent::getSetting(0, $name);
		} else {
			return parent::getSetting($contextId, $name);
		}
	}

	/**
	 * Register the plugin, if enabled
	 *
	 * @param $category
	 * @param $path
	 * @param $mainContextId
	 * @return true on success
	 */
	public function register($category, $path, $mainContextId = null)
	{
		$success = parent::register($category, $path, $mainContextId);
		$contextId = $this->getCurrentContextId();

		if ($success && $this->getEnabled($contextId)) {
			$request = Application::get()->getRequest();
			$settings = json_decode($this->getSetting($contextId, 'openIDSettings'), true);
			$user = $request->getUser();

			if ($user && $user->getData('openid::lastProvider') && isset($settings)
				&& key_exists('disableFields', $settings) && key_exists('providerSync', $settings) && $settings['providerSync'] == 1) {
				$templateMgr = TemplateManager::getManager($request);
				$settings['disableFields']['lastProvider'] = $user->getData('openid::lastProvider');
				$settings['disableFields']['generateAPIKey'] = $settings['generateAPIKey'];
				$templateMgr->assign('openIdDisableFields', $settings['disableFields']);
				HookRegistry::register('TemplateResource::getFilename', array($this, '_overridePluginTemplates'));
			}

			HookRegistry::register('LoadHandler', array($this, 'setPageHandler'));
		}

		return $success;
	}

	/**
	 * Loads Handler for login, registration, sign-out and the plugin specific urls.
	 * Adds JavaScript and Style files to the template.
	 *
	 * @param $hookName
	 * @param $args
	 * @return false
	 */
	public function setPageHandler(string $hookName, array $params): bool
	{
		$page = $params[0];
		$op = $params[1];
		$request = Application::get()->getRequest();
		$templateMgr = TemplateManager::getManager($request);

		define('KEYCLOAK_PLUGIN_NAME', $this->getName());

		$templateMgr->addStyleSheet('OpenIDPluginStyle', $request->getBaseUrl().'/'.$this->getPluginPath().'/css/style.css');
		$templateMgr->addJavaScript('OpenIDPluginScript', $request->getBaseUrl().'/'.$this->getPluginPath().'/js/scripts.js');
		$templateMgr->assign('openIDImageURL', $request->getBaseUrl().'/'.$this->getPluginPath().'/images/');

		switch ("$page/$op") {
			case 'openid/doAuthentication':
			case 'openid/registerOrConnect':
				define('HANDLER_CLASS', 'OpenIDHandler');
				$params[2] = $this->getPluginPath().'/handler/OpenIDHandler.inc.php';
				break;
			case 'login/index':
			case 'login/legacyLogin':
			case 'login/signOut':
				define('HANDLER_CLASS', 'OpenIDLoginHandler');
				$params[2] = $this->getPluginPath().'/handler/OpenIDLoginHandler.inc.php';
				break;
			case 'user/register':
				if (!$request->isPost()) {
					define('HANDLER_CLASS', 'OpenIDLoginHandler');
					$params[2] = $this->getPluginPath().'/handler/OpenIDLoginHandler.inc.php';
					break;
				}
				break;
		}

		return false;
	}

	/**
	 * @copydoc Plugin::getActions($request, $actionArgs)
	 */
	public function getActions($request, $actionArgs)
	{
		$actions = parent::getActions($request, $actionArgs);

		if (($this->getEnabled(0) && $this->getCurrentContextId() != 0) || (!$this->getEnabled())) {
			return $actions;
		}

		$router = $request->getRouter();
		$linkAction = new LinkAction(
			'settings',
			new AjaxModal(
				$router->url(
					$request,
					null,
					null,
					'manage',
					null,
					[
						'verb' => 'settings',
						'plugin' => $this->getName(),
						'category' => 'generic',
					]
				),
				$this->getDisplayName()
			),
			__('manager.plugins.settings'),
			null
		);
		array_unshift($actions, $linkAction);

		return $actions;
	}

	/**
	 * @copydoc Plugin::manage($args, $request)
	 */
	public function manage($args, $request)
	{
		switch ($request->getUserVar('verb')) {
			case 'settings':
				$form = new OpenIDPluginSettingsForm($this);

				if (!$request->getUserVar('save')) {
					$form->initData();

					return new JSONMessage(true, $form->fetch($request));
				}

				$form->readInputData();
				if ($form->validate()) {
					$form->execute();

					return new JSONMessage(true);
				}
		}

		return parent::manage($args, $request);
	}

	// /**
	//  * @param $templateMgr
	//  * @param $request
	//  * @param $args
	//  */
	// private function _addScriptsAndHandler($templateMgr, $request, $args): void
	// {
	// 	$templateMgr->addStyleSheet('OpenIDPluginStyle', $request->getBaseUrl().'/'.$this->getPluginPath().'/css/style.css');
	// 	$templateMgr->addJavaScript('OpenIDPluginScript', $request->getBaseUrl().'/'.$this->getPluginPath().'/js/scripts.js');
	// 	$templateMgr->assign('openIDImageURL', $request->getBaseUrl().'/'.$this->getPluginPath().'/images/');
	// 	define('HANDLER_CLASS', 'OpenIDLoginHandler');
	// 	$args[2] = $this->getPluginPath().'/handler/OpenIDLoginHandler.inc.php';
	// }

	public static function getOpenIDSettings(OpenIDPlugin $plugin, int $contextId): ?array
	{
		$settingsJson = $plugin->getSetting($contextId, 'openIDSettings');
		return $settingsJson ? json_decode($settingsJson, true) : null;
	}

	public static function getContextData(PKPRequest $request): ContextData
	{
		$context = $request->getContext();
		$site = $request->getSite();

		return new ContextData($site, $context);
	}

	public static function getOpenIDUserSetting(string $provider): string
	{
		return OpenIDPlugin::USER_OPENID_IDENTIFIER_SETTING_BASE . $provider;
	}

	/**
	 * De-/Encrypt function to hide some important things.
	 */
	public static function encryptOrDecrypt(OpenIDPlugin $plugin, int $contextId, ?string $string, bool $encrypt = true): ?string
	{
		if (!isset($string)) {
			return null;
		}

		$settings = OpenIDPlugin::getOpenIDSettings($plugin, $contextId);

		if (!isset($settings['hashSecret'])) {
			return $string;
		}

		$pwd = $settings['hashSecret'];
		
		$iv = substr($pwd, 0, 16);
		$alg = 'AES-256-CBC';

		return $encrypt
			? openssl_encrypt($string, $alg, $pwd, 0, $iv)
			: openssl_decrypt($string, $alg, $pwd, 0, $iv);
	}

	/**
	 * Returns whether the plugin is enabled sitewide
	 */
	function isEnabledSitewide()
	{
		return parent::getSetting(0, 'enabled');
	}
}

