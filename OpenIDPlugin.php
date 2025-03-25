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

namespace APP\plugins\generic\openid;

use APP\core\Application;
use APP\facades\Repo;
use APP\plugins\generic\openid\classes\ContextData;
use APP\plugins\generic\openid\forms\OpenIDPluginSettingsForm;
use APP\plugins\generic\openid\handler\OpenIDHandler;
use APP\plugins\generic\openid\handler\OpenIDLoginHandler;
use Illuminate\Support\Collection;
use PKP\core\PKPApplication;
use PKP\core\PKPRequest;
use PKP\linkAction\LinkAction;
use PKP\linkAction\request\AjaxModal;
use PKP\plugins\GenericPlugin;
use PKP\plugins\Hook;
use PKP\core\JSONMessage;
use APP\template\TemplateManager;

require_once(dirname(__FILE__) . '/vendor/autoload.php');

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
		// this plugin can't be enabled if it is already configured for the context == PKPApplication::CONTEXT_SITE
		if ($this->getCurrentContextId() != PKPApplication::CONTEXT_SITE && $this->getSetting(PKPApplication::CONTEXT_SITE, 'enabled')) {
			return false;
		}
		return true;
	}

	/**
	 * @copydoc LazyLoadPlugin::getCanDisable()
	 */
	function getCanDisable()
	{
		// this plugin can't be disabled if it is already configured for the context == PKPApplication::CONTEXT_SITE
		if ($this->getCurrentContextId() != PKPApplication::CONTEXT_SITE && $this->getSetting(PKPApplication::CONTEXT_SITE, 'enabled')) {
			return false;
		}

		return true;
	}

	/**
	 * @copydoc LazyLoadPlugin::setEnabled($enabled)
	 */
	function setEnabled($enabled)
	{
		$contextId = $this->getCurrentContextId();
		$this->updateSetting($contextId, 'enabled', $enabled, 'bool');
	}

	/**
	 * @copydoc LazyLoadPlugin::getEnabled()
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
		if (parent::getSetting(PKPApplication::CONTEXT_SITE, 'enabled')) {
			return parent::getSetting(PKPApplication::CONTEXT_SITE, $name);
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
			Hook::add('Schema::get::before::user', [$this, 'beforeGetSchema']);
			Hook::add('Schema::get::user', [$this, 'addToSchema']);
			Hook::add('User::edit', [$this, 'addIdpInfoToUser']);

			$settings = OpenIDPlugin::getOpenIDSettings($this, $contextId);
			if ($settings && isset($settings['provider']) && is_array($settings['provider']) && !empty($settings['provider'])) {
				$request = Application::get()->getRequest();

				$settings = OpenIDPlugin::getOpenIDSettings($this, $contextId);
				$requestUser = $request->getUser();

				$user = null;
				if ($requestUser) {
					$user = Repo::user()->get($request->getUser()->getId());
				}

				$lastProvider = null;
				if ($user) {
					$lastProvider = $user->getData(OpenIDPlugin::USER_OPENID_LAST_PROVIDER_SETTING);
				}

				if ($lastProvider && isset($settings)
					&& ($settings['disableFields'] ?? false) && ($settings['providerSync'] ?? false)) {
					
					$settings['disableFields']['lastProvider'] = $lastProvider;
					$settings['disableFields']['generateAPIKey'] = $settings['generateAPIKey'];
					
					$templateMgr = TemplateManager::getManager($request);
					$templateMgr->assign('openIdDisableFields', $settings['disableFields']);
					
					Hook::add('TemplateResource::getFilename', [$this, '_overridePluginTemplates']);
				}

				Hook::add('LoadHandler', [$this, 'setPageHandler']);
			}
		}

		return $success;
	}

	/**
	 * Add properties for OpenId to the User entity for storage in the database.
	 *
	 * @param string $hookName `Schema::get::user`
	 * @param array $args [
	 *
	 *      @option stdClass $schema
	 * ]
	 *
	 */
	public function addToSchema(string $hookName, array $args): bool
	{
		$schema = &$args[0];

		$pluginSpecificFields = $this->getPluginSpecificFields();

		foreach ($pluginSpecificFields as $pluginSpecificField) {
			$schema->properties->{$pluginSpecificField} = (object) [
				'type' => 'string',
				'apiSummary' => true,
				'validation' => ['nullable'],
			];
		}

		return false;
	}

	public function getPluginSpecificFields(): array
	{
		$pluginSpecificFields = [
			OpenIDPlugin::USER_OPENID_LAST_PROVIDER_SETTING,
		];

		$providers = OpenIDPlugin::$publicOpenidProviders;
		foreach ($providers as $key => $value) {
			$pluginSpecificFields[] = OpenIDPlugin::getOpenIDUserSetting($key);
		}

		return $pluginSpecificFields;
	}

	/**
	 * Manage force reload of this schema.
	 *
	 * @param string $hookName `Schema::get::before::user`
	 * @param array $args [
	 *
	 *      @option bool $forceReload
	 * ]
	 *
	 */
	public function beforeGetSchema(string $hookName, bool &$forceReload): bool
	{
		$forceReload = true;

		return false;
	}

	/**
	 * Manage force reload of this schema.
	 *
	 * @param string $hookName `Schema::get::before::user`
	 * @param array $args [
	 *
	 *      @option User $newUser
	 *      @option User $user
	 *      @option array $params
	 * ]
	 *
	 */
	public function addIdpInfoToUser(string $hookName, array $args): bool
	{
		$newUser = $args[0];

		$dbUser = Repo::user()->get($newUser->getId());

		$pluginSpecificFields = $this->getPluginSpecificFields();

		foreach ($pluginSpecificFields as $pluginSpecificField) {
			$dbUserFieldValue = $dbUser->getData($pluginSpecificField);
			$newUserFieldValue = $newUser->getData($pluginSpecificField);
			if (isset($dbUserFieldValue) && !isset($newUserFieldValue)) {
				$newUser->setData($pluginSpecificField, $dbUserFieldValue);
			}
		}

		return false;
	}

	/**
	 * Loads Handler for login, registration, sign-out and the plugin specific urls.
	 * Adds JavaScript and Style files to the template.
	 */
	public function setPageHandler(string $hookName, array $params): bool
	{
		$page = $params[0];
		$op = $params[1];
		$request = Application::get()->getRequest();
		$templateMgr = TemplateManager::getManager($request);

		$handler = & $params[3];

		$templateMgr->addStyleSheet('OpenIDPluginStyle', $request->getBaseUrl().'/'.$this->getPluginPath().'/css/style.css');
		$templateMgr->addJavaScript('OpenIDPluginScript', $request->getBaseUrl().'/'.$this->getPluginPath().'/js/scripts.js');
		$templateMgr->assign('openIDImageURL', $request->getBaseUrl().'/'.$this->getPluginPath().'/images/');

		switch ("$page/$op") {
			case 'openid/doAuthentication':
			case 'openid/registerOrConnect':
				$handler = new OpenIDHandler($this);
				return true;
			case 'login/index':
			case 'login/legacyLogin':
			case 'login/signOut':
				$handler = new OpenIDLoginHandler($this);
				return true;
			case 'user/register':
				if (!$request->isPost()) {
					$handler = new OpenIDLoginHandler($this);
					return true;
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

		if (($this->getEnabled(PKPApplication::CONTEXT_SITE) && $this->getCurrentContextId() != PKPApplication::CONTEXT_SITE) || (!$this->getEnabled())) {
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
		return parent::getSetting(PKPApplication::CONTEXT_SITE, 'enabled');
	}
}

