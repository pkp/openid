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
use Illuminate\Support\Facades\Crypt;
use Illuminate\Contracts\Encryption\DecryptException;
use Illuminate\Contracts\Encryption\EncryptException;
use PKP\core\PKPApplication;
use PKP\core\PKPRequest;
use PKP\form\FormBuilderVocabulary;
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
        // this plugin can't be enabled if it is already configured for the context == Application::SITE_CONTEXT_ID
        if ($this->getCurrentContextId() != Application::SITE_CONTEXT_ID && $this->getSetting(Application::SITE_CONTEXT_ID, 'enabled')) {
            return false;
        }
        return true;
    }

    /**
     * @copydoc LazyLoadPlugin::getCanDisable()
     */
    function getCanDisable()
    {
        // this plugin can't be disabled if it is already configured for the context == Application::SITE_CONTEXT_ID
        if ($this->getCurrentContextId() != Application::SITE_CONTEXT_ID && $this->getSetting(Application::SITE_CONTEXT_ID, 'enabled')) {
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
        // getEnabled() was called with no arguments
        if (func_num_args() === 0) {
            $contextId = $this->getCurrentContextId();
        }

        // getEnabled(Application::SITE_CONTEXT_ID) was called
        if ($contextId === Application::SITE_CONTEXT_ID) {
            $contextId = Application::SITE_CONTEXT_ID;
        }

        // Regular behavior
        return $this->getSetting($contextId, 'enabled');
    }

    /**
     * @copydoc Plugin::getSetting()
     */
    function getSetting($contextId, $name)
    {
        if (parent::getSetting(Application::SITE_CONTEXT_ID, 'enabled')) {
            return parent::getSetting(Application::SITE_CONTEXT_ID, $name);
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

                // Register Blade view namespace for this plugin
                app('view')->addNamespace('openid', $this->getPluginPath() . '/resources/views');

                if ($lastProvider && isset($settings)
                    && ($settings['disableFields'] ?? false) && ($settings['providerSync'] ?? false)) {
                    
                    $disableFields = $settings['disableFields'];
                    
                    // Assign $fieldReadonly array — fbvElement auto-checks this
                    // to make fields readonly without any template changes
                    $readonlyFields = [];
                    if (!empty($disableFields['givenName'])) $readonlyFields['givenName'] = true;
                    if (!empty($disableFields['familyName'])) $readonlyFields['familyName'] = true;
                    if (!empty($disableFields['email'])) $readonlyFields['email'] = true;

                    $templateMgr = TemplateManager::getManager($request);
                    $templateMgr->assign(FormBuilderVocabulary::TPL_VAR_FIELD_READONLY, $readonlyFields);
                    
                    $this->registerProfileHooks($settings, $lastProvider);
                }

                Hook::add('LoadHandler', [$this, 'setPageHandler']);
                $this->registerLoginHooks($request, $settings, $contextId);
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

        // Server-side protection: if fields are managed by IdP, reject any changes
        $lastProvider = $dbUser->getData(OpenIDPlugin::USER_OPENID_LAST_PROVIDER_SETTING);
        if ($lastProvider) {
            $contextId = $this->getCurrentContextId();
            $settings = OpenIDPlugin::getOpenIDSettings($this, $contextId);
            if (($settings['providerSync'] ?? false) && ($settings['disableFields'] ?? false)) {
                $df = $settings['disableFields'];
                if (!empty($df['givenName'])) {
                    $newUser->setData('givenName', $dbUser->getData('givenName'));
                }
                if (!empty($df['familyName'])) {
                    $newUser->setData('familyName', $dbUser->getData('familyName'));
                }
                if (!empty($df['email'])) {
                    $newUser->setEmail($dbUser->getEmail());
                }
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

        // `contexts` must include `backend` so the stylesheet also loads on
        // admin-area pages (e.g. /user/profile), not just the frontend login page.
        $templateMgr->addStyleSheet(
            'OpenIDPluginStyle',
            $request->getBaseUrl().'/'.$this->getPluginPath().'/css/style.css',
            ['contexts' => ['frontend', 'backend']]
        );
        $templateMgr->addJavaScript('OpenIDPluginScript', $request->getBaseUrl().'/'.$this->getPluginPath().'/js/scripts.js');
        $templateMgr->assign('openIDImageURL', $request->getBaseUrl().'/'.$this->getPluginPath().'/images/');

        switch ("$page/$op") {
            case 'openid/doAuthentication':
            case 'openid/registerOrConnect':
                $handler = new OpenIDHandler($this);
                return true;
            case 'login/signOut':
                $handler = new OpenIDLoginHandler($this);
                return true;
        }

        return false;
    }

    /**
     * Register hooks for injecting OpenID login buttons via Blade.
     */
    private function registerLoginHooks(PKPRequest $request, array $settings, ?int $contextId): void
    {
        $providerList = $settings['provider'] ?? [];
        $imageUrl = $request->getBaseUrl() . '/' . $this->getPluginPath() . '/images/';
        $contextData = self::getContextData($request);
        $dispatcher = $request->getDispatcher();

        $providers = [];
        foreach ($providerList as $provider => $providerSettings) {
            if (empty($providerSettings['authUrl']) || empty($providerSettings['clientId'])) continue;

            $contextPath = $this->isEnabledSitewide() ? 'index' : ($contextData->getPath() ?? 'index');
            $redirectUri = $dispatcher->url($request, PKPApplication::ROUTE_PAGE, $contextPath, 'openid', 'doAuthentication', null, ['provider' => $provider]);

            $authLink = self::buildAuthorizationUrl($providerSettings, $redirectUri);

            $label = ($provider === self::PROVIDER_CUSTOM)
                ? ($providerSettings['btnTxt'][\PKP\facades\Locale::getLocale()] ?? $providerSettings['btnTxt']['en'] ?? __('plugins.generic.openid.select.provider.custom'))
                : __('plugins.generic.openid.select.provider.' . $provider);

            $providers[] = [
                'name' => $provider,
                'url' => $authLink,
                'label' => $label,
                'img' => (!empty($providerSettings['btnImg']) && $provider === self::PROVIDER_CUSTOM)
                    ? $providerSettings['btnImg']
                    : $imageUrl . $provider . '-sign-in.png',
            ];
        }

        if (empty($providers)) return;

        $heading = __('plugins.generic.openid.select.provider.help');

        $plugin = $this;
        Hook::add('Templates::Login::BeforeForm', function ($hookName, $args) use ($providers, $heading, $plugin) {
            $plugin->loadStylesheet();
            $output = &$args[2];
            $output .= view('openid::login-providers', [
                'providers' => $providers,
                'heading' => $heading,
            ])->render();
            return false;
        });
    }

    /**
     * Build an OpenID Connect authorization URL for a provider.
     *
     * @param array $providerSettings Provider settings (must include 'authUrl' and 'clientId')
     * @param string $redirectUri Callback URL after authentication
     */
    public static function buildAuthorizationUrl(array $providerSettings, string $redirectUri): string
    {
        return $providerSettings['authUrl'] . '?' . http_build_query([
            'client_id' => $providerSettings['clientId'],
            'response_type' => 'code',
            'scope' => 'openid profile email',
            'redirect_uri' => $redirectUri,
        ]);
    }

    /**
     * Load the plugin stylesheet into the current page.
     * Safe to call multiple times (same id overwrites).
     */
    public function loadStylesheet(): void
    {
        $request = Application::get()->getRequest();
        $templateMgr = TemplateManager::getManager($request);
        $templateMgr->addStyleSheet(
            'OpenIDPluginStyle',
            $request->getBaseUrl() . '/' . $this->getPluginPath() . '/css/style.css',
            ['contexts' => ['frontend', 'backend']]
        );
    }

    /**
     * Register hooks for profile field protection via Blade.
     */
    private function registerProfileHooks(array $settings, string $lastProvider): void
    {
        $disableFields = $settings['disableFields'] ?? [];
        $message = __('plugins.generic.openid.disables.fields.info');

        // Identity form: show provider-specific notification listing managed fields
        if (!empty($disableFields['givenName']) || !empty($disableFields['familyName'])) {
            $plugin = $this;
            Hook::add('Templates::Identity::BeforeFields', function ($hookName, $args) use ($lastProvider, $disableFields, $plugin) {
                $plugin->loadStylesheet();
                $output = &$args[2];
                $providerLabel = __('plugins.generic.openid.provider.name.' . $lastProvider);
                
                $fieldNames = [];
                if (!empty($disableFields['givenName'])) $fieldNames[] = __('user.givenName');
                if (!empty($disableFields['familyName'])) $fieldNames[] = __('user.familyName');
                $fieldList = implode(', ', $fieldNames);
                
                $output .= view('openid::partials.field-notice', [
                    'message' => __('plugins.generic.openid.disables.fields.info.identity.provider', [
                        'provider' => $providerLabel,
                        'fields' => $fieldList,
                    ]),
                ])->render();

                return false;
            });
        }

        // Contact form: email notification
        if (!empty($disableFields['email'])) {
            $plugin = $this;
            Hook::add('Templates::Contact::BeforeFields', function ($hookName, $args) use ($lastProvider, $plugin) {
                $plugin->loadStylesheet();
                $output = &$args[2];
                $providerLabel = __('plugins.generic.openid.provider.name.' . $lastProvider);

                $output .= view('openid::partials.field-notice', [
                    'message' => __('plugins.generic.openid.disables.fields.info.identity.provider', [
                        'provider' => $providerLabel,
                        'fields' => __('user.email'),
                    ]),
                ])->render();

                return false;
            });
        }

        // Password form: show provider-specific notification and hide form
        $plugin = $this;
        Hook::add('Templates::Password::BeforeFields', function ($hookName, $args) use ($lastProvider, $plugin) {
            $plugin->loadStylesheet();
            $templateMgr = $args[1];
            $output = &$args[2];
            
            $providerLabel = __('plugins.generic.openid.provider.name.' . $lastProvider);
            $passwordMessage = __('plugins.generic.openid.disables.fields.info.password.provider', ['provider' => $providerLabel]);

            $output .= view('openid::partials.field-notice', ['message' => $passwordMessage])->render();
            // Hide ONLY the changePassword form area, not anything else that may render later in the tab.
            $templateMgr->assign(FormBuilderVocabulary::TPL_VAR_FORM_HIDDEN, ['changePasswordFormArea' => true]);

            return false;
        });

        // API form: show notification if generateAPIKey is enabled
        if (!empty($settings['generateAPIKey'])) {
            $plugin = $this;
            Hook::add('Templates::APIKey::BeforeFields', function ($hookName, $args) use ($plugin) {
                $plugin->loadStylesheet();
                $output = &$args[2];

                $output .= view('openid::partials.field-notice', [
                    'message' => __('plugins.generic.openid.disables.fields.info.api'),
                ])->render();

                return false;
            });
        }
    }

    /**
     * @copydoc Plugin::getActions($request, $actionArgs)
     */
    public function getActions($request, $actionArgs)
    {
        $actions = parent::getActions($request, $actionArgs);

        $currentContextId = $this->getCurrentContextId();
        $siteWideEnabled = $this->getEnabled(Application::SITE_CONTEXT_ID);

        if ($siteWideEnabled && $currentContextId != Application::SITE_CONTEXT_ID) {
            return $actions;
        }

        if (!$siteWideEnabled && !$this->getEnabled($currentContextId)) {
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

    public static function getOpenIDSettings(OpenIDPlugin $plugin, ?int $contextId = null): ?array
    {
        $settingsJson = $plugin->getSetting($contextId, 'openIDSettings');
        $settings = $settingsJson ? json_decode($settingsJson, true) : null;

        // Decrypt client secrets
        if ($settings && isset($settings["provider"]) && is_array($settings["provider"])) {
            foreach ($settings["provider"] as &$provider) {
                if (!empty($provider["clientSecret"])) {
                    $provider["clientSecret"] = self::decryptSecret($provider["clientSecret"]);
                }
            }
            unset($provider);
        }

        return $settings;
    }

    
    /**
     * Encrypt a client secret for storage in the database.
     * Uses Laravel Crypt facade (AES-256-CBC with random IV via app_key).
     * Requires app_key in config.inc.php. Logs warning on failure.
     */
    public static function encryptSecret(string $value): string
    {
        try {
            return Crypt::encryptString($value);
        } catch (EncryptException $e) {
            error_log("openidplugin WARNING: Failed to encrypt client secret. Error: " . $e->getMessage());
            return $value;
        } catch (\Exception $e) {
            error_log("openidplugin WARNING: Unexpected encryption failure — app_key may be missing from config.inc.php. Error: " . $e->getMessage());
            return $value;
        }
    }

    /**
     * Decrypt a client secret from the database.
     * Handles both encrypted and legacy plaintext values gracefully.
     * Note: clientId is intentionally NOT encrypted (public in auth URL).
     */
    public static function decryptSecret(string $value): string
    {
        try {
            return Crypt::decryptString($value);
        } catch (DecryptException $e) {
            // Expected for legacy plaintext values — not logged
            return $value;
        } catch (\Exception $e) {
            error_log("openidplugin WARNING: Failed to decrypt client secret — app_key may have changed. Error: " . $e->getMessage());
            return $value;
        }
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
    public static function encryptOrDecrypt(OpenIDPlugin $plugin, ?int $contextId, ?string $string, bool $encrypt = true): ?string
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
        return parent::getSetting(Application::SITE_CONTEXT_ID, 'enabled');
    }
}

