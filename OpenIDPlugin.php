<?php

/**
 * @file OpenIDPlugin.php
 *
 * Copyright (c) 2020 Leibniz Institute for Psychology Information (https://leibniz-psychology.org/)
 * Copyright (c) 2023 Simon Fraser University
 * Copyright (c) 2023 John Willinsky
 * Distributed under the GNU GPL v3. For full terms see the file LICENSE.
 *
 * @class OpenIDPlugin
 *
 * @ingroup plugins_generic_openid
 *
 * @brief OpenIDPlugin class for plugin and handler registration
 */

namespace APP\plugins\generic\openid;

use APP\core\Application;
use APP\facades\Repo;
use APP\plugins\generic\openid\enums\MicrosoftAudience;
use APP\plugins\generic\openid\enums\OpenIDProvider;
use APP\plugins\generic\openid\forms\OpenIDPluginSettingsForm;
use APP\plugins\generic\openid\handler\OpenIDHandler;
use APP\plugins\generic\openid\handler\OpenIDLoginHandler;
use Illuminate\Support\Collection;
use PKP\core\PKPApplication;
use PKP\linkAction\LinkAction;
use PKP\linkAction\request\AjaxModal;
use PKP\plugins\GenericPlugin;
use PKP\plugins\Hook;
use PKP\core\JSONMessage;
use APP\template\TemplateManager;

require_once(__DIR__ . '/vendor/autoload.php');

class OpenIDPlugin extends GenericPlugin
{
    /**
     * List of OpenID provider.
     */
    public static Collection $publicOpenidProviders;

    public function __construct() 
    {
        self::$publicOpenidProviders = collect([
            OpenIDProvider::CUSTOM->value => "",
            OpenIDProvider::ORCID->value => ["configUrl" => "https://orcid.org/.well-known/openid-configuration"],
            OpenIDProvider::GOOGLE->value => ["configUrl" => "https://accounts.google.com/.well-known/openid-configuration"],
            OpenIDProvider::MICROSOFT->value => ["configUrl" => "https://login.windows.net/{audience}/v2.0/.well-known/openid-configuration"],
            OpenIDProvider::APPLE->value => ["configUrl" => "https://appleid.apple.com/.well-known/openid-configuration"],
        ]);
    }

    /**
     * Replace the given provider's {$setting} placeholder in the configUrl with the provided value.
     */
    public static function prepareMicrosoftConfigUrl(MicrosoftAudience $audience): string
    {
        return str_replace(
            '{audience}', 
            $audience->value, 
            self::$publicOpenidProviders->get(OpenIDProvider::MICROSOFT->value)['configUrl']
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
        if (parent::getSetting(0, 'enabled')) {
            return parent::getSetting(0, $name);
        } else {
            return parent::getSetting($contextId, $name);
        }
    }

    /**
     * @copydoc LazyLoadPlugin::register()
     */
    public function register($category, $path, $mainContextId = null)
    {
        $success = parent::register($category, $path, $mainContextId);
        $contextId = $this->getCurrentContextId();

        if ($success && $this->getEnabled($contextId)) {
            $request = Application::get()->getRequest();

            Hook::add('Schema::get::before::user', $this->beforeGetSchema(...));

            Hook::add('Schema::get::user', $this->addToSchema(...));

            $settings = OpenIDHandler::getOpenIDSettings($this, $contextId);

            $requestUser = $request->getUser();

            $user = null;
            if ($requestUser) {
                $user = Repo::user()->get($request->getUser()->getId());
            }

            if ($user) {
                $lastProviderValue = $user->getData(OpenIDHandler::USER_OPENID_LAST_PROVIDER_SETTING);
                $lastProvider = OpenIDProvider::tryFrom($lastProviderValue);
            }

            if ($lastProvider && isset($settings)
                && ($settings['disableFields'] ?? false) && ($settings['providerSync'] ?? false)) {
                
                $settings['disableFields']['lastProvider'] = $lastProvider;
                $settings['disableFields']['generateAPIKey'] = $settings['generateAPIKey'];
                
                $templateMgr = TemplateManager::getManager($request);
                $templateMgr->assign('openIdDisableFields', $settings['disableFields']);
                
                Hook::add('TemplateResource::getFilename', [$this, '_overridePluginTemplates']);
            }

            Hook::add('LoadHandler', $this->setPageHandler(...));
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

        $settings = [
            OpenIDHandler::USER_OPENID_LAST_PROVIDER_SETTING,
        ];

        $providers = OpenIDPlugin::$publicOpenidProviders;
        foreach ($providers as $key => $value) {
            $settings[] = OpenIDHandler::getOpenIDUserSetting(OpenIDProvider::tryFrom($key));
        }

        foreach ($settings as $settingName) {
            $schema->properties->{$settingName} = (object) [
                'type' => 'string',
                'apiSummary' => true,
                'validation' => ['nullable'],
            ];
        }

        return false;
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
    public function beforeGetSchema(string $hookName, array $args): bool
    {
        $forceReload = &$args[0];

        $forceReload = true;

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
}

