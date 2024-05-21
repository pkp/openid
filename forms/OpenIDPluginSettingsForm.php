<?php

/**
 * @file forms/OpenIDPluginSettingsForm.php
 *
 * Copyright (c) 2020 Leibniz Institute for Psychology Information (https://leibniz-psychology.org/)
 * Copyright (c) 2023 Simon Fraser University
 * Copyright (c) 2023 John Willinsky
 * Distributed under the GNU GPL v3. For full terms see the file LICENSE.
 *
 * @class OpenIDPluginSettingsForm
 *
 * @ingroup plugins_generic_openid
 *
 * @brief Form class for OpenID Authentication Plugin settings
 */

namespace APP\plugins\generic\openid\forms;

use APP\core\Application;
use APP\notification\NotificationManager;
use APP\plugins\generic\openid\enums\MicrosoftAudience;
use APP\plugins\generic\openid\enums\OpenIDProvider;
use APP\plugins\generic\openid\handler\OpenIDHandler;
use APP\plugins\generic\openid\OpenIDPlugin;
use APP\template\TemplateManager;
use GuzzleHttp\Exception\ClientException;
use PKP\core\PKPApplication;
use PKP\form\Form;
use PKP\form\validation\FormValidatorPost;
use PKP\form\validation\FormValidatorCSRF;
use PKP\notification\PKPNotification;

class OpenIDPluginSettingsForm extends Form
{
    private const HIDDEN_CHARS = '******';

    /**
     * OpenIDPluginSettingsForm constructor.
     */
    public function __construct(private OpenIDPlugin $plugin)
    {
        parent::__construct($plugin->getTemplateResource('settings.tpl'));

        $this->addCheck(new FormValidatorPost($this));
        $this->addCheck(new FormValidatorCSRF($this));
    }

    /**
     * @copydoc Form::initData()
     */
    function initData()
    {
        $request = Application::get()->getRequest();
        $contextId = ($request->getContext() == null) ? PKPApplication::CONTEXT_SITE : $request->getContext()->getId();
        $settings = OpenIDHandler::getOpenIDSettings($this->plugin, $contextId);
        $provider = $settings['provider'];

        if ($provider && is_array($provider)) {
            foreach ($provider as &$prov) {
                if (!empty($prov['clientId'])) {
                    $prov['clientId'] = self::HIDDEN_CHARS;
                }
                if (!empty($prov['clientSecret'])) {
                    $prov['clientSecret'] = self::HIDDEN_CHARS;
                }
            }
        }
        if (isset($settings)) {
            $this->_data = [
                'initProvider' => OpenIDPlugin::$publicOpenidProviders,
                'provider' => $provider,
                'legacyLogin' => $settings['legacyLogin'] ?? true,
                'legacyRegister' => $settings['legacyRegister'] ?? true,
                'disableConnect' => $settings['disableConnect'] ?? false,
                'hashSecret' => $settings['hashSecret'],
                'generateAPIKey' => $settings['generateAPIKey'] ?? 0,
                'providerSync' => $settings['providerSync'] ?? false,
                'disableFields' => $settings['disableFields'],
                'microsoftAudiences' => MicrosoftAudience::toAssociativeArray(true),
                'microsoftAudienceDefault' => MicrosoftAudience::CONSUMERS->value,
            ];
        } else {
            $this->_data = [
                'initProvider' => OpenIDPlugin::$publicOpenidProviders,
                'legacyLogin' => true,
                'legacyRegister' => false,
                'generateAPIKey' => false,
                'microsoftAudiences' => MicrosoftAudience::toAssociativeArray(true),
                'microsoftAudienceDefault' => MicrosoftAudience::CONSUMERS->value,
            ];
        }
        parent::initData();
    }

    /**
     * @copydoc Form::readInputData()
     */
    function readInputData()
    {
        $this->readUserVars(
            [
                'provider',
                'legacyLogin',
                'legacyRegister',
                'disableConnect',
                'hashSecret',
                'generateAPIKey',
                'providerSync',
                'disableFields',
            ]
        );
        parent::readInputData();
    }

    /**
     * @copydoc Form::fetch()
     */
    public function fetch($request, $template = null, $display = false)
    {
        $context = $request->getContext();

        $basePath = $context == null ? '' : $context->getPath();
        $redirectURL = $request->getDispatcher()->url($request, PKPApplication::ROUTE_PAGE, $basePath, 'openid', 'doAuthentication');
        
        $templateMgr = TemplateManager::getManager($request);
        $templateMgr->assign([
            'pluginName' => $this->plugin->getName(),
            'redirectUrl' => $redirectURL,
        ]);

        return parent::fetch($request, $template, $display);
    }

    /**
     * @copydoc Form::execute()
     */
    function execute(...$functionArgs)
    {
        $request = Application::get()->getRequest();
        $contextId = ($request->getContext() == null) ? PKPApplication::CONTEXT_SITE : $request->getContext()->getId();
        $settingsTMP = OpenIDHandler::getOpenIDSettings($this->plugin, $contextId);

        $providerList = $this->getData('provider');
        $providerListResult = $this->_createProviderList($providerList, $settingsTMP['provider']);

        $settings = [
            'provider' => $providerListResult,
            'legacyLogin' => $this->getData('legacyLogin'),
            'legacyRegister' => $this->getData('legacyRegister'),
            'disableConnect' => $this->getData('disableConnect'),
            'hashSecret' => $this->getData('hashSecret'),
            'generateAPIKey' => $this->getData('generateAPIKey'),
            'providerSync' => $this->getData('providerSync'),
            'disableFields' => $this->getData('disableFields'),
        ];
        $this->plugin->updateSetting($contextId, 'openIDSettings', json_encode($settings), 'string');

        $notificationMgr = new NotificationManager();
        $notificationMgr->createTrivialNotification(
            $request->getUser()->getId(),
            PKPNotification::NOTIFICATION_TYPE_SUCCESS,
            ['contents' => __('common.changesSaved')]
        );

        return parent::execute();
    }

    /**
     * Creates a complete list of the provider with all necessary endpoint URL's.
     * Therefore this->_loadOpenIdConfig is called, to get the URL's via openid-configuration endpoint.
     * This function is called when the settings are executed to refresh the auth, token, cert and logout/revoke URL's.
     *
     * @return array complete list of enabled provider including all necessary endpoint URL's
     */
    private function _createProviderList(?array $providerList, ?array $providerListDB): array
    {
        $providerListResult = [];

        if (isset($providerList) && is_array($providerList)) {
            foreach ($providerList as $name => &$provider) { // Note: Use reference to modify $provider directly
                if (!($provider['active'] ?? false)) {
                    continue;
                }

                $providerDB = $providerListDB[$name] ?? null;
                if (is_array($providerListDB) && $providerDB) {
                    // Simplified checks and assignments for clientId and clientSecret
                    $provider['clientId'] = $provider['clientId'] ?? '';
                    if (empty($provider['clientId']) || $provider['clientId'] == self::HIDDEN_CHARS) {
                        $provider['clientId'] = !empty($providerDB['clientId']) ? $providerDB['clientId'] : '';
                    }

                    $provider['clientSecret'] = $provider['clientSecret'] ?? '';
                    if (empty($provider['clientSecret']) || $provider['clientSecret'] == self::HIDDEN_CHARS) {
                        $provider['clientSecret'] = !empty($providerDB['clientSecret']) ? $providerDB['clientSecret'] : '';
                    }
                }

                $providedEnum = OpenIDProvider::tryFrom($name);
                if ($providedEnum == OpenIDProvider::MICROSOFT) {
                    $audience = MicrosoftAudience::tryFrom($provider['audience']);
                    $provider['audience'] = $audience;

                    $provider['configUrl'] = OpenIDPlugin::prepareMicrosoftConfigUrl($audience);
                }

                $openIdConfig = $this->_loadOpenIdConfig($provider['configUrl'] ?? '');
                if (is_array($openIdConfig)) {
                    $provider['authUrl'] = $openIdConfig['authorization_endpoint'] ?? null;
                    $provider['tokenUrl'] = $openIdConfig['token_endpoint'] ?? null;
                    $provider['userInfoUrl'] = $openIdConfig['userinfo_endpoint'] ?? null;
                    $provider['certUrl'] = $openIdConfig['jwks_uri'] ?? null;
                    $provider['logoutUrl'] = $openIdConfig['end_session_endpoint'] ?? null;
                    $provider['revokeUrl'] = $openIdConfig['revocation_endpoint'] ?? null;
                    $providerListResult[$name] = $provider;
                }
            }
            unset($provider); // Unset reference to avoid potential issues later
        }

        return $providerListResult;
    }

    /**
     * Calls the .well-known/openid-configuration which is provided in the $configURL and returns the result on success
     *
     * @return mixed|null
     */
    private function _loadOpenIdConfig(string $configUrl)
    {
        $headers = [
            'Accept' => 'application/json',
        ];

        $httpClient = Application::get()->getHttpClient();
        try {
            $response = $httpClient->request(
                'GET',
                $configUrl,
                [
                    'headers' => $headers,
                    'allow_redirects' => ['strict' => true],
                ]
            );
        } catch (ClientException $exception) {
            return null;
        }

        return json_decode($response->getBody()->getContents(), true);
    }
}
