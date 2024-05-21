<?php

/**
 * @file handler/OpenIDLoginHandler.php
 *
 * Copyright (c) 2020 Leibniz Institute for Psychology Information (https://leibniz-psychology.org/)
 * Copyright (c) 2023 Simon Fraser University
 * Copyright (c) 2023 John Willinsky
 * Distributed under the GNU GPL v3. For full terms see the file LICENSE.
 *
 * @class OpenIDLoginHandler
 *
 * @ingroup plugins_generic_openid
 *
 * @brief Handler to overwrite default OJS/OMP/OPS login and registration
 */

namespace APP\plugins\generic\openid\handler;

use APP\core\Request;
use APP\facades\Repo;
use APP\handler\Handler;
use APP\plugins\generic\openid\enums\OpenIDProvider;
use APP\plugins\generic\openid\enums\SSOError;
use APP\plugins\generic\openid\OpenIDPlugin;
use APP\template\TemplateManager;
use PKP\config\Config;
use PKP\core\PKPApplication;
use PKP\facades\Locale;
use PKP\security\Validation;

class OpenIDLoginHandler extends Handler
{
    public function __construct(protected OpenIDPlugin $plugin)
    {
    }

    /**
     * This function overwrites the default login.
     * There a 2 different workflows implemented:
     * - If only one OpenID provider is configured and legacy login is disabled, the user is automatically redirected to the sign-in page of that provider.
     * - If more than one provider is configured, a login page is shown within the OJS/OMP/OPS and the user can select his preferred OpenID provider for login/registration.
     *
     * In case of an error or incorrect configuration, a link to the default login page is provided to prevent a complete system lockout.
     *
     * @see PKPHandler::index($args, $request)
     */
    function index($args, $request)
    {
        $this->setupTemplate($request);

        if ($this->isSSLRequired($request)) {
            $request->redirectSSL();
        }

        if (Validation::isLoggedIn()) {
            $request->redirect(null, 'index');
            return false;
        }

        $context = $request->getContext();
        $contextId = $context?->getId() ?? PKPApplication::CONTEXT_SITE;
        $settings = OpenIDHandler::getOpenIDSettings($this->plugin, $contextId);

        if ($settings) {
            $providerList = $settings['provider'] ?? [];

            if ($this->handleSingleProviderLogin($providerList, $settings, $request)) {
                return false;
            }

            $templateMgr = TemplateManager::getManager($request);
            $linkList = $this->generateProviderLinks($providerList, $request);

            if ($settings['legacyRegister'] ?? false) {
                $linkList['legacyRegister'] = $request->getRouter()->url($request, null, "user", "registerUser");
            }

            if (!empty($linkList)) {
                $templateMgr->assign('linkList', $linkList);
                $this->handleErrors($templateMgr, $request);
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

        $context = $request->getContext();
        $contextId = $context?->getId() ?? PKPApplication::CONTEXT_SITE;
        $settings = OpenIDHandler::getOpenIDSettings($this->plugin, $contextId);
        $user = $request->getUser() ? Repo::user()->get($request->getUser()->getId()) : null;

        if ($user) {
            $lastProviderValue = $user->getData(OpenIDHandler::USER_OPENID_LAST_PROVIDER_SETTING);

            $user->setData(OpenIDHandler::USER_OPENID_LAST_PROVIDER_SETTING, null);
            Repo::user()->edit($user);
        }

        $tokenEncrypted = $request->getSession()->pull('id_token');
        $token = OpenIDHandler::encryptOrDecrypt($this->plugin, $contextId, $tokenEncrypted, false);

        Validation::logout();

        if ($settings && isset($lastProviderValue)) {
            $providerSettings = $settings['provider'][$lastProviderValue] ?? [];
            if (!empty($providerSettings['logoutUrl'])) {
                $this->redirectToProviderLogout($request, $providerSettings, $context, $token);
                return;
            }
        }

        $request->redirect(null, 'index');
    }

    /**
     * Sets user friendly error messages, which are thrown during the OpenID auth process.
     */
    private function _setSSOErrorMessages(SSOError $ssoError, TemplateManager $templateMgr, Request $request)
    {
        $templateMgr->assign('openidError', true);
        $reason = htmlspecialchars($request->getUserVar('sso_error_msg') ?? '', ENT_QUOTES, 'UTF-8');
        $errorMessages = [
            SSOError::CONNECT_DATA->value => 'plugins.generic.openid.error.openid.connect.desc.data',
            SSOError::CONNECT_KEY->value => 'plugins.generic.openid.error.openid.connect.desc.key',
            SSOError::CERTIFICATION->value => 'plugins.generic.openid.error.openid.cert.desc',
            SSOError::USER_DISABLED->value => 'plugins.generic.openid.error.openid.disabled.' . (empty($reason) ? 'without' : 'with'),
            SSOError::API_RETURNED->value => 'plugins.generic.openid.error.openid.api.returned'
        ];

        $templateMgr->assign('errorMsg', $errorMessages[$ssoError->value] ?? '');
        if (in_array($ssoError, [SSOError::USER_DISABLED, SSOError::API_RETURNED])) {
            $templateMgr->assign('reason', $reason);
            if ($ssoError == SSOError::USER_DISABLED) {
                $templateMgr->assign('accountDisabled', true);
            }
        }

        $context = $request->getContext();
        $supportEmail = $context?->getSetting('supportEmail') ?? $request->getSite()->getLocalizedContactEmail();
        $templateMgr->assign('supportEmail', $supportEmail);
    }

    /**
     * This function is used
     *  - if the legacy login is activated via plugin settings,
     *  - or an error occurred during the Auth process to ensure that the Journal Manager can log in.
     */
    private function _enableLegacyLogin(TemplateManager $templateMgr, Request $request)
    {
        $context = $request->getContext();
        $loginUrl = $request->url(null, 'login', 'signIn');

        if (Config::getVar('security', 'force_login_ssl')) {
            $loginUrl = preg_replace('/^http:/', 'https:', $loginUrl);
        }

        // Apply htmlspecialchars to encode special characters
        $loginMessage = htmlspecialchars($request->getUserVar('loginMessage'), ENT_QUOTES, 'UTF-8');
        $username = htmlspecialchars($request->getSession()->get('username'), ENT_QUOTES, 'UTF-8');
        $remember = htmlspecialchars($request->getUserVar('remember'), ENT_QUOTES, 'UTF-8');
        $source = htmlspecialchars($request->getUserVar('source'), ENT_QUOTES, 'UTF-8');
        $journalName = $context != null ? htmlspecialchars($context->getName(Locale::getLocale()), ENT_QUOTES, 'UTF-8') : null;

        $templateMgr->assign([
            'loginMessage' => $loginMessage,
            'username' => $username,
            'remember' => $remember,
            'source' => $source,
            'showRemember' => Config::getVar('general', 'session_lifetime') > 0,
            'legacyLogin' => true,
            'loginUrl' => $loginUrl,
            'journalName' => $journalName,
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
        $redirectUrl = $providerSettings['authUrl'] .
            '?client_id=' . urlencode($providerSettings['clientId']) .
            '&response_type=code' .
            '&scope=openid' .
            '&redirect_uri=' . urlencode($router->url($request, null, "openid", "doAuthentication", null, ['provider' => $providerName]));

        $request->redirectUrl($redirectUrl);
    }

    private function redirectToProviderLogout(Request $request, array $providerSettings, $context, string $token): void
    {
        $router = $request->getRouter();
        $logoutUrl = $providerSettings['logoutUrl']
            . '?client_id=' . urlencode($providerSettings['clientId'])
            . '&post_logout_redirect_uri=' . urlencode($router->url($request, $context->getPath(), "index"))
            . '&id_token_hint=' . urlencode($token);

        $request->redirectUrl($logoutUrl);
    }

    private function generateProviderLinks(array $providerList, Request $request): array
    {
        $router = $request->getRouter();
        $linkList = [];

        foreach ($providerList as $name => $settings) {
            // Convert the key (which is a string) back to the enumeration type
            $provider = OpenIDProvider::tryFrom($name);

            if (!empty($settings['authUrl']) && !empty($settings['clientId'])) {
                $baseLink = "{$settings['authUrl']}?client_id={$settings['clientId']}&response_type=code&scope=openid profile email";
                $linkList[$provider->value] = "{$baseLink}&redirect_uri=" . urlencode($router->url($request, null, "openid", "doAuthentication", null, ['provider' => $provider->value]));
                $this->handleCustomProvider($provider, $settings, TemplateManager::getManager($request));
            }
        }
        return $linkList;
    }

    private function handleCustomProvider(OpenIDProvider $provider, array $settings, TemplateManager $templateMgr): void
    {
        if ($provider == OpenIDProvider::CUSTOM) {
            $customBtnTxt = htmlspecialchars($settings['btnTxt'][Locale::getLocale()] ?? '', ENT_QUOTES, 'UTF-8');
            $templateMgr->assign([
                'customBtnImg' => $settings['btnImg'] ?? null,
                'customBtnTxt' => $customBtnTxt
            ]);
        }
    }

    private function handleErrors(TemplateManager $templateMgr, Request $request): void
    {
        $ssoError = SSOError::tryFrom($request->getUserVar('sso_error'));

        if ($ssoError) {
            $this->_setSSOErrorMessages($ssoError, $templateMgr, $request);
        }
    }

    private function handleLegacyLogin(TemplateManager $templateMgr, Request $request, array $settings): void
    {
        if ($settings['legacyLogin'] ?? false) {
            $this->_enableLegacyLogin($templateMgr, $request);
        }
    }
}
