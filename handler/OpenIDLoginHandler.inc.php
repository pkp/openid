<?php
import('classes.handler.Handler');

/**
 * This file is part of OpenID Authentication Plugin (https://github.com/leibniz-psychology/pkp-openid).
 *
 * OpenID Authentication Plugin is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * OpenID Authentication Plugin is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with OpenID Authentication Plugin.  If not, see <https://www.gnu.org/licenses/>.
 *
 * Copyright (c) 2020 Leibniz Institute for Psychology Information (https://leibniz-psychology.org/)
 *
 * @file plugins/generic/openid/handler/OpenIDLoginHandler.inc.php
 * @ingroup plugins_generic_openid
 * @brief Handler to overwrite default OJS/OMP/OPS login and registration
 *
 */
class OpenIDLoginHandler extends Handler
{
	/**
	 * This function overwrites the default login.
	 * There a 2 different workflows implemented:
	 * - If only one OpenID provider is configured and legacy login is disabled, the user is automatically redirected to the sign-in page of that provider.
	 * - If more than one provider is configured, a login page is shown within the OJS/OMP/OPS and the user can select his preferred OpenID provider for login/registration.
	 *
	 * In case of an error or a mismatched configuration, the default login page is displayed to prevent a complete login lock of the system.
	 *
	 * @param $args
	 * @param $request
	 */
	function index($args, $request)
	{
		$this->setupTemplate($request);
		if (Config::getVar('security', 'force_login_ssl') && $request->getProtocol() != 'https') {
			$request->redirectSSL();
		}
		$plugin = PluginRegistry::getPlugin('generic', KEYCLOAK_PLUGIN_NAME);
		$showErrorPage = true;
		$legacyLogin = false;
		$templateMgr = TemplateManager::getManager($request);
		$context = Application::get()->getRequest()->getContext();
		if (!Validation::isLoggedIn()) {
			$router = $request->getRouter();
			$contextId = ($context == null) ? 0 : $context->getId();
			$settingsJson = $plugin->getSetting($contextId, 'openIDSettings');
			if ($settingsJson != null) {
				$settings = json_decode($settingsJson, true);
				$legacyLogin = key_exists('legacyLogin', $settings) && isset($settings['legacyLogin']) ? $settings['legacyLogin'] : false;
				$providerList = key_exists('provider', $settings) ? $settings['provider'] : null;
				if (isset($providerList)) {
					foreach ($providerList as $name => $settings) {
						if (key_exists('authUrl', $settings) && !empty($settings['authUrl'])
							&& key_exists('clientId', $settings) && !empty($settings['clientId'])) {
							$showErrorPage = false;
							if (sizeof($providerList) == 1 && !$legacyLogin) {
								$request->redirectUrl(
									$settings['authUrl'].
									'?client_id='.$settings['clientId'].
									'&response_type=code&scope=openid&redirect_uri='.
									$router->url($request, null, "openid", "doAuthentication", null, array('provider' => $name))
								);
							} else {
								if ($name == "custom") {
									$templateMgr->assign(
										'customBtnImg',
										key_exists('btnImg', $settings) && isset($settings['btnImg']) ? $settings['btnImg'] : null
									);
									$templateMgr->assign(
										'customBtnTxt',
										key_exists('btnTxt', $settings)
										&& isset($settings['btnTxt'])
										&& isset($settings['btnTxt'][AppLocale::getLocale()])
											? $settings['btnTxt'][AppLocale::getLocale()] : null
									);
								}
								$linkList[$name] = $settings['authUrl'].
									'?client_id='.$settings['clientId'].
									'&response_type=code&scope=openid profile email'.
									'&redirect_uri='.urlencode($router->url($request, null, "openid", "doAuthentication", null, array('provider' => $name)));
							}
						}
					}
				}
			}
			$loginUrl = $request->url(null, 'login', 'signIn');
			if (Config::getVar('security', 'force_login_ssl')) {
				$loginUrl = PKPString::regexp_replace('/^http:/', 'https:', $loginUrl);
			}
			if (isset($linkList)) {
				$templateMgr->assign('linkList', $linkList);
				if ($legacyLogin) {
					$templateMgr->assign('legacyLogin', true);
					$templateMgr->assign('loginUrl', $loginUrl);
					$templateMgr->assign('journalName', $context->getName(AppLocale::getLocale()));
				}
				$templateMgr->display($plugin->getTemplateResource('openidLogin.tpl'));
			} elseif ($showErrorPage) {
				$templateMgr->assign('loginMessage', 'plugins.generic.openid.settings.error');
				$templateMgr->assign('loginUrl', $loginUrl);
				$templateMgr->display('frontend/pages/userLogin.tpl');
			}
		}
		$request->redirect(Application::get()->getRequest()->getContext(), 'index');
	}

	/**
	 * Disables the default registration, because it is not needed anymore.
	 * User registration is done via OpenID provider.
	 *
	 * @param $args
	 * @param $request
	 */
	function register($args, $request)
	{
		$this->index($args, $request);
	}

	/**
	 * Disables default logout.
	 * Performs OJS logout and if logoutUrl is provided (e.g. Apple doesn't provide this url) it redirects to the oauth logout to delete session and tokens.
	 *
	 * @param $args
	 * @param $request
	 */
	function signOut($args, $request)
	{
		if (Validation::isLoggedIn()) {
			$plugin = PluginRegistry::getPlugin('generic', KEYCLOAK_PLUGIN_NAME);
			$router = $request->getRouter();
			$lastProvider = $request->getUser()->getSetting('openid::lastProvider');
			$context = Application::get()->getRequest()->getContext();
			$contextId = ($context == null) ? 0 : $context->getId();
			$settingsJson = $plugin->getSetting($contextId, 'openIDSettings');
			Validation::logout();
			if (isset($settingsJson) && isset($lastProvider)) {
				$providerList = json_decode($settingsJson, true)['provider'];
				$settings = $providerList[$lastProvider];
				if (isset($settings) && key_exists('logoutUrl', $settings) && !empty($settings['logoutUrl']) && key_exists('clientId', $settings)) {
					$request->redirectUrl(
						$settings['logoutUrl'].
						'?client_id='.$settings['clientId'].
						'&redirect_uri='.$router->url($request, $context, "index")
					);
				}
			}
		}
		$request->redirect(Application::get()->getRequest()->getContext(), 'index');
	}
}
