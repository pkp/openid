<?php

import('classes.handler.Handler');

class OpenIDLoginHandler extends Handler
{


	/**
	 * Disables the default login.
	 * This function redirects to the oauth login page.
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
		if (!Validation::isLoggedIn()) {
			$router = $request->getRouter();
			$context = Application::get()->getRequest()->getContext();
			$contextId = ($context == null) ? 0 : $context->getId();
			$settingsJson = $plugin->getSetting($contextId, 'openIDSettings');
			if ($settingsJson != null) {
				$settings = json_decode($settingsJson, true);
				$providerList = key_exists('provider', $settings) ? $settings['provider'] : null;
				if (isset($providerList)) {
					foreach ($providerList as $name => $settings) {
						if (key_exists('authUrl', $settings) && !empty($settings['authUrl'])
							&& key_exists('clientId', $settings) && !empty($settings['clientId'])) {
							$showErrorPage = false;
							if (sizeof($providerList) == 1) {
								$request->redirectUrl(
									$settings['authUrl'].
									'?client_id='.$settings['clientId'].
									'&response_type=code&scope=openid&redirect_uri='.
									$router->url($request, null, "openid", "doAuthentication", null, array('provider' => $name))
								);
							} else {
								if ($name == "custom") {
									$btnTxt = key_exists('btnTxt', $settings) && isset($settings['btnTxt']) && isset(
										$settings['btnTxt'][AppLocale::getLocale()]
									) ? $settings['btnTxt'][AppLocale::getLocale()] : null;
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
		}
		$templateMgr = TemplateManager::getManager($request);
		$legacyLoginEnabled = true;
		$loginUrl = $request->url(null, 'login', 'signIn');
		if (Config::getVar('security', 'force_login_ssl')) {
			$loginUrl = PKPString::regexp_replace('/^http:/', 'https:', $loginUrl);
		}
		if (isset($linkList)) {
			if (isset($btnTxt)) {
				$templateMgr->assign('customBtnTxt', $btnTxt);
			}
			$templateMgr->assign('linkList', $linkList);
			if ($legacyLoginEnabled) {
				$templateMgr->assign('legacyLoginEnabled', true);
				$templateMgr->assign('loginUrl', $loginUrl);
			}
			$templateMgr->display($plugin->getTemplateResource('provider.tpl'));
		} elseif ($showErrorPage) {
			$templateMgr->assign('loginMessage', 'plugins.generic.openid.settings.error');
			$templateMgr->assign('loginUrl', $loginUrl);
			$templateMgr->display('frontend/pages/userLogin.tpl');
		}
		$request->redirect(Application::get()->getRequest()->getContext(), 'index');

		return true;
	}

	/**
	 * Disables the default registration, because it is not needed anymore.
	 * User registration is done via oauth.
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
	 * Performs OJS logout and redirects to the oauth logout to delete session and tokens.
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


	/**
	 * Sign a user out.
	 * This is called after oauth logout via redirect_uri parameter.
	 *
	 * @param $args
	 * @param $request
	 */
	function signOutOjs($args, $request)
	{
		if (Validation::isLoggedIn()) {
			Validation::logout();
		}
		$request->redirect(Application::get()->getRequest()->getContext(), 'index');
	}


}
