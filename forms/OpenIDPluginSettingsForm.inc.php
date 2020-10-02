<?php

import('lib.pkp.classes.form.Form');

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
 * @file plugins/generic/openid/forms/OpenIDPluginSettingsForm.inc.php
 * @ingroup plugins_generic_openid
 * @brief Form class for OpenID Authentication Plugin settings
 */
class OpenIDPluginSettingsForm extends Form
{
	/**
	 * List of OpenID provider.
	 * TODO should be loaded via json in the future
	 */
	private const PUBLIC_OPENID_PROVIDER = [
		"custom" => "",
		"google" => ["configUrl" => "https://accounts.google.com/.well-known/openid-configuration"],
		"microsoft" => ["configUrl" => "https://login.windows.net/common/.well-known/openid-configuration"],
		"apple" => ["configUrl" => "https://appleid.apple.com/.well-known/openid-configuration"],
	];

	private OpenIDPlugin $plugin;

	/**
	 * OpenIDPluginSettingsForm constructor.
	 *
	 * @param $plugin
	 */
	public function __construct($plugin)
	{
		parent::__construct($plugin->getTemplateResource('settings.tpl'));
		$this->plugin = $plugin;
		$this->addCheck(new FormValidatorPost($this));
		$this->addCheck(new FormValidatorCSRF($this));
	}

	/**
	 * @copydoc Form::initData()
	 */
	function initData()
	{
		$request = Application::getRequest();
		$contextId = ($request->getContext() == null) ? 0 : $request->getContext()->getId();
		$settingsJson = $this->plugin->getSetting($contextId, 'openIDSettings');
		$settings = json_decode($settingsJson, true);
		if (isset($settings)) {
			$this->_data = array(
				'initProvider' => self::PUBLIC_OPENID_PROVIDER,
				'provider' => $settings['provider'],
				'legacyLogin' => key_exists('legacyLogin', $settings) ? $settings['legacyLogin'] : true,
				'hashSecret' => $settings['hashSecret'],
				'generateAPIKey' => $settings['generateAPIKey'] ? $settings['generateAPIKey'] : 0,
			);
		} else {
			$this->_data = array(
				'initProvider' => self::PUBLIC_OPENID_PROVIDER,
				'legacyLogin' => true,
				'generateAPIKey' => false,
			);
		}
		parent::initData();
	}

	/**
	 * @copydoc Form::readInputData()
	 */
	function readInputData()
	{
		$this->readUserVars(
			array('provider', 'legacyLogin', 'hashSecret', 'generateAPIKey')
		);
		parent::readInputData();
	}

	/**
	 * @copydoc Form::fetch()
	 *
	 * @param $request
	 * @param null $template
	 * @param bool $display
	 * @return string|null
	 */
	public function fetch($request, $template = null, $display = false)
	{
		$templateMgr = TemplateManager::getManager($request);
		$request->getBasePath();
		$templateMgr->assign('pluginName', $this->plugin->getName());
		$templateMgr->assign('redirectUrl', $request->getIndexUrl().'/'.$request->getContext()->getPath().'/openid/doAuthentication');

		return parent::fetch($request, $template, $display);
	}

	/**
	 * @copydoc Form::execute()
	 *
	 * @param mixed ...$functionArgs
	 * @return mixed|null
	 */
	function execute(...$functionArgs)
	{
		$request = Application::getRequest();
		$contextId = ($request->getContext() == null) ? 0 : $request->getContext()->getId();
		$providerList = $this->getData('provider');
		$providerListResult = $this->_createProviderList($providerList);
		$legacyLogin = $this->getData('legacyLogin');
		$settings = array(
			'provider' => $providerListResult,
			'legacyLogin' => $legacyLogin,
			'hashSecret' => $this->getData('hashSecret'),
			'generateAPIKey' => $this->getData('generateAPIKey'),
		);
		$this->plugin->updateSetting($contextId, 'openIDSettings', json_encode($settings), 'string');
		import('classes.notification.NotificationManager');
		$notificationMgr = new NotificationManager();
		$notificationMgr->createTrivialNotification(
			$request->getUser()->getId(),
			NOTIFICATION_TYPE_SUCCESS,
			['contents' => __('common.changesSaved')]
		);

		return parent::execute();
	}

	/**
	 * Creates a complete list of the provider with all necessary endpoint URL's.
	 * Therefore this->_loadOpenIdConfig is called, to get the URL's via openid-configuration endpoint.
	 * This function is called when the settings are executed to refresh the auth, token, cert and logout/revoke URL's.
	 *
	 * @param $providerList
	 * @return array complete list of enabled provider including all necessary endpoint URL's
	 */
	private function _createProviderList($providerList): array
	{
		$providerListResult = array();
		if (isset($providerList) && is_array($providerList)) {
			foreach ($providerList as $name => $provider) {
				if (key_exists('active', $provider) && $provider['active'] == 1) {
					$openIdConfig = $this->_loadOpenIdConfig($provider['configUrl']);
					if (is_array($openIdConfig)
						&& key_exists('authorization_endpoint', $openIdConfig)
						&& key_exists('token_endpoint', $openIdConfig)
						&& key_exists('jwks_uri', $openIdConfig)) {
						$provider['authUrl'] = $openIdConfig['authorization_endpoint'];
						$provider['tokenUrl'] = $openIdConfig['token_endpoint'];
						$provider['userInfoUrl'] = key_exists('userinfo_endpoint', $openIdConfig) ? $openIdConfig['userinfo_endpoint'] : null;
						$provider['certUrl'] = $openIdConfig['jwks_uri'];
						$provider['logoutUrl'] = key_exists('end_session_endpoint', $openIdConfig) ? $openIdConfig['end_session_endpoint'] : null;
						$provider['revokeUrl'] = key_exists('revocation_endpoint', $openIdConfig) ? $openIdConfig['revocation_endpoint'] : null;
						$providerListResult[$name] = $provider;
					}
				}
			}
		}

		return $providerListResult;
	}

	/**
	 * Calls the .well-known/openid-configuration which is provided in the $configURL and returns the result on success
	 *
	 * @param $configUrl
	 * @return mixed|null
	 */
	private function _loadOpenIdConfig($configUrl)
	{
		$curl = curl_init();
		curl_setopt_array(
			$curl,
			array(
				CURLOPT_URL => $configUrl,
				CURLOPT_RETURNTRANSFER => true,
				CURLOPT_HTTPHEADER => array('Accept: application/json'),
				CURLOPT_POST => false,
			)
		);
		$result = curl_exec($curl);
		if (isset($result)) {
			return json_decode($result, true);
		}

		return null;
	}

}
