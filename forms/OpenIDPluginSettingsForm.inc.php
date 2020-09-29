<?php

/**
 * @file plugins/generic/oauth/controllers/grid/form/OauthAppForm.inc.php
 *
 * Copyright (c) 2014-2016 Simon Fraser University Library
 * Copyright (c) 2003-2016 John Willinsky
 * Distributed under the GNU GPL v2. For full terms see the file docs/COPYING.
 *
 * @class OauthAppForm
 * @ingroup controllers_grid_oauthApp
 *
 * Form for managers to create and modify oauth app
 *
 */

import('lib.pkp.classes.form.Form');

class OpenIDPluginSettingsForm extends Form
{
	private const PUBLIC_OPENID_PROVIDER = [
		"custom" => "",
		"google" => ["configUrl" => "https://accounts.google.com/.well-known/openid-configuration"],
		"microsoft" => ["configUrl" => "https://login.windows.net/common/.well-known/openid-configuration"],
		"apple" => ["configUrl" => "https://appleid.apple.com/.well-known/openid-configuration"],
	];

	private OpenIDPlugin $plugin;

	/**
	 * Constructor
	 * @param OpenIDPlugin $plugin
	 */
	public function __construct(OpenIDPlugin $plugin)
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
		$request = Application::get()->getRequest();
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
	 * @param mixed ...$functionArgs
	 * @return mixed|null
	 */
	function execute(...$functionArgs)
	{
		$request = Application::get()->getRequest();
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
	 * @param $providerList
	 * @return array
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
