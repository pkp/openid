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
		$this->_data = array(
			'configUrl' => $settings['configUrl'],
			'clientId' => $settings['clientId'],
			'clientSecret' => $settings['clientSecret'],
			'hashSecret' => $settings['hashSecret'],
			'generateAPIKey' => $settings['generateAPIKey'] ? $settings['generateAPIKey'] : 0,
		);
		parent::initData();
	}

	/**
	 * @copydoc Form::readInputData()
	 */
	function readInputData()
	{
		$this->readUserVars(
			array('configUrl', 'clientId', 'clientSecret', 'hashSecret', 'generateAPIKey')
		);
		parent::readInputData();
	}


	public function fetch($request, $template = null, $display = false)
	{
		$templateMgr = TemplateManager::getManager($request);
		$templateMgr->assign('pluginName', $this->plugin->getName());

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
		$openIdConfig = $this->loadOpenIdConfig($this->getData('configUrl'));
		if (is_array($openIdConfig)
			&& key_exists('authorization_endpoint', $openIdConfig)
			&& key_exists('token_endpoint', $openIdConfig)
			&& key_exists('jwks_uri', $openIdConfig)) {
			$settings = array(
				'configUrl' => $this->getData('configUrl'),
				'authUrl' => $openIdConfig['authorization_endpoint'],
				'tokenUrl' => $openIdConfig['token_endpoint'],
				'userInfoUrl' => key_exists('userinfo_endpoint', $openIdConfig) ? $openIdConfig['userinfo_endpoint'] : null,
				'certUrl' => $openIdConfig['jwks_uri'],
				'logoutUrl' => key_exists('end_session_endpoint', $openIdConfig) ? $openIdConfig['end_session_endpoint'] : null,
				'revokeUrl' => key_exists('revocation_endpoint', $openIdConfig) ? $openIdConfig['revocation_endpoint'] : null,
				'clientId' => $this->getData('clientId'),
				'clientSecret' => $this->getData('clientSecret'),
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
		} else {
			import('classes.notification.NotificationManager');
			$notificationMgr = new NotificationManager();
			$notificationMgr->createTrivialNotification(
				$request->getUser()->getId(),
				NOTIFICATION_TYPE_ERROR,
				['contents' => __('common.changesSaved')] // TODO error msg
			);
		}

		return parent::execute();
	}


	private function loadOpenIdConfig($configUrl)
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
	}

}
