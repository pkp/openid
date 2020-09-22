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
			'authUrl' => $settings['authUrl'],
			'tokenUrl' => $settings['tokenUrl'],
			'certUrl' => $settings['certUrl'],
			'certString' => $settings['certString'],
			'logoutUrl' => $settings['logoutUrl'],
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
			array('authUrl', 'tokenUrl', 'certUrl', 'certString', 'logoutUrl', 'clientId', 'clientSecret', 'hashSecret', 'generateAPIKey')
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
		$settings = array(
			'authUrl' => $this->getData('authUrl'),
			'tokenUrl' => $this->getData('tokenUrl'),
			'certUrl' => $this->getData('certUrl'),
			'certString' => $this->getData('certString'),
			'logoutUrl' => $this->getData('logoutUrl'),
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

		return parent::execute();
	}

}
