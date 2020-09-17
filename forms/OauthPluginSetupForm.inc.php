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

class OauthPluginSetupForm extends Form
{

	private OauthPlugin $plugin;

	/**
	 * Constructor
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
		$request = Application::get()->getRequest();
		$contextId = ($request->getContext() == null) ? 0 : $request->getContext()->getId();
		$settingsJson = $this->plugin->getSetting($contextId, 'keycloakSettings');
		$settings = json_decode($settingsJson, true);
		$this->_data = array(
			'url' => $settings['url'],
			'realm' => $settings['realm'],
			'clientId' => $settings['clientId'],
			'clientSecret' => $settings['clientSecret'],
			'hashSecret' => $settings['hashSecret'],
		);
		parent::initData();
	}

	/**
	 * @copydoc Form::readInputData()
	 */
	function readInputData()
	{
		$this->readUserVars(array('url', 'realm', 'clientId', 'clientSecret', 'hashSecret'));
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
			'url' => $this->getData('url'),
			'realm' => $this->getData('realm'),
			'clientId' => $this->getData('clientId'),
			'clientSecret' => $this->getData('clientSecret'),
			'hashSecret' => $this->getData('hashSecret'),
		);
		$this->plugin->updateSetting($contextId, 'keycloakSettings', json_encode($settings), 'string');
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
