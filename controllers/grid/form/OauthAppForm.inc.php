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

class OauthAppForm extends Form
{

	private $plugin;

	/**
	 * Constructor
	 * @param $plugin
	 */
	public function __construct($plugin)
	{
		parent::__construct($plugin->getTemplateResource('editOauthAppForm.tpl'));
		$this->plugin = $plugin;
		// Add form checks
		$this->addCheck(new FormValidatorPost($this));
		$this->addCheck(new FormValidatorCSRF($this));
	}

	/**
	 * @copydoc Form::initData()
	 */
	function initData()
	{
		$contextId = Application::get()->getRequest()->getContext()->getId();
		$oauthAppName = $this->plugin->getName();
		$plugin = PluginRegistry::getPlugin('generic', OAUTH_PLUGIN_NAME);
		if ($oauthAppName) {
			$oauthAppSettingsJson = $plugin->getSetting($contextId, 'oauthAppSettings');
			error_log($oauthAppSettingsJson);
			$oauthAppSettingsArray = json_decode($oauthAppSettingsJson, true);
			$this->_data = array(
				'oauthAppName' => $oauthAppName,
				'oauthAPIAuth' => $oauthAppSettingsArray[$oauthAppName]['oauthAPIAuth'],
				'oauthAPIVerify' => $oauthAppSettingsArray[$oauthAppName]['oauthAPIVerify'],
				'oauthClientId' => $oauthAppSettingsArray[$oauthAppName]['oauthClientId'],
				'oauthClientSecret' => $oauthAppSettingsArray[$oauthAppName]['oauthClientSecret'],
				'oauthUniqueId' => $oauthAppSettingsArray[$oauthAppName]['oauthUniqueId'],
				'oauthScope' => $oauthAppSettingsArray[$oauthAppName]['oauthScope'],
			);
		}
	}

	/**
	 * @copydoc Form::readInputData()
	 */
	function readInputData()
	{
		$this->readUserVars(
			array(
				'oauthAppName',
				'oauthAPIAuth',
				'oauthAPIVerify',
				'oauthClientId',
				'oauthClientSecret',
				'oauthUniqueId',
				'oauthScope',
			)
		);
	}

	/**
	 * @copydoc Form::execute()
	 * @param mixed ...$functionArgs
	 */
	function execute(...$functionArgs)
	{
		$oauthAppName = $this->plugin->getName();
		$contextId = Application::get()->getRequest()->getContext()->getId();
		$plugin = PluginRegistry::getPlugin('generic', OAUTH_PLUGIN_NAME);
		$oauthAppNames = $plugin->getSetting($contextId, 'oauthAppNames');
		if (empty($oauthAppNames)) {
			$oauthAppNames = array();
		}
		$oauthAppSettingsJson = $plugin->getSetting($contextId, 'oauthAppSettings');
		$oauthAppSettingsArray = array();
		if (!empty($oauthAppSettingsJson)) {
			$oauthAppSettingsArray = json_decode($oauthAppSettingsJson, true);
		}
		if (!$oauthAppName) {
			$oauthAppName = $this->getData('oauthAppName');
			$oauthAppNames[] = $oauthAppName;
		}
		$oauthAppSettingsArray[$oauthAppName] = array(
			'oauthAPIAuth' => $this->getData('oauthAPIAuth'),
			'oauthAPIVerify' => $this->getData('oauthAPIVerify'),
			'oauthClientId' => $this->getData('oauthClientId'),
			'oauthClientSecret' => $this->getData('oauthClientSecret'),
			'oauthUniqueId' => $this->getData('oauthUniqueId'),
			'oauthScope' => $this->getData('oauthScope'),
		);
		// update plugin setting
		$plugin->updateSetting($contextId, 'oauthAppSettings', json_encode($oauthAppSettingsArray), 'string');
		$plugin->updateSetting($contextId, 'oauthAppNames', $oauthAppNames, 'object');
	}

}

?>
