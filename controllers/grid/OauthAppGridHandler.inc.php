<?php

/**
 * @file plugins/generic/oauth/controllers/grid/OauthAppGridHandler.inc.php
 *
 * Copyright (c) 2014-2016 Simon Fraser University Library
 * Copyright (c) 2003-2016 John Willinsky
 * Distributed under the GNU GPL v2. For full terms see the file docs/COPYING.
 *
 * @class OauthAppGridHandler
 * @ingroup controllers_grid_oauthApp
 *
 * @brief Handle oauth app grid requests.
 */

import('lib.pkp.classes.controllers.grid.GridHandler');
import('plugins.generic.oauth.controllers.grid.OauthAppGridRow');

class OauthAppGridHandler extends GridHandler {
	/** @var OauthPlugin The oauth plugin */
	var $plugin;

	/**
	 * Constructor
	 */
	function __construct() {
		parent::__construct();
		/*$this->addRoleAssignment(
			array(ROLE_ID_MANAGER),
			array('fetchGrid', 'fetchRow', 'addOauthApp', 'editOauthApp', 'updateOauthApp', 'deleteOauthApp')
		);*/
		$this->plugin = PluginRegistry::getPlugin('generic', OAUTH_PLUGIN_NAME);
	}


	//
	// Overridden template methods
	//
	/**
	 * @copydoc Gridhandler::initialize()
	 */
	function initialize($request, $args = null) {
		parent::initialize($request);
		$context = $request->getContext();

		// Set the grid title.
		$this->setTitle('plugins.generic.oauth.oauthApps');
		// Set the grid instructions.
		$this->setEmptyRowText('plugins.generic.oauth.oauthApps.noneCreated');

		// Get the OAuth applications and add the data to the grid
		$oauthPlugin = $this->plugin;
		$oauthAppNames = $oauthPlugin->getSetting($context->getId(), 'oauthAppNames');
		$gridData = array();
		if (is_array($oauthAppNames)) foreach ($oauthAppNames as $oauthAppName) {
			$gridData[$oauthAppName] = array(
				'title' => $oauthAppName
			);
		}
		$this->setGridDataElements($gridData);

		// Add grid-level actions
		$router = $request->getRouter();
		import('lib.pkp.classes.linkAction.request.AjaxModal');
		$this->addAction(
			new LinkAction(
				'addOauthApp',
				new AjaxModal(
					$router->url($request, null, null, 'addOauthApp'),
					__('plugins.generic.oauth.addOauthApp'),
					'modal_add_item'
				),
				__('plugins.generic.oauth.addOauthApp'),
				'add_item'
			)
		);

		// Columns
		$this->addColumn(
			new GridColumn(
				'title',
				'plugins.generic.oauth.oauthAppName',
				null,
				'controllers/grid/gridCell.tpl'
			)
		);
	}

	//
	// Overridden methods from GridHandler
	//
	/**
	 * @copydoc Gridhandler::getRowInstance()
	 */
	function getRowInstance() {
		return new OauthAppGridRow();
	}

	//
	// Public Grid Actions
	//
	/**
	 * An action to add a new OAuth application
	 * @param $args array Arguments to the request
	 * @param $request PKPRequest Request object
	 */
	function addOauthApp($args, $request) {
		// Calling editOauthApp with an empty ID/oauthAppName will add
		// a new OAuth application.
		return $this->editOauthApp($args, $request);
	}

	/**
	 * An action to edit an OAuth application
	 * @param $args array Arguments to the request
	 * @param $request PKPRequest Request object
	 * @return string Serialized JSON object
	 */
	function editOauthApp($args, $request) {
		$this->setupTemplate($request);
		import('plugins.generic.oauth.controllers.grid.form.OauthAppForm');
		$oauthAppForm = new OauthAppForm($this->plugin);
		$oauthAppForm->initData();
		$json = new JSONMessage(true, $oauthAppForm->fetch($request));
		return $json->getString();
	}

	/**
	 * Update an OAuth application
	 * @param $args array
	 * @param $request PKPRequest
	 * @return string Serialized JSON object
	 */
	function updateOauthApp($args, $request) {
		$this->setupTemplate($request);
		import('plugins.generic.oauth.controllers.grid.form.OauthAppForm');
		$oauthAppForm = new OauthAppForm($this->plugin);
		$oauthAppForm->readInputData();
		if ($oauthAppForm->validate()) {
			$oauthAppForm->execute();
			return DAO::getDataChangedEvent();
		} else {
			$json = new JSONMessage(true, $oauthAppForm->fetch($request));
			return $json->getString();
		}
	}

	/**
	 * Delete an OAuth application
	 * @param $args array
	 * @param $request PKPRequest
	 * @return string Serialized JSON object
	 */
	function deleteOauthApp($args, $request) {
		$oauthAppName = $request->getUserVar('oauthAppName');
		$context = $request->getContext();
		$oauthPlugin = $this->plugin;
		$oauthAppNames = $oauthPlugin->getSetting($context->getId(), 'oauthAppNames');
		$oauthAppSettingsJson = $oauthPlugin->getSetting($context->getId(), 'oauthAppSettings');
		$oauthAppSettingsArray = json_decode($oauthAppSettingsJson, true);
		$appNameIndex = array_search($oauthAppName, $oauthAppNames);
		unset($oauthAppNames[$appNameIndex]);
		unset($oauthAppSettingsArray[$oauthAppName]);
		$oauthPlugin->updateSetting($context->getId(), 'oauthAppSettings', json_encode($oauthAppSettingsArray), 'string');
		$oauthPlugin->updateSetting($context->getId(), 'oauthAppNames', $oauthAppNames, 'object');
		return DAO::getDataChangedEvent();
	}
}

?>
