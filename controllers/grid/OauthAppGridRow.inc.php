<?php

/**
 * @file plugins/generic/oauth/controllers/grid/OauthAppGridRow.inc.php
 *
 * Copyright (c) 2014-2016 Simon Fraser University Library
 * Copyright (c) 2003-2016 John Willinsky
 * Distributed under the GNU GPL v2. For full terms see the file docs/COPYING.
 *
 * @class OauthAppGridRow
 * @ingroup controllers_grid_oauthApp
 *
 * @brief Handle OAuth application grid row requests.
 */

import('lib.pkp.classes.controllers.grid.GridRow');

class OauthAppGridRow extends GridRow
{
	/**
	 * Constructor
	 */
	function __construct()
	{
		parent::__construct();
	}

	//
	// Overridden template methods
	//
	/**
	 * @copydoc GridRow::initialize()
	 * @param $request
	 * @param null $args
	 */
	function initialize($request, $args = null)
	{
		parent::__construct();

		$oauthAppName = $this->getId();
		if (!empty($oauthAppName)) {
			$router = $request->getRouter();

			// Create the "edit" action
			import('lib.pkp.classes.linkAction.request.AjaxModal');
			$this->addAction(
				new LinkAction(
					'editOauthApp',
					new AjaxModal(
						$router->url($request, null, null, 'editOauthApp', null, array('oauthAppName' => $oauthAppName)),
						__('grid.action.edit'),
						'modal_edit',
						true
					),
					__('grid.action.edit'),
					'edit'
				)
			);

			// Create the "delete" action
			import('lib.pkp.classes.linkAction.request.RemoteActionConfirmationModal');
			$this->addAction(
				new LinkAction(
					'deleteOauthApp',
					new RemoteActionConfirmationModal(
						$request->getSession(),
						__('common.confirmDelete'),
						__('grid.action.delete'),
						$router->url($request, null, null, 'deleteOauthApp', null, array('oauthAppName' => $oauthAppName)), 'modal_delete'
					),
					__('grid.action.delete'),
					'delete'
				)
			);
		}
	}
}

?>
