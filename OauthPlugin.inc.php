<?php

/**
 * @file plugins/generic/oauth/OauthPlugin.inc.php
 *
 * Copyright (c) 2015-2016 University of Pittsburgh
 * Copyright (c) 2014 Simon Fraser University Library
 * Copyright (c) 2014 John Willinsky
 * Distributed under the GNU GPL v2. For full terms see the file docs/COPYING.
 *
 * @class OauthPlugin
 * @ingroup plugins_generic_oauth
 *
 * @brief This plugin adds the ability to link local user accounts to OAuth sources.
 */

import('lib.pkp.classes.plugins.GenericPlugin');

class OauthPlugin extends GenericPlugin
{
	/**
	 * Register the plugin, if enabled
	 * @param $category string
	 * @param $path string
	 * @param null $mainContextId
	 * @return boolean
	 */
	public function register($category, $path, $mainContextId = null)
	{
		if (parent::register($category, $path)) {
			if ($this->getEnabled()) {
				// Register template callback
				HookRegistry::register('TemplateManager::display', array($this, 'templateCallback'));
				// Register load callback
				HookRegistry::register('LoadHandler', array($this, 'loadCallback'));
				// This hook is used to register the components this plugin implements to
				// permit administration of OAuth applications.
				HookRegistry::register('LoadComponentHandler', array($this, 'setupGridHandler'));
			}

			return true;
		}

		return false;
	}

	/**
	 * Hook callback function for LoadHander
	 * @param $hookName string
	 * @param $args array
	 * @return boolean
	 */
	function loadCallback($hookName, $args)
	{
		// Get the template manager from the hook parameters.
		$page =& $args[0];

		if ($this->getEnabled() && $page == 'oauth') {
			$this->import('pages/OauthHandler');
			define('HANDLER_CLASS', 'OauthHandler');

			return true;
		}

		// Permit additional plugins to use this hook; returning true
		// here would interrupt processing of this hook instead.
		return false;
	}

	/**
	 * Permit requests to the OAuth application grid handler
	 * @param $hookName string The name of the hook being invoked
	 * @param $params
	 * @return bool
	 */
	function setupGridHandler($hookName, $params)
	{
		$component =& $params[0];
		if ($component == 'plugins.generic.oauth.controllers.grid.OauthAppGridHandler') {
			define('OAUTH_PLUGIN_NAME', $this->getName());

			return true;
		}

		return false;
	}

	/**
	 * Hook callback function for TemplateManager::display
	 * @param $hookName string
	 * @param $args array
	 * @return boolean
	 */
	function templateCallback($hookName, $args)
	{
		$templateMgr =& $args[0];
		$template =& $args[1];
		if ($this->getEnabled()) {
			switch ($template) {
				case 'frontend/pages/userRegister.tpl':
				case 'frontend/pages/userLogin.tpl':
					$templateMgr->registerFilter('output', array($this, 'javascriptFilter'));
					$templateMgr->registerFilter('output', array($this, 'loginFilter'));
					break;
			}
		}

		return false;
	}

	/**
	 * Output filter adds javascript to display the OAuth options.
	 * @param $output string
	 * @param $templateMgr TemplateManager
	 * @return string
	 */
	function javascriptFilter($output, $templateMgr)
	{
		$matches = null;
		if (preg_match('/<\/body>/', $output, $matches, PREG_OFFSET_CAPTURE)) {
			$offset = $matches[0][1];
			$newOutput = substr($output, 0, $offset);
			$newOutput .= $templateMgr->fetch($this->getTemplateResource('oauthJsLoader.tpl'));
			$newOutput .= substr($output, $offset);
			$output = $newOutput;
			$templateMgr->unregisterFilter('output', array($this, 'javascriptFilter'));
		}

		return $output;
	}

	/**
	 * Output filter adds other oauth app interaction to login form.
	 * @param $output string
	 * @param $templateMgr TemplateManager
	 * @return string
	 */
	function loginFilter($output, $templateMgr)
	{

		if (preg_match('/<form.*id="login" (?s)(.*)<\/form>/', $output, $matches, PREG_OFFSET_CAPTURE)) {
			var_dump("222222");
			$match = $matches[0][0];
			$offset = $matches[0][1];
			$context = Application::get()->getRequest()->getContext();
			$contextId = ($context == null) ? 0 : $context->getId();
			$oauthAppSettings = $this->getSetting($contextId, 'oauthAppSettings');
			$templateMgr->assign(
				array(
					'targetOp' => 'login',
					'oauthAppSettings' => json_decode($oauthAppSettings, true),
				)
			);
			$newOutput = substr($output, 0, $offset + strlen($match));
			$newOutput .= $templateMgr->fetch($this->getTemplateResource('oauthLoader.tpl'));
			$newOutput .= substr($output, $offset + strlen($match));
			$output = $newOutput;
			$templateMgr->unregisterFilter('output', array($this, 'loginFilter'));
		}
		return $output;
	}

	/**
	 * Override the builtin to get the correct template path.
	 * @param bool $inCore
	 * @return string
	 */
	function getTemplatePath($inCore = false)
	{
		return parent::getTemplatePath().'/';
	}

	/**
	 * Get the display name of this plugin
	 * @return string
	 */
	function getDisplayName()
	{
		return __('plugins.generic.oauth.name');
	}

	/**
	 * Get the description of this plugin
	 * @return string
	 */
	function getDescription()
	{
		return __('plugins.generic.oauth.description');
	}

	/**
	 * @param $request
	 * @param $actionArgs
	 * @return array
	 * @see Plugin::getActions()
	 */
	function getActions($request, $actionArgs)
	{
		$router = $request->getRouter();
		import('lib.pkp.classes.linkAction.request.AjaxModal');

		return array_merge(
			$this->getEnabled() ? array(
				new LinkAction(
					'settings',
					new AjaxModal(
						$router->url(
							$request,
							null,
							null,
							'manage',
							null,
							array(
								'verb' => 'settings',
								'plugin' => $this->getName(),
								'category' => 'generic',
							)
						),
						$this->getDisplayName()
					),
					__('manager.plugins.settings'),
					null
				),
			) : array(),
			parent::getActions($request, $actionArgs)
		);
	}

	/**
	 * @param $args
	 * @param $request
	 * @return JSONMessage
	 * @see Plugin::manage()
	 */
	function manage($args, $request)
	{
		$request = $this->getRequest();
		switch ($request->getUserVar('verb')) {
			case 'settings':
				$templateMgr = TemplateManager::getManager($request);
				$dispatcher = $request->getDispatcher();

				return $templateMgr->fetchAjax(
					'oauthAppGridUrlGridContainer',
					$dispatcher->url(
						$request,
						ROUTE_COMPONENT,
						null,
						'plugins.generic.oauth.controllers.grid.OauthAppGridHandler',
						'fetchGrid'
					)
				);
		}

		return null;
	}
}

?>
