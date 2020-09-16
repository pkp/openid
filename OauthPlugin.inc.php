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
		$success = parent::register($category, $path);
		if ($success && $this->getEnabled()) {
			HookRegistry::register('LoadHandler', array($this, 'callbackLoadHandler'));
		}

		return $success;
	}


	public function callbackLoadHandler($hookName, $args)
	{
		$page = $args[0];
		$op = $args[1];
		define('KEYCLOAK_PLUGIN_NAME', $this->getName());
		if ($this->getEnabled())
			switch ("$page/$op") {
				case 'oauth/doAuthentication':
				case 'oauth/registerOrConnect':
					$request = Application::get()->getRequest();
					$templateMgr = TemplateManager::getManager($request);
					$templateMgr->addStyleSheet('OauthPluginStyle', '/'.$this->getPluginPath().'/css/oauth.css');
					$templateMgr->addJavaScript('OauthPluginScript', '/'.$this->getPluginPath().'/js/oauth.js');
					define('HANDLER_CLASS', 'OauthPluginHandler');
					$args[2] = $this->getPluginPath().'/handler/OauthPluginHandler.inc.php';
					break;
				case 'login/index':
				case 'user/register':
				case 'login/signOut':
				case 'login/signOutOjs':
					define('HANDLER_CLASS', 'OauthLoginRegisterHandler');
					$args[2] = $this->getPluginPath().'/handler/OauthLoginRegisterHandler.inc.php';
					break;
			}

		return false;
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


	public function getActions($request, $actionArgs)
	{
		$actions = parent::getActions($request, $actionArgs);
		if (!$this->getEnabled()) {
			return $actions;
		}
		$router = $request->getRouter();
		import('lib.pkp.classes.linkAction.request.AjaxModal');
		$linkAction = new LinkAction(
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
		);
		array_unshift($actions, $linkAction);

		return $actions;
	}

	public function manage($args, $request)
	{
		switch ($request->getUserVar('verb')) {
			case 'settings':
				$this->import('forms/OauthPluginSetupForm');
				$form = new OauthPluginSetupForm($this);
				if (!$request->getUserVar('save')) {
					$form->initData();

					return new JSONMessage(true, $form->fetch($request));
				}
				$form->readInputData();
				if ($form->validate()) {
					$form->execute();

					return new JSONMessage(true);
				}
		}

		return parent::manage($args, $request);
	}
}

