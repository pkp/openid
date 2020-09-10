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
			HookRegistry::register('TemplateManager::display', array($this, 'templateCallback'));
			HookRegistry::register('LoadHandler', array($this, 'callbackLoadHandler'));
		}

		return $success;
	}


	public function callbackLoadHandler($hookName, $args)
	{
		$page = $args[0];
		$op = $args[1];
		if ($this->getEnabled())
			switch ("$page/$op") {
				case 'keycloak/doAuthentication':
					define('HANDLER_CLASS', 'KeycloakHandler');
					define('KEYCLOAK_PLUGIN_NAME', $this->getName());
					$args[2] = $this->getPluginPath().'/'.'KeycloakHandler.inc.php';
					break;
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
					$templateMgr->registerFilter('output', array($this, 'loginFilter'));
					break;
			}
		}

		return false;
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
			$match = $matches[0][0];
			$offset = $matches[0][1];
			$context = Application::get()->getRequest()->getContext();
			$contextId = ($context == null) ? 0 : $context->getId();
			$settingsJson = $this->getSetting($contextId, 'keycloakSettings');
			if ($settingsJson != null) {
				$settings = json_decode($settingsJson, true);
				if (key_exists('url', $settings) && key_exists('realm', $settings) && key_exists('clientId', $settings)) {
					$templateMgr->assign(
						array(
							'targetOp' => 'login',
							'url' => $settings['url'],
							'realm' => $settings['realm'],
							'clientId' => $settings['clientId'],
						)
					);
					$newOutput = substr($output, 0, $offset + strlen($match));
					$newOutput .= $templateMgr->fetch($this->getTemplateResource('authLink.tpl'));
					$newOutput .= substr($output, $offset + strlen($match));
					$output = $newOutput;
				}
			}
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
				$this->import('KeycloakPluginSetupForm');
				$form = new KeycloakPluginSetupForm($this);
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

