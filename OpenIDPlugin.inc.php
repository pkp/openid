<?php

import('lib.pkp.classes.plugins.GenericPlugin');

/**
 * This file is part of OpenID Authentication Plugin (https://github.com/leibniz-psychology/pkp-openid).
 *
 * OpenID Authentication Plugin is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * OpenID Authentication Plugin is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with OpenID Authentication Plugin.  If not, see <https://www.gnu.org/licenses/>.
 *
 * Copyright (c) 2020 Leibniz Institute for Psychology Information (https://leibniz-psychology.org/)
 *
 * @file plugins/generic/openid/OpenIDPlugin.inc.php
 * @ingroup plugins_generic_openid
 * @brief OpenIDPlugin class for plugin and handler registration
 *
 */
class OpenIDPlugin extends GenericPlugin
{


	/**
	 * Get the display name of this plugin
	 * @return string
	 */
	function getDisplayName()
	{
		return __('plugins.generic.openid.name');
	}

	/**
	 * Get the description of this plugin
	 * @return string
	 */
	function getDescription()
	{
		return __('plugins.generic.openid.description');
	}


	/**
	 * Register the plugin, if enabled
	 *
	 * @param $category
	 * @param $path
	 * @param $mainContextId
	 * @return true on success
	 */
	public function register($category, $path, $mainContextId = null)
	{
		$success = parent::register($category, $path);
		if ($success && $this->getEnabled()) {
			HookRegistry::register('LoadHandler', array($this, 'callbackLoadHandler'));
		}

		return $success;
	}

	/**
	 * Loads Handler for login, registration, sign-out and the plugin specific urls.
	 * Adds JavaScript and Style files to the template.
	 *
	 * @param $hookName
	 * @param $args
	 * @return false
	 */
	public function callbackLoadHandler($hookName, $args)
	{
		$page = $args[0];
		$op = $args[1];
		define('KEYCLOAK_PLUGIN_NAME', $this->getName());
		switch ("$page/$op") {
			case 'openid/doAuthentication':
			case 'openid/registerOrConnect':
				$request = Application::get()->getRequest();
				$templateMgr = TemplateManager::getManager($request);
				$templateMgr->addStyleSheet('OpenIDPluginStyle', $request->getBaseUrl().'/'.$this->getPluginPath().'/css/style.css');
				$templateMgr->addJavaScript('OpenIDPluginScript', $request->getBaseUrl().'/'.$this->getPluginPath().'/js/scripts.js');
				define('HANDLER_CLASS', 'OpenIDHandler');
				$args[2] = $this->getPluginPath().'/handler/OpenIDHandler.inc.php';
				break;
			case 'login/index':
			case 'login/legacyLogin':
			case 'user/register':
			case 'login/signOut':
				$request = Application::get()->getRequest();
				$templateMgr = TemplateManager::getManager($request);
				$templateMgr->addStyleSheet('OpenIDPluginStyle', $request->getBaseUrl().'/'.$this->getPluginPath().'/css/style.css');
				$templateMgr->addJavaScript('OpenIDPluginScript', $request->getBaseUrl().'/'.$this->getPluginPath().'/js/scripts.js');
				$templateMgr->assign('openIDImageURL', $request->getBaseUrl().'/'.$this->getPluginPath().'/images/');
				define('HANDLER_CLASS', 'OpenIDLoginHandler');
				$args[2] = $this->getPluginPath().'/handler/OpenIDLoginHandler.inc.php';
				break;
		}

		return false;
	}

	/**
	 * Adds settings link to plugin actions
	 *
	 * @param $request
	 * @param $actionArgs
	 * @return array with plugin actions
	 */
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

	/**
	 * Opens the settings if settings link is clicked
	 *
	 * @param $args
	 * @param $request
	 * @return JSONMessage
	 */
	public function manage($args, $request)
	{
		switch ($request->getUserVar('verb')) {
			case 'settings':
				$this->import('forms/OpenIDPluginSettingsForm');
				$form = new OpenIDPluginSettingsForm($this);
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

