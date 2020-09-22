<?php


import('lib.pkp.classes.plugins.GenericPlugin');

class OpenIDPlugin extends GenericPlugin
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
			case 'user/register':
			case 'login/signOut':
			case 'login/signOutOjs':
				define('HANDLER_CLASS', 'OpenIDLoginHandler');
				$args[2] = $this->getPluginPath().'/handler/OpenIDLoginHandler.inc.php';
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

