<?php

/**
 * @file classes/AuthPageHooksHelper.php
 *
 * Copyright (c) 2026 Simon Fraser University
 * Copyright (c) 2026 John Willinsky
 * Distributed under the GNU GPL v3. For full terms see the file LICENSE.
 *
 * @class AuthPageHooksHelper
 *
 * @brief Provider buttons and SSO errors on the core login and registration pages.
 */

namespace APP\plugins\generic\openid\classes;

use APP\plugins\generic\openid\handler\OpenIDLoginHandler;
use APP\plugins\generic\openid\OpenIDPlugin;
use APP\template\TemplateManager;
use PKP\core\PKPRequest;
use PKP\plugins\Hook;
use Throwable;

class AuthPageHooksHelper
{
	public function __construct(protected OpenIDPlugin $plugin)
	{
	}

	public function register(PKPRequest $request, array $settings): void
	{
		$hideLogin = !($settings['legacyLogin'] ?? false) && $request->getRequestedOp() === 'index';
		$hideRegister = !($settings['legacyRegister'] ?? false);

		Hook::add('TemplateManager::display', function (string $hookName, array $args) use ($hideLogin, $hideRegister): bool {
			$template = &$args[1];

			if ($hideLogin && $template === 'frontend/pages/userLogin.tpl') {
				$template = $this->inheritTemplate($template, 'hideLoginForm');
			} elseif ($hideRegister && $template === 'frontend/pages/userRegister.tpl') {
				$template = $this->inheritTemplate($template, 'hideRegisterForm');
			}

			return false;
		});

		Hook::add('Templates::User::Login::BeforeForm', function (string $hookName, array $args) use ($request, $settings): bool {
			$output = &$args[2];
			$output .= $this->renderSsoError($request, $settings);

			return false;
		});

		Hook::add('Templates::User::Login::AfterForm', function (string $hookName, array $args) use ($request, $settings): bool {
			$output = &$args[2];
			$output .= $this->renderProviderButtons($request, $settings);

			return false;
		});

		Hook::add('Templates::User::Register::AfterForm', function (string $hookName, array $args) use ($request, $settings): bool {
			$output = &$args[2];
			$output .= $this->renderProviderButtons($request, $settings);

			return false;
		});
	}

	public function inheritTemplate(string $template, string $child): string
	{
		try {
			$viewName = TemplateManager::getManager()->smartyPathToViewName($template);
			$resolved = app('view.finder')->find(app('view')->resolveViewName($viewName));
		} catch (Throwable $e) {
			error_log($this->plugin->getName() . ' - could not resolve ' . $template . ': ' . $e->getMessage());

			return $template;
		}

		$engine = str_ends_with($resolved, '.blade') ? 'blade' : 'smarty';

		return $this->plugin->getTemplateViewNamespace() . '::' . $engine . '.' . $child;
	}

	public function inheritFormTemplate(string $formHook, string $template, string $child): void
	{
		Hook::add($formHook . '::display', function (string $hookName, array $args) use ($template, $child): bool {
			$args[0]->setTemplate($this->inheritTemplate($template, $child));

			return false;
		});
	}

	private function renderProviderButtons(PKPRequest $request, array $settings): string
	{
		$templateMgr = TemplateManager::getManager($request);

		$linkList = OpenIDLoginHandler::generateProviderLinks(
			$this->plugin,
			$settings['provider'] ?? [],
			$request,
			$templateMgr,
			($settings['legacyRegister'] ?? false) && $request->getRequestedPage() === 'login'
		);

		if (empty($linkList)) {
			return '';
		}

		$templateMgr->assign([
			'linkList' => $linkList,
			'openIDImageURL' => $request->getBaseUrl() . '/' . $this->plugin->getPluginPath() . '/images/',
		]);

		return $templateMgr->fetch($this->plugin->getTemplateResource('loginProviders.tpl'));
	}

	private function renderSsoError(PKPRequest $request, array $settings): string
	{
		if (!$request->getUserVar('sso_error')) {
			return '';
		}

		$templateMgr = TemplateManager::getManager($request);

		OpenIDLoginHandler::setSSOErrorMessages(
			$request->getUserVar('sso_error'),
			htmlspecialchars($request->getUserVar('sso_error_msg') ?? '', ENT_QUOTES, 'UTF-8'),
			$templateMgr,
			OpenIDPlugin::getContextData($request)
		);
		$templateMgr->assign('legacyLogin', (bool) ($settings['legacyLogin'] ?? false));

		return $templateMgr->fetch($this->plugin->getTemplateResource('loginError.tpl'));
	}
}
