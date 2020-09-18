<?php

use Sokil\IsoCodes\IsoCodesFactory;

import('lib.pkp.classes.form.Form');

class OpenIDStep2Form extends Form
{
	private array $credentials;
	private OpenIDPlugin $plugin;
	private ?int $contextId;

	/**
	 * OpenIDStep2Form constructor.
	 *
	 * @param OpenIDPlugin $plugin
	 * @param array $credentials
	 */
	function __construct(OpenIDPlugin $plugin, array $credentials = array())
	{
		$context = Application::get()->getRequest()->getContext();
		$this->contextId = ($context == null) ? 0 : $context->getId();
		$this->plugin = $plugin;
		$this->credentials = $credentials;
		$this->addCheck(new FormValidatorPost($this));
		$this->addCheck(new FormValidatorCSRF($this));
		parent::__construct($plugin->getTemplateResource('authStep2.tpl'));
	}

	/**
	 *
	 * @param PKPRequest $request
	 * @param null $template
	 * @param false $display
	 * @return string|null
	 */
	function fetch($request, $template = null, $display = false)
	{
		$templateMgr = TemplateManager::getManager($request);
		$isoCodes = new IsoCodesFactory();
		$countries = array();
		foreach ($isoCodes->getCountries() as $country) {
			$countries[$country->getAlpha2()] = $country->getLocalName();
		}
		asort($countries);
		$templateMgr->assign('countries', $countries);

		return parent::fetch($request, $template, $display);
	}

	/**
	 *
	 */
	function initData()
	{
		if (is_array($this->credentials) && !empty($this->credentials)) {
			// generate username if username is orchid id
			if (key_exists('username', $this->credentials)) {
				if (preg_match('/\d{4}-\d{4}-\d{4}-\d{4}/', $this->credentials['username'])) {
					$given = key_exists('given_name', $this->credentials) ? $this->credentials['given_name'] : '';
					$family = key_exists('family_name', $this->credentials) ? $this->credentials['family_name'] : '';
					$this->credentials['username'] = mb_strtolower($given.$family, 'UTF-8');
				}
			}
			$this->_data = array(
				'oauthId' => $this->_encryptOrDecrypt('encrypt', $this->credentials['id']),
				'username' => $this->credentials['username'],
				'givenName' => $this->credentials['given_name'],
				'familyName' => $this->credentials['family_name'],
				'email' => $this->credentials['email'],
			);
		}
	}

	/**
	 *
	 */
	function readInputData()
	{
		parent::readInputData();
		$this->readUserVars(
			array(
				'oauthId',
				'username',
				'email',
				'givenName',
				'familyName',
				'affiliation',
				'country',
				'privacyConsent',
				'emailConsent',
				'register',
				'connect',
				'usernameLogin',
				'passwordLogin',
			)
		);
	}

	/**
	 *
	 * @param bool $callHooks
	 * @return bool|mixed|null
	 */
	function validate($callHooks = true)
	{
		$userDao = DAORegistry::getDAO('UserDAO');
		$register = is_string($this->getData('register'));
		$connect = is_string($this->getData('connect'));
		if ($register) {
			$this->_data['returnTo'] = "register";
			$this->addCheck(new FormValidator($this, 'username', 'required', 'plugins.generic.openid.form.error.username.required'));
			$this->addCheck(
				new FormValidatorCustom(
					$this, 'username', 'required', 'plugins.generic.openid.form.error.usernameExists',
					array(DAORegistry::getDAO('UserDAO'), 'userExistsByUsername'), array(), true
				)
			);
			$this->addCheck(new FormValidator($this, 'givenName', 'required', 'plugins.generic.openid.form.error.givenName.required'));
			$this->addCheck(new FormValidator($this, 'familyName', 'required', 'plugins.generic.openid.form.error.familyName.required'));
			$this->addCheck(new FormValidator($this, 'country', 'required', 'plugins.generic.openid.form.error.country.required'));
			$this->addCheck(new FormValidator($this, 'affiliation', 'required', 'plugins.generic.openid.form.error.affiliation.required'));
			$this->addCheck(new FormValidatorEmail($this, 'email', 'required', 'plugins.generic.openid.form.error.email.required'));
			$this->addCheck(
				new FormValidatorCustom(
					$this, 'email', 'required', 'plugins.generic.openid.form.error.emailExists',
					array(DAORegistry::getDAO('UserDAO'), 'userExistsByEmail'), array(), true
				)
			);
			$context = Application::get()->getRequest()->getContext();
			if ($context && $context->getData('privacyStatement')) {
				$this->addCheck(new FormValidator($this, 'privacyConsent', 'required', 'plugins.generic.openid.form.error.privacyConsent.required'));
			}
		} elseif ($connect) {
			$this->_data['returnTo'] = "connect";
			$this->addCheck(new FormValidator($this, 'usernameLogin', 'required', 'plugins.generic.openid.form.error.usernameOrEmail.required'));
			$this->addCheck(new FormValidator($this, 'passwordLogin', 'required', 'plugins.generic.openid.form.error.password.required'));
			$username = $this->getData('usernameLogin');
			$password = $this->getData('passwordLogin');
			$user = $userDao->getByUsername($username, true);
			if (!isset($user)) {
				$user = $userDao->getUserByEmail($username, true);
			}
			if (!isset($user)) {
				$this->addError('usernameLogin', __('plugins.generic.openid.form.error.user.not.found'));
			} else {
				$valid = Validation::verifyPassword($user->getUsername(), $password, $user->getPassword(), $rehash);
				if (!$valid) {
					$this->addError('passwordLogin', __('plugins.generic.openid.form.error.invalid.credentials'));
				}
			}
		}

		return parent::validate($callHooks);
	}

	/**
	 *
	 * @param mixed ...$functionArgs
	 * @return bool|mixed|null
	 */
	function execute(...$functionArgs)
	{
		$userDao = DAORegistry::getDAO('UserDAO');
		$register = is_string($this->getData('register'));
		$connect = is_string($this->getData('connect'));
		$result = false;
		if ($register) {
			$oauthId = $this->getData('oauthId');
			if (!empty($oauthId)) {
				$user = $this->_registerUser($oauthId);
				if ($user) {
					if ($functionArgs[0] = true) {
						$this->_generateApiKey($user, $oauthId);
					}
					Validation::registerUserSession($user, $reason, true);
					$result = true;
				}
			}
		} elseif ($connect) {
			$username = $this->getData('usernameLogin');
			$password = $this->getData('passwordLogin');
			$oauthId = $this->getData('oauthId');
			$user = $userDao->getByUsername($username, true);
			if (!isset($user)) {
				$user = $userDao->getUserByEmail($username, true);
			}
			if (!empty($oauthId) && isset($user) && Validation::verifyPassword($user->getUsername(), $password, $user->getPassword(), $rehash)) {
				$userSettingsDao = DAORegistry::getDAO('UserSettingsDAO');
				$userSettingsDao->updateSetting($user->getId(), 'openid::identifier', $this->_encryptOrDecrypt('decrypt', $oauthId), 'string');
				if ($functionArgs[0] = true) {
					$this->_generateApiKey($user, $oauthId);
				}
				Validation::registerUserSession($user, $reason, true);
				$result = true;
			}
		}
		parent::execute(...$functionArgs);

		return $result;
	}


	/**
	 * This function creates a new OJS User if no user exists with the given username, email or openid::identifier!
	 *
	 * @param $credentials
	 * @return User|null
	 */
	private function _registerUser($oauthId)
	{
		$userDao = DAORegistry::getDAO('UserDAO');
		$user = $userDao->newDataObject();
		$user->setUsername($this->getData('username'));

		$request = Application::get()->getRequest();
		$site = $request->getSite();
		$sitePrimaryLocale = $site->getPrimaryLocale();
		$currentLocale = AppLocale::getLocale();

		$user->setGivenName($this->getData('givenName'), $currentLocale);
		$user->setFamilyName($this->getData('familyName'), $currentLocale);
		$user->setEmail($this->getData('email'));
		$user->setCountry($this->getData('country'));
		$user->setAffiliation($this->getData('affiliation'), $currentLocale);

		if ($sitePrimaryLocale != $currentLocale) {
			$user->setGivenName($this->getData('givenName'), $sitePrimaryLocale);
			$user->setFamilyName($this->getData('familyName'), $sitePrimaryLocale);
			$user->setAffiliation($this->getData('affiliation'), $sitePrimaryLocale);
		}

		$user->setDateRegistered(Core::getCurrentDate());
		$user->setInlineHelp(1);

		$user->setPassword(Validation::encryptCredentials($this->getData('username'), openssl_random_pseudo_bytes(16)));

		$userDao->insertObject($user);

		if ($user->getId()) {
			if ($request->getContext()) {
				$userGroupDao = DAORegistry::getDAO('UserGroupDAO');
				$defaultReaderGroup = $userGroupDao->getDefaultByRoleId($request->getContext()->getId(), ROLE_ID_READER);
				if ($defaultReaderGroup) {
					$userGroupDao->assignUserToGroup($user->getId(), $defaultReaderGroup->getId());
				}
			}
			$userSettingsDao = DAORegistry::getDAO('UserSettingsDAO');
			$userSettingsDao->updateSetting($user->getId(), 'openid::identifier', $this->_encryptOrDecrypt('decrypt', $oauthId), 'string');
		} else {
			$user = null;
		}

		return $user;
	}

	/**
	 * @param $user
	 * @param $value
	 * @return bool
	 */
	private function _generateApiKey($user, $value)
	{
		$secret = Config::getVar('security', 'api_key_secret', '');

		if ($secret) {
			$userDao = DAORegistry::getDAO('UserDAO');
			$user->setData('apiKeyEnabled', true);
			$user->setData('apiKey', $this->_encryptOrDecrypt('encrypt', $value));
			$userDao->updateObject($user);

			return true;
		}

		return false;
	}

	/**
	 * @param string $action
	 * @param string $string
	 * @return string|null
	 */
	private function _encryptOrDecrypt(string $action, string $string): string
	{
		$alg = 'AES-256-CBC';
		$settings = json_decode($this->plugin->getSetting($this->contextId, 'openIDSettings'), true);
		$result = null;
		if (key_exists('hashSecret', $settings) && !empty($settings['hashSecret'])) {
			$pwd = $settings['hashSecret'];
			if ($action == 'encrypt') {
				$result = openssl_encrypt($string, $alg, $pwd);
			} elseif ($action == 'decrypt') {
				$result = openssl_decrypt($string, $alg, $pwd);
			}
		} else {
			$result = $string;
		}

		return $result;
	}
}
