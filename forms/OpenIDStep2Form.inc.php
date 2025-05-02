<?php

/**
 * @file forms/OpenIDStep2Form.php
 *
 * Copyright (c) 2020 Leibniz Institute for Psychology Information (https://leibniz-psychology.org/)
 * Copyright (c) 2024 Simon Fraser University
 * Copyright (c) 2024 John Willinsky
 * Distributed under the GNU GPL v3. For full terms see the file LICENSE.
 *
 * @class OpenIDStep2Form
 *
 * @brief Form class for the second step which is needed if no local user was found with the OpenID identifier
 */

use Sokil\IsoCodes\IsoCodesFactory;

import('lib.pkp.classes.form.Form');
import('plugins.generic.openid.classes.UserClaims');
import('plugins.generic.openid.handler.OpenIDHandler');
import('lib.pkp.classes.user.form.UserFormHelper');
import('lib.pkp.classes.user.InterestManager');

class OpenIDStep2Form extends Form
{
	private $contextId;
	private OpenIDPlugin $plugin;
	private ?string $selectedProvider = null;
	private ?UserClaims $claims = null;

	/**
	 * OpenIDStep2Form constructor.
	 */
	function __construct(OpenIDPlugin $plugin, ?string $selectedProvider = null, ?UserClaims $claims = null)
	{
		$this->contextId = OpenIDPlugin::getContextData(Application::get()->getRequest())->getId();

		$this->plugin = $plugin;
		$this->selectedProvider = $selectedProvider;
		$this->claims = $claims;

		$this->addCheck(new FormValidatorPost($this));
		$this->addCheck(new FormValidatorCSRF($this));

		parent::__construct($plugin->getTemplateResource('authStep2.tpl'));
	}

	/**
	 * @copydoc Form::fetch()
	 */
	function fetch($request, $template = null, $display = false)
	{
		$settings = OpenIDPlugin::getOpenIDSettings($this->plugin, $this->contextId);

		$isoCodes = new IsoCodesFactory();
		$countries = [];
		foreach ($isoCodes->getCountries() as $country) {
			$countries[$country->getAlpha2()] = $country->getLocalName();
		}
		asort($countries);

		$contextData = OpenIDPlugin::getContextData($request);

		$templateMgr = TemplateManager::getManager($request);

		$disableFields = $settings['disableFields'];

		$openidIdentityFieldsGivenName = false;
		$openidIdentityFieldsFamilyName = false;
		$openidIdentityFieldsEmail = false;

		if (!empty($disableFields)) {
			if (array_key_exists('givenName', $disableFields) && $disableFields['givenName'] == 1) {
				$openidIdentityFieldsGivenName = true;
			}
			if (array_key_exists('familyName', $disableFields) && $disableFields['familyName'] == 1) {
				$openidIdentityFieldsFamilyName = true;
			}
			if (array_key_exists('email', $disableFields) && $disableFields['email'] == 1) {
				$openidIdentityFieldsEmail = true;
			}
		}

		// check if at least one field is disabled and assign the notification flag
		$showNotification = $openidIdentityFieldsGivenName || $openidIdentityFieldsFamilyName || $openidIdentityFieldsEmail;

		// Assign variables to the Smarty template
		$templateMgr->assign([
			'disableConnect' => $settings['disableConnect'],
			'countries' => $countries,
			'privacyStatement' => $contextData->getPrivacyStatement(),
			'contextId' => $contextData->getId(),
			'openidIdentityFieldsGivenName' => $openidIdentityFieldsGivenName,
			'openidIdentityFieldsFamilyName' => $openidIdentityFieldsFamilyName,
			'openidIdentityFieldsEmail' => $openidIdentityFieldsEmail,
			'showOpenIdNotification' => $showNotification,
		]);

		$userFormHelper = new UserFormHelper();
		$userFormHelper->assignRoleContent($templateMgr, $request);

		return parent::fetch($request, $template, $display);
	}

	/**
	 * @copydoc Form::initData()
	 */
	function initData()
	{
		if ($this->claims !== null) {
			// Generate username if username is ORCID ID
			if ($this->claims->username && preg_match('/\d{4}-\d{4}-\d{4}-\d{4}/', $this->claims->username)) {
				$given = $this->claims->givenName ?? '';
				$family = $this->claims->familyName ?? '';
				$this->claims->username = mb_strtolower($given . $family, 'UTF-8');
			}

			// Sanitize all string values in claims
			foreach (get_object_vars($this->claims) as $key => $value) {
				if (is_string($value)) {
					$this->claims->$key = htmlspecialchars($value, ENT_QUOTES, 'UTF-8');
				}
			}

			$this->_data = [
				'selectedProvider' => $this->selectedProvider ?? null,
				'oauthId' => OpenIDPlugin::encryptOrDecrypt($this->plugin, $this->contextId, $this->claims->id),
				'username' => $this->claims->username,
				'givenName' => $this->claims->givenName,
				'familyName' => $this->claims->familyName,
				'email' => $this->claims->email,
				'userGroupIds' => [],
			];
		}
	}

	/**
	 * @copydoc Form::readInputData()
	 */
	function readInputData()
	{
		parent::readInputData();
		$this->readUserVars(
			[
				'selectedProvider',
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
				'readerGroup',
				'reviewerGroup',
				'interests',
			]
		);
		// Collect the specified user group IDs into a single piece of data
		$this->setData(
			'userGroupIds',
			array_merge(
				array_keys((array)$this->getData('readerGroup')),
				array_keys((array)$this->getData('reviewerGroup'))
			)
		);
	}

	/**
	 * @copydoc Form::validate()
	 */
	function validate($callHooks = true)
	{
		/** @var UserDAO $userDao */
		$userDao = DAORegistry::getDAO('UserDAO');

		$register = is_string($this->getData('register'));
		$connect = is_string($this->getData('connect'));
		if ($register) {
			$this->_data['returnTo'] = "register";
			$this->addCheck(new FormValidator($this, 'username', 'required', 'plugins.generic.openid.form.error.username.required'));
			$this->addCheck(
				new FormValidatorCustom(
					$this, 'username', 'required', 'plugins.generic.openid.form.error.usernameExists', function ($username) {
						/** @var UserDAO $userDao */
						$userDao = DAORegistry::getDAO('UserDAO');
						$user = $userDao->getByUsername($username, true);
						return !isset($user);
					}
				)
			);

			$this->addCheck(new FormValidator($this, 'givenName', 'required', 'plugins.generic.openid.form.error.givenName.required'));
			$this->addCheck(new FormValidator($this, 'familyName', 'required', 'plugins.generic.openid.form.error.familyName.required'));
			$this->addCheck(new FormValidator($this, 'country', 'required', 'plugins.generic.openid.form.error.country.required'));
			$this->addCheck(new FormValidator($this, 'affiliation', 'required', 'plugins.generic.openid.form.error.affiliation.required'));
			$this->addCheck(new FormValidatorEmail($this, 'email', 'required', 'plugins.generic.openid.form.error.email.required'));
			$this->addCheck(
				new FormValidatorCustom(
					$this, 'email', 'required', 'plugins.generic.openid.form.error.emailExists', function ($email) {
						/** @var UserDAO $userDao */
						$userDao = DAORegistry::getDAO('UserDAO');
						$user = $userDao->getUserByEmail($email, true);
						return !isset($user);
					}
				)
			);

			if (OpenIDPlugin::getContextData(Application::get()->getRequest())->getPrivacyStatement()) {
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
	 * @copydoc Form::execute()
	 */
	function execute(...$functionArgs)
	{
		$userDao = DAORegistry::getDAO('UserDAO');
		$userSettingsDao = DAORegistry::getDAO('UserSettingsDAO');

		$register = is_string($this->getData('register'));
		$connect = is_string($this->getData('connect'));
		$oauthId = $this->getData('oauthId');
		$selectedProvider = $this->getData('selectedProvider');

		$result = false;
		$userClaims = null;

		if (!empty($oauthId) && !empty($selectedProvider)) {
			$decriptedOauthId = OpenIDPlugin::encryptOrDecrypt($this->plugin, $this->contextId, $oauthId, false);
			$userClaims = new UserClaims();
			$userClaims->id = $decriptedOauthId;

			// prevent saving one openid:ident to multiple accounts
			$userSameOauthID = $userDao->getBySetting(OpenIDPlugin::getOpenIDUserSetting($selectedProvider), $decriptedOauthId);

			if (!isset($userSameOauthID)) {
				$userSameOauthID = $userDao->getBySetting(OpenIDPlugin::getOpenIDUserSetting($selectedProvider), hash('sha256', $decriptedOauthId));
			}

			$considerDisabledFieldsInUpdate = false;

			if (!isset($userSameOauthID)) {
				if ($register) {
					$user = $this->_registerUser();
					if (isset($user)) {
						if ($selectedProvider == OpenIDPlugin::PROVIDER_ORCID) {
							$user->setOrcid($decriptedOauthId);
						}

						$userSettingsDao->updateSetting($user->getId(), OpenIDPlugin::getOpenIDUserSetting($selectedProvider), $decriptedOauthId, 'string');
						
						$userDao->updateObject($user);
						$result = true;
					}
				} elseif ($connect) {
					$userClaims->givenName = $this->getData('givenName');
					$userClaims->familyName = $this->getData('familyName');

					$username = $this->getData('usernameLogin');
					$password = $this->getData('passwordLogin');
					$user = $userDao->getByUsername($username, true);

					if (!isset($user)) {
						$user = $userDao->getUserByEmail($username, true);
					}
					
					if (isset($user) && Validation::verifyPassword($user->getUsername(), $password, $user->getPassword(), $rehash)) {
						$result = true;
					}

					$considerDisabledFieldsInUpdate = true;
				}

				if ($result && isset($user)) {
					$sessionManager = SessionManager::getManager();
					$session = $sessionManager->getUserSession();
					$encodedIdToken = $session->getSessionVar(OpenIDPlugin::ID_TOKEN_NAME);

					$contextData = OpenIDPlugin::getContextData(Application::get()->getRequest());

					OpenIDHandler::updateUserDetails($this->plugin, $userClaims, $user, $contextData, $selectedProvider, true, $considerDisabledFieldsInUpdate);
					$reason = null;
					Validation::registerUserSession($user, $reason);

					$session = $sessionManager->getUserSession();
					$session->setSessionVar(OpenIDPlugin::ID_TOKEN_NAME, $encodedIdToken);
				}
			}
		}
		parent::execute(...$functionArgs);

		return $result;
	}


	/**
	 * This function registers a new User if no user exists with the given username, email or openid::{provider_name}!
	 */
	private function _registerUser(): ?User
	{
		/** @var UserDAO $userDao */
		$userDao = DAORegistry::getDAO('UserDAO');

		$user = $userDao->newDataObject();
		$user->setUsername($this->getData('username'));
		
		$contextData = OpenIDPlugin::getContextData(Application::get()->getRequest());

		$sitePrimaryLocale = $contextData->getPrimaryLocale();
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
			// Insert the user interests
			$interestManager = new InterestManager();
			$interestManager->setInterestsForUser($user, $this->getData('interests'));

			/** @var UserGroupDAO $userGroupDao */
			$userGroupDao = DAORegistry::getDAO('UserGroupDAO');

			// Save the selected roles or assign the Reader role if none selected
			if ($contextData->IsInContext() && !$this->getData('reviewerGroup')) {
				$defaultReaderGroup = $userGroupDao->getDefaultByRoleId($contextData->getId(), ROLE_ID_READER);
				if ($defaultReaderGroup) {
					$userGroupDao->assignUserToGroup($user->getId(), $defaultReaderGroup->getId());
				}
			} else {
				$userFormHelper = new UserFormHelper();
				$userFormHelper->saveRoleContent($this, $user);
			}
		} else {
			$user = null;
		}

		return $user;
	}
}
