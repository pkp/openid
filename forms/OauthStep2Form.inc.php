<?php

use Sokil\IsoCodes\IsoCodesFactory;

import('lib.pkp.classes.form.Form');

class OauthStep2Form extends Form
{
	private array $credentials;

	function __construct(string $template, array $credentials = array())
	{
		$this->credentials = $credentials;
		$this->addCheck(new FormValidatorPost($this));
		$this->addCheck(new FormValidatorCSRF($this));
		parent::__construct($template);
	}

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

	function initData()
	{
		if (is_array($this->credentials) && !empty($this->credentials)) {
			$this->_data = array(
				'oauthId' => $this->_encryptOrDecrypt('encrypt', $this->credentials['id']),
				'username' => $this->credentials['username'],
				'givenName' => $this->credentials['given_name'],
				'familyName' => $this->credentials['family_name'],
				'email' => $this->credentials['email'],
			);
		}
	}

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

	function validate($callHooks = true)
	{


		return parent::validate($callHooks);
	}


	function execute(...$functionArgs)
	{
		$userDao = DAORegistry::getDAO('UserDAO');
		$register = is_string($this->getData('register'));
		$connect = is_string($this->getData('connect'));

		if ($register) {

		} elseif ($connect) {

		}

		$user = $userDao->newDataObject();

		$user->setUsername($this->getData('username'));
	}

	/**
	 * @param string $action
	 * @param string $string
	 * @return string|null
	 */
	private function _encryptOrDecrypt(string $action, string $string): string
	{
		$alg = 'AES-256-CBC';
		$pwd = '9wPp\28AE:Xj9P3E?i';
		$result = null;
		if ($action == 'encrypt') {
			$result = openssl_encrypt($string, $alg, $pwd);
		} elseif ($action == 'decrypt') {
			$result = openssl_decrypt($string, $alg, $pwd);
		}

		return $result;
	}
}
