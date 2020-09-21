<?php

use Firebase\JWT\JWT;

import('classes.handler.Handler');

class OpenIDHandler extends Handler
{
	/**
	 * @param $args
	 * @param $request
	 * @return bool
	 */
	function doAuthentication($args, $request)
	{
		$templateMgr = TemplateManager::getManager($request);
		$context = $request->getContext();
		$user = null;
		$tokenData = null;
		$plugin = PluginRegistry::getPlugin('generic', KEYCLOAK_PLUGIN_NAME);
		$contextId = ($context == null) ? 0 : $context->getId();
		$settings = json_decode($plugin->getSetting($contextId, 'openIDSettings'), true);
		$accessToken = $this->getAccessTokenViaAuthCode($settings, $request->getUserVar('code'));
		$publicKey = $this->getOpenIDAuthenticationCert($settings);
		$error = false;
		if ($accessToken != null && $publicKey != null) {
			$tokenData = $this->validateAndExtractToken($accessToken, $publicKey);
			if (isset($tokenData) && is_array($tokenData)) {
				$user = $this->getUserViaKeycloakId($tokenData);
				if ($user == null) {
					import($plugin->getPluginPath().'/forms/OpenIDStep2Form');
					$regForm = new OpenIDStep2Form($plugin, $tokenData);
					$regForm->initData();
					$regForm->display($request);
				} elseif (is_a($user, 'User') && !$user->getDisabled()) {
					Validation::registerUserSession($user, $reason, true);
					$request->redirect($context->getPath(), 'user', 'profile', null, $args);
				} elseif ($user->getDisabled()) {
					$error = true;
					$templateMgr->assign('errorType', 'plugins.generic.openid.error.openid.disabled.head');
					$reason = $user->getDisabledReason();
					if ($reason === null) {
						$templateMgr->assign('errorMsg', 'plugins.generic.openid.error.openid.disabled.without');
					} else {
						$templateMgr->assign('errorMsg', 'plugins.generic.openid.error.openid.disabled.with');
						$templateMgr->assign('reason', $reason);
					}
				}
			} else {
				$error = true;
				$templateMgr->assign('errorType', 'plugins.generic.openid.error.openid.cert.head');
				$templateMgr->assign('errorMsg', 'plugins.generic.openid.error.openid.cert.desc');
			}
		} else {
			$error = true;
			$templateMgr->assign('errorType', 'plugins.generic.openid.error.openid.connect.head');
			if (!isset($publicKey)) {
				$templateMgr->assign('errorMsg', 'plugins.generic.openid.error.openid.connect.desc.key');
			} else {
				$templateMgr->assign('errorMsg', 'plugins.generic.openid.error.openid.connect.desc.data');
			}
		}
		if ($error) {
			$supportEmail = $context ? $context->getSetting('supportEmail') : null;
			if ($supportEmail) {
				$templateMgr->assign('supportEmail', $supportEmail);
			}
			$templateMgr->display($plugin->getTemplateResource('error.tpl'));
		}
		return true;
	}

	/**
	 * @param $args
	 * @param $request
	 */
	function registerOrConnect($args, $request)
	{
		$generateApiKey = true;
		if (Validation::isLoggedIn()) {
			$this->setupTemplate($request);
			$templateMgr = TemplateManager::getManager($request);
			$templateMgr->assign('pageTitle', 'user.login.registrationComplete');
			$templateMgr->display('frontend/pages/userRegisterComplete.tpl');
		} elseif (!$request->isPost()) {
			$request->redirect(Application::get()->getRequest()->getContext(), 'login');
		} else {
			$plugin = PluginRegistry::getPlugin('generic', KEYCLOAK_PLUGIN_NAME);
			import($plugin->getPluginPath().'/forms/OpenIDStep2Form');
			$regForm = new OpenIDStep2Form($plugin);
			$regForm->readInputData();
			if (!$regForm->validate()) {
				$regForm->display($request);
			} elseif ($regForm->execute($generateApiKey)) {
				$request->redirect(Application::get()->getRequest()->getContext(), 'openid', 'registerOrConnect');
			} else {
				// TODO execution error display
				$regForm->addError('', '');
				$regForm->display($request);
			}
		}
	}

	/**
	 * Tries to find a user via OpenID credentials.
	 *
	 * @param array $credentials
	 * @return User|null
	 */
	private function getUserViaKeycloakId(array $credentials)
	{
		$userDao = DAORegistry::getDAO('UserDAO');
		$user = $userDao->getBySetting('openid::ident', hash('sha256', $credentials['id']));
		if (isset($user) && is_a($user, 'User')) {
			return $user;
		}
		return null;
	}


	/**
	 * This function returns the access token which contains the user data.
	 *
	 * @param array $settings
	 * @param string $authorizationCode
	 * @return string|null
	 */
	private function getAccessTokenViaAuthCode(array $settings, string $authorizationCode)
	{
		$accessToken = null;
		$curl = curl_init();
		curl_setopt_array(
			$curl,
			array(
				CURLOPT_URL => $settings['url'].'auth/realms/'.$settings['realm'].'/protocol/openid-connect/token',
				CURLOPT_RETURNTRANSFER => true,
				CURLOPT_HTTPHEADER => array('Accept: application/json'),
				CURLOPT_POST => true,
				CURLOPT_POSTFIELDS => http_build_query(
					array(
						'code' => $authorizationCode,
						'grant_type' => 'authorization_code',
						'client_id' => $settings['clientId'],
						'client_secret' => $settings['clientSecret'],
						'redirect_uri' => Application::get()->getRequest()->url(null, 'openid', 'doAuthentication'),
					)
				),
			)
		);
		$result = curl_exec($curl);
		curl_close($curl);
		if (isset($result) && !empty($result)) {
			$result = json_decode($result, true);
			if (is_array($result) && !empty($result) && key_exists('access_token', $result)) {
				$accessToken = $result['access_token'];
			}
		}

		return $accessToken;
	}

	/**
	 * This function uses the certs endpoint of the openid provider to get the server certificate.
	 * If no key is found, null is returned
	 *
	 * @param $settings
	 * @return string|null
	 */
	private function getOpenIDAuthenticationCert(array $settings)
	{

		$beginCert = '-----BEGIN CERTIFICATE-----';
		$endCert = '-----END CERTIFICATE----- ';
		$curl = curl_init();
		curl_setopt_array(
			$curl,
			array(
				CURLOPT_URL => $settings['url'].'auth/realms/'.$settings['realm'].'/protocol/openid-connect/certs',
				CURLOPT_RETURNTRANSFER => true,
				CURLOPT_HTTPHEADER => array('Accept: application/json'),
				CURLOPT_POST => false,
			)
		);
		$result = curl_exec($curl);
		curl_close($curl);
		$arr = json_decode($result, true);
		$publicKey = null;
		if (key_exists('keys', $arr)) {
			foreach ($arr['keys'] as $key) {
				if (key_exists('alg', $key) && key_exists('x5c', $key) && $key['alg'] = 'RS256') {
					if ($key['x5c'] != null && is_array($key['x5c'])) {
						foreach ($key['x5c'] as $n) {
							if (!empty($n)) {
								$publicKey = $beginCert.PHP_EOL.$n.PHP_EOL.$endCert;
								break;
							}
						}
					}
				}
			}
		}

		return $publicKey;
	}


	/**
	 * Validates the token via JWT and public key and returns the token payload data as array.
	 * In case of an error null is returned
	 *
	 * @param string $accessToken
	 * @param string $publicKey
	 * @return array|null
	 */
	private function validateAndExtractToken(string $accessToken, string $publicKey)
	{
		$jwtPayload = JWT::decode($accessToken, $publicKey, array('RS256'));
		$credentials = null;
		if ($jwtPayload) {
			$credentials = [
				'id' => $jwtPayload->sub,
				'email' => $jwtPayload->email,
				'username' => $jwtPayload->preferred_username,
				'given_name' => $jwtPayload->given_name,
				'family_name' => $jwtPayload->family_name,
				'email_verified' => $jwtPayload->email_verified,
			];
		}

		return $credentials;
	}
}

