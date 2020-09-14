<?php
/**
 * @file plugins/generic/oauth/pages/OauthHandler.inc.php
 *
 * Copyright (c) 2015-2016 University of Pittsburgh
 * Copyright (c) 2014-2016 Simon Fraser University Library
 * Copyright (c) 2003-2016 John Willinsky
 * Distributed under the GNU GPL v2 or later. For full terms see the file docs/COPYING.
 *
 * @class OauthHandler
 * @ingroup plugins_generic_oauth
 *
 * @brief Handle return call from OAuth
 */

use Firebase\JWT\JWT;

import('classes.handler.Handler');

class KeycloakHandler extends Handler
{
	function doAuthentication($args, $request)
	{
		$context = $request->getContext();
		$user = null;
		$credentials = null;
		$plugin = PluginRegistry::getPlugin('generic', KEYCLOAK_PLUGIN_NAME);
		$contextId = ($context == null) ? 0 : $context->getId();
		$settings = json_decode($plugin->getSetting($contextId, 'keycloakSettings'), true);
		$accessToken = $this->getAccessTokenViaAuthCode($settings, $request->getUserVar('code'));
		$publicKey = $this->getPublicKey($settings);
		if ($accessToken != null && $publicKey != null) {
			$jwtPayload = JWT::decode($accessToken, $publicKey, array('RS256'));
			$credentials = [
				'id' => $jwtPayload->sub,
				'email' => $jwtPayload->email,
				'username' => $jwtPayload->preferred_username,
				'given_name' => $jwtPayload->given_name,
				'family_name' => $jwtPayload->family_name,
				'email_verified' => $jwtPayload->email_verified,
			];
			$user = $this->getUserViaKeycloakId($credentials);
		}

		if ($user == null) {
			$user = $this->registerUser($credentials);
		}

		if ($user && is_a($user, 'User') && !$user->getDisabled()) {
			$user = $this->registerUserSession($user, true);
			// TODO save OJS-API-KEY into KEYCLOAK or use keycloak id as encrypted api-key???
			//$user = $this->setOjsApiKey($user, time());
			$user = $this->setOjsApiKey($user, $credentials['id']);
			error_log('##################### '.$user->getData('apiKey'));

			return $request->redirect($context->getPath(), 'user', 'profile', null, $args);
		} elseif ($user->getDisabled()) {
			$reason = $user->getDisabledReason();
			if ($reason === null) {
				$reason = '';
			}
		}

		// TODO return to login page with error messages
		return false;

	}

	private function getUserViaKeycloakId($credentials)
	{
		$userDao = DAORegistry::getDAO('UserDAO');
		$user = $userDao->getUserByEmail($credentials['email'], true);
		if (isset($user) && $user->getData('openid::keycloak') == $credentials['id']) {
			return $user;
		}
		$user = $userDao->getByUsername($credentials['username'], true);
		if (isset($user) && $user->getData('openid::keycloak') == $credentials['id']) {
			return $user;
		}
		$users = $userDao->getBySetting('openid::keycloak', $credentials['id'], true);
		if (isset($users)) {
			return $user;
		}

		return null;
	}

	/**
	 * This function creates a new OJS User if no user exists with the given username, email or openid::keycloak!
	 *
	 * @param $credentials
	 * @return User|null
	 */
	private function registerUser($credentials)
	{
		$userDao = DAORegistry::getDAO('UserDAO');
		$user = $userDao->newDataObject();
		$user->setUsername($credentials['username']);
		$request = Application::get()->getRequest();
		$site = $request->getSite();
		$sitePrimaryLocale = $site->getPrimaryLocale();
		$currentLocale = AppLocale::getLocale();
		$user->setGivenName($credentials['given_name'], $currentLocale);
		$user->setFamilyName($credentials['family_name'], $currentLocale);
		$user->setEmail($credentials['email']);
		if ($sitePrimaryLocale != $currentLocale) {
			$user->setGivenName($credentials['given_name'], $sitePrimaryLocale);
			$user->setFamilyName($credentials['family_name'], $sitePrimaryLocale);
		}
		$user->setDateRegistered(Core::getCurrentDate());
		$user->setInlineHelp(1);
		$user->setPassword(Validation::encryptCredentials($credentials['username'], openssl_random_pseudo_bytes(16)));
		$userDao->insertObject($user);
		if ($user->getId()) {
			// Save the selected roles or assign the Reader role if none selected
			if ($request->getContext()) {
				$userGroupDao = DAORegistry::getDAO('UserGroupDAO');
				$defaultReaderGroup = $userGroupDao->getDefaultByRoleId($request->getContext()->getId(), ROLE_ID_READER);
				if ($defaultReaderGroup) {
					$userGroupDao->assignUserToGroup($user->getId(), $defaultReaderGroup->getId());
				}
			}
			// save keycloak id to user settings
			$userSettingsDao = DAORegistry::getDAO('UserSettingsDAO');
			$userSettingsDao->updateSetting($user->getId(), 'openid::keycloak', $credentials['id'], 'string');
		} else {
			$user = null;
		}

		return $user;
	}


	private function setOjsApiKey($user, $value)
	{
		$secret = Config::getVar('security', 'api_key_secret', '');
		if ($secret) {
			$userDao = DAORegistry::getDAO('UserDAO');
			$user->setData('apiKeyEnabled', true);
			$user->setData('apiKey', hash('sha256', $value));
			$userDao->updateObject($user);
		}

		return $user;
	}

	/**
	 * This function is used to login a user to OJS after the Keycloak login was successful.
	 *
	 * @param $user
	 * @param $reason
	 * @param false $remember
	 * @return User
	 */
	private function registerUserSession($user, $remember = false)
	{
		$sessionManager = SessionManager::getManager();
		$sessionManager->regenerateSessionId();
		$session = $sessionManager->getUserSession();
		$session->setSessionVar('userId', $user->getId());
		$session->setUserId($user->getId());
		$session->setSessionVar('username', $user->getUsername());
		$session->getCSRFToken();
		$session->setRemember($remember);
		if ($remember && Config::getVar('general', 'session_lifetime') > 0) {
			$sessionManager->updateSessionLifetime(time() + Config::getVar('general', 'session_lifetime') * 86400);
		}
		$user->setDateLastLogin(Core::getCurrentDate());
		$userDao = DAORegistry::getDAO('UserDAO');
		$userDao->updateObject($user);

		return $user;
	}

	/**
	 * This function returns the access token which contains the user data.
	 *
	 * @param $settings
	 * @param $authorizationCode
	 * @return string|null
	 */
	private function getAccessTokenViaAuthCode($settings, $authorizationCode)
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
						'redirect_uri' => Application::get()->getRequest()->url(null, 'keycloak', 'doAuthentication'),
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
	 * This function returns the public key needed to certify the JWT token.
	 * If no key is found, null is returned
	 *
	 * @param $settings
	 * @return string|null
	 */
	private function getPublicKey($settings)
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

		return $publicKey;
	}
}

