<?php

$loader = require('plugins/generic/oauth/vendor/autoload.php');

use Firebase\JWT\JWT;
use phpseclib\Crypt\RSA;
use phpseclib\Math\BigInteger;

import('classes.handler.Handler');

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
 * @file plugins/generic/openid/handler/OpenIDHandler.inc.php
 * @ingroup plugins_generic_openid
 * @brief Handler for OpenID workflow:
 *  - receive auth-code
 *  - perform auth-code -> token exchange
 *  - token validation via server certificate
 *  - extract user details
 *  - register new accounts
 *  - connect existing accounts
 *
 *
 */
class OpenIDHandler extends Handler
{
	/**
	 * This function is called via OpenID provider redirect URL.
	 * It receives the authentication code via the get parameter and uses $this->_getTokenViaAuthCode to exchange the code into a JWT
	 * The JWT is validated with the public key of the server fetched by $this->_getOpenIDAuthenticationCert.
	 * If the JWT and the key are successfully retrieved, the JWT is validated and extracted using $this->_validateAndExtractToken.
	 *
	 * If no user was found with the provided OpenID identifier a second step is called to connect a local account with the OpenID account, or to register a
	 * new OJS account. It is possible for a user to connect his/her OJS account to more than one OpenID provider.
	 *
	 * If the OJS account is disabled or in case of errors/exceptions the user is redirect to the sign in page and some errors will be displayed.
	 *
	 * @param $args
	 * @param $request
	 * @return bool
	 */
	function doAuthentication($args, $request)
	{
		$context = $request->getContext();
		$plugin = PluginRegistry::getPlugin('generic', KEYCLOAK_PLUGIN_NAME);
		$contextId = ($context == null) ? 0 : $context->getId();
		$settings = json_decode($plugin->getSetting($contextId, 'openIDSettings'), true);
		$selectedProvider = $request->getUserVar('provider');
		$token = $this->_getTokenViaAuthCode($settings['provider'], $request->getUserVar('code'), $selectedProvider);
		$publicKey = $this->_getOpenIDAuthenticationCert($settings['provider'], $selectedProvider);
		if (isset($token) && isset($publicKey)) {
			$tokenPayload = $this->_validateAndExtractToken($token, $publicKey);
			if (isset($tokenPayload) && is_array($tokenPayload)) {
				$tokenPayload['selectedProvider'] = $selectedProvider;
				$user = $this->_getUserViaKeycloakId($tokenPayload);
				if (!isset($user)) {
					import($plugin->getPluginPath().'/forms/OpenIDStep2Form');
					$regForm = new OpenIDStep2Form($plugin, $tokenPayload);
					$regForm->initData();

					return $regForm->fetch($request, null, true);
				} elseif (is_a($user, 'User') && !$user->getDisabled()) {
					Validation::registerUserSession($user, $reason, true);
					$userSettingsDao = DAORegistry::getDAO('UserSettingsDAO');
					$userSettingsDao->updateSetting($user->getId(), 'openid::lastProvider', $selectedProvider, 'string');
					if ($user->hasRole(
						[ROLE_ID_SITE_ADMIN, ROLE_ID_MANAGER, ROLE_ID_SUB_EDITOR, ROLE_ID_AUTHOR, ROLE_ID_REVIEWER, ROLE_ID_ASSISTANT],
						$contextId
					)) {
						return $request->redirect($context->getPath(), 'submissions');
					} else {
						return $request->redirect($context->getPath(), 'user', 'profile', null, $args);
					}
				} elseif ($user->getDisabled()) {
					$reason = $user->getDisabledReason();
					$ssoErrors['sso_error'] = 'disabled';
					if ($reason != null) {
						$ssoErrors['sso_error_msg'] = $reason;
					}
				}
			} else {
				$ssoErrors['sso_error'] = 'cert';
			}
		} else {
			$ssoErrors['sso_error'] = !isset($publicKey) ? 'connect_key' : 'connect_data';
		}

		return $request->redirect(Application::get()->getRequest()->getContext(), 'login', null, null, isset($ssoErrors) ? $ssoErrors : null);
	}

	/**
	 * Step2 POST (Form submit) function.
	 * OpenIDStep2Form is used to handle form initialization, validation and persistence.
	 *
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
				$regForm->addError('', '');
				$regForm->display($request);
			}
		}
	}

	/**
	 * Tries to find a user via OpenID credentials via user settings openid::{provider}
	 * This is a very simple step, and it should be safe because the token is valid at this point.
	 * If the token is invalid, the auth process stops before this function is called.
	 *
	 * @param array $credentials
	 * @return User|null
	 */
	private function _getUserViaKeycloakId(array $credentials)
	{
		$userDao = DAORegistry::getDAO('UserDAO');
		$user = $userDao->getBySetting('openid::'.$credentials['selectedProvider'], hash('sha256', $credentials['id']));
		if (isset($user) && is_a($user, 'User')) {
			return $user;
		}

		return null;
	}


	/**
	 * This function swaps the Auth code into a JWT that contains the user_details and a signature.
	 * An array with the access_token, id_token and/or refresh_token is returned on success, otherwise null.
	 * The OpenID implementation differs a bit between the providers. Some use an id_token, others a refresh token.
	 *
	 * @param array $providerList
	 * @param string $authorizationCode
	 * @param string $selectedProvider
	 * @return array
	 */
	private function _getTokenViaAuthCode(array $providerList, string $authorizationCode, string $selectedProvider)
	{
		$token = null;
		if (isset($providerList) && key_exists($selectedProvider, $providerList)) {
			$settings = $providerList[$selectedProvider];
			$curl = curl_init();
			curl_setopt_array(
				$curl,
				array(
					CURLOPT_URL => $settings['tokenUrl'],
					CURLOPT_RETURNTRANSFER => true,
					CURLOPT_HTTPHEADER => array('Accept: application/json'),
					CURLOPT_POST => true,
					CURLOPT_POSTFIELDS => http_build_query(
						array(
							'code' => $authorizationCode,
							'grant_type' => 'authorization_code',
							'client_id' => $settings['clientId'],
							'client_secret' => $settings['clientSecret'],
							'redirect_uri' => Application::get()->getRequest()->url(
								null,
								'openid',
								'doAuthentication',
								null,
								array('provider' => $selectedProvider)
							),
						)
					),
				)
			);
			$result = curl_exec($curl);
			curl_close($curl);
			if (isset($result) && !empty($result)) {
				$result = json_decode($result, true);
				if (is_array($result) && !empty($result) && key_exists('access_token', $result)) {
					$token = [
						'access_token' => $result['access_token'],
						'id_token' => key_exists('id_token', $result) ? $result['id_token'] : null,
						'refresh_token' => key_exists('refresh_token', $result) ? $result['refresh_token'] : null,
					];
				}
			}
		}

		return $token;
	}

	/**
	 * This function uses the certs endpoint of the openid provider to get the server certificate.
	 * There are provider-specific differences in case of the certificate.
	 *
	 * E.g.
	 * - Keycloak uses x5c as certificate format which included the cert.
	 * - Other vendors provide the cert modulus and exponent and the cert has to be created via phpseclib/RSA
	 *
	 * If no key is found, null is returned
	 *
	 * @param array $providerList
	 * @param string $selectedProvider
	 * @return array
	 */
	private function _getOpenIDAuthenticationCert(array $providerList, string $selectedProvider)
	{
		$publicKeys = null;
		if (isset($providerList) && key_exists($selectedProvider, $providerList)) {
			$settings = $providerList[$selectedProvider];
			$beginCert = '-----BEGIN CERTIFICATE-----';
			$endCert = '-----END CERTIFICATE----- ';
			$curl = curl_init();
			curl_setopt_array(
				$curl,
				array(
					CURLOPT_URL => $settings['certUrl'],
					CURLOPT_RETURNTRANSFER => true,
					CURLOPT_HTTPHEADER => array('Accept: application/json'),
					CURLOPT_POST => false,
				)
			);
			$result = curl_exec($curl);
			curl_close($curl);
			$arr = json_decode($result, true);
			if (key_exists('keys', $arr)) {
				$publicKeys = array();
				foreach ($arr['keys'] as $key) {
					if ((key_exists('alg', $key) && $key['alg'] = 'RS256') || (key_exists('kty', $key) && $key['kty'] = 'RSA')) {
						if (key_exists('x5c', $key) && $key['x5c'] != null && is_array($key['x5c'])) {
							foreach ($key['x5c'] as $n) {
								if (!empty($n)) {
									$publicKeys[] = $beginCert.PHP_EOL.$n.PHP_EOL.$endCert;
								}
							}
						} elseif (key_exists('n', $key) && key_exists('e', $key)) {
							$rsa = new RSA();
							$modulus = new BigInteger(JWT::urlsafeB64Decode($key['n']), 256);
							$exponent = new BigInteger(JWT::urlsafeB64Decode($key['e']), 256);
							$rsa->loadKey(array('n' => $modulus, 'e' => $exponent));
							$publicKeys[] = $rsa->getPublicKey();
						}
					}
				}
			}
		}

		return $publicKeys;
	}

	/**
	 * Validates the token via JWT and public key and returns the token payload data as array.
	 * In case of an error null is returned
	 *
	 * @param array $token
	 * @param array $publicKeys
	 * @return array|null
	 */
	private function _validateAndExtractToken(array $token, array $publicKeys)
	{
		$credentials = null;
		foreach ($publicKeys as $publicKey) {
			foreach ($token as $t) {
				try {
					if (!empty($t)) {
						$jwtPayload = JWT::decode($t, $publicKey, array('RS256'));
						if (isset($jwtPayload)) {
							$credentials = [
								'id' => property_exists($jwtPayload, 'sub') ? $jwtPayload->sub : null,
								'email' => property_exists($jwtPayload, 'email') ? $jwtPayload->email : null,
								'username' => property_exists($jwtPayload, 'preferred_username') ? $jwtPayload->preferred_username : null,
								'given_name' => property_exists($jwtPayload, 'given_name') ? $jwtPayload->given_name : null,
								'family_name' => property_exists($jwtPayload, 'family_name') ? $jwtPayload->family_name : null,
								'email_verified' => property_exists($jwtPayload, 'email_verified') ? $jwtPayload->email_verified : null,
							];
						}
						if (isset($credentials) && key_exists('id', $credentials) && !empty($credentials['id'])) {
							break 2;
						}
					}
				} catch (Exception $e) {
					$credentials = null;
				}
			}
		}

		return $credentials;
	}


	/**
	 * This function is unused at the moment.
	 * It can be unsed to get the user details from an endpoint but usually all user data are provided in the JWT.
	 *
	 * @param $token
	 * @param $settings
	 */
	private function getClientDetails($token, $settings)
	{
		$curl = curl_init();
		curl_setopt_array(
			$curl,
			array(
				CURLOPT_URL => $settings['userInfoUrl'],
				CURLOPT_RETURNTRANSFER => true,
				CURLOPT_HTTPHEADER => array('Accept: application/json', 'Authorization: Bearer '.$token['access_token']),
				CURLOPT_POST => false,
			)
		);
		$result = curl_exec($curl);
		curl_close($curl);
	}


}

