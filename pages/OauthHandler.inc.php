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

class OauthHandler extends Handler
{
	function oauthAuthorize($args, $request)
	{
		$context = $request->getContext();
		$plugin = PluginRegistry::getPlugin('generic', 'oauthplugin');
		$contextId = ($context == null) ? 0 : $context->getId();
		$oauthAppName = $request->getUserVar('oauthAppName');

		$oauthSettings = json_decode($plugin->getSetting($contextId, 'oauthAppSettings'), true);
		$curl = curl_init();
		curl_setopt_array(
			$curl,
			array(
				CURLOPT_URL => $oauthSettings[$oauthAppName]['oauthAPIVerify'],
				CURLOPT_RETURNTRANSFER => true,
				CURLOPT_HTTPHEADER => array('Accept: application/json'),
				CURLOPT_POST => true,
				CURLOPT_POSTFIELDS => http_build_query(
					array(
						'code' => $request->getUserVar('code'),
						'grant_type' => 'authorization_code',
						'client_id' => $oauthSettings[$oauthAppName]['oauthClientId'],
						'client_secret' => $oauthSettings[$oauthAppName]['oauthClientSecret'],
						'redirect_uri' => Application::get()->getRequest()->url(null, 'oauth', 'oauthAuthorize')."?oauthAppName=".$oauthAppName,
					)
				),
			)
		);

		$result = curl_exec($curl);
		if (strpos($oauthSettings[$oauthAppName]['oauthAPIVerify'], 'openid-connect') == true) {
			$result = curl_exec($curl);
			$tokenParts = explode(".", $result);
			$tokenPayload = base64_decode($tokenParts[1]);
			$jwtPayload = json_decode($tokenPayload);
			$uniqueId = $jwtPayload->sub;
			$email = $jwtPayload->email;
			error_log("#### ".$email);
		} else {
			$response = json_decode($result, true);
			$subkey = explode('/', $oauthSettings[$oauthAppName]['oauthUniqueId'], 2);
			if (count($subkey) == 2) {
				// TODO: decode the JWT object and extract the $subkey[1]
				$uniqueId = $response[$subkey[0]];
			} else {
				$uniqueId = $response[$oauthSettings[$oauthAppName]['oauthUniqueId']];
			}
		}
		if ($uniqueId) {
			error_log($uniqueId);
			$userSettingsDao = DAORegistry::getDAO('UserSettingsDAO');
			$users = $userSettingsDao->getUsersBySetting('oauth::'.$oauthAppName, $uniqueId);
			$validUser = null;
			$matchCount = 0;
			while ($user = $users->next()) {
				$matchCount++;
				$validUser = $user;
			}
			if ($matchCount > 1) {
				$validUser = false;
				Validation::redirectLogin('plugins.generic.oauth.message.oauthTooManyMatches');
			}
			error_log(json_encode($validUser));
			if ($validUser) {
				// OAuth successful, with match -- log in user.
				$reason = null;
				Validation::registerUserSession($validUser, $reason);
			} else {
				// OAuth successful, but not linked to a user account (yet)
				$sessionManager = SessionManager::getManager();
				$userSession = $sessionManager->getUserSession();
				$user = $userSession->getUser();
				if (isset($user)) {
					// If the user is authenticated, link this user account
					$userSettingsDao->updateSetting($user->getId(), 'oauth::'.$oauthAppName, $uniqueId, 'string');
				} else {
					// Otherwise, send the user to the login screen (keep track of the oauthUniqueId to link upon login!)
					$userSession->setSessionVar('oauth', json_encode(array('oauth::'.$oauthAppName => $uniqueId)));
				}
			}
			Validation::redirectLogin();
		} else {
			// OAuth login was tried, but failed
			// Show a message?
			Validation::redirectLogin('plugins.generic.oauth.message.oauthLoginError');
		}
	}

}

?>
