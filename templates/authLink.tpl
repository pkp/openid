{**
 * plugins/generic/oauth/oauthLoader.tpl
 *
 * Copyright (c) 2015-2016 University of Pittsburgh
 * Copyright (c) 2014-2016 Simon Fraser University Library
 * Copyright (c) 2003-2016 John Willinsky
 * Distributed under the GNU GPL v2. For full terms see the file docs/COPYING.
 *
 * External services login buttons
 *
 *}

<p id="keycloakLogin">
	<span>{translate key="plugins.generic.keycloak.login.link"}</span>
	<a href="{$url|escape}auth/realms/{$realm|urlencode}/protocol/openid-connect/auth?client_id={$clientId|urlencode}&response_type=code&scope=openid&redirect_uri={url|urlencode router="page" page="keycloak" op="doAuthentication" escape=false}">
		Keycloak Login
	</a>
</p>
