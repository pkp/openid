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

<p id="externalLogin">
<span>{translate key="plugins.generic.oauth.externalLogIn"}</span>

{foreach from=$oauthAppSettings key=oauthAppName item=oauthAppSetting}
{assign var=oauthAPIAuth value=$oauthAppSetting.oauthAPIAuth}
{assign var=oauthClientId value=$oauthAppSetting.oauthClientId}
{assign var=oauthScope value=$oauthAppSetting.oauthScope}
<a href="{$oauthAPIAuth|escape}?client_id={$oauthClientId|urlencode}&response_type=code&scope={$oauthScope|escape}&redirect_uri={url|urlencode router="page" page="oauth" op="oauthAuthorize" oauthAppName=$oauthAppName escape=false}"><img id="{$oauthAppName|escape}-login-button" src="{$baseUrl}/plugins/generic/oauth/templates/images/{$oauthAppName|escape}.png" width="24" height="24" alt="{translate key="plugins.generic.oauth.submitAction" oauthAppName=$oauthAppName}"/></a>
{/foreach}
</p>
