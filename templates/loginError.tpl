{**
 * templates/loginError.tpl
 *
 * Copyright (c) 2026 Simon Fraser University
 * Copyright (c) 2026 John Willinsky
 * Distributed under the GNU GPL v3. For full terms see the file LICENSE.
 *
 * SSO error block, injected above the core login form.
 *}
{if $openidError}
	<div class="openid-error">
		<div>{translate key=$errorMsg supportEmail=$supportEmail}</div>
		{if $reason}
			<p>{$reason}</p>
		{/if}
	</div>
	{if !$legacyLogin && !$accountDisabled}
		<div class="openid-info margin-top-30">
			{translate key="plugins.generic.openid.error.legacy.link" legacyLoginUrl={url page="login" op="legacyLogin"}}
		</div>
	{/if}
{/if}
