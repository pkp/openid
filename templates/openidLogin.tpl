{**
 * templates/openidLogin.tpl
 *
 * Copyright (c) 2020 Leibniz Institute for Psychology Information (https://leibniz-psychology.org/)
 * Copyright (c) 2024 Simon Fraser University
 * Copyright (c) 2024 John Willinsky
 * Distributed under the GNU GPL v3. For full terms see the file LICENSE.
 *
 * Display the OpenID sign in page
 *}

{include file="frontend/components/header.tpl" pageTitle='plugins.generic.openid.select.provider'}
<div class="page page_openid_login">
	{include file="frontend/components/breadcrumbs.tpl" currentTitleKey='plugins.generic.openid.select.provider'}
	<h1>{translate key='plugins.generic.openid.select.provider'}</h1>
	{if $loginMessage}
		<div>
			<p>
				{translate key=$loginMessage}
			</p>
		</div>
	{/if}
	{if $openidError}
		<div class="openid-error">
			<div>{translate key=$errorMsg supportEmail=$supportEmail}</div>
			{if $reason}
				<p>{$reason}</p>
			{/if}
		</div>
		{if not $legacyLogin && not $accountDisabled}
			<div class="openid-info margin-top-30">
				{translate key="plugins.generic.openid.error.legacy.link" legacyLoginUrl={url page="login" op="legacyLogin"}}
			</div>
		{/if}
	{/if}
	<ul id="openid-provider-list">
		{if $legacyLogin}
			<li class="margin-top-30"><strong>{translate key='plugins.generic.openid.select.legacy' journalName=$siteTitle|escape}</strong></li>
			<li class="page_login">
				<form class="cmp_form cmp_form login" id="login" method="post" action="{$loginUrl}">
					{csrf}
					<fieldset class="fields">
						<div class="username">
							<label>
								<span class="label">
									{translate key="user.username"}
									<span class="required" aria-hidden="true">*</span>
									<span class="pkp_screen_reader">
										{translate key="common.required"}
									</span>
								</span>
								<input type="text" name="username" id="username" value="{$username|escape}" maxlength="32" required aria-required="true">
							</label>
						</div>
						<div class="password">
							<label>
								<span class="label">
									{translate key="user.password"}
									<span class="required" aria-hidden="true">*</span>
									<span class="pkp_screen_reader">
										{translate key="common.required"}
									</span>
								</span>
								<input type="password" name="password" id="password" value="{$password|escape}" maxlength="32" required aria-required="true">

								<a href="{url page="login" op="lostPassword"}">
									{translate key="user.login.forgotPassword"}
								</a>

							</label>
						</div>
						<div class="remember checkbox">
							<label>
								<input type="checkbox" name="remember" id="remember" value="1">
								<span class="label">
									{translate key="user.login.rememberUsernameAndPassword"}
								</span>
							</label>
						</div>
						<div class="buttons">
							<button class="submit" type="submit">
								{translate key="user.login"}
							</button>
						</div>
					</fieldset>
				</form>
			</li>
		{/if}
		{if $linkList}
			<li class="margin-top-30"><strong>{translate key='plugins.generic.openid.select.provider.help'}</strong></li>
			{foreach from=$linkList key=name item=url}
				{if $name == 'custom'}
					<li><a id="openid-provider-{$name}" href="{$url}">
							<div>
								{if $customBtnImg}
									<img src="{$customBtnImg}" alt="{$name}">
								{else}
									<img src="{$openIDImageURL}{$name}-sign-in.png" alt="{$name}">
								{/if}
								<span>
								{if isset($customBtnTxt)}
									{$customBtnTxt}
								{else}
									{{translate key="plugins.generic.openid.select.provider.$name"}}
								{/if}
							</span>
							</div>
						</a>
					</li>
				{else}
					<li class=""><a id="openid-provider-{$name}" href="{$url}">
							<div>
								<img src="{$openIDImageURL}{$name}-sign-in.png" alt="{$name}"/>
								<span>{{translate key="plugins.generic.openid.select.provider.$name"}}</span>
							</div>
						</a>
					</li>
				{/if}
			{/foreach}
		{/if}
	</ul>
</div><!-- .page -->
{include file="frontend/components/footer.tpl"}
