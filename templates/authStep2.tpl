{**
 * templates/authStep2.tpl
 *
 * Copyright (c) 2020 Leibniz Institute for Psychology Information (https://leibniz-psychology.org/)
 * Copyright (c) 2024 Simon Fraser University
 * Copyright (c) 2024 John Willinsky
 * Distributed under the GNU GPL v3. For full terms see the file LICENSE.
 *
 * Display the OpenID Auth second step.
 *}

{include file="frontend/components/header.tpl" pageTitle="plugins.generic.openid.step2.title"}
<div class="page page_oauth">
	{include file="frontend/components/breadcrumbs.tpl" currentTitleKey="plugins.generic.openid.step2.title"}
	<form class="cmp_form cmp_form oauth" id="oauth" method="post" action="{url page="openid" op="registerOrConnect"}">
		{csrf}
		<input type="hidden" name="oauthId" id="oauthId" value="{$oauthId}">
		<input type="hidden" name="selectedProvider" id="selectedProvider" value="{$selectedProvider}">
		<input type="hidden" name="returnTo" id="returnTo" value="{$returnTo}">

		{if $siteTitle}
			{assign var="headline" value="{translate key='plugins.generic.openid.step2.headline' journalName=$siteTitle|escape}"}
			{assign var="choiceNo" value="{translate key="plugins.generic.openid.step2.choice.no" journalName=$siteTitle|escape}"}
			{assign var="connect" value="{translate key="plugins.generic.openid.step2.connect" journalName=$siteTitle|escape}"}
			{assign var="help" value="{translate key="plugins.generic.openid.step2.help" journalName=$siteTitle|escape}"}
		{else}
			{assign var="headline" value="{translate key='plugins.generic.openid.step2.headline.siteNameMissing'}"}
			{assign var="choiceNo" value="{translate key='plugins.generic.openid.step2.choice.no.siteNameMissing'}"}
			{assign var="connect" value="{translate key='plugins.generic.openid.step2.connect.siteNameMissing'}"}
			{assign var="help" value="{translate key='plugins.generic.openid.step2.help.siteNameMissing'}"}
		{/if}

		{if empty($disableConnect) || $disableConnect != "1"}
			<h1>
				{$headline}
			</h1>
			<ul id="openid-choice-select">
				<li>
					<span id='showLoginForm' class='step2-choice-links'>
						{translate key="plugins.generic.openid.step2.choice.yes"}
					</span>
				</li>
				<li>
					<span id='showRegisterForm' class='step2-choice-links'>
						{$choiceNo}
					</span>
				</li>
			</ul>
		{/if}
		<div {if empty($disableConnect) || $disableConnect != "1" }id="register-form"{/if} class="page_register">
			<fieldset class="register">
				<p class="cmp_notification warning">
					{$help}
				</p>
				{if $returnTo == 'register'}
					{include file="common/formErrors.tpl"}
				{/if}
				<div class="fields">
					<div class="given_name">
						<label>
							<span class="label">
								{translate key="user.givenName"}
								<span class="required" aria-hidden="true">*</span>
								<span class="pkp_screen_reader">
									{translate key="common.required"}
								</span>
							</span>
							<input type="text" name="givenName" id="givenName" value="{$givenName|escape}" maxlength="255" required aria-required="true">
						</label>
					</div>
					<div class="family_name">
						<label>
							<span class="label">
								{translate key="user.familyName"}
								<span class="required" aria-hidden="true">*</span>
								<span class="pkp_screen_reader">
									{translate key="common.required"}
								</span>
							</span>
							<input type="text" name="familyName" id="familyName" value="{$familyName|escape}" maxlength="255">
						</label>
					</div>
					<div class="email">
						<label>
							<span class="label">
								{translate key="user.email"}
								<span class="required" aria-hidden="true">*</span>
								<span class="pkp_screen_reader">
									{translate key="common.required"}
								</span>
							</span>
							<input type="email" name="email" id="email" value="{$email|escape}" maxlength="90" required aria-required="true">
						</label>
					</div>
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
					<div class="affiliation">
						<label>
							<span class="label">
								{translate key="user.affiliation"}
								<span class="required" aria-hidden="true">*</span>
								<span class="pkp_screen_reader">
									{translate key="common.required"}
								</span>
							</span>
							<input type="text" name="affiliation" id="affiliation" value="{$affiliation|escape}" required aria-required="true">
						</label>
					</div>
					<div class="country">
						<label>
							<span class="label">
								{translate key="common.country"}
								<span class="required" aria-hidden="true">*</span>
								<span class="pkp_screen_reader">
									{translate key="common.required"}
								</span>
							</span>
							<select name="country" id="country" required aria-required="true">
								<option></option>
								{html_options options=$countries selected=$country}
							</select>
						</label>
					</div>
				</div>
			</fieldset>
			<fieldset class="consent">
				{if isset($privacyStatement)}
					{* Require the user to agree to the terms of the privacy policy *}
					<div class="fields">
						<div class="optin optin-privacy">
							<label>
								<input type="checkbox" name="privacyConsent" value="1" required{if $privacyConsent} checked="checked"{/if}>
								{capture assign="privacyUrl"}{url router=$smarty.const.ROUTE_PAGE page="about" op="privacy"}{/capture}
								{translate key="user.register.form.privacyConsent" privacyUrl=$privacyUrl}
								<span class="required" aria-hidden="true">*</span>
								<span class="pkp_screen_reader">
										{translate key="common.required"}
									</span>
							</label>
						</div>
					</div>
				{/if}
				{* Ask the user to opt into public email notifications *}
				<div class="fields">
					<div class="optin optin-email">
						<label>
							<input type="checkbox" name="emailConsent" id="emailConsent" value="1" {if $emailConsent} checked="checked"{/if}>
							{translate key="user.register.form.emailConsent"}
						</label>
					</div>
				</div>
			</fieldset>
			{* Allow the user to sign up as a reviewer *}
			{assign var=userCanRegisterReviewer value=0}
			{foreach from=$reviewerUserGroups[$contextId] item=userGroup}
				{if $userGroup->getPermitSelfRegistration()}
					{assign var=userCanRegisterReviewer value=$userCanRegisterReviewer+1}
				{/if}
			{/foreach}
			{if $userCanRegisterReviewer}
				<fieldset class="reviewer">
					{if $userCanRegisterReviewer > 1}
						<legend>
							{translate key="user.reviewerPrompt"}
						</legend>
						{capture assign="checkboxLocaleKey"}user.reviewerPrompt.userGroup{/capture}
					{else}
						{capture assign="checkboxLocaleKey"}user.reviewerPrompt.optin{/capture}
					{/if}
					<div class="fields">
						<div id="reviewerOptinGroup" class="optin">
							{foreach from=$reviewerUserGroups[$contextId] item=userGroup}
								{if $userGroup->getPermitSelfRegistration()}
									<label>
										{assign var="userGroupId" value=$userGroup->getId()}
										<input type="checkbox" name="reviewerGroup[{$userGroupId}]" class="reviewerGroupInput"
											value="1"{if in_array($userGroupId, $userGroupIds)} checked="checked"{/if}>
										{translate key=$checkboxLocaleKey userGroup=$userGroup->getLocalizedName()}
									</label>
								{/if}
							{/foreach}
						</div>
						<div id="reviewerInterests" class="reviewer_interests">
							<label>
								<span class="label">
									{translate key="user.interests"}
								</span>
								<input type="text" name="interests" id="interests" value="{$interests|escape}" class="reviewerGroupInput">
							</label>
						</div>
					</div>
				</fieldset>
			{/if}
			<div class="buttons">
				<button class="submit" type="submit" name="register">
					{translate key="plugins.generic.openid.step2.complete.btn"}
				</button>
			</div>
		</div>
		{if empty($disableConnect) || $disableConnect != "1"}
			<div id="login-form">
				<fieldset class="login">
					<p class="cmp_notification warning">
						{$connect}
					</p>
					{if $returnTo == 'connect'}
						{include file="common/formErrors.tpl"}
					{/if}
					<div class="username">
						<label>
						<span class="label">
							{translate key="plugins.generic.openid.step2.connect.username"}
							<span class="required" aria-hidden="true">*</span>
							<span class="pkp_screen_reader">
								{translate key="common.required"}
							</span>
						</span>
							<input type="text" name="usernameLogin" id="usernameLogin" value="{$usernameLogin|escape}" maxlength="32" required
							       aria-required="true">
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
							<input type="password" name="passwordLogin" id="passwordLogin" value="{$passwordLogin|escape}" maxlength="32" required
							       aria-required="true">
							<a href="{url page="login" op="lostPassword"}">
								{translate key="user.login.forgotPassword"}
							</a>
						</label>
					</div>
				</fieldset>
				<div class="buttons">
					<button class="submit" type="submit" name="connect">
						{translate key="plugins.generic.openid.step2.connect.btn"}
					</button>
				</div>
			</div>
		{/if}
	</form>
</div><!-- .page -->
{include file="frontend/components/footer.tpl"}
