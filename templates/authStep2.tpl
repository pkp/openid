{include file="frontend/components/header.tpl" pageTitle="plugins.generic.oauth.step2.headline"}

<div class="page page_oauth">
	{include file="frontend/components/breadcrumbs.tpl" currentTitleKey="plugins.generic.oauth.step2.headline"}
	<h1>
		{translate key="plugins.generic.oauth.step2.headline"}
	</h1>


	<form class="cmp_form cmp_form oauth" id="oauth" method="post" action="{url page="openid" op="registerOrConnect"}">
		{csrf}
		<input type="hidden" name="oauthId" id="oauthId" value="{$oauthId}">
		<input type="hidden" name="returnTo" id="returnTo" value="{$returnTo}">

		{include file="common/formErrors.tpl"}

		<div id="showRegisterForm">Show Register new Account</div>
		<div id="showLoginForm">Show Merge Accounts</div>

		<div id="register-form">
			<fieldset class="register">
				<legend>
					{translate key="user.profile"}
				</legend>
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
				{if $currentContext->getData('privacyStatement')}
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
			<div class="buttons">
				<button class="submit" type="submit" name="register">
					{translate key="user.oauth.step2.submit.register"}
				</button>
			</div>
		</div>
		<div id="login-form">
			<fieldset class="login">
				<div class="username">
					<label>
						<span class="label">
							{translate key="user.username"}
							<span class="required" aria-hidden="true">*</span>
							<span class="pkp_screen_reader">
								{translate key="common.required"}
							</span>
						</span>
						<input type="text" name="usernameLogin" id="usernameLogin" value="{$usernameLogin|escape}" maxlength="32" required aria-required="true">
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
					{translate key="user.oauth.step2.submit.connect"}
				</button>
			</div>
		</div>

	</form>

</div><!-- .page -->

{include file="frontend/components/footer.tpl"}
