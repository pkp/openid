{**
 * templates/user/changePassword.tpl
 *
 * Copyright (c) 2014-2020 Simon Fraser University
 * Copyright (c) 2003-2020 John Willinsky
 * Distributed under the GNU GPL v3. For full terms see the file docs/COPYING.
 *
 * Form to change a user's password.
 *}
<script>
	$(function() {ldelim}
		// Attach the form handler.
		$('#changePasswordForm').pkpHandler('$.pkp.controllers.form.AjaxFormHandler');
	{rdelim});
</script>

<form class="pkp_form" id="changePasswordForm" method="post" action="{url op="savePassword"}">
	{* Help Link *}
	{help file="user-profile" class="pkp_help_tab"}
	{csrf}
	{include file="controllers/notification/inPlaceNotification.tpl" notificationId="changePasswordFormNotification"}
	{if isset($openIdDisableFields) && !empty($openIdDisableFields)}
		{assign var="openidPWFields" value=true }
		<p class="cmp_notification">
			{translate key="plugins.generic.openid.disables.fields.info.password"}
		</p>
	{/if}
	<p><span class="instruct">{translate key="user.profile.changePasswordInstructions"}</span></p>
	{fbvFormArea id="changePasswordFormArea"}
		{fbvFormSection label="user.profile.oldPassword"}
			{fbvElement type="text" password="true" id="oldPassword" value=$oldPassword maxLength="32" size=$fbvStyles.size.MEDIUM readonly=$openidPWFields disabled=$openidPWFields}
		{/fbvFormSection}
		{fbvFormSection label="user.profile.newPassword"}
			{capture assign="passwordLengthRestriction"}{translate key="user.register.form.passwordLengthRestriction" length=$minPasswordLength}{/capture}
			{fbvElement type="text" password="true" id="password" value=$oldPassword label=$passwordLengthRestriction subLabelTranslate=false maxLength="32" size=$fbvStyles.size.MEDIUM readonly=$openidPWFields disabled=$openidPWFields}
			{fbvElement type="text" password="true" id="password2" value=$oldPassword maxLength="32" label="user.profile.repeatNewPassword" size=$fbvStyles.size.MEDIUM readonly=$openidPWFields disabled=$openidPWFields}
		{/fbvFormSection}
		{if !$openidPWFields}
			{fbvFormButtons submitText="common.save" }
		{/if}
		{*{fbvFormButtons submitText="common.save" }*}
		<p>
			{capture assign="privacyUrl"}{url router=$smarty.const.ROUTE_PAGE page="about" op="privacy"}{/capture}
			{translate key="user.privacyLink" privacyUrl=$privacyUrl}
		</p>
	{/fbvFormArea}
</form>
