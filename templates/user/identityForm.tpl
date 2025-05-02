{**
 * templates/user/identityForm.tpl
 *
 * Copyright (c) 2020 Leibniz Institute for Psychology Information (https://leibniz-psychology.org/)
 * Copyright (c) 2024 Simon Fraser University
 * Copyright (c) 2024 John Willinsky
 * Distributed under the GNU GPL v3. For full terms see the file LICENSE.
 *
 * User profile form.
 *}

<script>
	$(function() {ldelim}
		// Attach the form handler.
		$('#identityForm').pkpHandler('$.pkp.controllers.form.AjaxFormHandler');
	{rdelim});
</script>

<style>
	.cmp_notification {
		display: block;
		width: 100%;
		padding: 20px;
		margin-bottom: 40px;
		background: #ddd;
		border-left: 5px solid #007ab2;
		font-size: 14px;
		line-height: 20px;
	}
</style>

<form class="pkp_form" id="identityForm" method="post" action="{url op="saveIdentity"}" enctype="multipart/form-data">
	{* Help Link *}
	{help file="user-profile" class="pkp_help_tab"}
	{csrf}
	{if ($openIdGivenNameDisabledField || $openIdFamilyNameDisabledField)}
		{assign var="openidIdentityFields" value=true }
		<p class="cmp_notification">
			{translate key="plugins.generic.openid.disables.fields.info"}
		</p>
	{/if}
	{include file="controllers/notification/inPlaceNotification.tpl" notificationId="identityFormNotification"}

	{fbvFormArea id="userNameInfo"}
		{fbvFormSection title="user.username"}
			{$username|escape}
		{/fbvFormSection}
	{/fbvFormArea}

	{fbvFormArea id="userFormCompactLeft"}
		{fbvFormSection title="user.name"}
			{fbvElement type="text" label="user.givenName" multilingual="true" required="true" id="givenName" value=$givenName maxlength="255" inline=true size=$fbvStyles.size.MEDIUM readonly=$openIdGivenNameDisabledField}
			{fbvElement type="text" label="user.familyName" multilingual="true" id="familyName" value=$familyName maxlength="255" inline=true size=$fbvStyles.size.MEDIUM readonly=$openIdFamilyNameDisabledField}
		{/fbvFormSection}
	{/fbvFormArea}

	{fbvFormSection for="preferredPublicName" description="user.preferredPublicName.description"}
		{fbvElement type="text" label="user.preferredPublicName" multilingual="true" name="preferredPublicName" id="preferredPublicName" value=$preferredPublicName size=$fbvStyles.size.LARGE}
	{/fbvFormSection}

	<p>
		{capture assign="privacyUrl"}{url router=$smarty.const.ROUTE_PAGE page="about" op="privacy"}{/capture}
		{translate key="user.privacyLink" privacyUrl=$privacyUrl}
	</p>

	<p><span class="formRequired">{translate key="common.requiredField"}</span></p>

	{fbvFormButtons hideCancel=true submitText="common.save"}
</form>
