{**
 * plugins/generic/oauth/editOauthAppForm.tpl
 *
 * Copyright (c) 2014-2016 Simon Fraser University Library
 * Copyright (c) 2003-2016 John Willinsky
 * Distributed under the GNU GPL v2. For full terms see the file docs/COPYING.
 *
 * Form for editing a oauth app
 *
 *}
<div id="oauthAppSettings">
<div id="description">{translate key="plugins.generic.oauth.oauthApp.settings.description"}</div>
<script>
	$(function() {ldelim}
		// Attach the form handler.
		$('#oauthAppForm').pkpHandler('$.pkp.controllers.form.AjaxFormHandler');
	{rdelim});
</script>

<form class="pkp_form" id="oauthAppForm" method="post" action="{url router=$smarty.const.ROUTE_COMPONENT component="plugins.generic.oauth.controllers.grid.OauthAppGridHandler" op="updateOauthApp" existingOauthAppName=$oauthAppName}">
	{csrf}
	{include file="controllers/notification/inPlaceNotification.tpl" notificationId="oauthAppFormNotification"}

	{fbvFormArea id="oauthAppFormArea"}
		{fbvFormSection}
			{fbvElement type="text" required=true label="plugins.generic.oauth.oauthApp.settings.oauthAppName" id="oauthAppName" value=$oauthAppName maxlength="250" inline=true size=$fbvStyles.size.MEDIUM}
		{/fbvFormSection}
		{fbvFormSection}
			{fbvElement type="text" required="true" label="plugins.generic.oauth.oauthApp.settings.oauthAPIAuth" id="oauthAPIAuth" value=$oauthAPIAuth maxlength="250" inline=true size=$fbvStyles.size.MEDIUM}
		{/fbvFormSection}
		{fbvFormSection}
			{fbvElement type="text" required="true" label="plugins.generic.oauth.oauthApp.settings.oauthAPIVerify" id="oauthAPIVerify" value=$oauthAPIVerify maxlength="250" inline=true size=$fbvStyles.size.MEDIUM}
		{/fbvFormSection}
		{fbvFormSection}
			{fbvElement type="text" required="true" label="plugins.generic.oauth.oauthApp.settings.oauthClientId" id="oauthClientId" value=$oauthClientId maxlength="40" inline=true size=$fbvStyles.size.MEDIUM}
		{/fbvFormSection}
		{fbvFormSection}
			{fbvElement type="text" required="true" label="plugins.generic.oauth.oauthApp.settings.oauthClientSecret" id="oauthClientSecret" value=$oauthClientSecret maxlength="40" inline=true size=$fbvStyles.size.MEDIUM}
		{/fbvFormSection}
		{fbvFormSection}
			{fbvElement type="text" required="true" label="plugins.generic.oauth.oauthApp.settings.oauthUniqueId" id="oauthUniqueId" value=$oauthUniqueId maxlength="40" inline=true size=$fbvStyles.size.MEDIUM}
		{/fbvFormSection}
		{fbvFormSection}
			{fbvElement type="text" required="true" label="plugins.generic.oauth.oauthApp.settings.oauthScope" id="oauthScope" value=$oauthScope maxlength="40" inline=true size=$fbvStyles.size.MEDIUM}
		{/fbvFormSection}
	{/fbvFormArea}
	{fbvFormButtons}
</form>

<p><span class="formRequired">{translate key="common.requiredField"}</span></p>
</div>

