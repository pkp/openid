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
<script>
	$(function () {ldelim}
		$('#openIDSettings').pkpHandler('$.pkp.controllers.form.AjaxFormHandler');
		{rdelim});
</script>

<form
	class="pkp_form"
	id="openIDSettings"
	method="POST"
	action="{url router=$smarty.const.ROUTE_COMPONENT op="manage" category="generic" plugin=$pluginName verb="settings" save=true}">

	{csrf}
	{fbvFormArea title="plugins.generic.openid.settings.openid.head" }
		<p>{translate key="plugins.generic.openid.settings.openid.desc"}</p>
		{fbvFormSection title="plugins.generic.openid.settings.authUrl"}
			{fbvElement type="text" required="true" id="authUrl" value=$authUrl maxlength="250" label="plugins.generic.openid.settings.authUrl.desc"}
		{/fbvFormSection}
		{fbvFormSection title="plugins.generic.openid.settings.tokenUrl"}
			{fbvElement type="text" required="true" id="tokenUrl" value=$tokenUrl maxlength="250" label="plugins.generic.openid.settings.tokenUrl.desc"}
		{/fbvFormSection}
		{fbvFormSection title="plugins.generic.openid.settings.certUrl"}
			{fbvElement type="text" id="certUrl" value=$certUrl maxlength="250" label="plugins.generic.openid.settings.certUrl.desc"}
		{/fbvFormSection}
		{fbvFormSection title="plugins.generic.openid.settings.certString"}
			{fbvElement type="textarea" id="certString" value=$certString label="plugins.generic.openid.settings.certString.desc"}
		{/fbvFormSection}
		{fbvFormSection title="plugins.generic.openid.settings.logoutUrl"}
			{fbvElement type="text" required="true" id="logoutUrl" value=$logoutUrl maxlength="250" label="plugins.generic.openid.settings.logoutUrl.desc"}
		{/fbvFormSection}
		{fbvFormSection title="plugins.generic.openid.settings.clientId"}
			{fbvElement type="text" required="true"  id="clientId" value=$clientId maxlength="250" label="plugins.generic.openid.settings.clientId.desc"}
		{/fbvFormSection}
		{fbvFormSection title="plugins.generic.openid.settings.clientSecret"}
			{fbvElement type="text" required="true"  id="clientSecret" value=$clientSecret maxlength="250" label="plugins.generic.openid.settings.clientSecret.desc"}
		{/fbvFormSection}
	{/fbvFormArea}
	{fbvFormArea title="plugins.generic.openid.settings.features.head"}
		<p>{translate key="plugins.generic.openid.settings.features.desc"}</p>
		{fbvFormSection title="plugins.generic.openid.settings.hashSecret"}
			{fbvElement type="text" id="hashSecret" value=$hashSecret maxlength="50" label="plugins.generic.openid.settings.hashSecret.desc"}
		{/fbvFormSection}
		{fbvFormSection title="plugins.generic.openid.settings.generateAPIKey" list=true }
			{fbvElement type="checkbox" id="generateAPIKey" checked=$generateAPIKey label="plugins.generic.openid.settings.generateAPIKey.check"}
			<label class="sub_label">{translate key="plugins.generic.openid.settings.generateAPIKey.desc"}</label>
		{/fbvFormSection}
	{/fbvFormArea}
	{fbvFormButtons}
</form>

