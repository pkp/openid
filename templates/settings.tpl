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
		{fbvFormSection title="plugins.generic.openid.settings.url"}
			{fbvElement type="text" required="true" id="url" value=$url maxlength="250" label="plugins.generic.openid.settings.url.desc"}
		{/fbvFormSection}
		{fbvFormSection title="plugins.generic.openid.settings.realm"}
			{fbvElement type="text" required="true" id="realm" value=$realm maxlength="250" label="plugins.generic.openid.settings.realm.desc"}
		{/fbvFormSection}
		{fbvFormSection title="plugins.generic.openid.settings.clientId"}
			{fbvElement type="text" required="true"  id="clientId" value=$clientId maxlength="50" label="plugins.generic.openid.settings.clientId.desc"}
		{/fbvFormSection}
		{fbvFormSection title="plugins.generic.openid.settings.clientSecret"}
			{fbvElement type="text" required="true"  id="clientSecret" value=$clientSecret maxlength="50" label="plugins.generic.openid.settings.clientSecret.desc"}
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

