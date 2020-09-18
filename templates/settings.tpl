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
	{fbvFormArea}
		{fbvFormSection title="plugins.generic.keycloak.settings.url"}
			{fbvElement type="text" required="true" id="url" value=$url maxlength="250"}
		{/fbvFormSection}
		{fbvFormSection title="plugins.generic.keycloak.settings.realm"}
			{fbvElement type="text" required="true" id="realm" value=$realm maxlength="250"}
		{/fbvFormSection}
		{fbvFormSection title="plugins.generic.keycloak.settings.clientId"}
			{fbvElement type="text" required="true"  id="clientId" value=$clientId maxlength="50" size=$fbvStyles.size.MEDIUM}
		{/fbvFormSection}
		{fbvFormSection title="plugins.generic.keycloak.settings.clientSecret"}
			{fbvElement type="text" required="true"  id="clientSecret" value=$clientSecret maxlength="50" size=$fbvStyles.size.MEDIUM}
		{/fbvFormSection}
		{fbvFormSection title="plugins.generic.keycloak.settings.hashSecret"}
			{fbvElement type="text" required="true"  id="hashSecret" value=$hashSecret maxlength="50" size=$fbvStyles.size.MEDIUM}
		{/fbvFormSection}
	{/fbvFormArea}
	{fbvFormButtons}
</form>

