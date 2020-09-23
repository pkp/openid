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

	$( document ).ready(function() {ldelim}
		let checkboxes = document.querySelectorAll('.showContent input[type="checkbox"]');
		checkboxes.forEach(checkbox => {ldelim}
			if(checkbox.checked){ldelim}
				checkbox.closest('.showContent').querySelector('.hiddenContent').style.display = 'block';
			{rdelim}
			checkbox.addEventListener('click', showHideSettings);
		{rdelim})
	{rdelim});

	function showHideSettings(){ldelim}
		if(this.checked){ldelim}
			this.closest('.showContent').querySelector('.hiddenContent').style.display = 'block';
		{rdelim} else {ldelim}
			this.closest('.showContent').querySelector('.hiddenContent').style.display = 'none';
		{rdelim}
	{rdelim}

</script>

<style>
	.showContent{
		padding-bottom: 15px;
		padding-top: 15px;
		border-bottom: 1px solid black;
	}

	.hiddenContent{
		display: none;
		padding-top: 10px;
	}
</style>

<form
	class="pkp_form"
	id="openIDSettings"
	method="POST"
	action="{url router=$smarty.const.ROUTE_COMPONENT op="manage" category="generic" plugin=$pluginName verb="settings" save=true}">

	{csrf}
	{fbvFormArea title="plugins.generic.openid.settings.openid.head" }
		<p>{translate key="plugins.generic.openid.settings.openid.desc"}</p>
		{fbvFormSection title="plugins.generic.openid.settings.configUrl"}
			{fbvElement type="text" required="true" id="configUrl" value=$configUrl maxlength="250" label="plugins.generic.openid.settings.configUrl.desc"}
		{/fbvFormSection}
		{fbvFormSection title="plugins.generic.openid.settings.clientId"}
			{fbvElement type="text" required="true"  id="clientId" value=$clientId maxlength="250" label="plugins.generic.openid.settings.clientId.desc"}
		{/fbvFormSection}
		{fbvFormSection title="plugins.generic.openid.settings.clientSecret"}
			{fbvElement type="text" required="true"  id="clientSecret" value=$clientSecret maxlength="250" label="plugins.generic.openid.settings.clientSecret.desc"}
		{/fbvFormSection}

	{foreach from=$initProvider item=configUrl key=name}
		<div class="showContent">
			{fbvFormSection title="plugins.generic.openid.settings.{$name}.enable" list=true style="padding: 0;"}
				<p>{translate key="plugins.generic.openid.settings.{$name}.desc"}</p>
				{fbvElement type="checkbox" id="provider[{$name}][active]" checked=$provider[{$name}]['active']  value=1 label="plugins.generic.openid.settings.{$name}.enable.desc" }
				<div class="hiddenContent">
					{if $name eq 'custom'}
						{fbvElement type="text" id="provider[{$name}][configUrl]" value=$provider[{$name}]['configUrl'] maxlength="250" label="plugins.generic.openid.settings.configUrl.desc"}
					{else}
						{fbvElement type="hidden" id="provider[{$name}][configUrl]" value=$configUrl }
					{/if}
					{fbvElement type="text" id="provider[{$name}][clientId]" value=$provider[{$name}]['clientId'] maxlength="250" label="plugins.generic.openid.settings.clientId.desc" inline=true size=$fbvStyles.size.MEDIUM}
					{fbvElement type="text" id="provider[{$name}][clientSecret]" value=$provider[{$name}]['clientSecret'] maxlength="250" label="plugins.generic.openid.settings.clientSecret.desc" inline=true size=$fbvStyles.size.MEDIUM}
				</div>
			{/fbvFormSection}
		</div>
	{/foreach}
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

