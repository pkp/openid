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
		{rdelim});
		document.querySelector('#generateSecret').addEventListener('click', generatePWD);
	{rdelim});

	function showHideSettings(){ldelim}
		if(this.checked){ldelim}
			this.closest('.showContent').querySelector('.hiddenContent').style.display = 'block';
		{rdelim} else {ldelim}
			this.closest('.showContent').querySelector('.hiddenContent').style.display = 'none';
		{rdelim}
	{rdelim}

	function generatePWD(){ldelim}
		document.querySelector('input[name="hashSecret"]').value = random_password_generate(35,45);
		{rdelim}

	function random_password_generate(max,min)
	{ldelim}
		const passwordChars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz#@!%&()/";
		const randPwLen = Math.floor(Math.random() * (max - min + 1)) + min;
		return Array(randPwLen).fill(passwordChars).map(function (x) {ldelim}
			return x[Math.floor(Math.random() * x.length)]
		{rdelim}).join('');
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
	.provider_list .checkbox_and_radiobutton > li > label{
		font-weight: 600 !important;
	}

	.margin-top-15{
		margin-top: 15px;
	}
</style>

<form
	class="pkp_form"
	id="openIDSettings"
	method="POST"
	enctype="multipart/form-data"
	action="{url router=$smarty.const.ROUTE_COMPONENT op="manage" category="generic" plugin=$pluginName verb="settings" save=true}">
	{csrf}
	{fbvFormArea title="plugins.generic.openid.settings.openid.head" }
		<p>{translate key="plugins.generic.openid.settings.openid.desc"}</p>
		{foreach from=$initProvider item=settings key=name}
			<div class="showContent">
				{fbvFormSection list=true style="padding: 0;" class="provider_list"}
					{fbvElement type="checkbox" id="provider[{$name}][active]" checked=$provider[{$name}]['active']  value=1 label="plugins.generic.openid.settings.{$name}.enable" class="strong"}
					<div class="hiddenContent">
						{assign var='providerSuffix' value="?provider="|cat:$name}
						<p>{translate key="plugins.generic.openid.settings.{$name}.desc"}&nbsp;<strong>{$redirectUrl|escape}{if $name == 'microsoft'}{$providerSuffix|escape:'url'}{else}{$providerSuffix}{/if}</strong></p>
						{if $name eq 'custom'}
							{fbvElement type="text" id="provider[{$name}][configUrl]" value=$provider[{$name}]['configUrl'] maxlength="250" label="plugins.generic.openid.settings.configUrl.desc"}
							<div class="margin-15" style="clear: both;">&nbsp;</div>
							<div>
								<div><strong>{translate key="plugins.generic.openid.settings.btn.settings"}</strong></div>
								{fbvElement type="text" id="provider[{$name}][btnImg]" value=$provider[{$name}]['btnImg'] label="plugins.generic.openid.settings.btnImg.desc" inline=true size=$fbvStyles.size.MEDIUM}
								{fbvElement type="text" id="provider[{$name}][btnTxt]" value=$provider[{$name}]['btnTxt'] maxlength="40" label="plugins.generic.openid.settings.btnTxt.desc" inline=true size=$fbvStyles.size.MEDIUM multilingual=true}
							</div>
							<div class="margin-15" style="clear: both;">&nbsp;</div>
						{else}
							{fbvElement type="hidden" id="provider[{$name}][configUrl]" value=$settings['configUrl'] }
						{/if}
						<div>
							<div><strong>{translate key="plugins.generic.openid.settings.provider.settings"}</strong></div>
							{fbvElement type="text" id="provider[{$name}][clientId]" value=$provider[{$name}]['clientId'] maxlength="250" label="plugins.generic.openid.settings.clientId.desc" inline=true size=$fbvStyles.size.MEDIUM}
							{fbvElement type="text" id="provider[{$name}][clientSecret]" value=$provider[{$name}]['clientSecret'] maxlength="250" label="plugins.generic.openid.settings.clientSecret.desc" inline=true size=$fbvStyles.size.MEDIUM}
						</div>
					</div>
				{/fbvFormSection}
			</div>
		{/foreach}
	{/fbvFormArea}
	{fbvFormArea title="plugins.generic.openid.settings.features.head"}
		<p>{translate key="plugins.generic.openid.settings.features.desc"}</p>
		{fbvFormSection title="plugins.generic.openid.settings.hashSecret"}
			{fbvElement type="text" id="hashSecret" value=$hashSecret maxlength="50" label="plugins.generic.openid.settings.hashSecret.desc" inline=true size=$fbvStyles.size.LARGE readonly=true}
			<div class="inline pkp_helpers_fifth">
				<div class="pkp_button  submitFormButton" id="generateSecret">Generate secret</div>
			</div>
		{/fbvFormSection}

		{fbvFormSection title="plugins.generic.openid.settings.generateAPIKey" list=true }
			{fbvElement type="checkbox" id="generateAPIKey" checked=$generateAPIKey label="plugins.generic.openid.settings.generateAPIKey.check"}
			<label class="sub_label">{translate key="plugins.generic.openid.settings.generateAPIKey.desc"}</label>
		{/fbvFormSection}
	{/fbvFormArea}
	{fbvFormButtons}
</form>

