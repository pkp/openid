{include file="frontend/components/header.tpl" pageTitle=$errorType}
<div class="page page_oauth_error">
	{include file="frontend/components/breadcrumbs.tpl" currentTitleKey=$errorType}
	<h1>{translate key=$errorType}</h1>
	<p>{translate key=$errorMsg supportEmail=$supportEmail}</p>
	{if $reason}
		<p>{$reason}</p>
	{/if}
</div><!-- .page -->
{include file="frontend/components/footer.tpl"}
