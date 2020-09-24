{include file="frontend/components/header.tpl" pageTitle='plugins.generic.openid.select.provider'}
<div class="page page_oauth_error">
	{include file="frontend/components/breadcrumbs.tpl" currentTitleKey='plugins.generic.openid.select.provider'}
	<h1>{translate key='plugins.generic.openid.select.provider'}</h1>
	<p>{translate key='plugins.generic.openid.select.provider.help'}</p>
	{foreach from=$linkList key=name item=url}
		<a href="{$url}">{$name}</a>
	{/foreach}
</div><!-- .page -->
{include file="frontend/components/footer.tpl"}
