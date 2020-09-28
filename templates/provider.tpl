{include file="frontend/components/header.tpl" pageTitle='plugins.generic.openid.select.provider'}
<div class="page page_oauth_error">
	{include file="frontend/components/breadcrumbs.tpl" currentTitleKey='plugins.generic.openid.select.provider'}
	<h1>{translate key='plugins.generic.openid.select.provider'}</h1>
	<p>{translate key='plugins.generic.openid.select.provider.help'}</p>
	{if $loginMessage}
		<p>
			{translate key=$loginMessage}
		</p>
	{/if}
	<ul id="openid-provider-list">
		{foreach from=$linkList key=name item=url}
			{if $name == 'custom'}
				<li><a id="openid-provider-{$name}" href="{$url}">
						<div><img src="{$imageURL}{$name}-sign-in.png" alt="{$name}">
							<span>
								{if isset($customBtnTxt)}
									{$customBtnTxt}
								{else}
									{{translate key="plugins.generic.openid.select.provider.$name"}}
								{/if}
							</span>
						</div>
					</a>
				</li>
			{else}
				<li><a id="openid-provider-{$name}" href="{$url}">
						<div><img src="{$imageURL}{$name}-sign-in.png" alt="{$name}">
							<span>{{translate key="plugins.generic.openid.select.provider.$name"}}</span>
						</div>
					</a>
				</li>
			{/if}
		{/foreach}
	</ul>
</div><!-- .page -->
{include file="frontend/components/footer.tpl"}
