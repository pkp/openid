{**
 * templates/loginProviders.tpl
 *
 * Copyright (c) 2026 Simon Fraser University
 * Copyright (c) 2026 John Willinsky
 * Distributed under the GNU GPL v3. For full terms see the file LICENSE.
 *
 * OpenID provider buttons.
 *}
{if $linkList}
	<ul id="openid-provider-list">
		<li class="margin-top-30"><strong>{translate key='plugins.generic.openid.select.provider.help'}</strong></li>
		{foreach from=$linkList key=name item=url}
			<li><a id="openid-provider-{$name}" href="{$url}">
					<div>
						{if $name == 'custom' && $customBtnImg}
							<img src="{$customBtnImg}" alt="{$name}">
						{else}
							<img src="{$openIDImageURL}{$name}-sign-in.png" alt="{$name}"/>
						{/if}
						<span>
							{if $name == 'custom' && isset($customBtnTxt)}
								{$customBtnTxt}
							{else}
								{{translate key="plugins.generic.openid.select.provider.$name"}}
							{/if}
						</span>
					</div>
				</a>
			</li>
		{/foreach}
	</ul>
{/if}
