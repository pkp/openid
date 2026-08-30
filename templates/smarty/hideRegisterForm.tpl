{**
 * templates/smarty/hideRegisterForm.tpl
 *
 * Copyright (c) 2026 Simon Fraser University
 * Copyright (c) 2026 John Willinsky
 * Distributed under the GNU GPL v3. For full terms see the file LICENSE.
 *
 * Inherits the registration page and replaces the form with a link to the login page.
 *}
{extends file="frontend/pages/userRegister.tpl"}
{block name="userRegisterForm"}
	<a href="{url page="login"}" class="login">{translate key="user.login"}</a>
{/block}
