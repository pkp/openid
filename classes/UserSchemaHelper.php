<?php

/**
 * @file classes/UserSchemaHelper.php
 *
 * Copyright (c) 2026 Simon Fraser University
 * Copyright (c) 2026 John Willinsky
 * Distributed under the GNU GPL v3. For full terms see the file LICENSE.
 *
 * @class UserSchemaHelper
 *
 * @brief Declares this plugin's User properties and keeps them across edits.
 */

namespace APP\plugins\generic\openid\classes;

use APP\facades\Repo;
use APP\plugins\generic\openid\OpenIDPlugin;
use PKP\plugins\Hook;

class UserSchemaHelper
{
	public function __construct(protected OpenIDPlugin $plugin)
	{
	}

	public function register(): void
	{
		Hook::add('Schema::get::before::user', [$this, 'beforeGetSchema']);
		Hook::add('Schema::get::user', [$this, 'addToSchema']);
		Hook::add('User::edit', [$this, 'addIdpInfoToUser']);
	}

	/**
	 * Add properties for OpenId to the User entity for storage in the database.
	 *
	 * @param string $hookName `Schema::get::user`
	 * @param array $args [
	 *
	 *      @option stdClass $schema
	 * ]
	 */
	public function addToSchema(string $hookName, array $args): bool
	{
		$schema = &$args[0];

		foreach ($this->getPluginSpecificFields() as $pluginSpecificField) {
			$schema->properties->{$pluginSpecificField} = (object) [
				'type' => 'string',
				'apiSummary' => true,
				'validation' => ['nullable'],
			];
		}

		return false;
	}

	public function getPluginSpecificFields(): array
	{
		$pluginSpecificFields = [
			OpenIDPlugin::USER_OPENID_LAST_PROVIDER_SETTING,
			OpenIDPlugin::USER_OPENID_GENERATED_PASSWORD_SETTING,
		];

		foreach (OpenIDPlugin::$publicOpenidProviders as $key => $value) {
			$pluginSpecificFields[] = OpenIDPlugin::getOpenIDUserSetting($key);
		}

		return $pluginSpecificFields;
	}

	/**
	 * Manage force reload of this schema.
	 *
	 * @param string $hookName `Schema::get::before::user`
	 */
	public function beforeGetSchema(string $hookName, bool &$forceReload): bool
	{
		$forceReload = true;

		return false;
	}

	/**
	 * Keep this plugin's fields across a user edit.
	 *
	 * @param string $hookName `User::edit`
	 * @param array $args [
	 *
	 *      @option User $newUser
	 *      @option User $user
	 *      @option array $params
	 * ]
	 */
	public function addIdpInfoToUser(string $hookName, array $args): bool
	{
		$newUser = $args[0];

		$dbUser = Repo::user()->get($newUser->getId());

		foreach ($this->getPluginSpecificFields() as $pluginSpecificField) {
			$dbUserFieldValue = $dbUser->getData($pluginSpecificField);

			if (isset($dbUserFieldValue) && !$newUser->hasData($pluginSpecificField)) {
				$newUser->setData($pluginSpecificField, $dbUserFieldValue);
			}
		}

		if ($dbUser->getPassword() !== $newUser->getPassword()) {
			$newUser->setData(OpenIDPlugin::USER_OPENID_GENERATED_PASSWORD_SETTING, null);
		}

		return false;
	}
}
