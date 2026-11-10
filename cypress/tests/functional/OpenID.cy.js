/* npx cypress open --config specPattern=plugins/generic/openid/cypress/tests/functional */
const customProvider = {
	configUrl: 'http://127.0.0.1:8001/openid-configuration.json',
	btnTxt: 'Sign in with the test provider',
	clientId: 'openid-ci',
	clientSecret: 'openid-ci-secret',
};

describe('OpenID plugin tests', function () {

	it('Disable OpenID Authentication Plugin', function () {
		cy.login('admin', 'admin', 'publicknowledge');
		cy.get('nav').contains('Website').click({ force: true });
		cy.get('button[id="plugins-button"]').click();
		// disable plugin if enabled
		cy.get('input[id^="select-cell-openidplugin-enabled"]')
			.then($btn => {
				if ($btn.attr('checked') === 'checked') {
					cy.get('input[id^="select-cell-openidplugin-enabled"]').click();
					cy.get('div[class*="pkp_modal_panel"] button[class*="pkpModalConfirmButton"]').click();
					cy.get('div:contains(\'The plugin "OpenID Authentication Plugin" has been disabled.\')');
				}
			});
	});

	it('Enable OpenID Authentication Plugin', function () {
		cy.login('admin', 'admin', 'publicknowledge');
		cy.get('nav').contains('Website').click({ force: true });
		cy.get('button[id="plugins-button"]').click();
		// Find and enable the plugin
		cy.get('input[id^="select-cell-openidplugin-enabled"]').click();
		cy.get('div:contains(\'The plugin "OpenID Authentication Plugin" has been enabled.\')');
		cy.waitJQuery();
		cy.get('tr[id="component-grid-settings-plugins-settingsplugingrid-category-generic-row-openidplugin"] a[class="show_extras"]').click();
		cy.get('a[id^="component-grid-settings-plugins-settingsplugingrid-category-generic-row-openidplugin-settings-button"]').click();
		// Fill out settings form
		cy.get('form[id="openIDSettings"] input[name="provider[custom][active]"]').check({force: true});
		cy.waitJQuery();
		cy.get('form[id="openIDSettings"] input[name="provider[custom][configUrl]"]').clear().type(customProvider.configUrl);
		cy.get('form[id="openIDSettings"] input[name="provider[custom][btnTxt][en]"]').clear().type(customProvider.btnTxt);
		cy.get('form[id="openIDSettings"] input[name="provider[custom][clientId]"]').clear().type(customProvider.clientId);
		cy.get('form[id="openIDSettings"] input[name="provider[custom][clientSecret]"]').clear().type(customProvider.clientSecret);
		cy.get('form[id="openIDSettings"] input[name="legacyLogin"]').check({force: true});
		cy.get('form[id="openIDSettings"] div[id="generateSecret"]').click();
		cy.get('form[id="openIDSettings"] input[name="generateAPIKey"]').check({force: true});
		// submit settings form
		cy.get('form[id="openIDSettings"] button[id^="submitFormButton"]').click();
		cy.waitJQuery();
		cy.wait(3000);
		cy.get('div:contains(\'Your changes have been saved.\')');
	});

	it('Check OpenID Authentication Plugin Login Page', function () {
		cy.visit('/index.php/publicknowledge/login');
		cy.get('a[id="openid-provider-custom"]').contains(customProvider.btnTxt);
	});
});
