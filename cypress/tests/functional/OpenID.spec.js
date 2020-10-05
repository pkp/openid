/* npx cypress open  --config integrationFolder=plugins/generic/openid/cypress/tests */
describe('OpenID plugin tests', function () {

	it('Disable OpenID Authentication Plugin', function () {
		cy.login(Cypress.env("ojs_username"), Cypress.env("ojs_password"), Cypress.env("context"));
		cy.get('ul[id="navigationPrimary"] a:contains("Settings")').click();
		cy.get('ul[id="navigationPrimary"] a:contains("Website")').click();
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
		cy.server();
		cy.route('POST', Cypress.env("baseUrl") + '/index.php/' + Cypress.env("context") + '/$$$call$$$/grid/settings/plugins/settings-plugin-grid/manage?category=generic&plugin=openidplugin&verb=settings&save=1').as('saveSettings');
		cy.login(Cypress.env("ojs_username"), Cypress.env("ojs_password"), Cypress.env("context"));
		cy.get('ul[id="navigationPrimary"] a:contains("Settings")').click();
		cy.get('ul[id="navigationPrimary"] a:contains("Website")').click();
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
		cy.get('form[id="openIDSettings"] input[name="provider[custom][configUrl]"]').clear().type(Cypress.env("openid_custom_url"));
		cy.get('form[id="openIDSettings"] input[name="provider[custom][btnImg]"]').clear().type(Cypress.env("openid_custom_img"));
		cy.get('form[id="openIDSettings"] input[name="provider[custom][btnTxt][en_US]"]').clear().type(Cypress.env("openid_custom_txt"));
		cy.get('form[id="openIDSettings"] input[name="provider[custom][clientId]"]').clear().type(Cypress.env("openid_custom_id"));
		cy.get('form[id="openIDSettings"] input[name="provider[custom][clientSecret]"]').clear().type(Cypress.env("openid_custom_secret"));
		cy.get('form[id="openIDSettings"] input[name="legacyLogin"]').check({force: true});
		cy.get('form[id="openIDSettings"] div[id="generateSecret"]').click();
		cy.get('form[id="openIDSettings"] input[name="generateAPIKey"]').check({force: true});
		// submit settings form
		cy.get('form[id="openIDSettings"] button[id^="submitFormButton"]').click();
		cy.wait('@saveSettings');
		cy.waitJQuery();
		cy.get('div:contains(\'Your changes have been saved.\')');
	});

	it('Check OpenID Authentication Plugin Login Page', function () {
		cy.visit(Cypress.env("baseUrl") + '/index.php/' + Cypress.env("context") + '/login');
		cy.get('a[id="openid-provider-custom"]').contains(Cypress.env("openid_custom_txt"));
	});
});
