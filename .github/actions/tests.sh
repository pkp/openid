#!/bin/bash

set -e

# Install the plugin's dependencies (vendor/ is not committed)
composer install --no-dev --working-dir=plugins/generic/openid

# Serve a stub OpenID discovery document on a separate port, because the
# single-threaded test server can't fetch from itself while handling a request
php -S 127.0.0.1:8001 -t plugins/generic/openid/cypress/fixtures >& openid-fixtures.log &
sleep 2

npx cypress run --headless --browser chrome --config '{"specPattern":["plugins/generic/openid/cypress/tests/functional/*.cy.js"]}'
