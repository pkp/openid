<?php

/**
 * @defgroup plugins_generic_oauth OAuth generic plugin
 */

/**
 * @file plugins/generic/oauth/index.php
 *
 * Copyright (c) 2015-2016 University of Pittsburgh
 * Copyright (c) 2014 Simon Fraser University Library
 * Copyright (c) 2014 John Willinsky
 * Distributed under the GNU GPL v2. For full terms see the file docs/COPYING.
 *
 * @ingroup plugins_generic_oauth
 * @brief Wrapper for OAuth generic plugin.
 *
 */

require_once('OpenIDPlugin.inc.php');

return new OpenIDPlugin();

?>
