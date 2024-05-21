<?php

/**
 * @file enums/OpenIDProvider.php
 *
 * Copyright (c) 2023 Simon Fraser University
 * Copyright (c) 2023 John Willinsky
 * Distributed under the GNU GPL v3. For full terms see the file docs/COPYING.
 *
 * @class OpenIDProvider
 *
 * @ingroup plugins_generic_openid
 *
 * @brief Enumeration for openID supported providers
 */

namespace APP\plugins\generic\openid\enums;

enum OpenIDProvider: string
{
    case CUSTOM = 'custom';
    case ORCID = 'orcid';
    case GOOGLE = 'google';
    case APPLE = 'apple';
    case MICROSOFT = 'microsoft';
}
