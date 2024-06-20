<?php

/**
 * @file enums/OpenIDProvider.php
 *
 * Copyright (c) 2024 Simon Fraser University
 * Copyright (c) 2024 John Willinsky
 * Distributed under the GNU GPL v3. For full terms see the file docs/COPYING.
 *
 * @class OpenIDProvider
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
