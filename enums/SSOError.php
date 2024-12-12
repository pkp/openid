<?php

/**
 * @file enums/SSOError.php
 *
 * Copyright (c) 2024 Simon Fraser University
 * Copyright (c) 2024 John Willinsky
 * Distributed under the GNU GPL v3. For full terms see the file docs/COPYING.
 *
 * @class SSOError
 *
 * @brief Enumeration for openID possible errors
 */

namespace APP\plugins\generic\openid\enums;

enum SSOError: string
{
    case CONNECT_DATA = 'connect_data';
    case CONNECT_KEY = 'connect_key';
    case CERTIFICATION = 'cert';
    case USER_DISABLED = 'disabled';
    case API_RETURNED = 'api_returned';
}
