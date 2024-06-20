<?php

/**
 * @file enums/MicrosoftAudience.php
 *
 * Copyright (c) 2024 Simon Fraser University
 * Copyright (c) 2024 John Willinsky
 * Distributed under the GNU GPL v3. For full terms see the file docs/COPYING.
 *
 * @class MicrosoftAudience
 *
 * @brief Enumeration for Microsoft supported Audience
 */

namespace APP\plugins\generic\openid\enums;

enum MicrosoftAudience: string
{
    case COMMON = 'common';
    case CONSUMERS = 'consumers';
    case ORGANIZATIONS = 'organizations';

    public static function toArray(): array
    {
        return array_map(fn($case) => $case->value, self::cases());
    }

    public static function toAssociativeArray(bool $arrayFlip = false): array
    {
        $retArray = array_combine(
            array_map(fn($case) => $case->name, self::cases()),
            array_map(fn($case) => $case->value, self::cases())
        );

        if ($arrayFlip) {
            $retArray = array_flip($retArray);
        }

        return $retArray;
    }
}
