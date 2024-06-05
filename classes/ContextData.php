<?php

/**
 * @file classes/ContextData.php
 *
 * Copyright (c) 2024 Simon Fraser University
 * Copyright (c) 2024 John Willinsky
 * Distributed under the GNU GPL v3. For full terms see the file LICENSE.
 *
 * @class ContextData
 *
 * @brief Context Data Class.
 */

namespace APP\plugins\generic\openid\classes;

use PKP\context\Context;
use PKP\core\PKPApplication;
use PKP\site\Site;

class ContextData
{
    public function __construct(private Site $site, private ?Context $context = null) 
    {
    }

    public function getId(): int 
    {
        return $this->context ? $this->context->getId() : PKPApplication::CONTEXT_SITE;
    }

    public function getSupportEmail(): ?string
    {
        return $this->context?->getData('supportEmail') ?? $this->site->getLocalizedContactEmail();
    }

    public function getPrivacyStatement(): ?string
    {
        return $this->context?->getLocalizedData('privacyStatement') ?? $this->site->getLocalizedData('privacyStatement');
    }

    public function IsInContext(): bool 
    {
        return isset($this->context);
    }

    public function getPath(): ?string 
    {
        return $this->context ? $this->context->getPath() : null;
    }

    public function getPrimaryLocale(): ?string 
    {
        return $this->context ? $this->context->getPrimaryLocale() : $this->site->getPrimaryLocale();
    }
}
