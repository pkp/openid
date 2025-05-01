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

class ContextData
{
	/** @var Site */
	private $site;

	/** @var Context|null */
	private $context;

	public function __construct($site, $context = null)
	{
		$this->site = $site;
		$this->context = $context;
	}

	public function getId(): int
	{
		return $this->context ? $this->context->getId() : 0;
	}

	public function getSupportEmail(): ?string
	{
		return $this->context && $this->context->getData('supportEmail') !== null
			? $this->context->getData('supportEmail')
			: $this->site->getLocalizedContactEmail();
	}

	public function getPrivacyStatement(): ?string
	{
		return $this->context && $this->context->getData('supportEmail') !== null
			? $this->context->getData('supportEmail')
			: $this->site->getLocalizedContactEmail();
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
