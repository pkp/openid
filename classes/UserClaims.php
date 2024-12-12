<?php

/**
 * @file classes/UserClaims.php
 *
 * Copyright (c) 2024 Simon Fraser University
 * Copyright (c) 2024 John Willinsky
 * Distributed under the GNU GPL v3. For full terms see the file LICENSE.
 *
 * @brief UserClaims Data Class.
 */

namespace APP\plugins\generic\openid\classes;

class UserClaims
{
    public ?string $id = null;
    public ?string $email = null;
    public ?string $username = null;
    public ?string $givenName = null;
    public ?string $familyName = null;
    public ?bool $emailVerified = null;

    /**
     * Merge claims from another source into this object.
     * Non-null values in the new claims take precedence.
     */
    public function merge(UserClaims $other): void
    {
        foreach (get_object_vars($other) as $key => $value) {
            if ($value !== null) {
                $this->$key = $value;
            }
        }
    }

    /**
     * Check if all required claims are complete.
     */
    public function isComplete(): bool
    {
        return $this->id !== null && $this->email !== null && $this->username !== null && $this->givenName !== null && $this->familyName !== null && $this->emailVerified !== null;
    }

    /**
     * Check if claims exist.
     */
    public function isEmpty(): bool
    {
        return $this->id === null;
    }

    /**
     * Set the Claims values from an array.
     */
    public function setValues(array $claimsParams): void
    {
        $this->id = $claimsParams['sub'] ?? null;
        $this->email = $claimsParams['email'] ?? null;
        $this->username = $claimsParams['preferred_username'] ?? null;
        $this->givenName = $claimsParams['given_name'] ?? null;
        $this->familyName = $claimsParams['family_name'] ?? null;
        $this->emailVerified = $claimsParams['email_verified'] ?? null;
    }
}
