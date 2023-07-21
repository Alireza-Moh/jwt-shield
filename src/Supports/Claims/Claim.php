<?php

namespace AlirezaMoh\JwtShield\Supports\Claims;

/**
 * Class ClaimRegistry
 *
 * Represents a claim item with a name and its corresponding value.
 */
class Claim
{
    /**
     * @var mixed The name of the claim.
     */
    private mixed $name;

    /**
     * @var mixed The value of the claim.
     */
    private mixed $value;

    /**
     * ClaimRegistry constructor.
     *
     * @param mixed $name The name of the claim.
     * @param mixed $value The value of the claim.
     */
    public function __construct(mixed $name, mixed $value)
    {
        $this->name = $name;
        $this->value = $value;
    }

    /**
     * Get the name of the claim.
     *
     * @return mixed The name of the claim.
     */
    public function getName(): mixed
    {
        return $this->name;
    }

    /**
     * Get the value of the claim.
     *
     * @return mixed The value of the claim.
     */
    public function getValue(): mixed
    {
        return $this->value;
    }

    /**
     * Check if the claim is a registered claim.
     *
     * @return bool True if the claim is a registered claim, false otherwise.
     */
    public function isARegisteredClaim(): bool
    {
        return $this->name instanceof ClaimRegistry;
    }
}