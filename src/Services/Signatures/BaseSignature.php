<?php

namespace AlirezaMoh\JwtShield\Services\Signatures;

use AlirezaMoh\JwtShield\Supports\JWTAlgorithm;
use AlirezaMoh\JwtShield\Supports\Traits\Base64;
use AlirezaMoh\JwtShield\Supports\Traits\Signer;
use AlirezaMoh\JwtShield\Supports\Traits\TokenGenerator;

/**
 * Abstract base class for signatures.
 */
abstract class BaseSignature
{
    use Base64, TokenGenerator, Signer;

    /**
     * The algorithm used for generating or verifying tokens.
     *
     * @var JWTAlgorithm
     */
    protected JWTAlgorithm $algorithm;

    /**
     * Custom data to be stored in the payload
     *
     * @var array
     */
    protected array $customClaims;

    public function __construct(JWTAlgorithm $algorithm)
    {
        $this->algorithm = $algorithm;
    }

    /**
     * Adds additional claims to the JWT.
     *
     * @param array $data The additional claims to add.
     */
    public function addClaims(array $data): void
    {
        $this->customClaims = array_merge($this->customClaims, $data);
    }

    /**
     * @return JWTAlgorithm
     */
    public function getAlgorithm(): JWTAlgorithm
    {
        return $this->algorithm;
    }

    /**
     * @return array
     */
    public function getCustomClaims(): array
    {
        return $this->customClaims;
    }
}