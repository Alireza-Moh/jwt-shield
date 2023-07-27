<?php

namespace AlirezaMoh\JwtShield\Services\Signatures;

use AlirezaMoh\JwtShield\Supports\JWTAlgorithm;
use AlirezaMoh\JwtShield\Supports\Traits\Base64;
use AlirezaMoh\JwtShield\Supports\Traits\Signer;
use AlirezaMoh\JwtShield\Supports\Traits\ClaimHandler;

/**
 * Abstract base class for signatures.
 */
class BaseSignature
{
    use Base64, ClaimHandler, Signer;

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
    protected array $claims = [];

    public function __construct(JWTAlgorithm $algorithm)
    {
        $this->algorithm = $algorithm;
    }

    protected function initToken(): array
    {
        $header = $this->prepareHeader($this->algorithm);
        $payload = $this->preparePayload();

        return [$header, $payload];
    }

    /**
     * @return JWTAlgorithm
     */
    public function getAlgorithm(): JWTAlgorithm
    {
        return $this->algorithm;
    }

    public function addClaims(array $claims): void
    {
        $this->claims = array_merge($this->claims, $claims);
    }
}