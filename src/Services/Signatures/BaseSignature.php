<?php

namespace AlirezaMoh\JwtShield\Services\Signatures;

use AlirezaMoh\JwtShield\Supports\JWTAlgorithm;
use AlirezaMoh\JwtShield\Supports\Traits\Base64;
use AlirezaMoh\JwtShield\Supports\Traits\Signer;
use AlirezaMoh\JwtShield\Supports\Traits\TokenGenerator;
use DateTime;

/**
 * Abstract base class for signatures.
 */
class BaseSignature
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

    protected function initToken(array $customClaims, DateTime $expiration): array
    {
        $this->customClaims =  $customClaims;

        $header = $this->prepareHeader($this->algorithm);
        $payload = $this->preparePayload($expiration, $this->customClaims);

        return [$header, $payload];
    }

    /**
     * @return JWTAlgorithm
     */
    public function getAlgorithm(): JWTAlgorithm
    {
        return $this->algorithm;
    }
}