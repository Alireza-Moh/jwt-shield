<?php

namespace AlirezaMoh\JwtShield\Services\Signatures;

use AlirezaMoh\JwtShield\Supports\JWTAlgorithm;
use AlirezaMoh\JwtShield\Supports\Traits\Base64;
use AlirezaMoh\JwtShield\Supports\Traits\Key;
use AlirezaMoh\JwtShield\Supports\Traits\Signer;
use AlirezaMoh\JwtShield\Supports\Traits\TokenGenerator;

/**
 * Abstract base class for signatures.
 */
abstract class BaseSignature
{
    use Base64, TokenGenerator, Signer, Key;

    /**
     * The private key used for generating or verifying tokens.
     *
     * @var string
     */
    protected string $privateKey;

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

    /**
     * Expiration time for the token
     *
     * @var mixed
     */
    protected ?int $expiration;


    public function __construct(JWTAlgorithm $algorithm, array $customClaims, ?int $expiration = null) {
        $this->algorithm = $algorithm;
        $this->customClaims = $customClaims;
        $this->expiration = $expiration;
    }

    /**
     * Generates a JWT token with the provided custom claims.
     *
     * @return string The generated JWT token.
     */
    abstract public function generate(): string;

    /**
     * Set the expiration time for the token.
     *
     * @param ?int $expiration The expiration time for the token.
     * @return void
     */
    public function setExpiration(?int $expiration): void
    {
        $this->expiration = $expiration;
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

    /**
     * @return int|null
     */
    public function getExpiration(): ?int
    {
        return $this->expiration;
    }
}