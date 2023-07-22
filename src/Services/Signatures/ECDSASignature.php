<?php

namespace AlirezaMoh\JwtShield\Services\Signatures;

use AlirezaMoh\JwtShield\Exceptions\RSAException;
use AlirezaMoh\JwtShield\Supports\JWTAlgorithm;

/**
 * Represents an ECDSA signature for JWT (JSON Web Token) generation.
 *
 */
class ECDSASignature extends BaseSignature
{
    public function __construct(JWTAlgorithm $algorithm)
    {
        parent::__construct($algorithm);
    }

    /**
     * Generates the ECDSA signature for the JWT.
     * @param string $privateKey The private key for generating the signature.
     * @return string The generated ECDSA token.
     * @throws RSAException
     */
    public function generate(string $privateKey): string
    {
        [$header, $payload] = $this->initToken();

        $signature = $this->signWithPrivateKey($header . '.' . $payload, $privateKey, $this->algorithm);

        return $header . '.' . $payload . '.' . $signature;
    }
}