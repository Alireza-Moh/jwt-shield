<?php

namespace AlirezaMoh\JwtShield\Services\Verifiers;

use AlirezaMoh\JwtShield\Exceptions\RSAException;
use AlirezaMoh\JwtShield\Exceptions\TokenException;
use AlirezaMoh\JwtShield\Token;

/**
 * Represents an ECDSA verifier for JWT (JSON Web Token) validation.
 */
class ECDSAVerifier extends BaseVerifier
{
    public function __construct(Token $token)
    {
        parent::__construct($token);
    }

    /**
     * Checks if the token is valid by verifying its ECDSA signature.
     *
     * @return bool Returns true if the token's signature is valid, false otherwise.
     * @throws RSAException|TokenException
     */
    public function isTokenValid(string $publicKey): bool
    {
        $isTokenValid = $this->verifyEcdsa($publicKey);

        return !$this->token->isExpired() && $isTokenValid;
    }

    /**
     * Signs the given data using ECDSA with the public key and retrieves the token's signature.
     *
     * @param string $publicKey The public key to use for signing.
     *
     * @return bool The token's signature.
     * @throws RSAException
     */
    private function verifyEcdsa(string $publicKey): bool
    {
        return $this->verifyWithPublicKey($publicKey, $this->token);
    }
}