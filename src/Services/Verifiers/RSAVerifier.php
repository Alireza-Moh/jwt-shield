<?php

namespace AlirezaMoh\JwtShield\Services\Verifiers;

use AlirezaMoh\JwtShield\Exceptions\RSAException;
use AlirezaMoh\JwtShield\Token;

/**
 * Represents an RSA verifier for JWT (JSON Web Token) validation.
 */
class RSAVerifier extends BaseVerifier
{
    public function __construct(Token $token)
    {
        parent::__construct($token);
    }

    /**
     * Checks if the token is valid by verifying its RSA signature.
     *
     * @return bool Returns true if the token's signature is valid, false otherwise.
     * @throws RSAException
     */
    public function isTokenValid(string $publicKey): bool
    {
        if (is_null($publicKey)) {
            throw new RSAException("The public key is needed for token verification");
        }

        return $this->verifyRsa($publicKey);
    }

    /**
     * Signs the given data using RSA with the public key and retrieves the token's signature.
     *
     * @param string $publicKey The public key to use for signing.
     *
     * @return bool The token's signature.
     * @throws RSAException
     */
    private function verifyRsa(string $publicKey): bool
    {
        return $this->verifyWithPublicKey($publicKey, $this->token);
    }
}