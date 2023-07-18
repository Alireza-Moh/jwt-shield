<?php

namespace AlirezaMoh\JwtShield\Services\Verifiers;

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
     */
    public function isTokenValid(string $publicKey): bool
    {
        $expectedSignature = $this->signRsa(json_encode($this->token->getHeader()).'.'.json_encode($this->token->getPayload()), $publicKey);

        return $this->verify($expectedSignature);
    }

    /**
     * Signs the given data using RSA with the public key and retrieves the token's signature.
     *
     * @param string $data The data to sign.
     * @param string $publicKey The public key to use for signing.
     *
     * @return string The token's signature.
     */
    private function signRsa(string $data, string $publicKey): string
    {
        $publicKey = openssl_pkey_get_public($publicKey);
        openssl_verify($data, $this->token->getSignature(), $publicKey);
        unset($publicKey);

        return $this->token->getSignature();
    }
}