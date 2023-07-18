<?php

namespace AlirezaMoh\JwtShield\Services\Verifiers;

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
     */
    public function isTokenValid(string $publicKey): bool
    {
        $expectedSignature = $this->signEcdsa(
            json_encode($this->token->getHeader()).'.'.json_encode($this->token->getPayload()),
            $publicKey
        );

        return $this->verify($expectedSignature);
    }

    /**
     * Signs the given data using ECDSA with the public key and retrieves the token's signature.
     *
     * @param string $data The data to sign.
     * @param string $publicKey The public key to use for signing.
     *
     * @return string The token's signature.
     */
    private function signEcdsa(string $data, string $publicKey): string
    {
        $publicKey = openssl_pkey_get_public($publicKey);
        openssl_verify($data, $this->token->getSignature(), $publicKey);
        unset($publicKey);

        return $this->token->getSignature();
    }
}