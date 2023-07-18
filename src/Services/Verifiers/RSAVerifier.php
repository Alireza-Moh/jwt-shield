<?php

namespace AlirezaMoh\JwtShield\Services\Verifiers;

use AlirezaMoh\JwtShield\Exceptions\MissingKeyException;

/**
 * Represents an RSA verifier for JWT (JSON Web Token) validation.
 *
 * @throws MissingKeyException if the public key is missing.
 */
class RSAVerifier extends BaseVerifier
{
    /**
     * RSAVerifier constructor.
     *
     * @param string $providedToken The JWT token to verify.
     *
     * @throws MissingKeyException if the public key is missing.
     */
    public function __construct(string $providedToken)
    {
        parent::__construct($providedToken);
        $this->publicKey = $this->getPublicKey();
    }

    /**
     * Checks if the token is valid by verifying its RSA signature.
     *
     * @return bool Returns true if the token's signature is valid, false otherwise.
     */
    public function isTokenValid(): bool
    {
        $expectedSignature = $this->signRsa(json_encode($this->token->getHeader()).'.'.json_encode($this->token->getPayload()));

        return $this->verify($expectedSignature);
    }

    /**
     * Signs the given data using RSA with the public key and retrieves the token's signature.
     *
     * @param string $data The data to sign.
     *
     * @return string The token's signature.
     */
    private function signRsa(string $data): string
    {
        $publicKey = openssl_pkey_get_public($this->publicKey);
        openssl_verify($data, $this->token->getSignature(), $publicKey);
        unset($publicKey);

        return $this->token->getSignature();
    }
}