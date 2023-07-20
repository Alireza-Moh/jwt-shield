<?php

namespace AlirezaMoh\JwtShield\Services\Signatures;

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
     */
    public function generate(string $privateKey): string
    {
        [$header, $payload] = $this->initToken();

        $signature = $this->signEcdsa($header . '.' . $payload, $privateKey);

        return $header . '.' . $payload . '.' . $signature;
    }

    /**
     * Signs the given data using ECDSA with the private key.
     *
     * @param string $data The data to sign.
     * @param string $privateKey The private key for signing.
     *
     * @return string The base64-encoded ECDSA signature.
     */
    private function signEcdsa(string $data, string $privateKey): string
    {
        $privateKey = openssl_pkey_get_private($privateKey);
        openssl_sign($data, $signature, $privateKey, $this->algorithm->getHashAlgorithm());
        unset($privateKey);

        return $this->encodeBase64($signature);
    }
}