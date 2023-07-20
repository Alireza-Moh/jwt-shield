<?php

namespace AlirezaMoh\JwtShield\Services\Signatures;

use AlirezaMoh\JwtShield\Exceptions\RSAException;
use AlirezaMoh\JwtShield\Supports\JWTAlgorithm;

/**
 * Represents an RSA signature for JWT (JSON Web Token) generation.
 *
 */
class RSASignature extends BaseSignature
{
    public function __construct(JWTAlgorithm $algorithm)
    {
        parent::__construct($algorithm);
    }

    /**
     * Generates the RSA signature for the JWT.
     * @param string $privateKey The private key for generating the signature.
     * @return string The generated RSA signature.
     * @throws RSAException
     */
    public function generate(string $privateKey): string
    {
        [$header, $payload] = $this->initToken();

        $signature = $this->signRsa($header . '.' . $payload, $privateKey);

        return $header . '.' . $payload . '.' . $signature;
    }

    /**
     * Signs the given data using RSA with the private key.
     *
     * @param string $data The data to sign.
     * @param string $privateKey The private key for generating the signature.
     * @return string The base64-encoded RSA signature.
     * @throws RSAException
     */
    private function signRsa(string $data, string $privateKey): string
    {
        $privateKey = openssl_pkey_get_private($privateKey);

        $isSigned = openssl_sign($data, $signature, $privateKey, $this->algorithm->getHashAlgorithm());
        if (!$isSigned) {
            throw new RSAException('Failed to generate RSA signature.');
        }

        return $this->encodeBase64($signature);
    }
}