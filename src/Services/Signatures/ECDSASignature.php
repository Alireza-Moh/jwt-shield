<?php

namespace AlirezaMoh\JwtShield\Services\Signatures;

use AlirezaMoh\JwtShield\Exceptions\MissingKeyException;
use AlirezaMoh\JwtShield\Supports\JWTAlgorithm;

/**
 * Represents an ECDSA signature for JWT (JSON Web Token) generation.
 *
 * @throws MissingKeyException if the private key is missing.
 */
class ECDSASignature extends BaseSignature
{
    /**
     * ECDSASignature constructor.
     *
     * @param JWTAlgorithm $algorithm The algorithm used for signing.
     * @param array $customClaims Additional custom claims for the JWT.
     * @param int|null $expireTime The expiration time for the JWT (optional).
     *
     * @throws MissingKeyException if the private key is missing.
     */
    public function __construct(JWTAlgorithm $algorithm, array $customClaims, ?int $expireTime = null)
    {
        parent::__construct($algorithm, $customClaims, $expireTime);

        $this->privateKey = $this->getPrivateKey();
    }

    /**
     * Generates the ECDSA signature for the JWT.
     *
     * @return string The generated ECDSA signature.
     */
    public function generate(): string
    {
        $header = $this->prepareHeader($this->algorithm);
        $payload = $this->preparePayload($this->customClaims, $this->expireTime);

        $signature = $this->signEcdsa($header . '.' . $payload);

        return $header . '.' . $payload . '.' . $signature;
    }

    /**
     * Signs the given data using ECDSA with the private key.
     *
     * @param string $data The data to sign.
     *
     * @return string The base64-encoded ECDSA signature.
     */
    private function signEcdsa(string $data): string
    {
        $privateKey = openssl_pkey_get_private($this->privateKey);
        openssl_sign($data, $signature, $privateKey, $this->algorithm->getHashAlgorithm());
        unset($privateKey);

        return $this->encodeBase64($signature);
    }
}