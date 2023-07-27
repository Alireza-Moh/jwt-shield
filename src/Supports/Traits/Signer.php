<?php

namespace AlirezaMoh\JwtShield\Supports\Traits;

use AlirezaMoh\JwtShield\Exceptions\RSAException;
use AlirezaMoh\JwtShield\Supports\JWTAlgorithm;
use InvalidArgumentException;


/**
 * This trait provides a method for signing data using a JWTAlgorithm and secret key.
 */
trait Signer
{
    /**
     * Sign the given data using the specified JWTAlgorithm and secret key.
     *
     * @param JWTAlgorithm $algorithm The JWT algorithm object.
     * @param string $data The data to be signed.
     * @param string $secretKey The secret key.
     * @return string The generated signature.
     */
    public function sign(JWTAlgorithm $algorithm, string $data, string $secretKey): string
    {
        if (empty($secretKey)) {
            throw new InvalidArgumentException("The secret key can not be empty");
        }
        return hash_hmac($algorithm->getHashAlgorithm(), $data, $secretKey, true);
    }

    /**
     * Signs the given data with the private key.
     *
     * @param string $data The data to sign.
     * @param string $privateKey The private key for signing.
     * @param JWTAlgorithm $algorithm The algorithm for signing.
     *
     * @return string The base64-encoded ECDSA signature.
     * @throws RSAException
     */
    public function signWithPrivateKey(string $data, string $privateKey, JWTAlgorithm $algorithm): string
    {
        $privateKey = openssl_pkey_get_private($privateKey);
        $isSigned = openssl_sign($data, $signature, $privateKey, $algorithm->getHashAlgorithm());

        if (!$isSigned) {
            throw new RSAException('Failed to generate the signature ' .  $algorithm->getAlgorithm());
        }
        unset($privateKey);

        return $this->encodeBase64($signature);
    }
}