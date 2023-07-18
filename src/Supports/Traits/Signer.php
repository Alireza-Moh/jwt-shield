<?php

namespace AlirezaMoh\JwtShield\Supports\Traits;

use AlirezaMoh\JwtShield\Supports\JWTAlgorithm;
use InvalidArgumentException;


/**
 * Trait Signer
 *
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
}