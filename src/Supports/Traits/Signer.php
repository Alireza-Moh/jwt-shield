<?php

namespace AlirezaMoh\JwtShield\Supports\Traits;

use AlirezaMoh\JwtShield\Exceptions\MissingKeyException;
use AlirezaMoh\JwtShield\Exceptions\MissingSecretKeyException;
use AlirezaMoh\JwtShield\Supports\JWTAlgorithm;
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
     * @return string The generated signature.
     */
    public function sign(JWTAlgorithm $algorithm, string $data): string
    {
        return hash_hmac($algorithm->getHashAlgorithm(), $data, $this->getSecretKey(), true);
    }
}