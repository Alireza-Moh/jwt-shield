<?php

namespace AlirezaMoh\JwtShield\Supports\Traits;


use AlirezaMoh\JwtShield\Exceptions\MissingKeyException;

/**
 * Trait Key
 *
 * This trait provides methods for getting the public and private keys and the secret key.
 */
trait Key
{
    /**
     * @throws MissingKeyException
     */
    public function getPublicKey(): string
    {
        if (!file_exists("../keys/public_key.pem")) {
            throw new MissingKeyException("public key");
        }
        return file_get_contents("../keys/public_key.pem");
    }

    /**
     * @throws MissingKeyException
     */
    public function getPrivateKey(): string
    {
        if (!file_exists("../keys/private_key.pem")) {
            throw new MissingKeyException("private key");
        }
        return file_get_contents("../keys/private_key.pem");
    }

    /**
     * Gets the secret key from the .env file
     * @return string the secret key
     */
    public function getSecretKey(): string
    {
        return $_ENV["SECRET_KEY"];
    }
}