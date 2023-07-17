<?php

namespace AlirezaMoh\JwtShield\Supports\Traits;


use AlirezaMoh\JwtShield\Exceptions\MissingKeyException;

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

    public function getSecretKey(): string
    {
        return $_ENV["SECRET_KEY"];
    }
}