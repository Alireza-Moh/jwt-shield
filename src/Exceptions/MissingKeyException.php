<?php

namespace AlirezaMoh\JwtShield\Exceptions;

use Exception;

class MissingKeyException extends Exception
{
    private string $keyType;

    public function __construct(string $keyType)
    {
        $this->keyType = $keyType;
        $message = "Missing $keyType file";

        parent::__construct($message);
    }

    /**
     * @return string
     */
    public function getKeyType(): string
    {
        return $this->keyType;
    }
}