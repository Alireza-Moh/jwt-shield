<?php

namespace AlirezaMoh\JwtShield\Exceptions;

use Exception;

class AlgorithmNotFoundException extends Exception
{
    private mixed $algorithm;
    public function __construct($algorithm)
    {
        $this->algorithm = $algorithm;
        $message = "Algorithm $algorithm not found";
        parent::__construct($message);
    }

    /**
     * @return mixed
     */
    public function getAlgorithm(): mixed
    {
        return $this->algorithm;
    }
}