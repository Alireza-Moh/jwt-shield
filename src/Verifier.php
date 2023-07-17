<?php
namespace AlirezaMoh\JwtShield;

use AlirezaMoh\JwtShield\Exceptions\AlgorithmNotFoundException;
use AlirezaMoh\JwtShield\Services\Verifiers\HMACVerifier;
use AlirezaMoh\JwtShield\Supports\JWTAlgorithm;

class Verifier
{
    private Token $token;
    private string $providedToken;

    public function __construct(string $providedToken)
    {
        $this->providedToken = $providedToken;
        $this->token = new Token($providedToken);
    }

    /**
     * @throws AlgorithmNotFoundException
     */
    public function validateToken(): bool
    {
        return match ($this->token->getAlgorithm()) {
            JWTAlgorithm::HS256,  JWTAlgorithm::HS384, JWTAlgorithm::HS512 => (new HMACVerifier($this->providedToken))->isTokenValid(),
            default => throw new AlgorithmNotFoundException($this->token->getAlgorithm())
        };
    }
}