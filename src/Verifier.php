<?php
namespace AlirezaMoh\JwtShield;

use AlirezaMoh\JwtShield\Exceptions\AlgorithmNotFoundException;
use AlirezaMoh\JwtShield\Exceptions\MissingKeyException;
use AlirezaMoh\JwtShield\Services\Verifiers\ECDSAVerifier;
use AlirezaMoh\JwtShield\Services\Verifiers\HMACVerifier;
use AlirezaMoh\JwtShield\Services\Verifiers\RSAVerifier;
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
     * @throws MissingKeyException
     */
    public function validateToken(): bool
    {
        return match ($this->token->getAlgorithm()) {
            JWTAlgorithm::HS256,  JWTAlgorithm::HS384, JWTAlgorithm::HS512 => (new HMACVerifier($this->providedToken))->isTokenValid(),
            JWTAlgorithm::RS256, JWTAlgorithm::RS384, JWTAlgorithm::RS512 => (new RSAVerifier($this->providedToken))->isTokenValid(),
            JWTAlgorithm::ES256, JWTAlgorithm::ES384, JWTAlgorithm::ES512 => (new ECDSAVerifier($this->providedToken))->isTokenValid(),
            default => throw new AlgorithmNotFoundException($this->token->getAlgorithm())
        };
    }
}