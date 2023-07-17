<?php
namespace AlirezaMoh\JwtShield;

use AlirezaMoh\JwtShield\Exceptions\MissingKeyException;
use AlirezaMoh\JwtShield\Services\Verifiers\ECDSAVerifier;
use AlirezaMoh\JwtShield\Services\Verifiers\HMACVerifier;
use AlirezaMoh\JwtShield\Services\Verifiers\RSAVerifier;
use AlirezaMoh\JwtShield\Supports\JWTAlgorithm;

/**
 * Represents a JWT (JSON Web Token) verifier.
 * It provides an interface for validating a JWT token.
 */
class Verifier
{
    /**
     * @var Token The JWT token to verify.
     */
    private Token $token;

    /**
     * @var string The provided JWT token.
     */
    private string $providedToken;

    /**
     * Verifier constructor.
     *
     * @param string $providedToken The provided JWT token to verify.
     */
    public function __construct(string $providedToken)
    {
        $this->providedToken = $providedToken;
        $this->token = new Token($providedToken);
    }


    /**
     * Validates the JWT token by verifying its signature and other claims.
     *
     * @return bool Returns true if the token is valid, false otherwise.
     *
     * @throws MissingKeyException if a required key is missing.
     */
    public function validateToken(): bool
    {
        return match ($this->token->getAlgorithm()) {
            JWTAlgorithm::HS256,  JWTAlgorithm::HS384, JWTAlgorithm::HS512 => (new HMACVerifier($this->providedToken))->isTokenValid(),
            JWTAlgorithm::RS256, JWTAlgorithm::RS384, JWTAlgorithm::RS512 => (new RSAVerifier($this->providedToken))->isTokenValid(),
            JWTAlgorithm::ES256, JWTAlgorithm::ES384, JWTAlgorithm::ES512 => (new ECDSAVerifier($this->providedToken))->isTokenValid(),
        };
    }
}