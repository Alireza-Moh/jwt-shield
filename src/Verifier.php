<?php
namespace AlirezaMoh\JwtShield;

use AlirezaMoh\JwtShield\Services\Verifiers\ECDSAVerifier;
use AlirezaMoh\JwtShield\Services\Verifiers\HMACVerifier;
use AlirezaMoh\JwtShield\Services\Verifiers\RSAVerifier;
use AlirezaMoh\JwtShield\Supports\JWTAlgorithm;
use InvalidArgumentException;

/**
 * Represents a JWT (JSON Web Token) verifier.
 * It provides an interface for validating a JWT token.
 */
final class Verifier
{
    /**
     * Based on the specified algorithm, it will return the signature builder for generating the token.
     *
     * @param string $providedToken The token to be verified.
     *
     * @return HMACVerifier|RSAVerifier|ECDSAVerifier The signature builder for generating the token.
     */
    public static function getVerifierBuilder(string $providedToken): HMACVerifier|RSAVerifier|ECDSAVerifier
    {
        if (empty($providedToken)) {
            throw new InvalidArgumentException('The token cannot be empty');
        }

        $token = new Token($providedToken);

        return match ($token->getAlgorithm()) {
            JWTAlgorithm::HS256,  JWTAlgorithm::HS384, JWTAlgorithm::HS512 => (new HMACVerifier($token)),
            JWTAlgorithm::RS256, JWTAlgorithm::RS384, JWTAlgorithm::RS512 => (new RSAVerifier($token)),
            JWTAlgorithm::ES256, JWTAlgorithm::ES384, JWTAlgorithm::ES512 => (new ECDSAVerifier($token)),
        };
    }
}