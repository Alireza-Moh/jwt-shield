<?php
namespace AlirezaMoh\JwtShield;

use AlirezaMoh\JwtShield\Services\Signatures\ECDSASignature;
use AlirezaMoh\JwtShield\Services\Signatures\HMACSignature;
use AlirezaMoh\JwtShield\Services\Signatures\RSASignature;
use AlirezaMoh\JwtShield\Supports\JWTAlgorithm;

/**
 * Represents a JSON Web Token (JWT) generator.
 * It provides an interface for generating JWT tokens.
 */
final class JWT
{
    /**
     * Based on the specified algorithm, it will return the signature builder for generating the token.
     *
     * @param JWTAlgorithm $algorithm The algorithm used for signing the JWT token.
     *
     * @return ECDSASignature|HMACSignature|RSASignature The signature builder for generating the token.
     */
    public static function getSignatureBuilder(JWTAlgorithm $algorithm): ECDSASignature|HMACSignature|RSASignature
    {
        return match ($algorithm) {
            JWTAlgorithm::HS256,  JWTAlgorithm::HS384, JWTAlgorithm::HS512 => (new HMACSignature($algorithm)),
            JWTAlgorithm::RS256, JWTAlgorithm::RS384, JWTAlgorithm::RS512 => (new RSASignature($algorithm)),
            JWTAlgorithm::ES256, JWTAlgorithm::ES384, JWTAlgorithm::ES512 => (new ECDSASignature($algorithm)),
        };
    }
}