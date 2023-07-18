<?php

namespace AlirezaMoh\JwtShield\Supports\Traits;

use AlirezaMoh\JwtShield\Supports\JWTAlgorithm;
use DateTime;

/**
 * Trait TokenGenerator
 *
 * This trait provides methods for preparing the header and payload sections of a JWT (JSON Web Token).
 */
trait TokenGenerator
{
    /**
     * Prepare the JWT header.
     *
     * @param JWTAlgorithm $algorithm The JWT algorithm object.
     * @param string $type The token type. Default is "JWT".
     * @return string The encoded header.
     */
    public function prepareHeader(JWTAlgorithm $algorithm, string $type = "JWT"): string
    {
        $header = [
            "alg" => $algorithm->getAlgorithm(),
            "typ" => $type
        ];

        return $this->encodeBase64(json_encode($header));
    }

    /**
     * Prepare the JWT payload and merge the custom claims.
     *
     * @param array $customClaims An array of custom claims to include in the payload.
     * @param DateTime $expireTime The expiration time in Unix timestamp format. Null for no expiration.
     * @param string $issuer The issuer of the token. Default is "JWT shield".
     * @return string The encoded payload.
     */
    public function preparePayload(DateTime $expireTime, array $customClaims = [], string $issuer = "JWT shield"): string
    {
        $payload = array_merge($customClaims, [
            "iss" => $issuer,
            "exp" => $expireTime->getTimestamp() * 1000
        ]);

        return $this->encodeBase64(json_encode($payload));
    }
}