<?php

namespace AlirezaMoh\JwtShield\Supports\Traits;

use AlirezaMoh\JwtShield\Supports\JWTAlgorithm;

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
            "typ" => "JWT"
        ];

        return $this->encodeBase64(json_encode($header));
    }

    /**
     * Prepare the JWT payload and merge the custom claims.
     *
     * @param array $customClaims An array of custom claims to include in the payload.
     * @param int|null $expireTime The expiration time in Unix timestamp format. Null for no expiration.
     * @param string $issuer The issuer of the token. Default is "JWT shield".
     * @return string The encoded payload.
     */
    public function preparePayload(array $customClaims = [], int|null $expireTime = null, string $issuer = "JWT shield"): string
    {
        $payload = array_merge($customClaims, [
            "iss" => $issuer,
        ]);

        if ($expireTime !== null) {
            $payload["exp"] = $expireTime;
        }

        return $this->encodeBase64(json_encode($payload));
    }
}