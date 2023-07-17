<?php

namespace AlirezaMoh\JwtShield\Supports;

/**
 * Enumeration of supported JWT algorithms.
 */
enum JWTAlgorithm: string
{
    case HS256 = 'HS256';
    case HS384 = 'HS384';
    case HS512 = 'HS512';
    case RS256 = 'RS256';
    case RS384 = 'RS384';
    case RS512 = 'RS512';
    case ES256 = 'ES256';
    case ES384 = 'ES384';
    case ES512 = 'ES512';

    /**
     * Checks if the algorithm is HMAC.
     *
     * @return bool True if the algorithm is HMAC, false otherwise.
     */
    public function isHMAC(): bool
    {
        return $this === JWTAlgorithm::HS256 || $this === JWTAlgorithm::HS384 || $this === JWTAlgorithm::HS512;
    }

    /**
     * Checks if the algorithm is RSA.
     *
     * @return bool True if the algorithm is RSA, false otherwise.
     */
    public function isRSA(): bool
    {
        return $this === JWTAlgorithm::RS256 || $this === JWTAlgorithm::RS384 || $this === JWTAlgorithm::RS512;
    }

    /**
     * Checks if the algorithm is ECDSA.
     *
     * @return bool True if the algorithm is ECDSA, false otherwise.
     */
    public function isECDSA(): bool
    {
        return $this === JWTAlgorithm::ES256 || $this === JWTAlgorithm::ES384 || $this === JWTAlgorithm::ES512;
    }

    /**
     * Retrieves the algorithm value as a string.
     *
     * @return string The algorithm value.
     */
    public function getAlgorithm(): string
    {
        return $this->value;
    }

    /**
     * Get the hash algorithm based on the JWT algorithm.
     *
     * @return int|string The hash algorithm.
     */
    public function getHashAlgorithm(): int|string
    {
        return match ($this) {
            self::HS256 => 'sha256',
            self::HS384 => 'sha384',
            self::HS512 => 'sha512',

            self::RS256, self::ES256 => OPENSSL_ALGO_SHA256,
            self::RS384, self::ES384 => OPENSSL_ALGO_SHA384,
            self::RS512, self::ES512 => OPENSSL_ALGO_SHA512,
        };
    }
}
