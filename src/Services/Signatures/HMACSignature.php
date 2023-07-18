<?php

namespace AlirezaMoh\JwtShield\Services\Signatures;

use AlirezaMoh\JwtShield\Supports\JWTAlgorithm;

/**
 * Class HMACSignature
 *
 * This class represents an HMAC-based signature for a JWT (JSON Web Token).
 */
class HMACSignature extends BaseSignature
{
    /**
     * HMACSignature constructor.
     *
     * @param JWTAlgorithm $algorithm The JWT algorithm object.
     * @param array $customClaims An array of custom claims to include in the payload.
     * @param ?int $expiration The expiration time in Unix timestamp format. Null for no expiration.
     */
    public function __construct(JWTAlgorithm $algorithm, array $customClaims, ?int $expiration = null)
    {
        parent::__construct($algorithm, $customClaims, $expiration);
    }

    /**
     * Generate the JWT with the HMAC signature.
     *
     * @return string The generated JWT with the HMAC signature.
     */
    public function generate(): string
    {
        $header = $this->prepareHeader($this->algorithm);
        $payload = $this->preparePayload($this->customClaims, $this->expiration);

        $encodedSignature = $this->encodeBase64($this->sign($this->algorithm, $header . '.' . $payload));

        return $header . '.' . $payload . '.' . $encodedSignature;
    }
}