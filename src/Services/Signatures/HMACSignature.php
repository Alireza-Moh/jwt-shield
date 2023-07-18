<?php

namespace AlirezaMoh\JwtShield\Services\Signatures;


use AlirezaMoh\JwtShield\Supports\JWTAlgorithm;
use DateTime;

/**
 * Class HMACSignature
 *
 * This class represents an HMAC-based signature for a JWT (JSON Web Token).
 */
class HMACSignature extends BaseSignature
{
    public function __construct(JWTAlgorithm $algorithm)
    {
        parent::__construct($algorithm);
    }

    /**
     * Generate the JWT with the HMAC signature.
     * @param DateTime $expiration The expiration date of the JWT.
     * @param array $customClaims The custom claims of the JWT.
     * @param string $secretKey The secret key of the JWT.
     * @return string The generated JWT with the HMAC signature.
     */
    public function generate(DateTime $expiration, array $customClaims, string $secretKey): string
    {
        $this->customClaims = $customClaims;

        $header = $this->prepareHeader($this->algorithm);
        $payload = $this->preparePayload($expiration, $customClaims);

        $encodedSignature = $this->encodeBase64($this->sign($this->algorithm, $header . '.' . $payload, $secretKey));
        return $header . '.' . $payload . '.' . $encodedSignature;
    }
}