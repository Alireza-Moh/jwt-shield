<?php

namespace AlirezaMoh\JwtShield\Services\Verifiers;

use AlirezaMoh\JwtShield\Exceptions\TokenException;
use AlirezaMoh\JwtShield\Token;

/**
 * Class HMACVerifier
 *
 * This class represents an HMAC-based verifier for a JWT (JSON Web Token).
 */
class HMACVerifier extends BaseVerifier
{
    public function __construct(Token $token)
    {
        parent::__construct($token);
    }

    /**
     * Verify the JWT token using HMAC signature.
     * @param string $secretKey The secret key used to sign the token.
     * @return bool True if the token is verified successfully, false otherwise.
     * @throws TokenException
     */
    public function isTokenValid(string $secretKey): bool
    {
        $expectedSignature = $this->getExpectedSignature($secretKey);

        return !$this->token->isExpired() && hash_equals($expectedSignature, $this->token->getSignature());
    }

    /**
     * Get the expected signature for the payload based on the algorithm and secret key.
     *
     * @return string The expected signature for the payload.
     */
    public function getExpectedSignature(string $secretKey): string
    {

        $data = $this->token->getOriginalHeader() . '.' . $this->token->getOriginalPayload();
        return $this->sign($this->token->getAlgorithm(), $data, $secretKey);
    }
}