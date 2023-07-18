<?php

namespace AlirezaMoh\JwtShield\Services\Verifiers;

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
     */
    public function isTokenValid(string $secretKey): bool
    {
        $expectedSignature = $this->getExpectedSignature($secretKey);

        return $this->verify($expectedSignature);
    }

    /**
     * Get the expected signature for the payload based on the algorithm and secret key.
     *
     * @return string The expected signature for the payload.
     */
    public function getExpectedSignature(string $secretKey): string
    {
        $header = $this->prepareHeader($this->token->getAlgorithm());
        $payload = $this->preparePayload($this->token->getExpirationTime(), $this->token->getPayload());

        return $this->encodeBase64($this->sign($this->token->getAlgorithm(), $header . '.' . $payload,  $secretKey));
    }
}