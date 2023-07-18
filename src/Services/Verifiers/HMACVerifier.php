<?php

namespace AlirezaMoh\JwtShield\Services\Verifiers;

/**
 * Class HMACVerifier
 *
 * This class represents an HMAC-based verifier for a JWT (JSON Web Token).
 */
class HMACVerifier extends BaseVerifier
{
    /**
     * HMACVerifier constructor.
     *
     * @param string $providedToken The JWT token to verify.
     */
    public function __construct(string $providedToken)
    {
        parent::__construct($providedToken);
    }

    /**
     * Verify the JWT token using HMAC signature.
     *
     * @return bool True if the token is verified successfully, false otherwise.
     */
    public function isTokenValid(): bool
    {
        $expectedSignature = $this->getExpectedSignature();

        return $this->verify($expectedSignature);
    }

    /**
     * Get the expected signature for the payload based on the algorithm and secret key.
     *
     * @return string The expected signature for the payload.
     */
    public function getExpectedSignature(): string
    {
        $header = $this->prepareHeader($this->token->getAlgorithm());
        $payload = $this->preparePayload($this->token->getPayload());

        return $this->encodeBase64($this->sign($this->token->getAlgorithm(), $header . '.' . $payload));
    }
}