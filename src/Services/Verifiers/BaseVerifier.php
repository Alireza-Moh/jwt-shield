<?php

namespace AlirezaMoh\JwtShield\Services\Verifiers;

use AlirezaMoh\JwtShield\Supports\Traits\Base64;
use AlirezaMoh\JwtShield\Supports\Traits\Key;
use AlirezaMoh\JwtShield\Supports\Traits\Signer;
use AlirezaMoh\JwtShield\Supports\Traits\TokenGenerator;
use AlirezaMoh\JwtShield\Token;
use DateTime;

abstract class BaseVerifier
{
    use Base64, TokenGenerator, Signer, Key;

    /**
     * The public key used for verifying tokens.
     *
     * @var string
     */
    protected string $publicKey;

    protected Token $token;

    /**
     * The verifier constructor.
     *
     * @param string $providedToken The JWT token to verify.
     */
    public function __construct(string $providedToken)
    {
        $this->token = new Token($providedToken);
    }

    /**
     * Verifies the authenticity of a JWT token.
     *
     * @return bool true or false
     */
    abstract public function isTokenValid(): bool;

    /**
     * Verifies if the provided signature matches the expected signature and the token is not expired.
     *
     * @param string $expectedSignature The expected signature to verify against.
     *
     * @return bool Returns true if the signature is valid and the token is not expired, false otherwise.
     */
    public function verify(string $expectedSignature): bool
    {
        return !$this->token->isExpired() && $this->token->isValid($expectedSignature);
    }

    /**
     * Checks if the token is expired.
     *
     * @return bool Returns true if the token is expired, false otherwise.
     */
    public function isTokenExpired(): bool
    {
        return $this->token->isExpired();
    }

    /**
     * Formats the expiration time of the token to a readable string representation.
     *
     * @return string The formatted expiration time in "Y-m-d H:i:s" format.
     */
    private function formatExpiration(): string
    {
        return DateTime::createFromFormat('U', $this->token->getExpirationTime())->format("Y-m-d H:i:s");
    }
}