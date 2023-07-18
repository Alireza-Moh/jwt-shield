<?php

namespace AlirezaMoh\JwtShield\Services\Verifiers;

use AlirezaMoh\JwtShield\Supports\Traits\Base64;
use AlirezaMoh\JwtShield\Supports\Traits\Signer;
use AlirezaMoh\JwtShield\Supports\Traits\TokenGenerator;
use AlirezaMoh\JwtShield\Token;

abstract class BaseVerifier
{
    use Base64, TokenGenerator, Signer;

    protected Token $token;

    public function __construct(Token $token)
    {
        $this->token = $token;
    }

    /**
     * Verifies if the provided signature matches the expected signature and the token is not expired.
     *
     * @param string $expectedSignature The expected signature to verify against.
     *
     * @return bool Returns true if the signature is valid and the token is not expired, false otherwise.
     */
    protected function verify(string $expectedSignature): bool
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
}