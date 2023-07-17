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
     * @param string $token The JWT token to verify.
     */
    public function __construct(string $token)
    {
        $this->token = new Token($token);
    }

    /**
     * Verifies the authenticity of a JWT token.
     *
     * @return bool true or false
     */
    abstract public function isTokenValid(): bool;

    public function verify(string $expectedSignature): bool
    {
        return !$this->token->isExpired() && $this->token->isValid($expectedSignature);
    }

    public function isTokenExpired(): bool
    {
        return $this->token->isExpired();
    }

    private function formatExpiration(): string
    {
        return DateTime::createFromFormat('U', $this->token->getExpirationTime())->format("Y-m-d H:i:s");
    }
}