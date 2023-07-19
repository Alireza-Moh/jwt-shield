<?php

namespace AlirezaMoh\JwtShield\Services\Verifiers;

use AlirezaMoh\JwtShield\Exceptions\RSAException;
use AlirezaMoh\JwtShield\Supports\Traits\Base64;
use AlirezaMoh\JwtShield\Supports\Traits\Signer;
use AlirezaMoh\JwtShield\Supports\Traits\TokenGenerator;
use AlirezaMoh\JwtShield\Token;
use OpenSSLAsymmetricKey;

/**
 * Class BaseVerifier
 *
 * Represents a base verifier for JWT (JSON Web Token) validation.
 */
class BaseVerifier
{
    use Base64, TokenGenerator, Signer;

    /**
     * @var Token The JWT token.
     */
    protected Token $token;

    /**
     * BaseVerifier constructor.
     *
     * @param Token $token The JWT token.
     */
    public function __construct(Token $token)
    {
        $this->token = $token;
    }

    /**
     * Get the public key resource from the provided public key string.
     *
     * @param string $publicKey The public key string.
     * @return OpenSSLAsymmetricKey The public key resource.
     * @throws RSAException If an error occurs while getting the public key.
     */
    protected function getPublicKey(string $publicKey): OpenSSLAsymmetricKey
    {
        $publicKeyResource = openssl_pkey_get_public($publicKey);

        if ($publicKeyResource === false) {
            throw new RSAException("An error occurred while getting the public key:  ". openssl_error_string());
        }
        return $publicKeyResource;
    }

    /**
     * Verify the provided token with the given public key.
     *
     * @param string $publicKey The public key string.
     * @param Token $providedToken The token to verify.
     * @return bool Returns true if the token is valid, false otherwise.
     * @throws RSAException If an error occurs during token verification.
     */
    protected function verifyWithPublicKey(string $publicKey, Token $providedToken): bool
    {
        $publicKeyResource = $this->getPublicKey($publicKey);
        $data = $providedToken->getOriginalHeader() . "." . $providedToken->getOriginalPayload();

        $isTokenValid = openssl_verify($data, $providedToken->getSignature(), $publicKeyResource, $providedToken->getAlgorithm()->getHashAlgorithm());

        return $isTokenValid === 1;
    }
}