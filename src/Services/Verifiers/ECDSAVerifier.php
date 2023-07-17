<?php

namespace AlirezaMoh\JwtShield\Services\Verifiers;

use AlirezaMoh\JwtShield\Exceptions\MissingKeyException;

class ECDSAVerifier extends BaseVerifier
{
    /**
     * @throws MissingKeyException
     */
    public function __construct(string $token)
    {
        parent::__construct($token);
        $this->publicKey = $this->getPublicKey();
    }

    public function isTokenValid(): bool
    {
        $expectedSignature = $this->signEcdsa(json_encode($this->token->getHeader()).'.'.json_encode($this->token->getPayload()));

        return $this->verify($expectedSignature);
    }

    private function signEcdsa(string $data): string
    {
        $publicKey = openssl_pkey_get_public($this->publicKey);
        openssl_verify($data, $this->token->getSignature(), $publicKey);
        unset($publicKey);

        return $this->token->getSignature();
    }
}