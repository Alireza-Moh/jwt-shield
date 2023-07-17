<?php

namespace AlirezaMoh\JwtShield\Services\Signatures;

use AlirezaMoh\JwtShield\Exceptions\MissingKeyException;
use AlirezaMoh\JwtShield\Supports\JWTAlgorithm;

class RSASignature extends BaseSignature
{
    /**
     * @throws MissingKeyException
     */
    public function __construct(JWTAlgorithm $algorithm, array $customClaims, ?int $expireTime = null)
    {
        parent::__construct($algorithm, $customClaims, $expireTime);
        $this->privateKey = $this->getPrivateKey();
    }

    public function generate(): string
    {
        $header = $this->prepareHeader($this->algorithm);
        $payload = $this->preparePayload($this->customClaims, $this->expireTime);

        $signature = $this->signRsa($header . '.' . $payload);

        return $header . '.' . $payload . '.' . $signature;
    }

    private function signRsa(string $data): string
    {
        $privateKey = openssl_pkey_get_private($this->privateKey);
        openssl_sign($data, $signature, $privateKey, $this->algorithm->getHashAlgorithm());
        unset($privateKey);

        return $this->encodeBase64($signature);
    }
}