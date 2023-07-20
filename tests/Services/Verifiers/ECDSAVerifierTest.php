<?php

namespace AlirezaMoh\JwtShield\Test\Services\Verifiers;

use AlirezaMoh\JwtShield\Exceptions\RSAException;
use AlirezaMoh\JwtShield\Services\Verifiers\ECDSAVerifier;
use AlirezaMoh\JwtShield\Token;
use PHPUnit\Framework\TestCase;

class ECDSAVerifierTest extends TestCase
{
    private Token $token;
    private string $publicKey;

    protected function setUp(): void
    {
        $this->token = new Token('eyJhbGciOiJFUzUxMiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOiI1NDY4NDM1MSIsInVzZXJuYW1lIjoiVGVzdCB1c2VyIiwiaXNzIjoiSldUIHNoaWVsZCIsImV4cCI6MTY4OTg5MDY2NTAwMH0.NaWVvMEbFzSr97bzcRA7oxnHUK_aPB40jWGWtNVLOoJSf-5mTiHhtz_jDXeivD7tbrMiViDK3jCnYVLeiAtrSqfqTimKVte52auWeWY_mudz8d2ykaaHObTtk76M7beT6u3tTbfM0GzgY1MeXjw8g80Sw72UbnVJIUanZZrq0KfdJbc9zVGAcsijtsfTTsudndwmY61VHBalaRiStJJCjLS24uw2dzW_sRXDt_B9g74kCr2Xa5bTutfxpMa0H7uN040xJwHMbWmo3eaqz9lQy5AtxCWHr7N2iSQjouTM89GZf9atPsa2Nmh9WUqC1K4AQqENNNnYiLUWiBtkeuyZ9w');
        $this->publicKey = file_get_contents(__DIR__."/public_key.pem");
    }


    /**
     * @test
     * @throws RSAException
     */
    public function should_return_true_when_token_is_valid_with_correct_public_key_and_hashed_signature_with_ES512(): void
    {
        $verifier = new ECDSAVerifier($this->token);

        $result = $verifier->isTokenValid($this->publicKey);

        $this->assertTrue($result);
    }


    /**
     * @test
     * @throws RSAException
     */
    public function should_return_true_when_token_is_valid_with_wrong_public_key_and_hashed_signature_with_ES512(): void
    {
        $verifier = new ECDSAVerifier($this->token);

        $result = $verifier->isTokenValid(file_get_contents(__DIR__."/public_key_wrong.pem"));

        $this->assertFalse($result);
    }
}
