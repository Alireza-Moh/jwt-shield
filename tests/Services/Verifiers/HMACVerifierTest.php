<?php

namespace AlirezaMoh\JwtShield\Test\Services\Verifiers;

use AlirezaMoh\JwtShield\Services\Verifiers\HMACVerifier;
use AlirezaMoh\JwtShield\Token;
use PHPUnit\Framework\TestCase;

class HMACVerifierTest extends TestCase
{
    private Token $token;

    protected function setUp(): void
    {
        $this->token = new Token('eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOiI1NDY4NDM1MSIsInVzZXJuYW1lIjoiVGVzdCB1c2VyIiwiaXNzIjoiSldUIHNoaWVsZCIsImV4cCI6MTY4OTg3ODAzNDAwMH0.DVu9cB6iVEymBnUTBP68hd-JI4TiDem8yBhQPzCfsVQrjYCyu5xnTqZk60L9MeSp0_hAdLD1Ei7B25idPylc0Q');

    }

    /**
     * @test
     */
    public function should_return_true_when_token_is_valid_with_correct_secret_key_and_hashed_signature_with_HS512()
    {
        $verifier = new HMACVerifier($this->token);
        $secretKey = 'secret';

        $result = $verifier->isTokenValid($secretKey);

        $this->assertTrue($result);
    }

    /**
     * @test
     */
    public function should_return_true_when_token_is_valid_with_wrong_secret_key_and_hashed_signature_with_HS512()
    {
        $verifier = new HMACVerifier($this->token);
        $secretKey = 'secrets';

        $result = $verifier->isTokenValid($secretKey);

        $this->assertFalse($result);
    }

    /**
     * @test
     */
    public function should_return_false_when_signature_is_manipulated_and_hashed_signature_with_HS512()
    {
        $manipulatedToken = "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOiI1NDY4NDM1MSIsInVzZXJuYW1lIjoiVGVzdCB1c2VyIiwiaXNzIjoiSldUIHNoaWVsZCIsImV4cCI6MTY4OTg3ODAzNDAwMH0.DVu9cB6iVEymBnUTBP68hd-JI4TiDem8yBhQPzCfsVQrjYCyu5xnTqZk60L9MeSp0_hAdLD1Ei7B25idPylc0Qmanipulated";
        $verifier = new HMACVerifier(new Token($manipulatedToken));
        $secretKey = 'secret';

        $result = $verifier->isTokenValid($secretKey);

        $this->assertFalse($result);
    }
}
