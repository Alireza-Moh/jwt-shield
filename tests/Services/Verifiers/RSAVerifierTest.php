<?php

namespace AlirezaMoh\JwtShield\Test\Services\Verifiers;

use AlirezaMoh\JwtShield\Exceptions\RSAException;
use AlirezaMoh\JwtShield\Services\Verifiers\RSAVerifier;
use AlirezaMoh\JwtShield\Token;
use PHPUnit\Framework\TestCase;

class RSAVerifierTest extends TestCase
{
    private Token $token;
    private string $publicKey;

    protected function setUp(): void
    {
        $this->token = new Token('eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOiI1NDY4NDM1MSIsInVzZXJuYW1lIjoiVGVzdCB1c2VyIiwiaXNzIjoiSldUIHNoaWVsZCIsImV4cCI6MTY4OTg3ODU3NDAwMH0.JealihKR_r_qHxXWCSPOBjsSCJWQvh7GH24Tn2UG-D9ohwc4QkPMcl8F0E_VYr5AhdqoWF_TOVDT3bQMcDiQNvngL1tsNoc6UMvA5tlIMvrdemqq3XbQrUNOF5rfWvXVGSvh5vc6loHjpq6XAFOKVLMsvGiHSuScW5eOV5IxQoz7xl0xrNhevPaw9-uGWefAERZHBcSAp8f3uB4xxkuzsJuj71xEoqscqLdTfjzXhJJNYocX30yyNuOL_lM09VfyrAgUZr_kKSTW_h8nNSQqPO9aq9O4mQFCg2gvQ5Sa52klrSB_99GLYMlpBS3T_fPgR5Ntws1G2_n8F4lLf6-azg');
        $this->publicKey = file_get_contents(__DIR__."/public_key.pem");
    }


    /**
     * @test
     * @throws RSAException
     */
    public function should_return_true_when_token_is_valid_with_correct_public_key_and_hashed_signature_with_RS512(): void
    {
        $verifier = new RSAVerifier($this->token);

        $result = $verifier->isTokenValid($this->publicKey);

        $this->assertTrue($result);
    }


    /**
     * @test
     * @throws RSAException
     */
    public function should_return_true_when_token_is_valid_with_wrong_public_key_and_hashed_signature_with_RS512(): void
    {
        $verifier = new RSAVerifier($this->token);

        $result = $verifier->isTokenValid(file_get_contents(__DIR__."/public_key_wrong.pem"));

        $this->assertFalse($result);
    }
}
