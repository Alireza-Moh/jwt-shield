<?php

namespace AlirezaMoh\JwtShield\Services\Signatures;

use AlirezaMoh\JwtShield\Supports\JWTAlgorithm;
use PHPUnit\Framework\TestCase;

class HMACSignatureTest extends TestCase
{
    /**
     * @test
     */
    public function should_not_be_empty_token(): void
    {
        $signature = new HMACSignature(JWTAlgorithm::HS512);
        $expiration = new \DateTime("+1 day");
        $claims = ["userId" => 545432, "username" => "test"];

        $token = $signature->generate($expiration, $claims, "secret");

        $this->assertNotEmpty($token);
        $this->assertIsString($token);
    }
}
