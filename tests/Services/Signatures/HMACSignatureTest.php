<?php

namespace AlirezaMoh\JwtShield\Tests\Services\Signatures;

use AlirezaMoh\JwtShield\Services\Signatures\HMACSignature;
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

        $token = $signature->generate($claims, "secret", $expiration);

        $this->assertNotEmpty($token);
        $this->assertIsString($token);
    }
}
