<?php

namespace AlirezaMoh\JwtShield\Tests\Services\Signatures;

use AlirezaMoh\JwtShield\Exceptions\RSAException;
use AlirezaMoh\JwtShield\Services\Signatures\RSASignature;
use AlirezaMoh\JwtShield\Supports\JWTAlgorithm;
use PHPUnit\Framework\TestCase;

class RSASignatureTest extends TestCase
{
    /**
     * @test
     * @throws RSAException
     */
    public function should_not_be_empty_token(): void
    {
        $signature = new RSASignature(JWTAlgorithm::HS512);
        $expiration = new \DateTime("+1 day");
        $claims = ["userId" => 545432, "username" => "test"];
        $token = $signature->generate($expiration, $claims, file_get_contents(__DIR__."/private_key.pem"));

        $this->assertNotEmpty($token);
        $this->assertIsString($token);
    }
}
