<?php

namespace AlirezaMoh\JwtShield\Test\Services\Signatures;

use AlirezaMoh\JwtShield\Services\Signatures\ECDSASignature;
use AlirezaMoh\JwtShield\Supports\Claims\Claim;
use AlirezaMoh\JwtShield\Supports\Claims\ClaimRegistry;
use AlirezaMoh\JwtShield\Supports\JWTAlgorithm;
use PHPUnit\Framework\TestCase;

class ECDSASignatureTest extends TestCase
{
    /**
     * @test
     */
    public function should_not_be_empty_token(): void
    {
        $signature = new ECDSASignature(JWTAlgorithm::HS512);

        $signature->addClaims([
            new Claim("username",  "test"),
            new Claim(ClaimRegistry::EXP,  new \DateTime("+1 day")),
            new Claim("userId",  545432),
        ]);
        $token = $signature->generate(file_get_contents(__DIR__."/private_key.pem"));

        $this->assertNotEmpty($token);
        $this->assertIsString($token);
    }
}
