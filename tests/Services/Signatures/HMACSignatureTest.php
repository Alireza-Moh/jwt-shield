<?php

namespace AlirezaMoh\JwtShield\Services\Signatures;

use AlirezaMoh\JwtShield\Supports\JWTAlgorithm;
use PHPUnit\Framework\TestCase;

class HMACSignatureTest extends TestCase
{
    private array $customClaims;
    private JWTAlgorithm $algorithm;
    protected function setUp(): void
    {
        $this->customClaims = ["userId" => 10544, "username" => "test"];
        $this->algorithm = JWTAlgorithm::HS512;
        $_ENV['SECRET_KEY'] = 'secret';
    }

    /**
     * @test
     */
    public function should_set_correct_values(): void {
        $signature = new HMACSignature($this->algorithm, $this->customClaims);

        $this->assertEquals($this->algorithm, $signature->getAlgorithm());
        $this->assertEquals($this->customClaims, $signature->getCustomClaims());
        $this->assertEquals(null, $signature->getExpiration());
    }

    /**
     * @test
     */
    public function should_generate_correct_token(): void
    {
        $signature = new HMACSignature($this->algorithm, $this->customClaims);

        $token = $signature->generate();

        $this->assertNotEmpty($token);
    }
}
