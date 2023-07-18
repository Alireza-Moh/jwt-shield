<?php

namespace AlirezaMoh\JwtShield;

use AlirezaMoh\JwtShield\Exceptions\MissingKeyException;
use AlirezaMoh\JwtShield\Supports\JWTAlgorithm;
use PHPUnit\Framework\TestCase;

class JWTTest extends TestCase
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
     * @throws MissingKeyException
     */
    public function should_return_expected_token(): void
    {
        $expectedToken = "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOjEwNTQ0LCJ1c2VybmFtZSI6InRlc3QiLCJpc3MiOiJKV1Qgc2hpZWxkIn0.OG-u1V65krYe-UwF-GnEBX7iSY7VuDLtPsDJ5hyReVt5xiXsdj1US0OY7VECXPrRkud33_qbgG4eOpnh--lzJA";
        $jwt = new JWT($this->customClaims, $this->algorithm);

        $token = $jwt->getToken();

        self::assertEquals($expectedToken, $token);
    }
}
