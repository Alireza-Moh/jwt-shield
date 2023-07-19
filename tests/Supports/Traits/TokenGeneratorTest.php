<?php

namespace AlirezaMoh\JwtShield\Tests\Supports\Traits;

use AlirezaMoh\JwtShield\Supports\JWTAlgorithm;
use AlirezaMoh\JwtShield\Supports\Traits\Base64;
use AlirezaMoh\JwtShield\Supports\Traits\TokenGenerator;
use DateTime;
use PHPUnit\Framework\TestCase;

class TokenGeneratorTest extends TestCase
{
    use TokenGenerator, Base64;

    /**
     * @test
     */
    public function should_return_encoded_token()
    {
        $algorithm = JWTAlgorithm::HS512;
        $type = 'JWT';
        $expected = 'eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9';

        $actual = $this->prepareHeader($algorithm, $type);

        $this->assertEquals($expected, $actual);
    }

    /**
     * @test
     */
    public function should_return_encoded_payload()
    {
        $expireTime = new DateTime("2023-07-20 14:41:57");
        $customClaims = ['foo' => 'bar'];
        $issuer = 'JWT shield';
        $expected = "eyJmb28iOiJiYXIiLCJpc3MiOiJKV1Qgc2hpZWxkIiwiZXhwIjoxNjg5ODY0MTE3MDAwfQ";

        $actual = $this->preparePayload($expireTime, $customClaims, $issuer);

        $this->assertEquals($expected, $actual);
    }
}
