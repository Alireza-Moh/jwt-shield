<?php

namespace AlirezaMoh\JwtShield\Test\Supports\Traits;

use AlirezaMoh\JwtShield\Supports\JWTAlgorithm;
use AlirezaMoh\JwtShield\Supports\Traits\Base64;
use AlirezaMoh\JwtShield\Supports\Traits\ClaimHandler;
use PHPUnit\Framework\TestCase;

class TokenGeneratorTest extends TestCase
{
    use ClaimHandler, Base64;

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
}
