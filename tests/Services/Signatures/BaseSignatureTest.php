<?php

namespace AlirezaMoh\JwtShield\Test\Services\Signatures;

use AlirezaMoh\JwtShield\Services\Signatures\BaseSignature;
use AlirezaMoh\JwtShield\Supports\JWTAlgorithm;
use PHPUnit\Framework\TestCase;

class BaseSignatureTest extends TestCase
{
    /**
     * @dataProvider algorithmDataProvider
     * @test
     */
    public function should_set_the_correct_algorithm(JWTAlgorithm $algorithm): void
    {
        $signature = new BaseSignature($algorithm);
        $this->assertEquals($algorithm, $signature->getAlgorithm());
    }

    /**
     * Data provider for testing the algorithm constructor.
     *
     * @return array
     */
    public function algorithmDataProvider(): array
    {
        return [
            [JWTAlgorithm::HS256],
            [JWTAlgorithm::HS384],
            [JWTAlgorithm::HS512],
            [JWTAlgorithm::RS256],
            [JWTAlgorithm::RS384],
            [JWTAlgorithm::RS512],
            [JWTAlgorithm::ES256],
            [JWTAlgorithm::ES384],
            [JWTAlgorithm::ES512],
        ];
    }
}
