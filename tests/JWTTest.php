<?php

namespace AlirezaMoh\JwtShield\Test;


use AlirezaMoh\JwtShield\JWT;
use AlirezaMoh\JwtShield\Services\Signatures\ECDSASignature;
use AlirezaMoh\JwtShield\Services\Signatures\HMACSignature;
use AlirezaMoh\JwtShield\Services\Signatures\RSASignature;
use AlirezaMoh\JwtShield\Supports\JWTAlgorithm;
use PHPUnit\Framework\TestCase;

class JWTTest extends TestCase
{
    /**
     * @dataProvider algorithmDataProvider
     * * @test
     */
    public function should_return_correct_signature_builder($algorithm, $expectedSignatureBuilderClass)
    {
        $signatureBuilder = JWT::getSignatureBuilder($algorithm);

        $this->assertInstanceOf($expectedSignatureBuilderClass, $signatureBuilder);
    }

    public function algorithmDataProvider(): array
    {
        return [
            [JWTAlgorithm::HS256, HMACSignature::class],
            [JWTAlgorithm::HS384, HMACSignature::class],
            [JWTAlgorithm::HS512, HMACSignature::class],
            [JWTAlgorithm::RS256, RSASignature::class],
            [JWTAlgorithm::RS384, RSASignature::class],
            [JWTAlgorithm::RS512, RSASignature::class],
            [JWTAlgorithm::ES256, ECDSASignature::class],
            [JWTAlgorithm::ES384, ECDSASignature::class],
            [JWTAlgorithm::ES512, ECDSASignature::class],
        ];
    }
}
