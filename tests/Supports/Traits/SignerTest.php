<?php

namespace AlirezaMoh\JwtShield\Test\Supports\Traits;

use AlirezaMoh\JwtShield\Supports\JWTAlgorithm;
use AlirezaMoh\JwtShield\Supports\Traits\Base64;
use AlirezaMoh\JwtShield\Supports\Traits\Signer;
use InvalidArgumentException;
use PHPUnit\Framework\TestCase;

class SignerTest extends TestCase
{
    use Signer, Base64;

    /**
     * @test
     */
    public function should_sign_data_with_HS256()
    {
        $algorithm = JWTAlgorithm::HS512;
        $data = 'This is the data to be signed.';
        $secretKey = 'secret';
        $expected = 'JOmS1GO8bkEICP5DF7f2Zu8ELa8pB93y0K2HG64v73jdHvMg4dJcgiU5NdujSg1XKLhOdGdjS6PIst2W_vpBOg';

        $actual = $this->encodeBase64($this->sign($algorithm, $data, $secretKey));

        $this->assertEquals($expected, $actual);
    }

    /**
     * @test
     */
    public function should_throw_exception_when_secret_key_is_empty_with_HS256()
    {
        $algorithm = JWTAlgorithm::HS256;
        $data = 'This is the data to be signed.';
        $secretKey = '';

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The secret key can not be empty');

        $this->sign($algorithm, $data, $secretKey);
    }
}
