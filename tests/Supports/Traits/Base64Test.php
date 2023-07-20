<?php

namespace AlirezaMoh\JwtShield\Test\Supports\Traits;

use AlirezaMoh\JwtShield\Supports\Traits\Base64;
use PHPUnit\Framework\TestCase;

class Base64Test extends TestCase
{
    use Base64;

    private array $encodeData;
    private string $decodedData;

    protected function setUp(): void
    {
        $this->encodeData = [
            "userId" => 54544542,
            "username" => "test",
        ];

        $this->decodedData = "eyJ1c2VySWQiOjU0NTQ0NTQyLCJ1c2VybmFtZSI6InRlc3QifQ";
    }

    /**
     * @test
     */
    public function should_encode_base64_string()
    {
        $actual = $this->encodeBase64(json_encode($this->encodeData));

        $this->assertEquals($this->decodedData, $actual);
    }

    /**
     * @test
     */
    public function should_decode_base64_string()
    {
        $actual = json_decode($this->decodeBase64($this->decodedData), true);

        $this->assertEquals($this->encodeData, $actual);
    }
}
