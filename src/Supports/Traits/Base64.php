<?php

namespace AlirezaMoh\JwtShield\Supports\Traits;

/**
 * Trait Base64
 *
 * This trait provides base64 encoding and decoding methods with URL-safe modifications.
 */
trait Base64
{
    /**
     * Encodes data using base64 and makes it URL-safe.
     *
     * @param string $data The data to encode.
     * @return string The URL-safe base64 encoded string.
     */
    public function encodeBase64(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    /**
     * Decodes a URL-safe base64 encoded string.
     *
     * @param string $data The URL-safe base64 encoded string to decode.
     * @return string The decoded data.
     */
    public function decodeBase64(string $data): string
    {
        $paddedData = str_pad($data, strlen($data) % 4, '=', STR_PAD_RIGHT);
        return base64_decode(strtr($paddedData, '-_', '+/'));
    }
}