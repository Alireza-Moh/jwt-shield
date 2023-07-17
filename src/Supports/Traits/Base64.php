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
        $base64 = base64_encode($data);
        return $this->getUrlSafe($base64);
    }

    /**
     * Decodes a URL-safe base64 encoded string.
     *
     * @param string $data The URL-safe base64 encoded string to decode.
     * @return array The decoded data.
     */
    public function decodeBase64(string $data): array
    {
        return json_decode(base64_decode($data), true);
    }

    /**
     * Replaces characters to make base64 URL-safe.
     *
     * @param string $base64 The base64 string to modify.
     * @return string The URL-safe base64 string.
     */
    private function getUrlSafe(string $base64): string
    {
        return str_replace(['+', '/', '='], ['-', '_', ''], $base64);
    }
}