<?php

namespace AlirezaMoh\JwtShield;

use AlirezaMoh\JwtShield\Supports\JWTAlgorithm;
use AlirezaMoh\JwtShield\Supports\Traits\Base64;
use DateTime;

/**
 * Class Token
 *
 * Represents a JWT token.
 */
final class Token
{
    use Base64;

    /**
     * @var string The JWT token.
     */
    protected string $providedToken;

    /**
     * @var array The decoded header of the JWT token.
     */
    protected array $header;

    /**
     * @var array The decoded payload of the JWT token.
     */
    protected array $payload;

    /**
     * @var string The signature of the JWT token.
     */
    public string $signature;

    /**
     * @var JWTAlgorithm The algorithm used for signing and verifying the JWT token.
     */
    protected JWTAlgorithm $algorithm;

    /**
     * @var string The issuer of the JWT token.
     */
    protected string $issuer;

    protected DateTime $expirationTime;

    protected string $originalHeader;
    protected string $originalPayload;

    /**
     * Token constructor.
     *
     * @param string $providedToken The JWT token.
     */
    public function __construct(string $providedToken) {
        $this->providedToken = $providedToken;

        if ($providedToken !== '') {
            $this->parseToken();
        }
    }

    /**
     * @return string
     */
    public function getToken(): string
    {
        return $this->providedToken;
    }

    /**
     * @return array
     */
    public function getHeader(): array
    {
        return $this->header;
    }

    /**
     * @return array
     */
    public function getPayload(): array
    {
        return $this->payload;
    }

    /**
     * @return string
     */
    public function getSignature(): string
    {
        return $this->signature;
    }

    /**
     * @return JWTAlgorithm
     */
    public function getAlgorithm(): JWTAlgorithm
    {
        return $this->algorithm;
    }

    /**
     * @return string
     */
    public function getIssuer(): string
    {
        return $this->issuer;
    }

    /**
     * @return DateTime
     */
    public function getExpirationTime(): DateTime
    {
        return $this->expirationTime;
    }

    /**
     * @return string
     */
    public function getOriginalHeader(): string
    {
        return $this->originalHeader;
    }

    /**
     * @return string
     */
    public function getOriginalPayload(): string
    {
        return $this->originalPayload;
    }

    /**
     * Checks if the token is valid based on the provided signature.
     * @param string $expectedSignature
     * @return bool true if its valid and false if not
     */
    public function isValid(string $expectedSignature): bool
    {
        if ($this->providedToken === '') {
            return false;
        }
        return hash_equals($expectedSignature, $this->signature);
    }

    /**
     * Checks if the token is expired
     * @return bool
     */
    public function isExpired(): bool
    {
        $currentDateTime = new DateTime();
        return $this->expirationTime < $currentDateTime;
    }

    public function getFormattedExpirationTime(): string
    {
        return $this->expirationTime->format('Y-m-d H:i:s');
    }

    /**
     * Parses the provided token and extracts its components.
     */
    private function parseToken(): void
    {
        [$header, $payload, $signature] = explode('.', $this->providedToken);

        $this->parseHeader($header);
        $this->parsePayload($payload);
        $this->parseSignature($signature);

        $this->originalHeader = $header;
        $this->originalPayload = $payload;

        $this->extractAlgorithm();
        $this->extractIssuer();
        $this->setExpirationTime($this->payload['exp']);
    }

    /**
     * Parses the header component of the token.
     *
     * @param string $header The base64-encoded header string.
     */
    private function parseHeader(string $header): void
    {
        $decodedHeader = $this->decodeBase64($header);
        $this->header = json_decode($decodedHeader, true);
    }

    /**
     * Parses the payload component of the token.
     *
     * @param string $payload The base64-encoded payload string.
     */
    private function parsePayload(string $payload): void
    {
        $decodedPayload = $this->decodeBase64($payload);
        $this->payload = json_decode($decodedPayload, true);
    }

    /**
     * Parses the signature component of the token.
     *
     * @param string $signature The base64-encoded signature string.
     */
    private function parseSignature(string $signature): void
    {
        $this->signature = $this->decodeBase64($signature);
    }

    /**
     * Extracts the algorithm from the parsed header.
     */
    private function extractAlgorithm(): void
    {
        $this->algorithm = JWTAlgorithm::from($this->header['alg']);
    }

    /**
     * Extracts the issuer from the parsed payload.
     */
    private function extractIssuer(): void
    {
        $this->issuer = $this->payload['iss'];
    }

    private function setExpirationTime(int $exp): void
    {
        $date = new DateTime();
        $date->setTimestamp(floor($exp / 1000));
        $this->expirationTime = $date;
    }
}