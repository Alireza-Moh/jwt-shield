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
    protected string $signature;

    /**
     * @var JWTAlgorithm The algorithm used for signing and verifying the JWT token.
     */
    protected JWTAlgorithm $algorithm;

    /**
     * @var string The issuer of the JWT token.
     */
    protected string $issuer;

    protected DateTime $expirationTime;

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
     * Parses the JWT token and extracts the header, payload, signature, algorithm, and issuer.
     *
     */
    private function parseToken(): void
    {
        [$header, $payload, $this->signature] = explode('.', $this->providedToken);

        // Decode the base64-encoded header and payload
        $this->header = $this->decodeBase64($header);
        $this->payload = $this->decodeBase64($payload);

        // Extract the algorithm, issuer and the expiration time
        $this->algorithm = JWTAlgorithm::from($this->header['alg']);
        $this->issuer = $this->payload['iss'];

        $this->setExpirationTime($this->payload['exp']);
    }

    private function setExpirationTime(int $exp): void
    {
        $date = new DateTime();
        $date->setTimestamp(floor($exp / 1000));
        $this->expirationTime = $date;
    }
}