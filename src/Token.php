<?php

namespace AlirezaMoh\JwtShield;

use AlirezaMoh\JwtShield\Exceptions\TokenException;
use AlirezaMoh\JwtShield\Supports\Claims\Claim;
use AlirezaMoh\JwtShield\Supports\Claims\ClaimRegistry;
use AlirezaMoh\JwtShield\Supports\JWTAlgorithm;
use AlirezaMoh\JwtShield\Supports\Traits\Base64;
use DateTime;
use ValueError;

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
    private string $providedToken;

    /**
     * @var array The decoded header of the JWT token.
     */
    private array $header;

    /**
     * @var array The decoded payload of the JWT token.
     */
    private array $payload;

    /**
     * @var string The signature of the JWT token.
     */
    private string $signature;

    /**
     * @var JWTAlgorithm The algorithm used for signing and verifying the JWT token.
     */
    private JWTAlgorithm $algorithm;

    /**
     * @var DateTime $expirationTime The expiration time of the JWT (JSON Web Token).
     *
     */
    private DateTime $expirationTime;

    /**
     * @var string $originalHeader The original header of the JWT (JSON Web Token).
     *
     */
    private string $originalHeader;

    /**
     * @var string $originalPayload The original payload of the JWT (JSON Web Token).
     *
     */
    private string $originalPayload;

    /**
     * @var array $claims The list of Claim objects representing the JWT claims.
     *
     */
    private array $claims;

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
     * Checks if the token is expired
     * @return bool
     * @throws TokenException
     */
    public function isExpired(): bool
    {
        $currentDateTime = new DateTime();
        $expiration = $this->getClaim("exp");

        if (is_null($expiration)) {
            throw new TokenException("Expiration date not found");
        }
        return $expiration < $currentDateTime;
    }

    public function getClaim(mixed $claimName): Claim|null
    {
        $foundedClaim = null;
        foreach ($this->claims as $claim) {
            if ($claim->getName() === $claimName) {
                $foundedClaim = $claim;
            }
        }
        return $foundedClaim;
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
        $this->convertToClaimObject();
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
     * Convert the payload data into Claim objects and add them to the claims array.
     *
     * This method iterates through each key-value pair in the payload array. For each key,
     * it attempts to create a Claim object using the ClaimRegistry::from() method to identify
     * the claim type.
     *
     * @throws ValueError If an invalid claim type is encountered in the payload.
     *
     * @return void
     */
    private function convertToClaimObject(): void
    {
        $claimRegistry = null;

        foreach ($this->payload as $key => $value) {
            try {
                $claimRegistry = ClaimRegistry::from($key);
                $this->claims[] = new Claim($key, $value);
            } catch (ValueError $e) {
                $this->claims[] = new Claim($claimRegistry, $value);
            }
        }
    }
}