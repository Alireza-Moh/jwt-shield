<?php
namespace AlirezaMoh\JwtShield;

use AlirezaMoh\JwtShield\Exceptions\AlgorithmNotFoundException;
use AlirezaMoh\JwtShield\Exceptions\MissingKeyException;
use AlirezaMoh\JwtShield\Services\Signatures\ECDSASignature;
use AlirezaMoh\JwtShield\Services\Signatures\HMACSignature;
use AlirezaMoh\JwtShield\Services\Signatures\RSASignature;
use AlirezaMoh\JwtShield\Supports\JWTAlgorithm;
use Dotenv\Dotenv;

/**
 * Represents a JSON Web Token (JWT) generator.
 * It provides an interface for generating JWT tokens.
 */
class JWT
{
    /**
     * @var array The custom claims for the JWT.
     */
    private array $customClaims;

    /**
     * @var mixed|null The expiration time for the JWT.
     */
    private mixed $expireTime;

    /**
     * @var JWTAlgorithm The algorithm used for signing the JWT.
     */
    private JWTAlgorithm $algorithm;

    /**
     * JWT constructor.
     *
     * @param array $customClaims The custom claims for the JWT.
     * @param JWTAlgorithm $algorithm The algorithm used for signing the JWT.
     * @param int|null $expireTime The expiration time for the JWT (optional).
     */
    public function __construct(array $customClaims,JWTAlgorithm $algorithm, int $expireTime = null)
    {
        $this->customClaims = $customClaims;
        $this->algorithm = $algorithm;
        $this->expireTime = $expireTime;
        $this->loadEnvs();
    }

    /**
     * Generates the JWT token based on the specified algorithm and custom claims.
     *
     * @return string The generated JWT token.
     *
     * @throws AlgorithmNotFoundException if the algorithm is not supported.
     * @throws MissingKeyException if a required key is missing.
     */
    public function getToken(): string
    {
        return match ($this->algorithm) {
            JWTAlgorithm::HS256,  JWTAlgorithm::HS384, JWTAlgorithm::HS512 => (new HMACSignature($this->algorithm, $this->customClaims, $this->expireTime))->generate(),
            JWTAlgorithm::RS256, JWTAlgorithm::RS384, JWTAlgorithm::RS512 => (new RSASignature($this->algorithm, $this->customClaims, $this->expireTime))->generate(),
            JWTAlgorithm::ES256, JWTAlgorithm::ES384, JWTAlgorithm::ES512 => (new ECDSASignature($this->algorithm, $this->customClaims, $this->expireTime))->generate(),
            default => throw new AlgorithmNotFoundException($this->algorithm)
        };
    }

    /**
     * Adds additional claims to the JWT.
     *
     * @param array $data The additional claims to add.
     */
    public function addClaims(array $data): void
    {
        $this->customClaims = array_merge($this->customClaims, $data);
    }

    /**
     * Loads environment variables from a .env file.
     */
    private function loadEnvs(): void
    {
        $dotenv = Dotenv::createImmutable(FilesManager::getRootDirectory());
        $dotenv->load();
    }
}