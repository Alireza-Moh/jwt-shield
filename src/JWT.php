<?php
namespace AlirezaMoh\JwtShield;

use AlirezaMoh\JwtShield\Exceptions\AlgorithmNotFoundException;
use AlirezaMoh\JwtShield\Exceptions\MissingKeyException;
use AlirezaMoh\JwtShield\Services\Signatures\ECDSASignature;
use AlirezaMoh\JwtShield\Services\Signatures\HMACSignature;
use AlirezaMoh\JwtShield\Services\Signatures\RSASignature;
use AlirezaMoh\JwtShield\Supports\JWTAlgorithm;
use Dotenv\Dotenv;

class JWT
{
    private array $customClaims;
    private mixed $expireTime;
    private JWTAlgorithm $algorithm;

    public function __construct(array $customClaims,JWTAlgorithm $algorithm, int $expireTime = null)
    {
        $this->customClaims = $customClaims;
        $this->algorithm = $algorithm;
        $this->expireTime = $expireTime;
        $this->loadEnvs();
    }

    /**
     * @throws AlgorithmNotFoundException
     * @throws MissingKeyException
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

    public function addClaims(array $data): void
    {
        $this->customClaims = array_merge($this->customClaims, $data);
    }

    private function loadEnvs(): void
    {
        $dotenv = Dotenv::createImmutable(FilesManager::getRootDirectory());
        $dotenv->load();
    }
}