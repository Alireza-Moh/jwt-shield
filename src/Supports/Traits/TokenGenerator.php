<?php

namespace AlirezaMoh\JwtShield\Supports\Traits;

use AlirezaMoh\JwtShield\Supports\Claims\Claim;
use AlirezaMoh\JwtShield\Supports\JWTAlgorithm;
use DateTime;

/**
 * Trait TokenGenerator
 *
 * This trait provides methods for preparing the header and payload sections of a JWT (JSON Web Token).
 */
trait TokenGenerator
{
    /**
     * Prepare the JWT header.
     *
     * @param JWTAlgorithm $algorithm The JWT algorithm object.
     * @param string $type The token type. Default is "JWT".
     * @return string The encoded header.
     */
    public function prepareHeader(JWTAlgorithm $algorithm, string $type = "JWT"): string
    {
        $header = [
            "alg" => $algorithm->getAlgorithm(),
            "typ" => $type
        ];

        return $this->encodeBase64(json_encode($header));
    }

    /**
     * Prepare the JWT payload and merge the custom claims.
     *
     * @return string The encoded payload.
     */
    public function preparePayload(): string
    {
        $this->prepareModifiedClaims();

        return $this->encodeBase64(json_encode($this->claims));
    }

    /**
     * Prepare and modify the custom claims by processing each claim and updating them as needed.
     * This function loops through the custom claims and calls the addToModifiedClaims method
     * to handle each claim individually.
     */
    private function prepareModifiedClaims(): void
    {
        $modifiedClaims = [];

        foreach ($this->claims as $claim) {
            $this->addToModifiedClaims($claim, $modifiedClaims);
        }

        $this->claims = $modifiedClaims;
    }

    /**
     * Add the claim to the list of modified claims if it has not been added before.
     * This function takes a Claim object and adds its name and value to the list of modified claims
     *
     * @param Claim $claim The claim to be added to the list of modified claims.
     * @param array $modifiedClaims The array containing the modified claims.
     * @return void
     */
    private function addToModifiedClaims(Claim $claim, array &$modifiedClaims): void
    {
        $claimName = $this->getClaimName($claim);
        $value = $this->getClaimValue($claim);

        if (!$this->isClaimAlreadyModified($claimName, $modifiedClaims)) {
            $modifiedClaims[$claimName] = $value;
        }
    }

    /**
     * Get the appropriate claim name based on the claim type (registered or custom).
     * This function returns the actual claim name if it's a registered claim; otherwise,
     *
     * @param Claim $claim The claim for which to determine the appropriate name.
     * @return string The appropriate claim name.
     */
    private function getClaimName(Claim $claim): string
    {
        $claimName = $claim->getName();
        if ($claim->isARegisteredClaim()) {
            return $claimName->getActualName();
        }
        return (string) $claimName;
    }

    /**
     * Get the modified value for the claim based on its type (e.g., datetime instance).
     * This function returns the modified value for the claim. If the claim is a datetime instance,
     *
     * @param Claim $claim The claim for which to get the modified value.
     * @return mixed The modified value of the claim.
     */
    private function getClaimValue(Claim $claim): mixed
    {
        if ($claim->getValue() instanceof DateTime) {
            return $claim->getValue()->getTimestamp() * 1000;
        }
        return $claim->getValue();
    }

    /**
     * Check if the claim name already exists in the list of modified claims.
     *
     * @param string $claimName The claim name to check for existence.
     * @param array $modifiedClaims The array containing the modified claims.
     * @return bool True if the claim name exists in the modified claims array, false otherwise.
     */
    private function isClaimAlreadyModified(string $claimName, array $modifiedClaims): bool
    {
        return array_key_exists($claimName, $modifiedClaims);
    }
}