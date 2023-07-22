## Generating token with ECDSA
```php
$privateKey = file_get_contents("../keys/private_key.pem");
$expireDate = new DateTime("+2 days");

try {
    $jwt = JWT::getSignatureBuilder(JWTAlgorithm::ES256);
    $jwt->addClaims([
        new Claim(ClaimRegistry::EXI,  new DateTime("+2 days")),
        new Claim(ClaimRegistry::EXP,  $expireDate),
        new Claim("my_custom_claim",  "my_custom_data"),
    ]);
    $token = $jwt->generate($privateKey);
  
} catch (RSAException|TokenException $e) {
    echo $e->getMessage();
}

```

## Verifying token with RSA
```php
$publicKey = file_get_contents("../keys/public_key.pem");
$token = "your.provided.token"

try {
    $verify = Verifier::getVerifierBuilder($token);

    $isValid = $verify->isTokenValid($publicKey);
    
} catch (RSAException|TokenException $e) {
    echo $e->getMessage();
}
```