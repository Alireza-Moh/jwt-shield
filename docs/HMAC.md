## Generating token with HMAC
```php
$secretKey = "your_super_secret_key";
$expireDate = new DateTime("+2 days");

try {
    $jwt = JWT::getSignatureBuilder(JWTAlgorithm::HS512);
    $jwt->addClaims([
        new Claim(ClaimRegistry::EXI,  new DateTime("+2 days")),
        new Claim(ClaimRegistry::EXP,  $expireDate),
        new Claim("my_custom_claim",  "my_custom_data"),
    ]);
    $token = $jwt->generate($secretKey);
  
} catch (RSAException|TokenException $e) {
    echo $e->getMessage();
}
```

## Verifying token with HMAC
```php
$secretKey = "your_super_secret_key";
$token = "your.provided.token"

try {
    $verify = Verifier::getVerifierBuilder($token);

    $isValid = $verify->isTokenValid($secretKey);
    
} catch (RSAException $e) {
    echo $e->getMessage();
}
```