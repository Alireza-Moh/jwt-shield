## Generating token with HMAC
```php
$claims = [
    "userId" => "54684351",
    "username" => "Test user",
];

$secretKey = "your_super_secret_key";
$expireDate = new DateTime("+2 days");

try {
    $jwt = JWT::getSignatureBuilder(JWTAlgorithm::HS512);
    
    $token = $jwt->generate($claims, $privateKey, $expireDate);
    
} catch (RSAException $e) {
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