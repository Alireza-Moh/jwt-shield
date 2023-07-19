## Generating token with RSA
```php
$claims = [
    "userId" => "54684351",
    "username" => "Test user",
];

$privateKey = file_get_contents("../keys/private_key.pem");
$expireDate = new DateTime("+2 days");

try {
    $jwt = JWT::getSignatureBuilder(JWTAlgorithm::RS256);
    
    $token = $jwt->generate($claims, $privateKey, $expireDate);
    
} catch (RSAException $e) {
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
    
} catch (RSAException $e) {
    echo $e->getMessage();
}
```