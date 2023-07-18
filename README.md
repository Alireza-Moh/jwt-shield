# JWT shield
## A simple JWT token handler

&nbsp;

> This PHP package provides a simple and convenient way to handle JSON Web Tokens (JWT) in your applications.
> It supports various algorithms for token signing

## Algorithms:
- HMACSignature
- RSASignature
- ECDSASignature

## Installation
```sh
composer require alireza/jwt-shield
```

### Generating secret key
Create an .env file in your root folder before generating the secret key and then execute the key generator
```sh
composer generate-secret-key
```

### Generating public and private key
```sh
composer generate-public-and-private-key
```

## Usage
```php
$claims = [
    "userId" => "54684351",
    "username" => "Test user",
];
try {
    $jwt = new JWT($claims, JWTAlgorithm::ES512, time() + 3600);
    $token = $jwt->getToken();
} catch (AlgorithmNotFoundException|MissingKeyException $e) {
    echo $e->getMessage();
}
```

## License
> This package is open-source and released under the MIT License.