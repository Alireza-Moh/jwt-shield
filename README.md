# JWT shield
## A simple JWT token handler

&nbsp;

> This PHP package provides a simple and convenient way to handle JSON Web Tokens (JWT) in your applications.
> It supports various algorithms for token signing

## Algorithms:
- HMACSignature
- RSASignature
- ECDSASignature

### HMACSignature
- HS256
- HS384
- HS512


### RSASignature
- RS256
- RS384
- RS512


### ECDSASignature
- ES256
- ES384
- ES512

## Installation
```sh
composer require alireza/jwt-shield
```

> To learn how to create a token using RSA, ECDSA or HMAC, please navigate to the "docs" folder.
- [Token Creation with HMAC](docs/HMAC.md)
- [Token Creation with RSA](docs/RSA.md)
- [Token Creation with ECDSA](docs/ECDSA.md)

## License
> This package is open-source and released under the MIT License.