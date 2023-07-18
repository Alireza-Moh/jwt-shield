<?php

namespace AlirezaMoh\JwtShield\Tests\Services\Signatures;

use AlirezaMoh\JwtShield\Services\Signatures\ECDSASignature;
use AlirezaMoh\JwtShield\Supports\JWTAlgorithm;
use PHPUnit\Framework\TestCase;

class ECDSASignatureTest extends TestCase
{
    private string $privateKey = "-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCmwDpNDhNp9Njc
9blwijc3FprSIb6HM0q9K2DLXGYfEYNKFcApSms4V9X1HoBAjS4iRMPT9LCVUKN5
bBSpAwF7zNiWiB8sq/iM4DzgQUpYrlKpphlRLibl+xzelCAQXsB7z5YCA3Ptn2K5
rpjBdql9iTJwSKsUz/TYyv6U+yvnIHZ7Zm6TM9NYrWEJkTQcD6u64xCtGMtSgwfX
IEIh2JnUxtCpuFDF90732x3Gqm02/5GscifLPv7b/CTxWO5b+6yb6E1aPuPo+tht
j/cZsAQFwYn+phiJx/uTatpILUOKHf0xKQ+E94+qdCijsqGA1Wba8dHUWhBpIcFj
SgPVw6fDAgMBAAECggEARp2KMv5+fzT2r6AJ31xQ5K3Yc5thraytfm3DyGsBPi/y
6ulKHtJKlKoxy+OWSX/gJRf83CI3s4vaJr38A9TniG9n21ua5BaRo8sETK2pl+N+
0yQpfYTvaR5OC/4rk/MkTWpL6t9edSc1rk9/lhIz1ZtHtmA3vxEP7c0NQbcaUP5x
tPXvXoJt71EDMhCTkuzfsmSyX3HV1hQWoiKwx5zOHX6hPYYRFjRtfgapl9CEwfNA
iXM3SOzK3eKrlQLpPfZjM/kVeg0l41BwSqgarJYbeokggQe8Y/OkrpPxCxDlKerr
57Y2fjfp8gxbVVH+kW07DHBhK6kAM7Z5yg/zgFPwdQKBgQDX4XmGosqijs4rtOj0
YN1K2h9jjzjypNGCCPTaojF+9tReB7Jy3cjPkOxC/p0NcIov2UbBsNC7codMwXBp
JHKipxjtxkE5D/cU2IHSs7nBgEi3tu7egxgF4QP4KK9d8G0tOlkHFX0Y5RPS8X+g
ZIWkDnLu7NpQgrtH2itWS8t8FwKBgQDFvWZcXaAqn+clQJ/p6kgQJYMkajAQwvb/
EUH9fQJf/BbLBDXRLN0mGrfA6tqFbZphRQK0aNy5MA8yFByUIicZ09vrJWg14LMv
rGzkr5mC5RCGSnZYaJBE7fXkXBqJq6PROgEUe5Obc2nCGtfbmNj0iuibXw9KhsXW
cwHuNfwhNQKBgQCcuSoanjBx1y7B+DJux6uf3b6P7rgvH4yh1JK97qX0QIloQjpA
vdY9Kj77XBD0YtFPb3O4xf6jNsAW7xAGpNk8UAb/B8DuBjMgRRXqu2ONoO4pwXqk
u5NDIVpaXF8D2bnI7eUYCXeqDRRZPc2jyZZjxcGWxwivDlmcDj0MBzaQvQKBgGCV
mYjmJlSLlDCK91EfISHZ4MuJnn6hbFm8CTqSs/VEQbHaFZtdSYvSIwz06dWgana2
aZLLYXyG7/UrA6aLZAPmipW5yMQARCW2F94/s0DPOBoQBuw57rXscV2ga0nxb2vD
5EEn9zpHzlGEIQlfCCGyM9moPeTOHZYYyMmcztE9AoGAHUsKuoO1XkMt9a+bFV3v
SbkgV3Fd8m9O1su+yDNtdWhnkVYOQ6M6km8UBjHvyg3ymoVScIHs+OYtaxU+z6ny
yEj7YcTYvay5QWBLDcTQQhF7dRfAuhfoa0Jzq3c3vUs3FULUm9cyVGdPjf/C8XvD
lrLszhxp+vnofH/sHM8uXo4=
-----END PRIVATE KEY-----
";


    /**
     * @test
     */
    public function should_not_be_empty_token(): void
    {
        $signature = new ECDSASignature(JWTAlgorithm::HS512);
        $expiration = new \DateTime("+1 day");
        $claims = ["userId" => 545432, "username" => "test"];
        $token = $signature->generate($expiration, $claims, $this->privateKey);

        $this->assertNotEmpty($token);
        $this->assertIsString($token);
    }
}
