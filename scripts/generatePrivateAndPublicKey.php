<?php

$config = [
    'private_key_bits' => 2048, //feel free to increase the value but keep in mind that it will take longer to generate the key
    'private_key_type' => OPENSSL_KEYTYPE_RSA,
];

// Generate the private key
$privateKey = openssl_pkey_new($config);

// Extract the public key from the private key
$publicKeyDetails = openssl_pkey_get_details($privateKey);
$publicKey = $publicKeyDetails['key'];

// Save the private and public keys to files
openssl_pkey_export($privateKey, $privateKeyFile);
file_put_contents('./keys/private_key.pem', $privateKeyFile);
file_put_contents('./keys/public_key.pem', $publicKey);

// Free the private key from memory
unset($privateKey);

echo "Private and Public Key generated successfully\n";