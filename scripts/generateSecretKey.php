<?php

$secretKey = bin2hex(openssl_random_pseudo_bytes(50));
$envFile = '.env';
$content = file_get_contents($envFile);

if (str_contains($content, "SECRET_KEY=")) {
    echo "Key 'SECRET_KEY' already exists in the .env file.\n";
    return;
}

$content .= "SECRET_KEY={$secretKey}\n";

file_put_contents($envFile, $content);

echo "Secret key added to .env file.\n";
