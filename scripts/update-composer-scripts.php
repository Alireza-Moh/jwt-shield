<?php

$composerFilePath = __DIR__ . '/../../../composer.json'; // Path to the user's composer.json file

// Read the user's composer.json file
$userComposerJson = json_decode(file_get_contents($composerFilePath), true);

// Merge the scripts from your package's composer.json
$packageComposerJson = json_decode(file_get_contents(__DIR__ . '/../composer.json'), true);
$userComposerJson['scripts'] = array_merge($userComposerJson['scripts'], $packageComposerJson['scripts']);

// Update the user's composer.json file
file_put_contents($composerFilePath, json_encode($userComposerJson, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
