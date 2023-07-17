<?php

namespace AlirezaMoh\JwtShield;

/**
 * Provides file management utilities.
 */
class FilesManager
{
    /**
     * Retrieves the root directory path.
     *
     * @return string The root directory path.
     */
    public static function getRootDirectory(): string
    {
        // Change the second parameter to suit your needs
        return dirname(__FILE__, 2);
    }
}