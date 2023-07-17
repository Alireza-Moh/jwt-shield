<?php

namespace AlirezaMoh\JwtShield;

class FilesManager
{
    public static function getRootDirectory(): string
    {
        // Change the second parameter to suit your needs
        return dirname(__FILE__, 2);
    }
}