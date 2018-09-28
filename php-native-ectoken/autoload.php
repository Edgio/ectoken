<?php

/**
 * Class autoloader for the PHP Native ECToken library.
 * 
 * Include this file to use this library in your project. Example:
 * 
 *   require_once('path/to/php-native-ectoken/autoload.php');
 * 
 * If you are using Composer to manage dependencies, do not include this file
 * in your project, include composer's autoloader.
 * 
 */

require __DIR__ . '/vendor/autoload.php';

$loader = new \Aura\Autoload\Loader();
$loader->register();

$loader->addPrefix('ECToken3', __DIR__ . '/src');
$loader->addPrefix('ECToken3\\Rules', __DIR__ . '/src/rules');
