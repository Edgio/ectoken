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

spl_autoload_register(function($className) {
  if (class_exists($className, false) || interface_exists($className, false)) {
    return false;
  }

  $classFile = dirname(__FILE__) . '/src/'. preg_replace('/^.*\\\/', '', $className) . '.php';
  
  if (file_exists($classFile)) {
    require($classFile);
    return true;
  }

  return false;
});