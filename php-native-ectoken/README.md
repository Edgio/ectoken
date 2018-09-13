# Native PHP ECToken Generator

This is a native PHP implementation of the EdgeCast Token Generator that does
not require a PHP extension to operate, making it suitable for environments in
which PHP extensions are not available.

## Requirements

Efforts have been made to ensure that this code will operate properly on PHP 
5.4+ or PHP 7.1+, with or without the mbstring or openssl modules.

- Composer (<https://getcomposer.org>) is required for dependency management

## Installation

Clone or download this repository and run `composer install` from the direcory
containing `composer.json`

_Note:_ `composer install` should be performed in an environment closely
resembling the production environment because dependant library versions will be 
chosen based on the PHP version encountered during install.

## Usage

```
require_once('path/to/ectoken3.php');

use \ECToken3\ECToken3;

$key = "12345678";
$params = "ec_secure=1&ec_expire=1185943200&ec_clientip=111.11.111.11&ec_country_allow=US&ec_ref_allow=ec1.com";

// Generate the token
$token = ECToken3::encrypt($key, $params);

echo $token;
```

## Migrating from php-ectoken

Existing code bases should be simple to migrate from php extension versions of
php-ectoken.

1. Remove any checks for the `ectoken` PHP extension (e.g. `extension_loaded('ectoken'`)
2. Refactor calls to `ectoken_encrypt_token` or `ectoken_decrypt_token` as above or include the following shim:

```
require_once('path/to/ectoken3.php');

use ECToken3\ECToken3;

function ectoken_encrypt_token($key, $input) {
  return ECToken3::encrypt($key, $input);
}

function ectoken_decrypt_token($key, $input) {
  return ECToken3::decrypt($key, $input);
}
```

## Libraries used directly by php-native-ectoken

These libraries are used directly:

- php-aes-gcm: AES GCM (Galois Counter Mode) PHP Implementation <https://github.com/Spomky-Labs/php-aes-gcm>
- random_compat: PHP 5.x polyfill for `random_bytes()` and `random_int()` <https://github.com/paragonie/random_compat>
- constant_time_encoding: Constant-Time Character Encoding in PHP Projects <https://github.com/paragonie/constant_time_encoding>
- polyfill-mbstring: Symfony Polyfill / Mbstring <https://github.com/symfony/polyfill>