# Native PHP ECToken Generator

This is a native PHP implementation of the EdgeCast Token Generator that does
not require a PHP extension to operate, making it suitable for environments in
which PHP extensions are not available.

Additional ECToken parameter management has been included in order to assist
users of this library to construct parameter strings for encrypting.

## Requirements

Efforts have been made to ensure that this code will operate properly on PHP 
5.6+ or PHP 7+, with or without mbstring or openssl support.

- Composer (<https://getcomposer.org>) is required for dependency management

## Installation

Clone or download this repository and run `composer install` from the direcory
containing `composer.json`

_Note:_ `composer install` should be performed in an environment closely
resembling the production environment because dependant library versions will be 
chosen based on the PHP version encountered during install.

## Usage

```
require_once('path/to/autoload.php');

$key = "12345678";

// Configure the token
$token = new ECToken3\ECToken();
$token
  ->addValue('ec_clientip', '111.11.111.11')
  ->addValue('ec_expire', 1185943200)
  ->addValue('ec_country_allow', 'US')
  ->addValue('ec_country_allow', 'CA')
  ->addValue('ec_ref_allow', 'ec1.com');

// Set up the encryption
$encryptor = new ECToken\Crypto($key);

// Generate and encrypt the token
$ectoken = $encryptor->encrypt($token->encode());

echo $ectoken;
```

The library contains a mechanism to configure tokens using the simple ECToken
class. Paremeter names and values are validated for proper content based on the
_VDMS Token-Based Authentication Administration Guide_. Parameter definitions are
aware of whether each parameter can accommodate multiple values.

A parser is provided for consuming decrypted ectokens back into this data
structure.  For example:

```
require_once('path/to/autoload.php);

$key = '12345678';
$ectoken = '3JfiJSVMLupuU6JIk88cjm9kmr8A0ERvcB8WH_8n-9pJKPsBf1l7QNnRQQ6H4M4gysS3J3SRJtAqUQhHmt6HWnaAV-UejGp38iQxd3uZgYnYLWiompbbQTFc5fwu9-x-mtwnsQ5bz2W-ma1LPlj9ZPdXGxN9Pg';

$encryptor = ECToken3\Crypto($key);

$token = new ECToken3\ECToken();

$token->decode($encryptor->decrypt($ectoken));

foreach ($token->getParameters() as $name => $parameter) {
  print("$name: " . implode(', ', $parameter->getValues()) . "\n");
}

```

Output:
```
ec_clientip: 111.11.111.11
ec_expire: 1185943200
ec_country_allow: US, CA
ec_ref_allow: ec1.com
```

## Migrating from php-ectoken

Existing code bases should be simple to migrate from php extension versions of
php-ectoken.

1. Remove any checks for the `ectoken` PHP extension (e.g. `extension_loaded('ectoken')`)
2. Refactor calls to `ectoken_encrypt_token` or `ectoken_decrypt_token` as above or include the following shim:

```
require_once('path/to/autoload.php');

function ectoken_encrypt_token($key, $input) {
  $encryptor = new ECToken\Crypto($key);
  return $encryptor->encrypt($input);
}

function ectoken_decrypt_token($key, $input) {
  $encryptor = new ECToken\Crypto($key);
  return $encryptor->decrypt($input);
}
```

## Libraries used directly by php-native-ectoken

These libraries are used directly:

- php-aes-gcm: AES GCM (Galois Counter Mode) PHP Implementation <https://github.com/Spomky-Labs/php-aes-gcm>
- random_compat: PHP 5.x polyfill for `random_bytes()` and `random_int()` <https://github.com/paragonie/random_compat>
- constant_time_encoding: Constant-Time Character Encoding in PHP Projects <https://github.com/paragonie/constant_time_encoding>
- polyfill-mbstring: Symfony Polyfill / Mbstring <https://github.com/symfony/polyfill>
- Respect\Validation: Validation library <https://github.com/Respect/Validation>