Verizon Digital Media Services Token-Based Authentication Version 3.0
Copyright (C) Verizon.  All rights reserved.

Use of source and binary forms, with or without modification is permitted provided
that there is written consent by Verizon. Redistribution in source and binary
forms  is not permitted.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


EdgeCast Token Authentication extension for PHP
===============================================

Files included in this release:
base64.c  base64.h  build.sh  config.m4  ectoken.c  ectoken_v3.c  ectoken_v3.h  example_memcache.php  example.php  Makefile.in  php_ectoken.h  README.txt

===============================================
To build:
./build.sh

===============================================
To deploy:
Copy modules/ectoken.so into your PHP extensions directory.
Enable the extension in php.ini:

extension=ectoken.so

Restart your HTTP server
===============================================

Usage:

PHP:
ectoken_encrypt_token($key, $string);  // generate a token

Follow the instructions in the EdgeCast Token Authentication 1.4 guide. Pass the above function your key as the first parameter ($key), and all of your token authentication parameters as the second ($string). ectoken_encrypt_token or ectoken_generate will return your token as a string. On error this function will return null, and in most cases output the error to your php ERROR_LOG. Please note that in this release the maximum length of $string is 256 characters.

Example:
<?php
$key = "12345678";

$params = "ec_secure=1&ec_expire=1185943200&ec_clientip=111.11.111.11&ec_country_allow=US&ec_ref_allow=ec1.com";

$token = ectoken_generate($key, $params);
echo $token;

?>

<?php
$key = "12345678";

$params = "ec_secure=1&ec_expire=1185943200&ec_clientip=111.11.111.11&ec_country_allow=US&ec_ref_allow=ec1.com";

$token = ectoken_encrypt_token($key, $params);
echo $token;

?>

To test directly from command-line:

Token Examples:

php -d extension=.libs/ectoken.so example.php
php -d extension=.libs/ectoken.so -r '$token = ectoken_encrypt_token("12345678", "ec_expire=1185943200&ec_clientip=111.11.111.11&ec_country_allow=US&ec_ref_allow=ec1.com"); echo $token;'


Supported Versions
===============================================

This PHP module has been tested to work on the following Ubuntu/PHP versions:

Ubuntu         PHP Version
--------------------------
12.04 LTS      5.3.10
14.04 LTS      5.5.9
16.04 LTS      7.0.4
