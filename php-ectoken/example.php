<?php
$key = "12345678";
$params = "ec_secure=1&ec_expire=1185943200&ec_clientip=111.11.111.11&ec_country_allow=US&ec_ref_allow=ec1.com";

// Generate the token
// Check to see if the extension properly loaded before using it.
if (extension_loaded('ectoken')){
    $token = ectoken_encrypt_token($key, $params);
} else {
    trigger_error('The EdgeCast Token module could not be loaded.', E_USER_ERROR);
}

echo $token;

?>
