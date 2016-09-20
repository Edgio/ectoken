<?php

/**
* Copyright (C) 2016 Verizon. All Rights Reserved.
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*     http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/

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
