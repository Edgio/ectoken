#!/usr/bin/perl

# /**
# * Copyright (C) 2016 Verizon. All Rights Reserved.
# *
# * Licensed under the Apache License, Version 2.0 (the "License");
# * you may not use this file except in compliance with the License.
# * You may obtain a copy of the License at
# *     http://www.apache.org/licenses/LICENSE-2.0
# *
# * Unless required by applicable law or agreed to in writing, software
# * distributed under the License is distributed on an "AS IS" BASIS,
# * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# * See the License for the specific language governing permissions and
# * limitations under the License.
# */

#: -----------------------------------------------------------------------------
#: use...
#: -----------------------------------------------------------------------------
use Digest::SHA qw(sha256 sha256_hex);
use Bytes::Random::Secure qw(random_bytes);
use Crypt::Random::Seed;
use Crypt::GCM;
use Crypt::Rijndael;
use MIME::Base64::URLSafe;
use strict;

#: -----------------------------------------------------------------------------
#: ec_encrypt
#: -----------------------------------------------------------------------------
sub encrypt_v3
{
    my ($a_key, $a_token) = @_;

    #print "+-------------------------------------------------------------\n";
    #print "| key              $a_key\n";
    #print "| key              $a_token\n";
    #print "+-------------------------------------------------------------\n";

    #---------------------------------------------
    # Get sha-256 of key
    #---------------------------------------------
    my $l_key_sha256 = sha256($a_key);

    #---------------------------------------------
    # Seed rand/generate iv
    #---------------------------------------------
    my $l_rand_source = new Crypt::Random::Seed;
    my $l_ivbytes = $l_rand_source->random_bytes(12);

    #---------------------------------------------
    # AES GCM encrypt
    #---------------------------------------------
    my $l_cipher = Crypt::GCM->new(
        -key => $l_key_sha256,
        -cipher => 'Crypt::Rijndael',
    );
    $l_cipher->set_iv($l_ivbytes);
    $l_cipher->aad('');
    my $l_ciphertext = $l_cipher->encrypt($a_token);
    my $l_tag = $l_cipher->tag;

    #---------------------------------------------
    # iv + ciphertext + tag
    #---------------------------------------------
    my $l_iv_ciphertext_tag = $l_ivbytes . $l_ciphertext . $l_tag;

    #---------------------------------------------
    # URL Safe Base64 encode
    #---------------------------------------------
    my $l_iv_ciphertext_tag_base64 = urlsafe_b64encode($l_iv_ciphertext_tag);

	return $l_iv_ciphertext_tag_base64;
}

#: -----------------------------------------------------------------------------
#: usage/args
#: -----------------------------------------------------------------------------
if($ARGV[0] eq "--version")
{
	print("EC Token encryption and decryption utility.  Version: 3.0.0\n");
	exit(0);
}


my $usage = "Usage ./ec_encrypt.pl <key> <token> \n";

my $key = $ARGV[0];
die $usage if (!(defined $key));

my $token = $ARGV[1];
die $usage if (!(defined $token));

#: -----------------------------------------------------------------------------
#: main
#: -----------------------------------------------------------------------------
my $token_enc = &encrypt_v3($key, $token);
print "$token_enc\n";
