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
use strict;
use warnings;
use feature "say";
use Getopt::Long qw(:config no_ignore_case);

use Digest::SHA qw(sha256 sha256_hex);
use Bytes::Random::Secure qw(random_bytes);
use Crypt::Random::Seed;
use Crypt::GCM;
use Crypt::Rijndael;
use MIME::Base64::URLSafe;

GetOptions(
	"h|help"	=> sub { usage(); },
	"V|version"	=> sub { version(); },
);

#: -----------------------------------------------------------------------------
#: ec_encrypt
#: -----------------------------------------------------------------------------
sub encrypt_v3 {
	my ($a_key, $a_token) = @_;

#---------------------------------------------
# Get sha-256 of key
#---------------------------------------------
	my $l_key_sha256 = sha256($a_key);

#---------------------------------------------
# Seed rand/generate iv
#---------------------------------------------
	my $l_rand_source = Crypt::Random::Seed->new(NonBlocking => 1);

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
# URL Safe Base64 encode and return
#---------------------------------------------

	return urlsafe_b64encode("$l_ivbytes$l_ciphertext$l_tag");
}

sub usage {
	say "Usage $0 <key> <token>";
	exit 1;
}

sub version {
	say "EC Token encryption and decryption utility.  Version: 3.0.0";
	exit 0;
}

#: -----------------------------------------------------------------------------
#: usage/args
#: -----------------------------------------------------------------------------

my $key = $ARGV[0];
usage() unless $key;

my $token = $ARGV[1];
usage() unless $token;

#: -----------------------------------------------------------------------------
#: main
#: -----------------------------------------------------------------------------
my $token_enc = encrypt_v3($key, $token);
say "$token_enc";
