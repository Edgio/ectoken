#!/usr/bin/python

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

# ------------------------------------------------------------------------------
# ectoken tool
# References:
# 1. Using cryptography for aes-gcm:
#    https://cryptography.io/en/latest/hazmat/primitives/symmetric-encryption/#cryptography.hazmat.primitives.ciphers.modes.GCM
# 2. OpenSSL rand:
#    http://pythonhosted.org//pyOpenSSL/api/rand.html
# 3. hashlib:
#    https://docs.python.org/2/library/hashlib.html
# 4. Using cryptography for hashes (not using this currently)
#    https://cryptography.io/en/latest/hazmat/primitives/cryptographic-hashes/
# ------------------------------------------------------------------------------


# ------------------------------------------------------------------------------
# Imports
# ------------------------------------------------------------------------------
import argparse
import base64
import sys
import random
import time
import re
from struct import pack
import hashlib

import OpenSSL

from cryptography.hazmat.backends import default_backend
#from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import (Cipher, algorithms, modes)

# ------------------------------------------------------------------------------
# Constants
# ------------------------------------------------------------------------------
G_ALPHANUMERIC = '-_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxzy'
G_RAND_SENTINEL_MIN_LEN = 4
G_RAND_SENTINEL_MAX_LEN = 8
G_IV_SIZE_BYTES = 12
G_AES_GCM_TAG_SIZE_BYTES = 16

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
def url_safe_base64_encode(a_str):
    l_str = base64.urlsafe_b64encode(a_str)
    return l_str.replace('=', '')

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
def url_safe_base64_decode(a_str):
    # If string % 4 -add back '='
    l_str = a_str
    l_mod = len(a_str) % 4
    if l_mod:
        l_str += '=' * (4 - l_mod)
    return base64.urlsafe_b64decode(l_str)

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
def decrypt_v3(a_key, a_token, a_verbose = False):

    # Get sha-256 of key
    l_key = hashlib.sha256(a_key).hexdigest().decode('hex')

    # Base 64 decode
    #l_decoded_token = base64.urlsafe_b64decode(a_token)
    l_decoded_token = url_safe_base64_decode(a_token)

    # Split first 12 bytes off and use as iv
    l_iv = l_decoded_token[:G_IV_SIZE_BYTES]

    # Split last 16 bytes off and use as tag
    l_tag = l_decoded_token[-G_AES_GCM_TAG_SIZE_BYTES:]

    # Remainder is ciphertext
    l_ciphertext = l_decoded_token[G_IV_SIZE_BYTES:len(l_decoded_token)-G_AES_GCM_TAG_SIZE_BYTES]

    if a_verbose:
        print '+-------------------------------------------------------------'
        print '| l_decoded_token: %s'%(l_decoded_token.encode('hex'))
        print '+-------------------------------------------------------------'
        print '| l_iv:            %s'%(l_iv.encode('hex'))
        print '| l_ciphertext:    %s'%(l_ciphertext.encode('hex'))
        print '| l_tag:           %s'%(l_tag.encode('hex'))
        print '+-------------------------------------------------------------'

    # Construct a Cipher object, with the key, iv, and additionally the
    # GCM tag used for authenticating the message.
    l_decryptor = Cipher(
        algorithms.AES(l_key),
        modes.GCM(l_iv, l_tag),
        backend=default_backend()
    ).decryptor()

    # Decryption gets us the authenticated plaintext.
    # If the tag does not match an InvalidTag exception will be raised.
    l_decrypted_str = l_decryptor.update(l_ciphertext) + l_decryptor.finalize()

    if a_verbose:
        print '| l_decrypted_str: %s'%(l_decrypted_str)

    return l_decrypted_str

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
def encrypt_v3(a_key, a_token, a_verbose = False):

    # Get sha-256 of key
    l_key = hashlib.sha256(a_key).hexdigest().decode('hex')

    # Seed rand with time...
    OpenSSL.rand.seed(str(time.time()))

    # Generate iv
    l_iv = OpenSSL.rand.bytes(G_IV_SIZE_BYTES) # TODO Make constant...

    # Construct an AES-GCM Cipher object with the given key and a
    # randomly generated IV.
    l_encryptor = Cipher(
        algorithms.AES(l_key),
        modes.GCM(l_iv),
        backend=default_backend()
    ).encryptor()

    # Encrypt the plaintext and get the associated ciphertext.
    # GCM does not require padding.
    l_ciphertext = l_encryptor.update(a_token) + l_encryptor.finalize()

    l_iv_ciphertext = l_iv + l_ciphertext + l_encryptor.tag

    #print 'TAG (len:%d) : %s'%(len(l_encryptor.tag), l_encryptor.tag)

    if a_verbose:
        print '+-------------------------------------------------------------'
        print '| l_iv:            %s'%(l_iv.encode('hex'))
        print '| l_ciphertext:    %s'%(l_ciphertext.encode('hex'))
        print '| l_tag:           %s'%(l_encryptor.tag.encode('hex'))
        print '+-------------------------------------------------------------'
        print '| l_encoded_token: %s'%(l_iv_ciphertext.encode('hex'))
        print '+-------------------------------------------------------------'

    return url_safe_base64_encode(l_iv_ciphertext)

# ------------------------------------------------------------------------------
# main
# ------------------------------------------------------------------------------
def main(argv):

    l_arg_parser = argparse.ArgumentParser(
                description='Generate Random Security Config Post from Template.',
                usage= '%(prog)s',
                epilog= '')

    # key
    l_arg_parser.add_argument('-k',
                            '--key',
                            dest='key',
                            help='Token Key.',
                            required=True)

    # token
    l_arg_parser.add_argument('-t',
                            '--token',
                            dest='token',
                            help='Token to encrypt or decrypt.',
                            required=True)

    # decrypt
    l_arg_parser.add_argument('-d',
                            '--decrypt',
                            dest='decrypt',
                            help='Decrypt.',
                            action='store_true',
                            default=False,
                            required=False)

    # verbose
    l_arg_parser.add_argument('-v',
                            '--verbose',
                            dest='verbose',
                            help='Verbosity.',
                            action='store_true',
                            default=False,
                            required=False)


    l_args = l_arg_parser.parse_args()

    l_token = ''
    if l_args.decrypt:
        try:
            l_token = decrypt_v3(a_key=l_args.key, a_token=l_args.token, a_verbose=l_args.verbose)
        except Exception as e:
            if l_args.verbose:
                print '| Failed to decrypt v3 token trying to decrypt as v1/2 token'
                print '| Error detail: type: %s error: %s, doc: %s, message: %s'% (type(e), e, e.__doc__, e.message)
    else:
        l_token = encrypt_v3(a_key=l_args.key, a_token=l_args.token, a_verbose=l_args.verbose)

    print l_token

# ------------------------------------------------------------------------------
# ------------------------------------------------------------------------------
if __name__ == "__main__":
    main(sys.argv[1:])
