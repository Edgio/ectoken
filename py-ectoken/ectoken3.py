#!/usr/bin/env python3
'''
Copyright Verizon.

file: ectoken3.py
details: python implementation of EdgeCast v3 token

References:
1. Using cryptography for aes-gcm:
   https://cryptography.io/en/latest/hazmat/primitives/symmetric-encryption/#cryptography.hazmat.primitives.ciphers.modes.GCM
2. hashlib:
   https://docs.python.org/2/library/hashlib.html
3. Using cryptography for hashes (not using this currently)
   https://cryptography.io/en/latest/hazmat/primitives/cryptographic-hashes/
NOTE: encode() decode() default is utf-8

Licensed under the terms of the Apache 2.0 open source license.
Please refer to the LICENSE file in the project root for the terms
'''

# ------------------------------------------------------------------------------
# imports
# ------------------------------------------------------------------------------
import argparse
import base64
import hashlib
import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import (Cipher, algorithms, modes)

# ------------------------------------------------------------------------------
# constants
# ------------------------------------------------------------------------------
G_ALPHANUMERIC = '-_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxzy'
G_RAND_SENTINEL_MIN_LEN = 4
G_RAND_SENTINEL_MAX_LEN = 8
G_IV_SIZE_BYTES = 12
G_AES_GCM_TAG_SIZE_BYTES = 16

# ------------------------------------------------------------------------------
# url safe b64 encode
# ------------------------------------------------------------------------------
def url_safe_base64_encode(a_str):
    '''
    base64 encode string (url safe b64 character set)
    '''

    l_str = base64.urlsafe_b64encode(a_str).decode().replace('=', '')
    l_str = l_str.encode()
    return l_str

# ------------------------------------------------------------------------------
# url safe b64 decode
# ------------------------------------------------------------------------------
def url_safe_base64_decode(a_str):
    '''
    base64 decode string (url safe b64 character set)
    '''

    # If string % 4 -add back '='
    l_str = a_str.decode()
    l_mod = len(a_str) % 4
    if l_mod:
        l_str += '=' * (4 - l_mod)
    return base64.urlsafe_b64decode(l_str)

# ------------------------------------------------------------------------------
# ectoken v3 decrypt
# ------------------------------------------------------------------------------
def decrypt_v3(a_key, a_token, a_verbose=False):
    '''
    decrypt ectoken
    '''

    # Get sha-256 of key
    a_key = a_key.encode()
    a_token = a_token.encode()

    l_key = hashlib.sha256(a_key).digest()

    # Base 64 decode
    l_decoded_token = url_safe_base64_decode(a_token)

    # Split first 12 bytes off and use as iv
    l_iv = l_decoded_token[:G_IV_SIZE_BYTES]

    # Split last 16 bytes off and use as tag
    l_tag = l_decoded_token[-G_AES_GCM_TAG_SIZE_BYTES:]

    # Remainder is ciphertext
    l_ciphertext = l_decoded_token[G_IV_SIZE_BYTES:len(l_decoded_token)-G_AES_GCM_TAG_SIZE_BYTES]

    if a_verbose:
        print('+-------------------------------------------------------------')
        print('| l_decoded_token: %s'%(l_decoded_token.hex()))
        print('+-------------------------------------------------------------')
        print('| l_iv:            %s'%(l_iv.hex()))
        print('| l_ciphertext:    %s'%(l_ciphertext.hex()))
        print('| l_tag:           %s'%(l_tag.hex()))
        print('+-------------------------------------------------------------')

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
    l_decrypted_str = l_decrypted_str.decode()

    if a_verbose:
        print('| l_decrypted_str: %s'%(l_decrypted_str))

    return l_decrypted_str

# ------------------------------------------------------------------------------
# ectoken v3 encrypt
# ------------------------------------------------------------------------------
def encrypt_v3(a_key, a_token, a_verbose=False):
    '''
    encrypt ectoken
    '''

    # Get sha-256 of key
    a_key = a_key.encode()
    a_token = a_token.encode()

    l_key = hashlib.sha256(a_key).digest()

    # Generate iv
    l_iv = os.urandom(G_IV_SIZE_BYTES)

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

    if a_verbose:
        print('+-------------------------------------------------------------')
        print('| l_iv:            %s'%(l_iv.hex()))
        print('| l_ciphertext:    %s'%(l_ciphertext.hex()))
        print('| l_tag:           %s'%(l_encryptor.tag.hex()))
        print('+-------------------------------------------------------------')
        print('| l_encoded_token: %s'%(l_iv_ciphertext.hex()))
        print('+-------------------------------------------------------------')

    return url_safe_base64_encode(l_iv_ciphertext).decode()

# ------------------------------------------------------------------------------
# main
# ------------------------------------------------------------------------------
def main():
    '''
    main parse args and encrypt/decrypt
    '''

    l_ap = argparse.ArgumentParser(
                description='Generate Random Security Config Post from Template.',
                usage='%(prog)s',
                epilog='')

    # key
    l_ap.add_argument('-k',
                      '--key',
                      dest='key',
                      help='Token Key.',
                      required=True)

    # token
    l_ap.add_argument('-t',
                      '--token',
                      dest='token',
                      help='Token to encrypt or decrypt.',
                      required=True)

    # decrypt
    l_ap.add_argument('-d',
                      '--decrypt',
                      dest='decrypt',
                      help='Decrypt.',
                      action='store_true',
                      default=False,
                      required=False)

    # verbose
    l_ap.add_argument('-v',
                      '--verbose',
                      dest='verbose',
                      help='Verbosity.',
                      action='store_true',
                      default=False,
                      required=False)

    l_args = l_ap.parse_args()

    l_token = ''
    if l_args.decrypt:
        try:
            l_token = decrypt_v3(a_key=l_args.key,
                                 a_token=l_args.token,
                                 a_verbose=l_args.verbose)
        except Exception as l_e:
            if l_args.verbose:
                print('| Failed to decrypt v3 token trying to decrypt as v1/2 token')
                print('| Error detail: type: {} error message: {}, doc: {}'.format(
                    type(l_e), l_e, l_e.__doc__))
    else:
        l_token = encrypt_v3(a_key=l_args.key,
                             a_token=l_args.token,
                             a_verbose=l_args.verbose)

    print(l_token)

# ------------------------------------------------------------------------------
# called from cmd line
# ------------------------------------------------------------------------------
if __name__ == '__main__':
    main()
