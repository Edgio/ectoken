#!/usr/bin/env python2

import binascii
import bitstring
import copy
import math
import subprocess
import sys
import traceback

from python_ectoken import ectoken3

def generate_test_token(a_key, a_message):
    """
    Wrapper to generate a token with a given key and content.
    """
    return ectoken3.encrypt_v3(a_key, a_message, False, '\0'*12)

def unwrap_token(a_token):
    """
    Wrapper to decode the b64 encoding of a token.
    """
    return ectoken3.url_safe_base64_decode(a_token)

def calculate_extra_bits_in_b64_encoding(a_token):
    """
    Base64 necessarily pads encoded bytes with extra bits when the length is not
    exactly right. We would like to know what that padding is for the given
    token.
    """
    # Get the length of used bits, not bytes. base64 encoding will pad the final
    # encoding if (len(unencoded)*8) % 6 != 0.
    l_encoded_len = len(bitstring.Bits(bytes=a_token))
    l_decoded_len = len(bitstring.Bits(bytes=unwrap_token(a_token)))
    l_padding = 6 - l_decoded_len%6
    if l_padding == 6:
        l_padding = 0

    assert l_decoded_len <= l_encoded_len
    print('decoded:\t{}\nencoded:\t{}\npadding:\t{}'.format(
        l_decoded_len,
        l_encoded_len,
        l_padding))
    return l_padding

def validate_token_fails(a_key, a_token, a_canonical):
    """
    Decodes and decrypts a_token and validates the contents. Expects the
    decryption to fail. Raises an exception if nothing fails.
    """
    l_failed = False
    try:
        l_decrypted = ectoken3.decrypt_v3(a_key, a_token)
    except Exception as l_e:
        l_failed = True
        print("Expected exception '{}':\n{}\n".format(str(l_e), a_token,
            a_canonical))

    # I don't think we support decrypting with php
    # "php -d extension=php-ectoken/.libs/ectoken.so -r \$token = ectoken_decrypt_token('{}', '{}'); echo \$token;",
    l_exes = [
        "./c-ectoken/ecencrypt/ectoken3 decrypt '{}' '{}'",
        "./c++-ectoken/ectoken3 -d '{}' '{}'",
        #"./perl-ectoken/ectoken3.pl '{}' '{}'",
        "java -jar java-ectoken/ECToken3.jar decrypt '{}' '{}'",
        "./c#-ectoken/ecencryptdotnet/bin/Debug/ectoken3.exe decrypt '{}' '{}'",
    ]

    l_fail_map = {}
    for i_exe in l_exes:
        l_exe = i_exe.format(a_key, a_token)
        l_child = subprocess.Popen(l_exe, shell=True, stdout=subprocess.PIPE)
        l_result, _ = l_child.communicate()
        print(l_exe, l_result)
        l_fail_map[l_exe] = l_child.returncode != 0
        if len(l_result) == len(a_canonical) and not l_fail_map[l_exe]:
            for i_pos in xrange(0, len(a_canonical)):
                l_fail_map[l_exe] = l_result[i_pos] != a_canonical[i_pos]
                if l_fail_map[l_exe]:
                    break
        else:
            l_fail_map[l_exe] = True

    if not l_failed:
        raise AssertionError("This token should have failed to decrypt '{}': '{}'.".format(a_key, a_token))

    for i_k, i_v in l_fail_map.iteritems():
        if not i_v:
            raise AssertionError("This token should have failed to decrypt '{}'.".format(l_exe))


def validate_token_passes(a_key, a_token, a_canonical):
    """
    Decodes and decrypts a_token and validates the contents. Raises an exception
    on failure.
    """
    # First let's do python since it's easy
    l_decrypted = ectoken3.decrypt_v3(a_key, a_token)
    assert len(l_decrypted) == len(a_canonical)
    for i_pos in xrange(0, len(a_canonical)):
        assert l_decrypted[i_pos] == a_canonical[i_pos]

    # I don't think we support decrypting with php
    # "php -d extension=php-ectoken/.libs/ectoken.so -r \$token = ectoken_decrypt_token('{}', '{}'); echo \$token;",
    l_exes = [
        "./c-ectoken/ecencrypt/ectoken3 decrypt '{}' '{}'",
        "./c++-ectoken/ectoken3 -d '{}' '{}'",
        #"./perl-ectoken/ectoken3.pl '{}' '{}'",
        "java -jar java-ectoken/ECToken3.jar decrypt '{}' '{}'",
        "./c#-ectoken/ecencryptdotnet/bin/Debug/ectoken3.exe decrypt '{}' '{}'",
    ]

    for i_exe in l_exes:
        l_exe = i_exe.format(a_key, a_token)
        print(l_exe)
        l_child = subprocess.Popen(l_exe, shell=True, stdout=subprocess.PIPE)
        l_result, _ = l_child.communicate()
        assert l_child.returncode == 0
        for i_pos in xrange(0, len(a_canonical)):
            assert l_result[i_pos] == a_canonical[i_pos]

g_map = {}
def b64_repr_to_unencoded_bits(a_char):
    global g_map
    if len(g_map) == 0:
        l_alphabet = [
            "A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M",
            "N", "O", "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z",
            "a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m",
            "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z",
            "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "-", "_"
        ]

        for i_index in xrange(0, len(l_alphabet)):
            g_map[l_alphabet[i_index]] = i_index

    return g_map[a_char]

def test_cases():
    l_tests = [
            {
                'key': 'this is a very bad key, do not do this',
                'message': 'all your base is belong to us',
            },
            {
                'key': 'testkey',
                'message': 'testmessage',
            },
            {
                'key': '333test',
                'message': '333',
            },
            {
                'key': 'si9sK_jvSALTrlXIVMI4CgIGuu1MJeHXH0B3HxuRP48N5ZYwSa',
                'message': ' &ec_expire=1000000000',
            },
        ]

    return l_tests

def main():
    l_tests = test_cases()
    for i_test in l_tests:
        l_key = i_test['key']
        l_message = i_test['message']

        l_token = generate_test_token(l_key, l_message)
        validate_token_passes(l_key, l_token, l_message)

        l_extra_bits = calculate_extra_bits_in_b64_encoding(l_token)
        l_encoded_bit_len = len(bitstring.Bits(bytes=l_token))

        for i_pos in xrange(0, len(l_token)):
            l_unencoded_token_bits = b64_repr_to_unencoded_bits(l_token[i_pos])

            for i_char in ectoken3.G_ALPHANUMERIC:
                if l_token[i_pos] == i_char:
                    continue
                l_flipped = bytearray(l_token)
                l_flipped[i_pos] = i_char


                l_mask = 0
                for i_count in xrange(0, l_extra_bits):
                    l_mask |= 1<<i_count
                l_mask_inverse = l_mask ^ 0xff

                l_unencoded_flip_bits = b64_repr_to_unencoded_bits(chr(l_flipped[i_pos]))

                print(i_test)
                print("{}/{} [{}]".format(i_pos, len(l_token)-1, l_extra_bits))
                print(bitstring.Bits(bytes=l_token))
                print(bitstring.Bits(bytes=l_flipped))
                print("index: {}/{}, mask: {}, inverse_mask: {}, should_pass?: {}, inverse masked: {}, masked: {}".format(
                        i_pos,
                        len(l_token)-1,
                        bitstring.Bits(
                            int=l_mask,
                            length=8).bin,
                        bitstring.Bits(
                            int=l_mask_inverse,
                            length=9).bin[1:],
			i_pos == len(l_token)-1 and
                            (l_unencoded_token_bits ^
                                l_unencoded_flip_bits) &
                                l_mask_inverse == 0,
                        bitstring.Bits(
                            int=(l_unencoded_flip_bits & l_mask_inverse),
                            length=8).bin,
                        bitstring.Bits(
                            int=(l_unencoded_flip_bits & l_mask),
                            length=8).bin
			)
                    )

                if (i_pos == len(l_token)-1 and
                    ((l_unencoded_token_bits ^
                        l_unencoded_flip_bits) &
                        l_mask_inverse) == 0):

                    validate_token_passes(l_key, l_flipped, l_message)
                else:
                    validate_token_fails(l_key, l_flipped, l_message)

if __name__ == '__main__':
    main()

