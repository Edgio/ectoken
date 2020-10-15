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
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <openssl/blowfish.h>
#define VERSION_STRING "3.0.0"
extern "C" {
#include "ectoken_v3.h"
}
//! ----------------------------------------------------------------------------
//! ectoken v2
//! ----------------------------------------------------------------------------
//! ----------------------------------------------------------------------------
//! \details hex char to binary rep
//! \return  integer value for hex character
//! ----------------------------------------------------------------------------
inline int hexchar2bin(const char c)
{
        switch (c)
        {
        case '0': return 0x0;
        case '1': return 0x1;
        case '2': return 0x2;
        case '3': return 0x3;
        case '4': return 0x4;
        case '5': return 0x5;
        case '6': return 0x6;
        case '7': return 0x7;
        case '8': return 0x8;
        case '9': return 0x9;
        case 'a': case 'A': return 0xA;
        case 'b': case 'B': return 0xB;
        case 'c': case 'C': return 0xC;
        case 'd': case 'D': return 0xD;
        case 'e': case 'E': return 0xE;
        case 'f': case 'F': return 0xF;
        }
        return -1;
}
//! ----------------------------------------------------------------------------
//! \details hexadecimal to binary conversion
//! \return  NA
//! \note    d needs to be half of s
//! ----------------------------------------------------------------------------
inline void hex2bin(const char *s, std::vector<unsigned char>& d)
{
        const size_t len = strlen(s)/2;
        d.resize(0);
        d.reserve(len);
        for (size_t i = 0; i < len; ++i)
        {
                const int c1 = hexchar2bin(s[i*2]);
                const int c2 = hexchar2bin(s[i*2+1]);
                if (c1 < 0 || c2 < 0)
                {
                        break; // stop on non-hex chars
                }
                d.push_back(((c1 << 4) + c2) & 0xFF);
        }
}
//! ----------------------------------------------------------------------------
//! \details binary to hexadecimal conversion
//! \return  hexadecimal string
//! ----------------------------------------------------------------------------
inline std::string bin2hex(const unsigned char *s, size_t len)
{
        static const char hexchars[] =
                { '0', '1', '2', '3',
                  '4', '5', '6', '7',
                  '8', '9', 'a', 'b',
                  'c', 'd', 'e', 'f' };
        std::string result;
        for (size_t i = 0; i < len; ++i)
        {
                result += hexchars[(s[i] & 0xf0) >> 4];
                result += hexchars[s[i] & 0x0f];
        }
        return result;
}
//! ----------------------------------------------------------------------------
//! \details Encrypt a v2 ectoken
//! \return  NA
//! \param   keydata: ascii text, the encryption passphrase
//! \param   keydatalen: passphrase length
//! \param   in: data to be encrypted
//! \param   out: encrypted data.
//! \param   inlen: length of the in array
//! ----------------------------------------------------------------------------
inline void bfencrypt_v2(const unsigned char *keydata,
                         int keydatalen,
                         const unsigned char *in,
                         unsigned char *out,
                         unsigned int inlen)
{
        BF_KEY key;
        unsigned char ivec[32];
        int num=0;
        // set up for encryption
        BF_set_key(&key, keydatalen, keydata);
        memset(ivec, '\0', 32);
        BF_cfb64_encrypt(in, out, inlen, &key, ivec, &num, BF_ENCRYPT);
}
//! ----------------------------------------------------------------------------
//! \details Decrypt a v2 ectoken
//! \return  NA
//! \param   keydata: ascii text, the encryption passphrase
//! \param   keydatalen: passphrase length
//! \param   in: data to be decrypted
//! \param   out: decrypted data.
//! \param   inlen: length of the in array
//! ----------------------------------------------------------------------------
inline void bfdecrypt_v2(const unsigned char *keydata,
                         int keydatalen,
                         const unsigned char *in,
                         unsigned char *out,
                         unsigned int inlen)
{
        BF_KEY key;
        unsigned char ivec[32];
        int num=0;
        // set up for decryption
        BF_set_key(&key, keydatalen, keydata);
        memset(ivec, '\0', 32);
        BF_cfb64_encrypt(in, out, inlen, &key, ivec, &num, BF_DECRYPT);
}
//! ----------------------------------------------------------------------------
//! \details Decrypt a v2 ectoken
//! \return  decrypted string
//! ----------------------------------------------------------------------------
static std::string do_decrypt_v2(const std::string& key,
                                 const std::string& ciphertext,
                                 const bool verbose)
{
        std::vector<unsigned char> encBin;
        hex2bin(ciphertext.c_str(), encBin);
        std::vector<unsigned char> plaintext(encBin.size());
        bfdecrypt_v2((const unsigned char*) key.c_str(),
                     key.size(),
                     &encBin[0],
                     &plaintext[0],
                     encBin.size());
        const std::string result((const char*) &plaintext[0], plaintext.size());
        if(verbose)
        {
                fprintf(stderr, "decrypt key:    %s (len %zu)\ncipher: %s (len %zu)\nplain:  %s (len %zu)\n",
                        key.c_str(),
                        key.length(),
                        ciphertext.c_str(),
                        ciphertext.length(),
                        result.c_str(),
                        result.length());
        }
        return result;
}
//! ----------------------------------------------------------------------------
//! \details Encrypt a v2 ectoken
//! \return  encrypted string
//! ----------------------------------------------------------------------------
static std::string do_encrypt_v2(const std::string& key,
                                 const std::string& plaintext,
                                 const bool verbose)
{
        std::vector<unsigned char> ciphertext(plaintext.size());
        bfencrypt_v2((const unsigned char*) key.c_str(),
                        key.size(),
                     (const unsigned char*) &plaintext[0],
                     &ciphertext[0],
                     plaintext.size());
        const std::string cipher = bin2hex(&ciphertext[0], plaintext.size());
        if(verbose)
        {
                fprintf(stderr, "encrypt key:    %s (len %zu)\nplain:  %s (len %zu)\ncipher: %s (len %zu)\n",
                        key.c_str(),
                        key.length(),
                        plaintext.c_str(),
                        plaintext.length(),
                        cipher.c_str(),
                        cipher.length());
        }
        return cipher;
}
//! ----------------------------------------------------------------------------
//! ectoken v3
//! ----------------------------------------------------------------------------
//! ----------------------------------------------------------------------------
//! \details Decrypt a v3 ectoken
//! \return  true on success
//!          false  on failure
//! \param   ao_plaintext  Pointer to the string object to populate with result
//!                        on success.  ASSUMPTION: valid string
//! \param   a_key         The key to use to decrypt the
//! \param   a_ciphertext  The text to decrypt
//! \param   a_verbose     Whether to print output to stderr during processing
//!                        or not
//! ----------------------------------------------------------------------------
bool do_decrypt(std::string* ao_plaintext, const std::string& a_key, const std::string& a_ciphertext, bool a_verbose)
{
        bool retval = false;
        int result = 0;
        int token_len = 1024;
        char* token = new char[token_len];
        if((result =
             ectoken_decrypt_token(token, &token_len,
                                   a_ciphertext.c_str(), a_ciphertext.length(),
                                   a_key.c_str(), a_key.length())) < 0)
        {
                // failed
                if(a_verbose)
                {
                        fprintf(stderr, "Failed to decrypt ciphertext: '%s' (len %zu) using key: '%s' (len %zu).  Reason: ", a_ciphertext.c_str(), a_ciphertext.length(),
                                a_key.c_str(), a_key.length());
                        switch (result)
                        {
                        case -1:
                                fprintf(stderr, "failed to decrypt the token with the provided key\n");
                                break;
                        case -2:
                                fprintf(stderr, "failed to validate the cryptographic tag\n");
                                break;
                        case -3:
                                fprintf(stderr, "failed to validate the internal hash\n");
                                break;
                        default:
                                break;
                        }
                }
                goto done;
        }
        ao_plaintext->assign(token, token_len);
        retval = true;
        if(a_verbose)
        {
                fprintf(stderr, "decrypt key:    %s (len %zu)\ncipher: %s (len %zu)\nplain:  %s (len %zu)\n",
                        a_key.c_str(),
                        a_key.length(),
                        a_ciphertext.c_str(),
                        a_ciphertext.length(),
                        ao_plaintext->c_str(),
                        ao_plaintext->length());
        }
done:
        return retval;
}
//! ----------------------------------------------------------------------------
//! \brief   encrypt a v3 ectoken
//! \details Call the C implementation to encrypt/generate a token from a
//!          plaintext string
//! \return  true on success
//!          false  on failure
//! \param   ao_ciphertext Pointer to the string object to populate with the result
//!                        on success.  ASSUMPTION: valid string
//! \param   a_key         The key to use to decrypt the
//! \param   a_plaintext   The text to decrypt
//! \param   a_verbose     Whether to print output to stderr during processing or
//!                        not
//! ----------------------------------------------------------------------------
bool do_encrypt(std::string* ao_ciphertext,
                const std::string& a_key,
                const std::string& a_plaintext,
                bool a_verbose)
{
        bool retval = false;
        int result = 0;
        int token_len = 1024;
        char* token = new char[token_len];
        if((result =
             ectoken_encrypt_token(token, &token_len,
                                   a_plaintext.c_str(), a_plaintext.length(),
                                   a_key.c_str(), a_key.length())) < 0)
        {
                // failed
                if(a_verbose)
                {
                        fprintf(stderr, "Failed to encrypt plaintext: '%s' (len %zu) using key: '%s' (len %zu).  Reason: ", a_plaintext.c_str(), a_plaintext.length(),
                                a_key.c_str(), a_key.length());
                        switch (result)
                        {
                        case -1:
                                fprintf(stderr, "failed to encrypt the token with the provided key\n");
                                break;
                        case -2:
                                fprintf(stderr, "failed to gather the cryptographic tag\n");
                                break;
                        case -3:
                                fprintf(stderr, "failed to generate the internal hash\n");
                                break;
                        default:
                                break;
                        }
                }
                goto done;
        }
        ao_ciphertext->assign(token, token_len);
        retval = true;
        if(a_verbose)
                fprintf(stderr, "decrypt key:    %s (len %zu)\nplain: %s (len %zu)\ncipher:  %s (len %zu)\n",
                        a_key.c_str(), a_key.length(),
                        a_plaintext.c_str(), a_plaintext.length(),
                        ao_ciphertext->c_str(), ao_ciphertext->length());
done:
        return retval;
}
//! ----------------------------------------------------------------------------
//! \details usage
//! ----------------------------------------------------------------------------
static void usage(const char* argv0)
{
        fprintf(stderr,
                "usage: %s [VERSION_OPTION] ACTION_OPTION KEY PLAINTEXT\n"
                "\n"
                "VERSION_OPTION:\n"
                "  -2      Use version2 of the ectoken generation.\n"
                "  -3      Use version3 of the ectoken generation.  Default.\n"
                "\n"
                "ACTION_OPTION:\n"
                "  -e      Encrypt PLAINTEXT using KEY\n"
                "  -E      Encrypt PLAINTEXT using KEY.  Verbose mode\n"
                "  -d      Decrypt PLAINTEXT using KEY\n"
                "  -D      Decrypt PLAINTEXT using KEY.  Verbose mode\n",
                argv0);
        exit(-1);
}
//! ----------------------------------------------------------------------------
//! \details version
//! ----------------------------------------------------------------------------
static void version()
{
        fprintf(stderr, "EC Token encryption and decryption utility.  Version: %s\n", VERSION_STRING);
        exit(0);
}
//! ----------------------------------------------------------------------------
//! \details: main
//! \return:  0 on SUCCESS non-zero on ERROR
//! \param:   argc: ...
//! \param:   argv: ...
//! ----------------------------------------------------------------------------
int main(int argc, char **argv)
{
        if(argc == 2 &&
            std::string(argv[1]) == "--version")
        {
                version();
        }
        if(argc < 4)
        {
                usage(argv[0]);
        }
        int action_option_idx = 1;
        bool v2 = false;
        bool force_v3 = false;
        if(argc == 5)
        {
                ++action_option_idx;
                const std::string version_option(argv[1]);
                if(version_option == "-2" ||
                    version_option == "--v2")
                {
                        v2 = true;
                }
                else if(version_option == "-3" ||
                    version_option == "--v3")
                {
                        v2 = false;
                        force_v3 = true;
                }
                else
                {
                        usage(argv[0]);
                }
        }
        // initialize the ectoken library functions
        ectoken_init();
        const std::string action_option(argv[action_option_idx]);
        const std::string key(argv[action_option_idx + 1]);
        bool verbose = false;
        if(action_option == "-d" ||
            action_option == "-D")
        {
                if(action_option == "-D") verbose = true;
                const std::string ciphertext(argv[action_option_idx + 2]);
                std::string plain;
                if(v2)
                {
                        plain = do_decrypt_v2(key, ciphertext, verbose);
                }
                else
                {
                        if(false == do_decrypt(&plain, key,
                                                ciphertext, verbose))
                        {
                                // failed
                                if(force_v3)
                                {
                                        fprintf(stderr, "Failed to decrypt v3 ciphertext\n");
                                        return -1;
                                }
                                // not forced
                                // drop back to v2
                                plain = do_decrypt_v2(key, ciphertext, verbose);
                                v2 = true;
                        }
                }
                if(verbose) fprintf(stderr, "\n");
                else fprintf(stdout, "%s\n", plain.c_str());
                std::string cipher2;
                if(v2)
                {
                        cipher2 = do_encrypt_v2(key, plain, verbose);
                        if(cipher2 != ciphertext)
                        {
                                fprintf(stderr, "\nWARNING: re-encrypted ciphertext does not match original");
                                if(verbose)
                                {
                                        fprintf(stderr, " ('%s' vs '%s')\n", cipher2.c_str(), ciphertext.c_str());
                                }
                                else
                                {
                                        fprintf(stderr, "\n");
                                }
                                return -1;
                        }
                }
        }
        else if(action_option == "-e" ||
                 action_option == "-E")
        {
                if(action_option == "-E")
                {
                        verbose = true;
                }
                const std::string plaintext(argv[action_option_idx + 2]);
                std::string cipher;
                if(v2)
                {
                        cipher = do_encrypt_v2(key, plaintext, verbose);
                }
                else
                {
                        if(false == do_encrypt(&cipher, key,
                                                plaintext, verbose))
                        {
                                // failed
                                fprintf(stderr, "Failed to encrypt v3 plaintext\n");
                                return -1;
                        }
                }
                if(verbose) fprintf(stderr, "\n");
                else fprintf(stdout, "%s\n", cipher.c_str());
                std::string plain2;
                if(v2)
                {
                        plain2 = do_decrypt_v2(key, cipher, verbose);
                }
                else
                {
                        if(false == do_decrypt(&plain2, key,
                                                cipher, verbose))
                        {
                                // failed
                                fprintf(stderr, "Failed to re-decrypt v3 ciphertext\n");
                                return -1;
                        }
                }
                if(plain2 != plaintext)
                {
                        fprintf(stderr, "\nWARNING: re-decrypted plaintext does not match original!\n");
                        return -1;
                }
        }
        else
        {
                usage(argv[0]);
        }
        return 0;
}
