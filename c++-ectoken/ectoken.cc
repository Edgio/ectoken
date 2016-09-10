/*********** -*- mode: c++; c-file-style: "linux"; -*- **********
 *
 * Copyright (c) 2007-2009 EdgeCast Networks, Inc.
 * All Rights Reserved
 *
 * $Id$
 *
 * Compile this file with "c++ ectoken.cc -o ectoken -lcrypto"
 *
 ****************************************************************/

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#define VERSION_STRING "3.0.0"

extern "C" {
#include "ectoken_v3.h"
}


static void usage(const char* argv0)
{
        fprintf(stderr,
                "usage: %s [VERSION_OPTION] ACTION_OPTION KEY PLAINTEXT\n"
                "\n"
                "ACTION_OPTION:\n"
                "  -e      Encrypt PLAINTEXT using KEY\n"
                "  -E      Encrypt PLAINTEXT using KEY.  Verbose mode\n"
                "  -d      Decrypt PLAINTEXT using KEY\n"
                "  -D      Decrypt PLAINTEXT using KEY.  Verbose mode\n",
                argv0);
        exit(-1);
}


static void version()
{
        fprintf(stderr, "EC Token encryption and decryption utility.  Version: %s\n", VERSION_STRING);
        exit(0);
}


////////////////////////////////////////////////////////
//
//  v3 FUNCTIONALITY
//
////////////////////////////////////////////////////////


/// \brief   Decrypt a v3 ectoken
/// \details Call the C implementation
/// \return  true on success
///          false  on failure
/// \param   ao_plaintext  Pointer to the string object to populate with the result on success.  ASSUMPTION: valid string
/// \param   a_key         The key to use to decrypt the
/// \param   a_ciphertext  The text to decrypt
/// \param   a_verbose     Whether to print output to stderr during processing or not
bool do_decrypt(std::string* ao_plaintext, const std::string& a_key, const std::string& a_ciphertext, bool a_verbose)
{

        bool retval = false;

        int result = 0;
        int token_len = 1024;
        char* token = new char[token_len];

        if ((result =
             ectoken_decrypt_token(token, &token_len,
                                   a_ciphertext.c_str(), a_ciphertext.length(),
                                   a_key.c_str(), a_key.length())) < 0)
        {
                // failed

                if (a_verbose)
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
        if (a_verbose)
                fprintf(stderr, "decrypt key:    %s (len %zu)\ncipher: %s (len %zu)\nplain:  %s (len %zu)\n",
                        a_key.c_str(), a_key.length(),
                        a_ciphertext.c_str(), a_ciphertext.length(),
                        ao_plaintext->c_str(), ao_plaintext->length());

done:
        return retval;

}

/// \brief   encrypt a v3 ectoken
/// \details Call the C implementation to encrypt/generate a token from a plaintext string
/// \return  true on success
///          false  on failure
/// \param   ao_ciphertext Pointer to the string object to populate with the result on success.  ASSUMPTION: valid string
/// \param   a_key         The key to use to decrypt the
/// \param   a_plaintext   The text to decrypt
/// \param   a_verbose     Whether to print output to stderr during processing or not
bool do_encrypt(std::string* ao_ciphertext, const std::string& a_key, const std::string& a_plaintext, bool a_verbose)
{

        bool retval = false;

        int result = 0;
        int token_len = 1024;
        char* token = new char[token_len];

        if ((result =
             ectoken_encrypt_token(token, &token_len,
                                   a_plaintext.c_str(), a_plaintext.length(),
                                   a_key.c_str(), a_key.length())) < 0)
        {
                // failed

                if (a_verbose)
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
        if (a_verbose)
                fprintf(stderr, "decrypt key:    %s (len %zu)\nplain: %s (len %zu)\ncipher:  %s (len %zu)\n",
                        a_key.c_str(), a_key.length(),
                        a_plaintext.c_str(), a_plaintext.length(),
                        ao_ciphertext->c_str(), ao_ciphertext->length());

done:
        return retval;

}




////////////////////////////////////////////////////////
//
//  standalone functionality
//
////////////////////////////////////////////////////////

int main(int argc, char **argv)
{

        if (argc == 2 &&
            std::string(argv[1]) == "--version")
                version();

        if (argc < 4)
                usage(argv[0]);
        int action_option_idx = 1;

        // initialize the ectoken library functions
        ectoken_init();

        const std::string action_option(argv[action_option_idx]);
        const std::string key(argv[action_option_idx + 1]);

        bool verbose = false;

        if (action_option == "-d" ||
            action_option == "-D")
        {
                if (action_option == "-D") verbose = true;

                const std::string ciphertext(argv[action_option_idx + 2]);
                std::string plain;
                if (false == do_decrypt(&plain, key,
                                        ciphertext, verbose))
                {
                        // failed
                        fprintf(stderr, "Failed to decrypt v3 ciphertext\n");
                        return -1;
                }
                if (verbose) fprintf(stderr, "\n");
                else fprintf(stdout, "%s\n", plain.c_str());
        }
        else if (action_option == "-e" ||
                 action_option == "-E")
        {
                if (action_option == "-E") verbose = true;

                const std::string plaintext(argv[action_option_idx + 2]);
                std::string cipher;
                if (false == do_encrypt(&cipher, key,
                                        plaintext, verbose))
                {
                        // failed
                        fprintf(stderr, "Failed to encrypt v3 plaintext\n");
                        return -1;
                }
                if (verbose) fprintf(stderr, "\n");
                else fprintf(stdout, "%s\n", cipher.c_str());
                std::string plain2;
                if (false == do_decrypt(&plain2, key,
                                        cipher, verbose))
                {
                        // failed
                        fprintf(stderr, "Failed to re-decrypt v3 ciphertext\n");
                        return -1;
                }
                if (plain2 != plaintext)
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
