//! ----------------------------------------------------------------------------
//! Copyright Verizon.
//!
//! \file:    ec_encrypt.c
//! \details: TODO
//!
//! Licensed under the terms of the Apache 2.0 open source license.
//! Please refer to the LICENSE file in the project root for the terms.
//! ----------------------------------------------------------------------------
//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "ectoken.h"
//! ----------------------------------------------------------------------------
//! types
//! ----------------------------------------------------------------------------
typedef enum {
     EC_ACTION_ENCRYPT = 0,
     EC_ACTION_DECRYPT,
} ec_action_t;
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int print_usage(void)
{
        printf("Usage: \n");
        printf(" To Encrypt:\n");
        printf("     ec_encrypt <key> <text>\n");
        printf(" or:\n");
        printf("     ec_encrypt encrypt <key> <text>\n");
        printf(" To Decrypt:\n");
        printf("     ec_encrypt decrypt <key> <text>\n");
        return 0;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int main(int argc, char **argv)
{
        ec_action_t ec_action = EC_ACTION_ENCRYPT;
        char *key = NULL;
        char *string = NULL;
        if (argc == 2 &&
            strcmp("--version", argv[1]) == 0)
        {
                fprintf(stderr, "EC Token encryption and decryption utility.  Version: 3.0.0\n");
                return 0;
        }
        // Action specified
        if(argc == 4)
        {
                char *action = argv[1];
                key = argv[2];
                string = argv[3];
                if(0 == strncmp(action, "encrypt", sizeof("encrypt")))
                {
                        ec_action = EC_ACTION_ENCRYPT;
                }
                else if(0 == strncmp(action, "decrypt", sizeof("decrypt")))
                {
                        ec_action = EC_ACTION_DECRYPT;
                }
                else
                {
                        printf("Error unrecognized action type %s -valid actions are encrypt or decrypt\n", action);
                        print_usage();
                        return 0;
                }
        }
        // Action NOT specified -assume encrypt
        else if(argc == 3)
        {
                ec_action = EC_ACTION_ENCRYPT;
                key = argv[1];
                string = argv[2];
        }
        // Invalid number of arguments specified
        else
        {
                printf("Error wrong number of arguments specified\n");
                print_usage();
                return -1;
        }
        size_t l_key_len = strlen(key);
        size_t l_string_len = strlen(string);
        if (ec_action == EC_ACTION_ENCRYPT)
        {
                int l_token_len = (l_string_len+(16*2))*4;
                char l_token[l_token_len];
                int l_ret = ectoken_encrypt_token(l_token, &l_token_len,
                                                  string, l_string_len,
                                                  key, l_key_len);
                if (l_ret < 0)
                {
                        printf("Encryption failed: %d\n", l_ret);
                        return -1;
                }
                printf("%s\n", l_token);
        }
        else if (ec_action == EC_ACTION_DECRYPT)
        {
                int l_plaintext_len = l_string_len;
                char l_plaintext[l_plaintext_len];
                int l_ret = ectoken_decrypt_token(l_plaintext,
                                                  &l_plaintext_len,
                                                  string, l_string_len,
                                                  key, l_key_len);
                if (l_ret < 0)
                {
                        printf("Decryption failed: %d\n", l_ret);
                        return -1;
                }
                printf("%s\n", l_plaintext);
        }
        return 0;
}
