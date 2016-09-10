#include <stdio.h>

#include "ectoken_v3.c"

int test_message_building(unsigned char* a_orig_iv, int a_orig_iv_len,
                          unsigned char* a_orig_ct, int a_orig_ct_len,
                          unsigned char* a_orig_tag, int a_orig_tag_len)
{
        printf("\ntest_message_building\n");
        int l_msg_len = a_orig_iv_len  + a_orig_ct_len + a_orig_tag_len;
        l_msg_len *= 10; /* ensure we have plenty of space */
        unsigned char l_msg[l_msg_len];
        unsigned char l_ct[l_msg_len];
        unsigned char l_iv[a_orig_iv_len+1];
        unsigned char l_tag[a_orig_tag_len+1];

        OPENSSL_cleanse(l_iv, a_orig_iv_len+1);
        OPENSSL_cleanse(l_ct, l_msg_len+1);
        OPENSSL_cleanse(l_tag, a_orig_tag_len+1);
        int len = construct_base64_encoded_token(l_msg, &l_msg_len, a_orig_iv,
                                                 a_orig_iv_len, a_orig_tag,
                                                 a_orig_tag_len, a_orig_ct,
                                                 a_orig_ct_len);
        l_msg[l_msg_len] = 0;
        if (len < 0)
        {
                printf("l_msg\t%s\n", l_msg);
                return -1;
        }
        if (l_msg_len <= a_orig_ct_len + a_orig_iv_len + a_orig_tag_len)
        {
                printf("l_msg_len was bad, %d, %zd\n", l_msg_len, strlen((char*)l_msg));
                return -1;
        }

        len = deconstruct_base64_encoded_token(l_ct, l_iv, a_orig_iv_len,
                                               l_tag, a_orig_tag_len, l_msg,
                                               l_msg_len);
        if (len <= 0                                    ||
            len != strlen((char*)l_ct)                  ||
            memcmp(l_iv, a_orig_iv, a_orig_iv_len) != 0 ||
            memcmp(l_ct, a_orig_ct, a_orig_ct_len) != 0 ||
            memcmp(l_tag, a_orig_tag, a_orig_tag_len) != 0)
        {
                printf("len was bad, %d, %zd\n", len, strlen((char*)l_ct));
                printf("l_msg\t\t%s\n", l_msg);
                printf("l_iv\t\t%s\n", l_iv);
                printf("a_orig_iv\t%s\n", a_orig_iv);
                printf("l_ct\t\t%s\n", l_ct);
                printf("a_orig_ct\t%s\n", a_orig_ct);
                printf("l_tag\t\t%s\n", l_tag);
                printf("a_orig_tag\t%s\n", a_orig_tag);
                return -1;
        }

        printf("success\n");
        return 0;
}

int test_decrypt_garbage()
{
        printf("\ntest_decrypt_garbage\n");
        unsigned char l_iv[] = {
                0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0,
        };
        unsigned char l_garbage[] = {
                1, 2, 3, 4, 5, 6, 7, 8,
                9, 0, 1, 2, 3, 4, 5, 6,
        };
        unsigned char l_tag[] = {
                0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0,
        };
        unsigned char l_key[] = "12345678901234567890123456789012";
        int l_plaintext_len = 128;
        unsigned char l_plaintext[l_plaintext_len];

        int l_ret = ec_decrypt(l_plaintext, &l_plaintext_len, l_garbage, 16,
                            l_key, l_iv, 16, l_tag, 16);

        if (l_ret != -7)
        {
                printf("Authentication did not fail. l_ret was %d\n", l_ret);
                return -1;
        }

        printf("success\n");
        return 0;
}

int test_encrypt_decrypt(const unsigned char* a_message,
                         const int a_message_len,
                         const unsigned char a_key[32],
                         const unsigned char a_iv[16])
{
        printf("\ntest_encrypt_decrypt:\t%s\n", a_message);
        int ret = 0;
        const int l_key_len = 32;
        const int l_iv_len  = 16;
        const int l_tag_len = 16;
        unsigned char l_tag[l_tag_len];

        int l_plaintext_len = a_message_len*10;
        int l_ciphertext_len = l_plaintext_len;
        unsigned char l_ciphertext[l_ciphertext_len];
        unsigned char l_plaintext[l_plaintext_len];
        OPENSSL_cleanse(l_plaintext, a_message_len*10);

        int i;
        ret = ec_encrypt(l_ciphertext, &l_ciphertext_len, l_tag, a_message,
                      a_message_len, a_key, a_iv,
                          l_iv_len);
        if (ret < 0) {
                printf("a_message:\t");
                for (i = 0; i < a_message_len; ++i)
                        printf("%02x", a_message[i]);
                printf("\n");
                printf("a_key:\t");
                for (i = 0; i < l_key_len; ++i)
                        printf("%02x", a_key[i]);
                printf("\n");
                printf("a_iv:\t");
                for (i = 0; i < l_iv_len; ++i)
                        printf("%02x", a_iv[i]);
                printf("\n");
                printf("l_ciphertext_len:\t%d\n", l_ciphertext_len);
                printf("l_ciphertext:\t");
                for (i = 0; i < l_ciphertext_len; ++i)
                        printf("%02x", l_ciphertext[i]);
                printf("\n");
                printf("l_tag:\t");
                for (i = 0; i < l_tag_len; ++i)
                        printf("%02x", l_tag[i]);
                printf("\n");
                return 1;
        }

        ret = ec_decrypt(l_plaintext, &l_plaintext_len, l_ciphertext,
                      l_ciphertext_len, a_key, a_iv, l_iv_len, l_tag,
                      l_tag_len);

        if (ret != 0)
        {
                printf("ret was %d\n", ret);
                return 1;
        }

        if (l_plaintext_len <= 0)
        {
                printf("%d\n", l_plaintext_len);
                printf("%s\n", l_plaintext);
                return 1;
        }

        if (l_plaintext_len != a_message_len ||
            memcmp(a_message, l_plaintext, a_message_len) != 0)
        {
                printf("a_message was: %s\n", a_message);
                printf("decryl_plaintexted a_message was: %s\n", l_plaintext);
                return 1;
        }

        printf("success\n");
        return ret;
}

int test_full_flow(const char* a_query_string, const int a_query_string_len,
                   const char* a_key, const int a_key_len)
{
        printf("\ntest_full_flow\n");
        int l_ciphertext_len = ectoken_encrypt_required_size(a_query_string_len);
        unsigned char l_ciphertext[l_ciphertext_len];
        int l_ret = 0;

        l_ret = ectoken_encrypt_token((char*)l_ciphertext, &l_ciphertext_len,
                                      a_query_string, a_query_string_len,
                                      (char*)a_key, a_key_len);

        if (l_ret != 0)
        {
                int i;
                printf("encrypt failed, l_ret nonzero, %d\n", l_ret);
                printf("a_key:\t\t");
                for (i = 0; i < a_key_len; ++i)
                        printf("%02x", a_key[i]);
                printf("\n");
                return 0;
        }

        int l_decrypted_str_len = ectoken_decrypt_required_size(l_ciphertext_len);
        if (l_decrypted_str_len == 0)
        {
                printf("l_decrypted_str_len was 0, ct_len: %d!\n", l_ciphertext_len);
                return 1;
        }
        char l_decrypted_str[l_decrypted_str_len];
        memset(l_decrypted_str, 0, l_decrypted_str_len);

        l_ret = ectoken_decrypt_token(l_decrypted_str, &l_decrypted_str_len,
                                      (char*)l_ciphertext, l_ciphertext_len,
                                      (char*)a_key, a_key_len);
        if (l_ret != 0)
        {
                int i;
                printf("decrypt failed, l_ret nonzero, %d\n", l_ret);
                printf("token:\t%s\n", l_ciphertext);
                printf("l_ciphertext:\t%s\n", l_ciphertext);
                printf("a_key:\t\t");
                for (i = 0; i < a_key_len; ++i)
                        printf("%02x", a_key[i]);
                printf("\n");
                return 0;
        }

        if (memcmp(l_decrypted_str, a_query_string, a_query_string_len) != 0)
        {
                printf("token: %s\n", l_decrypted_str);
                printf("l_decrypted_str was wrong, %s != l_decrypted_str\n", l_decrypted_str);
        }

        printf("success\n");
        return 0;
}

int test_bad_decrypt_args(const char* a_ciphertext, const int a_ciphertext_len,
                          const char* a_key, const int a_key_len)
{
        printf("test_bad_decrypt_args: %d\n", a_ciphertext_len);
        int l_decrypted_str_len = 100;
        char l_decrypted_str[l_decrypted_str_len];

        int l_ret = ectoken_decrypt_token(l_decrypted_str, &l_decrypted_str_len,
                                          (char*)a_ciphertext, a_ciphertext_len,
                                          (char*)a_key, a_key_len);

        if (l_ret == -3)
                printf("success\n");

        return 0;
}

int test_sha256(unsigned char* a_text, int a_text_len,
                unsigned char* a_known_sha, int a_known_len)
{
        printf("\ntest_sha256\n");
        unsigned char l_sha[a_known_len];
        int l_len = sha256(l_sha, a_text, a_text_len);
        if (l_len <= 0)
        {
                printf("sha256 returned %d\n", l_len);
                return 1;
        }

        if (memcmp(a_known_sha, l_sha, a_known_len) != 0)
        {
                int i;
                printf("l_sha did not match a_known_sha\n");
                printf("l_sha:\t\t");
                for (i = 0; i < l_len; ++i)
                        printf("%02x", l_sha[i]);
                printf("\na_known_sha:\t");
                for (i = 0; i < a_known_len; ++i)
                        printf("%02x", a_known_sha[i]);
                printf("\n");
                return 1;
        }

        printf("success\n");
        return 0;
}

int test_random_nonce()
{
        printf("\ntest_random_nonce\n");
        int l_nonce_len = 8;
        unsigned char l_nonce[l_nonce_len];
        memset(l_nonce, 5, l_nonce_len);
        int l_len = generate_nonce(l_nonce, &l_nonce_len);
        if (l_len < 0)
        {
                printf("generate nonce failed\n");
                return -1;
        }

        int i, j;
        int l_good = 0;
        for (i = 0; i < l_nonce_len; ++i) {
                if (l_nonce[i] == 5)
                {
                        printf("l_nonce has improper value: l_nonce[%d] = %d\n", i, l_nonce[i]);
                        return -1;
                }
                for (j = 0; j < s_alphanum_len; ++j)
                {
                        if (l_nonce[i] == s_alphanum[j])
                        {
                                l_good++;
                                break;
                        }
                }
        }
        if (l_good != l_nonce_len)
        {
                printf("All values in l_nonce not in s_alphanum\n");
                printf("l_nonce:\t\t");
                for (i = 0; i < l_nonce_len; ++i)
                        printf("%02x", l_nonce[i]);
                printf("\n");
                return -1;
        }
        printf("success\n");

        return 0;
}

int test_base64_encode_decode()
{
        printf("\ntest_base64_encode_decode\n");
        const char l_text[] = {
                0x0, 0x0
        };
        char l_b64[100];
        char l_result[2];
        memset(l_b64, 0, 100);
        memset(l_result, 0, 2);

        int l_len = url_safe_base64_encode(l_b64, l_text, 2);

        l_len = base64_decode_binary((unsigned char*)l_result, l_b64, l_len);

        if (l_len != 2)
        {
                printf("l_len bad %d\n", l_len);
                return -1;
        }

        if (memcmp(l_text, l_result, l_len))
        {
                int i;
                printf("l_text != l_result\n");
                printf("l_text:\t\t");
                for (i = 0; i < l_len; ++i)
                        printf("%02x", l_text[i]);
                printf("\n");
                printf("l_result:\t\t");
                for (i = 0; i < l_len; ++i)
                        printf("%02x", l_result[i]);
                printf("\n");
                return -1;
        }

        printf("success\n");
        return 0;
}

int test_correct_size_calculations(size_t a_initial)
{
        size_t l_encrypted, l_decrypted;

        l_encrypted = ectoken_encrypt_required_size(a_initial);
        l_decrypted = ectoken_decrypt_required_size(l_encrypted);

        if (l_decrypted < a_initial)
        {
                printf("%lu\t%lu\t%lu\n", a_initial, l_decrypted, l_encrypted);
                return -1;
        }
        return 0;
}

int test_short_size_calculations(size_t a_initial)
{
        printf("test_short_size_calculations\n");
        size_t l_decrypted;

        l_decrypted = ectoken_decrypt_required_size(a_initial);
        if (l_decrypted != 0)
        {
                printf("l_decrypted != 0, %zd\n", l_decrypted);
                return 1;
        }
        printf("success\n");
        return 0;
}

int main()
{
        ectoken_init();

        {
                int i;
                // b64 encoded tokens need to be ((12+16)*8)/6 = 37 bytes to
                // hold the full tag and IV, so we check we get 0 for that
                // range of lengths
                for (i = 0; i < 38; ++i)
                {
                        test_short_size_calculations(i);
                }
        }

        {
                printf("\ntest_correct_size_calculations\n");
                int l_status = 0;
                int i;
                for(i = 0; i < 8192; ++i)
                {
                        l_status |= test_correct_size_calculations(i);
                }
                if(!l_status)
                {
                        printf("success\n");
                }
        }

        {
                unsigned char l_iv[]  = "54b8617eca0e54c7d3c8e6732c6b687a";
                unsigned char l_tag[] = "632ecdeae131a273";
                unsigned char l_ct[]  = "This is only a test. I repeat, this is only a test. A kitten test. I love kittens. :D :D :D :D :D nyan~";
                test_message_building(l_iv, strlen((char*)l_iv), l_ct,
                                      strlen((char*)l_ct), l_tag,
                                      strlen((char*)l_tag));
        }
        {
                unsigned char l_text[] = "kitties";
                unsigned char l_known_sha[] = {
                        0xbc, 0xcd, 0x8e, 0x33, 0x03, 0x36, 0xef, 0x38,
                        0xd0, 0xd7, 0xcc, 0x83, 0x99, 0xce, 0xcb, 0x2d,
                        0xa7, 0xd7, 0xc1, 0xbb, 0x40, 0x2f, 0xce, 0x2a,
                        0x5b, 0xb3, 0xa5, 0x82, 0xd4, 0x6d, 0xc0, 0xbe
                };
                test_sha256(l_text, strlen((char*)l_text), l_known_sha, 32);
        }
        {
                unsigned char l_text[] = {
                        'k', 'i', 't', 't', 'i', 'e', 's', 0,
                        0,   0,   0,   0,   0,   0,   0,   0
                };
                unsigned char l_known_sha[] = {
                        0xe4, 0xd6, 0xb7, 0xc9, 0x45, 0x76, 0x4a, 0x17,
                        0x6d, 0x2b, 0xad, 0x85, 0x5a, 0x43, 0x3d, 0x5b,
                        0xfb, 0xee, 0x32, 0xf4, 0xbd, 0xc7, 0x26, 0x7d,
                        0xba, 0x9d, 0xc3, 0x06, 0x73, 0xe0, 0x8e, 0xdb
                };
                test_sha256(l_text, 16, l_known_sha, 32);
        }
        {
                const unsigned char l_message[] = "kitties are cute :3kitties are cute :3kitties are cute :3";
                const unsigned char l_key[] = {
                        0xf7, 0x68, 0x4e, 0xcd, 0xf4, 0x20, 0x02, 0x75,
                        0xf6, 0x26, 0xea, 0x5e, 0xdb, 0xc2, 0x49, 0x80,
                        0x00, 0x68, 0x17, 0x79, 0x73, 0x26, 0xef, 0x75,
                        0xc7, 0x22, 0xe8, 0x51, 0x96, 0x48, 0x28, 0x62
                };
                const unsigned char l_iv[] = "ea34cdca466b86b1ea34cdca466b86b1";
                test_encrypt_decrypt(l_message, strlen((char*)l_message),
                                     l_key, l_iv);
        }
        {
                const unsigned char l_message[] = "a";
                const unsigned char l_key[] = {
                        0xf7, 0x68, 0x4e, 0xcd, 0xf4, 0x20, 0x02, 0x75,
                        0xf6, 0x26, 0xea, 0x5e, 0xdb, 0xc2, 0x49, 0x80,
                        0x00, 0x68, 0x17, 0x79, 0x73, 0x26, 0xef, 0x75,
                        0xc7, 0x22, 0xe8, 0x51, 0x96, 0x48, 0x28, 0x62
                };
                const unsigned char l_iv[] = "ea34cdca466b86b1ea34cdca466b86b1";
                test_encrypt_decrypt(l_message, strlen((char*)l_message),
                                     l_key, l_iv);
        }
        test_base64_encode_decode();
        test_decrypt_garbage();
        test_random_nonce();

        {
                const char l_token[] = "";
                const char l_key[] = "kitties";
                test_bad_decrypt_args(l_token, strlen(l_token),
                                      l_key, strlen(l_key));
        }
        {
                const char l_token[] = "a";
                const char l_key[] = "kitties";
                test_bad_decrypt_args(l_token, strlen(l_token),
                                      l_key, strlen(l_key));
        }
        {
                const char l_token[] = "1234567890123456789012345678901";
                const char l_key[] = "kitties";
                test_bad_decrypt_args(l_token, strlen(l_token),
                                      l_key, strlen(l_key));
        }
        {
                const char l_token[] = "12345678901234567890123456789012";
                const char l_key[] = "kitties";
                test_bad_decrypt_args(l_token, strlen(l_token),
                                      l_key, strlen(l_key));
        }
        {
                const char l_token[] = "1234567890123456789012345678901234567";
                const char l_key[] = "kitties";
                test_bad_decrypt_args(l_token, strlen(l_token),
                                      l_key, strlen(l_key));
        }

        {
                const char l_query_string[] = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
                const char l_key[] = "kitties";
                test_full_flow(l_query_string, strlen(l_query_string),
                               l_key, strlen(l_key));
        }
        {
                const char l_query_string[] = "a";
                const char l_key[] = "kitties";
                test_full_flow(l_query_string, strlen(l_query_string),
                               l_key, strlen(l_key));
        }
        {
                const char l_query_string[] = "a";
                const char l_key[] = "a";
                test_full_flow(l_query_string, strlen(l_query_string),
                               l_key, strlen(l_key));
        }
        {
                const char l_query_string[] =
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                ;
                const char l_key[] = "a";
                test_full_flow(l_query_string, strlen(l_query_string),
                               l_key, strlen(l_key));
        }
        {
                const char l_query_string[] = "a";
                const char l_key[] =
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                ;
                test_full_flow(l_query_string, strlen(l_query_string),
                               l_key, strlen(l_key));
        }
        {
                const char l_query_string[] =
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                ;
                const char l_key[] =
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                        "01234567890123456789012345678901234567890123456789"
                ;
                test_full_flow(l_query_string, strlen(l_query_string),
                               l_key, strlen(l_key));
        }
        return 0;
}
