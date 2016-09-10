#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <string.h>

#include "php.h"
#include "php_ectoken.h"
#include "ectoken_v3.h"

#pragma mark ======== Preprocessor tables ========

/*******************************************************************************
 * constants
 *******************************************************************************/
// Set limit to 512
#define kMAX_TOKEN_LENGTH 512

/***********************************************************
 * Max length to support extra random sentinels is
 * example -using min=4 max=8 and query parameter is "r"
 *   &r=rand_str[4-8]...&r=rand_str[4-8]
 *   2x("&r=") + 2x8 (max random str size)
 *   6 + 16 == 22
 ***********************************************************/
#define kRAND_QUERY_STR "r"
#define kRAND_QUERY_SIZE (sizeof(kRAND_QUERY_STR) + 1)
#define kRAND_STR_SIZE_MIN 4
#define kRAND_STR_SIZE_MAX 8
#define kMAX_TOKEN_RAND_LENGTH (kMAX_TOKEN_LENGTH - ((2*kRAND_QUERY_SIZE)+(2*kRAND_STR_SIZE_MAX)))

/*******************************************************************************
 * macros
 *******************************************************************************/
#define n2l(c,l) (l =((unsigned long)(*((c)++)))<<24L, \
                  l|=((unsigned long)(*((c)++)))<<16L, \
                  l|=((unsigned long)(*((c)++)))<< 8L, \
                  l|=((unsigned long)(*((c)++))))

#define l2n(l,c) (*((c)++)=(unsigned char)(((l)>>24L)&0xff), \
                  *((c)++)=(unsigned char)(((l)>>16L)&0xff), \
                  *((c)++)=(unsigned char)(((l)>> 8L)&0xff), \
                  *((c)++)=(unsigned char)(((l)     )&0xff))

#pragma mark ======== Function Prototypes ========

#pragma mark ======== PHP macros ========

static zend_function_entry ectoken_functions[] = {
    PHP_FE(ectoken_init, NULL)
    PHP_FE(ectoken_encrypt_token, NULL)
    PHP_FE(ectoken_decrypt_token, NULL)
    {NULL, NULL, NULL}
};

zend_module_entry ectoken_module_entry = {
#if ZEND_MODULE_API_NO >= 20010901
    STANDARD_MODULE_HEADER,
#endif
    PHP_ECTOKEN_EXTNAME,
    ectoken_functions,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
#if ZEND_MODULE_API_NO >= 20010901
    PHP_ECTOKEN_VERSION,
#endif
    STANDARD_MODULE_PROPERTIES
};

#ifdef COMPILE_DL_ECTOKEN
ZEND_GET_MODULE(ectoken)
#endif

#if PHP_MAJOR_VERSION >= 7
#define _RETVAL_STRINGL(str, len) RETVAL_STRINGL(str, len); efree(str);
#define PARSE_PARAM_LEN_T size_t
#else
#define _RETVAL_STRINGL(str, len) RETVAL_STRINGL(str, len, 0)
#define PARSE_PARAM_LEN_T int
#endif

#pragma mark ======== PHP Functionality ========

PHP_FUNCTION(ectoken_init)
{
        if (-1 == ectoken_init())
        {
                RETURN_FALSE;
        }
        RETURN_TRUE;
}

PHP_FUNCTION(ectoken_decrypt_token)
{
        char *key;
        char *token;
        PARSE_PARAM_LEN_T key_len, token_len = 0;
        // Parse the incoming variables
#ifdef ZEND_ENGINE_2
        zval *this = getThis();
#endif
        if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ss", &key,
                                  &key_len, &token, &token_len) == FAILURE)
        {
                RETURN_NULL();
        }

        int plaintext_length = ectoken_decrypt_required_size(token_len);
        char* plaintext = emalloc(sizeof(char)*plaintext_length);

        int ret = ectoken_decrypt_token(plaintext, &plaintext_length,
                                        token, token_len,
                                        key, key_len);
        if (ret < 0)
        {
                efree(plaintext);
                RETURN_NULL();
        }
        _RETVAL_STRINGL(plaintext, plaintext_length);

}

PHP_FUNCTION(ectoken_encrypt_token)
{
        char *key;
        char *query_string;
        PARSE_PARAM_LEN_T key_len, query_string_len = 0;
        // Parse the incoming variables
#ifdef ZEND_ENGINE_2
        zval *this = getThis();
#endif
        if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ss", &key,
                                  &key_len, &query_string,
                                  &query_string_len) == FAILURE)
        {
                RETURN_NULL();
        }

        int ciphertext_length = ectoken_encrypt_required_size(query_string_len);
        char* ciphertext = emalloc(sizeof(char)*ciphertext_length);

        int ret = ectoken_encrypt_token(ciphertext, &ciphertext_length,
                                        query_string, query_string_len,
                                        key, key_len);

        if (ret < 0)
        {
                efree(ciphertext);
                RETURN_NULL();
        }
        _RETVAL_STRINGL(ciphertext, ciphertext_length);
}

#pragma mark ======== Non-PHP crypto functions ========
