/**
 * \file     mod_vulture_const_global.c
 * \authors  Hugo Soszynski
 * \version  1.0
 * \date     21/12/17
 * \license  GPLv3
 * \brief   mod_vulture global constant content
 */

#include <openssl/ossl_typ.h>
#include <mod_vulture.h>
#include <openssl/evp.h>

/***************************/
/* OpenSSL Ciphers Binding */
/***************************/

const cipher_func_t OPENSSL_CIPHERS[NBR_CIPHERS] = {
    EVP_enc_null,
    EVP_rc4,
    EVP_aes_128_cfb,
    EVP_aes_256_cfb
};

const char* OPENSSL_CIPHERS_NAME[NBR_CIPHERS] = {
    "None",
    "rc4",
    "aes128",
    "aes256"
};