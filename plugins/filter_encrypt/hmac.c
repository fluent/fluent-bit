//
// Created by alisrasic on 10/10/22.
//
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include "utils.h"


unsigned char *mx_hmac_sha256(const void *key, int keylen,
                              const unsigned char *data, int datalen,
                              unsigned char *result, unsigned int *resultlen) {

    char* hash_value = HMAC(EVP_sha256(), key, keylen, data, datalen, result, resultlen);
    return hash_value;
}