//
// Created by alisrasic on 11/22/22.
//

#ifndef FLUENT_BIT_PLUGINS_FILTER_ENCRYPT_UTILS_CRYPTO_UTILS_H_
#define FLUENT_BIT_PLUGINS_FILTER_ENCRYPT_UTILS_CRYPTO_UTILS_H_
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <stdio.h>
#include <stdlib.h>

void generate_key_from_pbkdf2(char *passphrase, char *pbkdf2_salt, unsigned char *out, int iterations, int key_length);
#endif //FLUENT_BIT_PLUGINS_FILTER_ENCRYPT_UTILS_CRYPTO_UTILS_H_
