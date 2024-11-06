#ifndef FLUENT_BIT_PLUGINS_FILTER_ENCRYPT_UTILS_CRYPTO_UTILS_H_
#define FLUENT_BIT_PLUGINS_FILTER_ENCRYPT_UTILS_CRYPTO_UTILS_H_
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <stdio.h>
#include <stdlib.h>
#include "utils.h"

void crypto_utils_generate_key_from_pbkdf2(char *passphrase, char *pbkdf2_salt, unsigned char *out, int iterations, int key_length);
void derive_key(const char* password, unsigned char* salt, size_t salt_len, unsigned char* key_out, int key_len);
#endif //FLUENT_BIT_PLUGINS_FILTER_ENCRYPT_UTILS_CRYPTO_UTILS_H_
