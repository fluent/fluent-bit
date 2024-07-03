//
// Created by alisrasic on 11/22/22.
//

#include "crypto_utils.h"

void generate_key_from_pbkdf2(char *passphrase, char *pbkdf2_salt, unsigned char *out, int iterations, int key_length) {
    size_t i;
    size_t len = strlen(pbkdf2_salt);
    if (PKCS5_PBKDF2_HMAC(passphrase, strlen(passphrase), pbkdf2_salt, len, iterations, EVP_sha512(), key_length, out)!=0) {
        for (i = 0; i < key_length; i++) {
            printf("%02x", out[i]);
        }
        printf("\n");
    } else {
        exit(EXIT_FAILURE);
    }

}