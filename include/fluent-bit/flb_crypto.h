/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2022 The Fluent Bit Authors
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#ifndef FLB_CRYPTO_H
#define FLB_CRYPTO_H

#include <stdint.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/engine.h>
#include <fluent-bit/flb_crypto_constants.h>


struct flb_crypto {
    const EVP_MD *digest_algorithm;
    EVP_PKEY_CTX *backend_context;
    int           last_operation;
    int           padding_type;
    size_t        block_size;
    unsigned long last_error;
    EVP_PKEY     *key;
};

int flb_crypto_init(struct flb_crypto *context,
                    int padding_type,
                    int digest_algorithm,
                    int key_type,
                    unsigned char *key,
                    size_t key_length);

int flb_crypto_cleanup(struct flb_crypto *context);

int flb_crypto_transform(struct flb_crypto *context,
                         int operation,
                         unsigned char *input_buffer,
                         size_t input_length,
                         unsigned char *output_buffer,
                         size_t *output_length);

int flb_crypto_sign(struct flb_crypto *context,
                    unsigned char *input_buffer,
                    size_t input_length,
                    unsigned char *output_buffer,
                    size_t *output_length);

int flb_crypto_encrypt(struct flb_crypto *context,
                       unsigned char *input_buffer,
                       size_t input_length,
                       unsigned char *output_buffer,
                       size_t *output_length);

int flb_crypto_decrypt(struct flb_crypto *context,
                       unsigned char *input_buffer,
                       size_t input_length,
                       unsigned char *output_buffer,
                       size_t *output_length);

int flb_crypto_sign_simple(int key_type,
                           int padding_type,
                           int digest_algorithm,
                           unsigned char *key,
                           size_t key_length,
                           unsigned char *input_buffer,
                           size_t input_length,
                           unsigned char *output_buffer,
                           size_t *output_length);

int flb_crypto_encrypt_simple(int padding_type,
                              unsigned char *key,
                              size_t key_length,
                              unsigned char *input_buffer,
                              size_t input_length,
                              unsigned char *output_buffer,
                              size_t *output_length);

int flb_crypto_decrypt_simple(int padding_type,
                              unsigned char *key,
                              size_t key_length,
                              unsigned char *input_buffer,
                              size_t input_length,
                              unsigned char *output_buffer,
                              size_t *output_length);

int flb_crypto_init_from_rsa_components(struct flb_crypto *context,
                                        int padding_type,
                                        int digest_algorithm,
                                        unsigned char *modulus_bytes,
                                        size_t modulus_len,
                                        unsigned char *exponent_bytes,
                                        size_t exponent_len);

int flb_crypto_verify(struct flb_crypto *context,
                      unsigned char *data,
                      size_t data_length,
                      unsigned char *signature,
                      size_t signature_length);

int flb_crypto_verify_simple(int padding_type,
                             int digest_algorithm,
                             unsigned char *modulus_bytes,
                             size_t modulus_len,
                             unsigned char *exponent_bytes,
                             size_t exponent_len,
                             unsigned char *data,
                             size_t data_length,
                             unsigned char *signature,
                             size_t signature_length);

#endif