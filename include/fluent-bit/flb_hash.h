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

/*
 * A wrapper for the OpenSSL SHA512 functions if OpenSSL is available.
 * Otherwise, the functions in this header file provide
 * the following public domain sha512 hash implementation.
 *
 * This is based on the musl libc SHA512 implementation. Follow the
 * link for the original source code.
 * https://git.musl-libc.org/cgit/musl/tree/src/crypt/crypt_sha512.c?h=v1.1.22
 *
 * Here is how to use it:
 *
 * #include <fluent-bit/flb_crypto.h>
 *
 * void main(void)
 * {
 *     char buf[64];
 *
 *     result = flb_hash_simple(FLB_CRYPTO_SHA256,
 *                                (unsigned char *) "aiueo", 5,
 *                                buf, sizeof(buf));
 *
 *     if (result != FLB_CRYPTO_SUCCESS) {
 *         printf("error\n");
 *         return NULL;
 *     }
 * }
 */

#ifndef FLB_HASH_H
#define FLB_HASH_H

#include <stdint.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/engine.h>
#include <fluent-bit/flb_crypto_constants.h>


struct flb_hash {
    EVP_MD_CTX   *backend_context;
    size_t        digest_size;
    unsigned long last_error;
};

int flb_hash_init(struct flb_hash *context, int digest_type);

int flb_hash_cleanup(struct flb_hash *context);

int flb_hash_finalize(struct flb_hash *context, 
                      unsigned char *digest_buffer,
                      size_t digest_buffer_size);

int flb_hash_update(struct flb_hash *context, 
                    unsigned char *data, 
                    size_t data_length);

int flb_hash_simple_batch(int hash_type,
                          size_t entry_count,
                          unsigned char **data_entries,
                          size_t *length_entries,
                          unsigned char *digest_buffer,
                          size_t digest_buffer_size);

int flb_hash_simple(int hash_type,
                    unsigned char *data, 
                    size_t data_length,
                    unsigned char *digest_buffer, 
                    size_t digest_buffer_size);

#endif