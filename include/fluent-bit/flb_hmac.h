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

#ifndef FLB_HMAC_H
#define FLB_HMAC_H

#include <stdint.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/engine.h>
#include <fluent-bit/flb_crypto_constants.h>

struct flb_hmac {
#if FLB_CRYPTO_OPENSSL_COMPAT_MODE >= 3
    EVP_MAC_CTX  *backend_context;
    EVP_MAC      *mac_algorithm;
#else
    HMAC_CTX     *backend_context;
#endif

    size_t        digest_size;
    unsigned long last_error;
};

int flb_hmac_init(struct flb_hmac *context, 
                  int algorithm_id, 
                  unsigned char *key, 
                  size_t key_length);

int flb_hmac_cleanup(struct flb_hmac *context);

int flb_hmac_finalize(struct flb_hmac *context,
                      unsigned char *signature_buffer,
                      size_t signature_buffer_size);

int flb_hmac_update(struct flb_hmac *context, 
                    unsigned char *data, 
                    size_t data_length);

int flb_hmac_simple_batch(int hash_type,
                          unsigned char *key, size_t key_length,
                          size_t entry_count,
                          unsigned char **data_entries, 
                          size_t *length_entries,
                          unsigned char *signature_buffer, 
                          size_t signature_buffer_size);

int flb_hmac_simple(int hash_type,
                    unsigned char *key, size_t key_length,
                    unsigned char *data, size_t data_length,
                    unsigned char *signature_buffer, 
                    size_t signature_buffer_size);
#endif