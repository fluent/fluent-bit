/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2020 The Fluent Bit Authors
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

#include <fluent-bit/flb_hash.h>
#include <openssl/bio.h>

static const EVP_MD *flb_crypto_get_digest_algorithm_instance_by_id(int algorithm_id)
{
    const EVP_MD *algorithm;

    if (algorithm_id == FLB_HASH_SHA256) {
        algorithm = EVP_sha256();
    }
    else if (algorithm_id == FLB_HASH_SHA512) {
        algorithm = EVP_sha512();
    }
    else if (algorithm_id == FLB_HASH_MD5) {
        algorithm = EVP_md5();
    }
    else {
        algorithm = NULL;
    }

    return algorithm;
}

int flb_hash_init(struct flb_hash *context, int hash_type)
{
    const EVP_MD *digest_algorithm;
    int           result;

    if (context == NULL) {
        return FLB_CRYPTO_INVALID_ARGUMENT;
    }

    digest_algorithm = flb_crypto_get_digest_algorithm_instance_by_id(hash_type);

    if (digest_algorithm == NULL) {
        return FLB_CRYPTO_INVALID_ARGUMENT;
    }

    context->backend_context = EVP_MD_CTX_create();

    if (context->backend_context == NULL) {
        context->last_error = ERR_get_error();

        return FLB_CRYPTO_BACKEND_ERROR;
    }

    result = EVP_DigestInit_ex(context->backend_context, digest_algorithm, 0);

    if (result == 0) {
        context->last_error = ERR_get_error();

        return FLB_CRYPTO_BACKEND_ERROR;
    }

    context->digest_size = EVP_MD_CTX_size(context->backend_context);

    return FLB_CRYPTO_SUCCESS;
}

int flb_hash_finalize(struct flb_hash *context,
                      unsigned char *digest_buffer,
                      size_t digest_buffer_size)
{
    unsigned int digest_length;
    int          result;

    if (context->backend_context == NULL) {
        return FLB_CRYPTO_INVALID_ARGUMENT;
    }

    if (digest_buffer == NULL) {
        return FLB_CRYPTO_INVALID_ARGUMENT;
    }

    if (digest_buffer_size < context->digest_size) {
        return FLB_CRYPTO_INVALID_ARGUMENT;
    }

    result = EVP_DigestFinal_ex(context->backend_context,
                                digest_buffer, &digest_length);

    if (result == 0) {
        context->last_error = ERR_get_error();

        return FLB_CRYPTO_BACKEND_ERROR;
    }

    (void) digest_length;

    return FLB_CRYPTO_SUCCESS;
}

int flb_hash_update(struct flb_hash *context,
                    unsigned char *data,
                    size_t data_length)
{
    int result;

    if (context->backend_context == NULL) {
        return FLB_CRYPTO_INVALID_ARGUMENT;
    }

    if (data == NULL) {
        return FLB_CRYPTO_INVALID_ARGUMENT;
    }

    result = EVP_DigestUpdate(context->backend_context,
                              data,
                              data_length);

    if (result == 0) {
        context->last_error = ERR_get_error();

        return FLB_CRYPTO_BACKEND_ERROR;
    }

    return FLB_CRYPTO_SUCCESS;
}

int flb_hash_cleanup(struct flb_hash *context)
{
    if (context->backend_context == NULL) {
        return FLB_CRYPTO_INVALID_ARGUMENT;
    }

    EVP_MD_CTX_destroy(context->backend_context);

    context->backend_context = NULL;

    return FLB_CRYPTO_SUCCESS;
}

int  flb_hash_simple_batch(int hash_type,
                           size_t entry_count,
                           unsigned char **data_entries,
                           size_t *length_entries,
                           unsigned char *digest_buffer,
                           size_t digest_buffer_size)
{
    struct flb_hash digest_context;
    size_t          entry_index;
    int             result;

    result = flb_hash_init(&digest_context, hash_type);

    if (result == FLB_CRYPTO_SUCCESS) {
        for (entry_index = 0 ;
             entry_index < entry_count && result == FLB_CRYPTO_SUCCESS;
             entry_index++) {
            if (data_entries[entry_index] != NULL &&
                length_entries[entry_index] > 0) {
                result = flb_hash_update(&digest_context,
                                         data_entries[entry_index],
                                         length_entries[entry_index]);
            }
        }

        if (result == FLB_CRYPTO_SUCCESS) {
            result = flb_hash_finalize(&digest_context,
                                       digest_buffer,
                                       digest_buffer_size);
        }

        flb_hash_cleanup(&digest_context);
    }

    return result;
}

int flb_hash_simple(int hash_type,
                    unsigned char *data,
                    size_t data_length,
                    unsigned char *digest_buffer,
                    size_t digest_buffer_size)
{
    size_t         length_entries[1];
    unsigned char *data_entries[1];

    data_entries[0] = data;
    length_entries[0] = data_length;

    return flb_hash_simple_batch(hash_type,
                                 1,
                                 data_entries,
                                 length_entries,
                                 digest_buffer,
                                 digest_buffer_size);
}
