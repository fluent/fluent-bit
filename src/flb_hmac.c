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

#include <fluent-bit/flb_hmac.h>
#include <fluent-bit/flb_mem.h>

#if FLB_CRYPTO_OPENSSL_COMPAT_MODE >= 3
#include <openssl/params.h>
#endif

#include <openssl/evp.h>
#include <openssl/bio.h>
#include <string.h>

#if FLB_CRYPTO_OPENSSL_COMPAT_MODE >= 3
static const char *flb_crypto_get_algorithm_name_by_id(int algorithm_id)
{
    const char *algorithm_name;

    if (algorithm_id == FLB_HASH_SHA256) {
        algorithm_name = "SHA-256";
    }
    else if (algorithm_id == FLB_HASH_SHA512) {
        algorithm_name = "SHA-512";
    }
    else if (algorithm_id == FLB_HASH_MD5) {
        algorithm_name = "MD5";
    }
    else {
        algorithm_name = NULL;
    }

    return algorithm_name;
}

int flb_hmac_init(struct flb_hmac *context,
                  int algorithm_id,
                  unsigned char *key,
                  size_t key_length)
{
    const char *digest_algorithm_name;
    OSSL_PARAM  hmac_parameters[2];
    int         result;


    if (context == NULL) {
        return FLB_CRYPTO_INVALID_ARGUMENT;
    }

    if (key == NULL) {
        return FLB_CRYPTO_INVALID_ARGUMENT;
    }

    if (key_length == 0) {
        return FLB_CRYPTO_INVALID_ARGUMENT;
    }

    memset(context, 0, sizeof(struct flb_hmac));

    digest_algorithm_name = flb_crypto_get_algorithm_name_by_id(algorithm_id);

    if (digest_algorithm_name == NULL) {
        return FLB_CRYPTO_INVALID_ARGUMENT;
    }

    context->mac_algorithm = EVP_MAC_fetch(NULL, "HMAC", NULL);

    if (context->mac_algorithm == NULL) {
        context->last_error = ERR_get_error();

        flb_hmac_cleanup(context);

        return FLB_CRYPTO_INVALID_ARGUMENT;
    }

    context->backend_context = EVP_MAC_CTX_new(context->mac_algorithm);

    if (context->backend_context == NULL) {
        context->last_error = ERR_get_error();

        flb_hmac_cleanup(context);

        return FLB_CRYPTO_BACKEND_ERROR;
    }

    hmac_parameters[0] = OSSL_PARAM_construct_utf8_string("digest",
                                                          (char *) digest_algorithm_name,
                                                          0);
    hmac_parameters[1] = OSSL_PARAM_construct_end();


    result = EVP_MAC_init(context->backend_context,
                          key, key_length,
                          hmac_parameters);

    if (result == 0) {
        context->last_error = ERR_get_error();

        return FLB_CRYPTO_BACKEND_ERROR;
    }

    context->digest_size = EVP_MAC_CTX_get_mac_size(context->backend_context);

    return FLB_CRYPTO_SUCCESS;
}

#else

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

int flb_hmac_init(struct flb_hmac *context,
                  int algorithm_id,
                  unsigned char *key,
                  size_t key_length)
{
    const EVP_MD *digest_algorithm_instance;
    int           result;


    if (context == NULL) {
        return FLB_CRYPTO_INVALID_ARGUMENT;
    }

    if (key == NULL) {
        return FLB_CRYPTO_INVALID_ARGUMENT;
    }

    if (key_length == 0) {
        return FLB_CRYPTO_INVALID_ARGUMENT;
    }

    memset(context, 0, sizeof(struct flb_hmac));

    digest_algorithm_instance = flb_crypto_get_digest_algorithm_instance_by_id(algorithm_id);

    if (digest_algorithm_instance == NULL) {
        return FLB_CRYPTO_INVALID_ARGUMENT;
    }

#if FLB_CRYPTO_OPENSSL_COMPAT_MODE == 0
    context->backend_context = flb_calloc(1, sizeof(HMAC_CTX));

    if (context->backend_context == NULL) {
        return FLB_CRYPTO_ALLOCATION_ERROR;
    }

    HMAC_CTX_init(context->backend_context);
#else
    context->backend_context = HMAC_CTX_new();

    if (context->backend_context == NULL) {
        context->last_error = ERR_get_error();

        return FLB_CRYPTO_BACKEND_ERROR;
    }
#endif

    result = HMAC_Init_ex(context->backend_context,
                          key, key_length,
                          digest_algorithm_instance,
                          NULL);

    if (result != 1) {
        context->last_error = ERR_get_error();

        return FLB_CRYPTO_BACKEND_ERROR;
    }

    context->digest_size = EVP_MD_size(digest_algorithm_instance);

    return FLB_CRYPTO_SUCCESS;
}
#endif

int flb_hmac_finalize(struct flb_hmac *context,
                      unsigned char *signature_buffer,
                      size_t signature_buffer_size)
{
    size_t signature_length;
    int    error_detected;
    int    result;

    if (context->backend_context == NULL) {
        return FLB_CRYPTO_INVALID_ARGUMENT;
    }

    if (signature_buffer == NULL) {
        return FLB_CRYPTO_INVALID_ARGUMENT;
    }

    if (signature_buffer_size < context->digest_size) {
        return FLB_CRYPTO_INVALID_ARGUMENT;
    }

#if FLB_CRYPTO_OPENSSL_COMPAT_MODE >= 3
    result = EVP_MAC_final(context->backend_context,
                           signature_buffer,
                           &signature_length,
                           signature_buffer_size);

    error_detected = (result == 0);
#else
    signature_length = 0;

    result = HMAC_Final(context->backend_context,
                        signature_buffer,
                        (unsigned int *) &signature_length);

    error_detected = (result != 1);
#endif

    if (error_detected) {
        context->last_error = ERR_get_error();

        return FLB_CRYPTO_BACKEND_ERROR;
    }

    (void) signature_length;

    return FLB_CRYPTO_SUCCESS;
}

int flb_hmac_update(struct flb_hmac *context,
                    unsigned char *data,
                    size_t data_length)
{
    int error_detected;
    int result;

    if (context->backend_context == NULL) {
        return FLB_CRYPTO_INVALID_ARGUMENT;
    }

    if (data == NULL) {
        return FLB_CRYPTO_INVALID_ARGUMENT;
    }

#if FLB_CRYPTO_OPENSSL_COMPAT_MODE >= 3
    result = EVP_MAC_update(context->backend_context,
                            data,
                            data_length);

    error_detected = (result == 0);
#else
    result = HMAC_Update(context->backend_context,
                         data,
                         data_length);

    error_detected = (result != 1);
#endif

    if (error_detected) {
        context->last_error = ERR_get_error();

        return FLB_CRYPTO_BACKEND_ERROR;
    }

    return FLB_CRYPTO_SUCCESS;
}

int flb_hmac_cleanup(struct flb_hmac *context)
{
#if FLB_CRYPTO_OPENSSL_COMPAT_MODE >= 3
    if (context->backend_context != NULL) {
        EVP_MAC_CTX_free(context->backend_context);

        context->backend_context = NULL;
    }

    if (context->mac_algorithm != NULL) {
        EVP_MAC_free(context->mac_algorithm);

        context->mac_algorithm = NULL;
    }
#else
    if (context->backend_context != NULL) {
#if FLB_CRYPTO_OPENSSL_COMPAT_MODE == 0
        HMAC_CTX_cleanup(context->backend_context);

        flb_free(context->backend_context);
#else
        HMAC_CTX_reset(context->backend_context);

        HMAC_CTX_free(context->backend_context);
#endif

        context->backend_context = NULL;
    }
#endif

    return FLB_CRYPTO_SUCCESS;
}

int flb_hmac_simple_batch(int hash_type,
                          unsigned char *key, size_t key_length,
                          size_t entry_count,
                          unsigned char **data_entries,
                          size_t *length_entries,
                          unsigned char *signature_buffer,
                          size_t signature_buffer_size)
{
    struct flb_hmac digest_context;
    size_t          entry_index;
    int             result;

    result = flb_hmac_init(&digest_context,
                           hash_type,
                           key, key_length);

    if (result == FLB_CRYPTO_SUCCESS) {
        for (entry_index = 0 ;
             entry_index < entry_count && result == FLB_CRYPTO_SUCCESS;
             entry_index++) {
            result = flb_hmac_update(&digest_context,
                                    data_entries[entry_index],
                                    length_entries[entry_index]);
        }

        if (result == FLB_CRYPTO_SUCCESS) {
            result = flb_hmac_finalize(&digest_context,
                                       signature_buffer,
                                       signature_buffer_size);
        }

        flb_hmac_cleanup(&digest_context);
    }

    return result;
}

int flb_hmac_simple(int hash_type,
                    unsigned char *key, size_t key_length,
                    unsigned char *data, size_t data_length,
                    unsigned char *signature_buffer,
                    size_t signature_buffer_size)
{
    size_t         length_entries[1];
    unsigned char *data_entries[1];

    length_entries[0] = data_length;
    data_entries[0] = data;

    return flb_hmac_simple_batch(hash_type,
                                 key, key_length,
                                 1,
                                 data_entries,
                                 length_entries,
                                 signature_buffer,
                                 signature_buffer_size);
}
