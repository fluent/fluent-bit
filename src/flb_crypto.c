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

#include <fluent-bit/flb_crypto.h>
#include <openssl/bio.h>
#include <string.h>

static int flb_crypto_get_rsa_padding_type_by_id(int padding_type_id)
{
    int result;

    if (padding_type_id == FLB_CRYPTO_PADDING_PKCS1) {
        result = RSA_PKCS1_PADDING;
    }
    else if (padding_type_id == FLB_CRYPTO_PADDING_PKCS1_OEAP) {
        result = RSA_PKCS1_OAEP_PADDING;
    }
    else if (padding_type_id == FLB_CRYPTO_PADDING_PKCS1_X931) {
        result = RSA_X931_PADDING;
    }
    else if (padding_type_id == FLB_CRYPTO_PADDING_PKCS1_PSS) {
        result = RSA_PKCS1_PSS_PADDING;
    }
    else {
        result = FLB_CRYPTO_PADDING_NONE;
    }

    return result;
}

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

static int flb_crypto_import_pem_key(int key_type,
                                     unsigned char *key,
                                     size_t key_length,
                                     EVP_PKEY **ingested_key)
{
    BIO *io_provider;
    int  result;

    if (key_type != FLB_CRYPTO_PUBLIC_KEY &&
        key_type != FLB_CRYPTO_PRIVATE_KEY) {
        return FLB_CRYPTO_INVALID_ARGUMENT;
    }

    if (ingested_key == NULL) {
        return FLB_CRYPTO_INVALID_ARGUMENT;
    }

    result = FLB_CRYPTO_BACKEND_ERROR;

    io_provider = BIO_new_mem_buf((void*) key, key_length);

    if (io_provider != NULL) {
        if (ingested_key != NULL) {
            if (key_type == FLB_CRYPTO_PRIVATE_KEY) {
                *ingested_key = PEM_read_bio_PrivateKey(io_provider,
                                                        NULL, NULL,
                                                        NULL);
            }
            else if (key_type == FLB_CRYPTO_PUBLIC_KEY) {
                *ingested_key = PEM_read_bio_PUBKEY(io_provider,
                                                    NULL, NULL,
                                                    NULL);

                // printf("\n\nFAILURE? %p\n\n", *ingested_key);
                // printf("ERROR : %s\n", ERR_error_string(ERR_get_error(), NULL));
                // exit(0);
            }

            if (*ingested_key != NULL) {
                result = FLB_CRYPTO_SUCCESS;
            }
        }

        BIO_free_all(io_provider);
    }

    return result;
}

int flb_crypto_init(struct flb_crypto *context,
                    int padding_type,
                    int digest_algorithm,
                    int key_type,
                    unsigned char *key,
                    size_t key_length)
{
    int result;

    if (context == NULL) {
        return FLB_CRYPTO_INVALID_ARGUMENT;
    }

    if (key == NULL) {
        return FLB_CRYPTO_INVALID_ARGUMENT;
    }

    if (key_length == 0) {
        return FLB_CRYPTO_INVALID_ARGUMENT;
    }

    memset(context, 0, sizeof(struct flb_crypto));

    result = flb_crypto_import_pem_key(key_type,
                                       key,
                                       key_length,
                                       &context->key);

    if (result != FLB_CRYPTO_SUCCESS) {
        if (result == FLB_CRYPTO_BACKEND_ERROR) {
            context->last_error = ERR_get_error();
        }

        flb_crypto_cleanup(context);

        return result;
    }

    context->backend_context = EVP_PKEY_CTX_new(context->key, NULL);

    if (context->backend_context == NULL) {
        context->last_error = ERR_get_error();

        flb_crypto_cleanup(context);

        return result;
    }

    context->block_size = (size_t) EVP_PKEY_size(context->key);

    context->padding_type = flb_crypto_get_rsa_padding_type_by_id(padding_type);

    context->digest_algorithm = flb_crypto_get_digest_algorithm_instance_by_id(digest_algorithm);

    return FLB_CRYPTO_SUCCESS;
}


int flb_crypto_cleanup(struct flb_crypto *context)
{
    if (context->backend_context != NULL) {
        EVP_PKEY_free(context->key);

        context->key = NULL;
    }

    if (context->backend_context != NULL) {
        EVP_PKEY_CTX_free(context->backend_context);

        context->backend_context = NULL;
    }

    return FLB_CRYPTO_SUCCESS;
}

int flb_crypto_transform(struct flb_crypto *context,
                         int operation,
                         unsigned char *input_buffer,
                         size_t input_length,
                         unsigned char *output_buffer,
                         size_t *output_length)
{
    int result = FLB_CRYPTO_BACKEND_ERROR;

    if (context == NULL) {
        return FLB_CRYPTO_INVALID_ARGUMENT;
    }

    if (operation != FLB_CRYPTO_OPERATION_SIGN    &&
        operation != FLB_CRYPTO_OPERATION_ENCRYPT &&
        operation != FLB_CRYPTO_OPERATION_DECRYPT) {
        return FLB_CRYPTO_INVALID_ARGUMENT;
    }

    if (context->last_operation == FLB_CRYPTO_OPERATION_NONE) {
        if (operation == FLB_CRYPTO_OPERATION_SIGN) {
            result = EVP_PKEY_sign_init(context->backend_context);
        }
        else if (operation == FLB_CRYPTO_OPERATION_ENCRYPT) {
            result = EVP_PKEY_encrypt_init(context->backend_context);
        }
        else if (operation == FLB_CRYPTO_OPERATION_DECRYPT) {
            result = EVP_PKEY_decrypt_init(context->backend_context);
        }

        if (result == 1) {
            result = EVP_PKEY_CTX_set_rsa_padding(context->backend_context,
                                                  context->padding_type);

            if (result > 0) {
                if (context->digest_algorithm != NULL) {
                    result = EVP_PKEY_CTX_set_signature_md(context->backend_context,
                                                           context->digest_algorithm);
                }
            }

            if (result > 0) {
                result = 1;
            }
        }

        if (result != 1) {
            context->last_error = ERR_get_error();

            return FLB_CRYPTO_BACKEND_ERROR;
        }

        context->last_operation = operation;
    }
    else if (context->last_operation != operation) {
        return FLB_CRYPTO_INVALID_STATE;
    }

    if (operation == FLB_CRYPTO_OPERATION_SIGN) {
        result = EVP_PKEY_sign(context->backend_context,
                               output_buffer, output_length,
                               input_buffer, input_length);
    }
    else if(operation == FLB_CRYPTO_OPERATION_ENCRYPT) {
        result = EVP_PKEY_encrypt(context->backend_context,
                                  output_buffer, output_length,
                                  input_buffer, input_length);
    }
    else if(operation == FLB_CRYPTO_OPERATION_DECRYPT) {
        result = EVP_PKEY_decrypt(context->backend_context,
                                  output_buffer, output_length,
                                  input_buffer, input_length);
    }

    if (result != 1) {
        context->last_error = ERR_get_error();

        return FLB_CRYPTO_BACKEND_ERROR;
    }

    return FLB_CRYPTO_SUCCESS;
}

int flb_crypto_sign(struct flb_crypto *context,
                    unsigned char *input_buffer,
                    size_t input_length,
                    unsigned char *output_buffer,
                    size_t *output_length)
{
    return flb_crypto_transform(context,
                                FLB_CRYPTO_OPERATION_SIGN,
                                input_buffer,
                                input_length,
                                output_buffer,
                                output_length);
}

int flb_crypto_encrypt(struct flb_crypto *context,
                       unsigned char *input_buffer,
                       size_t input_length,
                       unsigned char *output_buffer,
                       size_t *output_length)
{
    return flb_crypto_transform(context,
                                FLB_CRYPTO_OPERATION_ENCRYPT,
                                input_buffer,
                                input_length,
                                output_buffer,
                                output_length);
}

int flb_crypto_decrypt(struct flb_crypto *context,
                       unsigned char *input_buffer,
                       size_t input_length,
                       unsigned char *output_buffer,
                       size_t *output_length)
{
    return flb_crypto_transform(context,
                                FLB_CRYPTO_OPERATION_DECRYPT,
                                input_buffer,
                                input_length,
                                output_buffer,
                                output_length);
}

int flb_crypto_sign_simple(int key_type,
                           int padding_type,
                           int digest_algorithm,
                           unsigned char *key,
                           size_t key_length,
                           unsigned char *input_buffer,
                           size_t input_length,
                           unsigned char *output_buffer,
                           size_t *output_length)
{
    struct flb_crypto context;
    int               result;

    result = flb_crypto_init(&context,
                             padding_type,
                             digest_algorithm,
                             key_type,
                             key,
                             key_length);

    if (result == FLB_CRYPTO_SUCCESS) {
        result = flb_crypto_sign(&context,
                                 input_buffer, input_length,
                                 output_buffer, output_length);

        flb_crypto_cleanup(&context);
    }

    return result;
}

int flb_crypto_encrypt_simple(int padding_type,
                              unsigned char *key,
                              size_t key_length,
                              unsigned char *input_buffer,
                              size_t input_length,
                              unsigned char *output_buffer,
                              size_t *output_length)
{
    struct flb_crypto context;
    int               result;

    result = flb_crypto_init(&context,
                             padding_type,
                             FLB_HASH_NONE,
                             FLB_CRYPTO_PUBLIC_KEY,
                             key,
                             key_length);

    if (result == FLB_CRYPTO_SUCCESS) {
        result = flb_crypto_encrypt(&context,
                                    input_buffer, input_length,
                                    output_buffer, output_length);


        flb_crypto_cleanup(&context);
    }

    return result;
}

int flb_crypto_decrypt_simple(int padding_type,
                              unsigned char *key,
                              size_t key_length,
                              unsigned char *input_buffer,
                              size_t input_length,
                              unsigned char *output_buffer,
                              size_t *output_length)
{
    struct flb_crypto context;
    int               result;

    result = flb_crypto_init(&context,
                             padding_type,
                             FLB_HASH_NONE,
                             FLB_CRYPTO_PRIVATE_KEY,
                             key,
                             key_length);

    if (result == FLB_CRYPTO_SUCCESS) {
        result = flb_crypto_decrypt(&context,
                                    input_buffer, input_length,
                                    output_buffer, output_length);

        flb_crypto_cleanup(&context);
    }

    return result;
}



