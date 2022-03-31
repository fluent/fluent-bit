/*
 * Test driver for cipher functions.
 * Currently only supports multi-part operations using AES-CTR.
 */
/*  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_PSA_CRYPTO_DRIVERS) && defined(PSA_CRYPTO_DRIVER_TEST)
#include "psa/crypto.h"
#include "psa_crypto_cipher.h"
#include "psa_crypto_core.h"
#include "mbedtls/cipher.h"

#include "test/drivers/cipher.h"

#include "test/random.h"

#if defined(MBEDTLS_TEST_LIBTESTDRIVER1)
#include "libtestdriver1/library/psa_crypto_cipher.h"
#endif

#include <string.h>

mbedtls_test_driver_cipher_hooks_t mbedtls_test_driver_cipher_hooks =
    MBEDTLS_TEST_DRIVER_CIPHER_INIT;

psa_status_t mbedtls_test_transparent_cipher_encrypt(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer,
    size_t key_buffer_size,
    psa_algorithm_t alg,
    const uint8_t *iv,
    size_t iv_length,
    const uint8_t *input,
    size_t input_length,
    uint8_t *output,
    size_t output_size,
    size_t *output_length )
{
    mbedtls_test_driver_cipher_hooks.hits++;

    if( mbedtls_test_driver_cipher_hooks.forced_output != NULL )
    {
        if( output_size < mbedtls_test_driver_cipher_hooks.forced_output_length )
            return( PSA_ERROR_BUFFER_TOO_SMALL );

        memcpy( output,
                mbedtls_test_driver_cipher_hooks.forced_output,
                mbedtls_test_driver_cipher_hooks.forced_output_length );
        *output_length = mbedtls_test_driver_cipher_hooks.forced_output_length;

        return( mbedtls_test_driver_cipher_hooks.forced_status );
    }

    if( mbedtls_test_driver_cipher_hooks.forced_status != PSA_SUCCESS )
        return( mbedtls_test_driver_cipher_hooks.forced_status );

#if defined(MBEDTLS_TEST_LIBTESTDRIVER1) && \
    defined(LIBTESTDRIVER1_MBEDTLS_PSA_BUILTIN_CIPHER)
    return( libtestdriver1_mbedtls_psa_cipher_encrypt(
                (const libtestdriver1_psa_key_attributes_t *)attributes,
                key_buffer, key_buffer_size,
                alg, iv, iv_length, input, input_length,
                output, output_size, output_length ) );
#elif defined(MBEDTLS_PSA_BUILTIN_CIPHER)
    return( mbedtls_psa_cipher_encrypt(
                attributes, key_buffer, key_buffer_size,
                alg, iv, iv_length, input, input_length,
                output, output_size, output_length ) );
#endif

    return( PSA_ERROR_NOT_SUPPORTED );
}

psa_status_t mbedtls_test_transparent_cipher_decrypt(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer,
    size_t key_buffer_size,
    psa_algorithm_t alg,
    const uint8_t *input,
    size_t input_length,
    uint8_t *output,
    size_t output_size,
    size_t *output_length )
{
   mbedtls_test_driver_cipher_hooks.hits++;

    if( mbedtls_test_driver_cipher_hooks.forced_output != NULL )
    {
        if( output_size < mbedtls_test_driver_cipher_hooks.forced_output_length )
            return( PSA_ERROR_BUFFER_TOO_SMALL );

        memcpy( output,
                mbedtls_test_driver_cipher_hooks.forced_output,
                mbedtls_test_driver_cipher_hooks.forced_output_length );
        *output_length = mbedtls_test_driver_cipher_hooks.forced_output_length;

        return( mbedtls_test_driver_cipher_hooks.forced_status );
    }

    if( mbedtls_test_driver_cipher_hooks.forced_status != PSA_SUCCESS )
        return( mbedtls_test_driver_cipher_hooks.forced_status );

#if defined(MBEDTLS_TEST_LIBTESTDRIVER1) && \
    defined(LIBTESTDRIVER1_MBEDTLS_PSA_BUILTIN_CIPHER)
    return( libtestdriver1_mbedtls_psa_cipher_decrypt(
                (const libtestdriver1_psa_key_attributes_t *)attributes,
                key_buffer, key_buffer_size,
                alg, input, input_length,
                output, output_size, output_length ) );
#elif defined(MBEDTLS_PSA_BUILTIN_CIPHER)
    return( mbedtls_psa_cipher_decrypt(
                attributes, key_buffer, key_buffer_size,
                alg, input, input_length,
                output, output_size, output_length ) );
#endif

    return( PSA_ERROR_NOT_SUPPORTED );
}

psa_status_t mbedtls_test_transparent_cipher_encrypt_setup(
    mbedtls_transparent_test_driver_cipher_operation_t *operation,
    const psa_key_attributes_t *attributes,
    const uint8_t *key, size_t key_length,
    psa_algorithm_t alg)
{
    mbedtls_test_driver_cipher_hooks.hits++;

    /* Wiping the entire struct here, instead of member-by-member. This is
     * useful for the test suite, since it gives a chance of catching memory
     * corruption errors should the core not have allocated (enough) memory for
     * our context struct. */
    memset( operation, 0, sizeof( *operation ) );

    if( mbedtls_test_driver_cipher_hooks.forced_status != PSA_SUCCESS )
        return( mbedtls_test_driver_cipher_hooks.forced_status );

#if defined(MBEDTLS_TEST_LIBTESTDRIVER1) && \
    defined(LIBTESTDRIVER1_MBEDTLS_PSA_BUILTIN_CIPHER)
    return( libtestdriver1_mbedtls_psa_cipher_encrypt_setup(
                operation,
                (const libtestdriver1_psa_key_attributes_t *)attributes,
                key, key_length, alg ) );
#elif defined(MBEDTLS_PSA_BUILTIN_CIPHER)
    return( mbedtls_psa_cipher_encrypt_setup(
                operation, attributes, key, key_length, alg ) );
#endif

    return( PSA_ERROR_NOT_SUPPORTED );
}

psa_status_t mbedtls_test_transparent_cipher_decrypt_setup(
    mbedtls_transparent_test_driver_cipher_operation_t *operation,
    const psa_key_attributes_t *attributes,
    const uint8_t *key, size_t key_length,
    psa_algorithm_t alg)
{
    mbedtls_test_driver_cipher_hooks.hits++;

    if( mbedtls_test_driver_cipher_hooks.forced_status != PSA_SUCCESS )
        return( mbedtls_test_driver_cipher_hooks.forced_status );

#if defined(MBEDTLS_TEST_LIBTESTDRIVER1) && \
    defined(LIBTESTDRIVER1_MBEDTLS_PSA_BUILTIN_CIPHER)
    return( libtestdriver1_mbedtls_psa_cipher_decrypt_setup(
                operation,
                (const libtestdriver1_psa_key_attributes_t *)attributes,
                key, key_length, alg ) );
#elif defined(MBEDTLS_PSA_BUILTIN_CIPHER)
    return( mbedtls_psa_cipher_decrypt_setup(
                operation, attributes, key, key_length, alg ) );
#endif

    return( PSA_ERROR_NOT_SUPPORTED );
}

psa_status_t mbedtls_test_transparent_cipher_abort(
    mbedtls_transparent_test_driver_cipher_operation_t *operation)
{
    mbedtls_test_driver_cipher_hooks.hits++;

    if( operation->alg == 0 )
        return( PSA_SUCCESS );

#if defined(MBEDTLS_TEST_LIBTESTDRIVER1) && \
    defined(LIBTESTDRIVER1_MBEDTLS_PSA_BUILTIN_CIPHER)
    libtestdriver1_mbedtls_psa_cipher_abort( operation );
#elif defined(MBEDTLS_PSA_BUILTIN_CIPHER)
    mbedtls_psa_cipher_abort( operation );
#endif

    /* Wiping the entire struct here, instead of member-by-member. This is
     * useful for the test suite, since it gives a chance of catching memory
     * corruption errors should the core not have allocated (enough) memory for
     * our context struct. */
    memset( operation, 0, sizeof( *operation ) );

    return( mbedtls_test_driver_cipher_hooks.forced_status );
}

psa_status_t mbedtls_test_transparent_cipher_set_iv(
    mbedtls_transparent_test_driver_cipher_operation_t *operation,
    const uint8_t *iv,
    size_t iv_length)
{
    mbedtls_test_driver_cipher_hooks.hits++;

    if( mbedtls_test_driver_cipher_hooks.forced_status != PSA_SUCCESS )
        return( mbedtls_test_driver_cipher_hooks.forced_status );

#if defined(MBEDTLS_TEST_LIBTESTDRIVER1) && \
    defined(LIBTESTDRIVER1_MBEDTLS_PSA_BUILTIN_CIPHER)
    return( libtestdriver1_mbedtls_psa_cipher_set_iv(
                operation, iv, iv_length ) );
#elif defined(MBEDTLS_PSA_BUILTIN_CIPHER)
    return( mbedtls_psa_cipher_set_iv( operation, iv, iv_length ) );
#endif

    return( PSA_ERROR_NOT_SUPPORTED );
}

psa_status_t mbedtls_test_transparent_cipher_update(
    mbedtls_transparent_test_driver_cipher_operation_t *operation,
    const uint8_t *input,
    size_t input_length,
    uint8_t *output,
    size_t output_size,
    size_t *output_length)
{
    mbedtls_test_driver_cipher_hooks.hits++;

    if( mbedtls_test_driver_cipher_hooks.forced_output != NULL )
    {
        if( output_size < mbedtls_test_driver_cipher_hooks.forced_output_length )
            return PSA_ERROR_BUFFER_TOO_SMALL;

        memcpy( output,
                mbedtls_test_driver_cipher_hooks.forced_output,
                mbedtls_test_driver_cipher_hooks.forced_output_length );
        *output_length = mbedtls_test_driver_cipher_hooks.forced_output_length;

        return( mbedtls_test_driver_cipher_hooks.forced_status );
    }

    if( mbedtls_test_driver_cipher_hooks.forced_status != PSA_SUCCESS )
        return( mbedtls_test_driver_cipher_hooks.forced_status );

#if defined(MBEDTLS_TEST_LIBTESTDRIVER1) && \
    defined(LIBTESTDRIVER1_MBEDTLS_PSA_BUILTIN_CIPHER)
    return( libtestdriver1_mbedtls_psa_cipher_update(
                operation, input, input_length,
                output, output_size, output_length ) );
#elif defined(MBEDTLS_PSA_BUILTIN_CIPHER)
    return( mbedtls_psa_cipher_update(
                operation, input, input_length,
                output, output_size, output_length ) );
#endif

    return( PSA_ERROR_NOT_SUPPORTED );
}

psa_status_t mbedtls_test_transparent_cipher_finish(
    mbedtls_transparent_test_driver_cipher_operation_t *operation,
    uint8_t *output,
    size_t output_size,
    size_t *output_length)
{
    mbedtls_test_driver_cipher_hooks.hits++;

    if( mbedtls_test_driver_cipher_hooks.forced_output != NULL )
    {
        if( output_size < mbedtls_test_driver_cipher_hooks.forced_output_length )
            return PSA_ERROR_BUFFER_TOO_SMALL;

        memcpy( output,
                mbedtls_test_driver_cipher_hooks.forced_output,
                mbedtls_test_driver_cipher_hooks.forced_output_length );
        *output_length = mbedtls_test_driver_cipher_hooks.forced_output_length;

        return( mbedtls_test_driver_cipher_hooks.forced_status );
    }

    if( mbedtls_test_driver_cipher_hooks.forced_status != PSA_SUCCESS )
        return( mbedtls_test_driver_cipher_hooks.forced_status );

#if defined(MBEDTLS_TEST_LIBTESTDRIVER1) && \
    defined(LIBTESTDRIVER1_MBEDTLS_PSA_BUILTIN_CIPHER)
    return( libtestdriver1_mbedtls_psa_cipher_finish(
                operation, output, output_size, output_length ) );
#elif defined(MBEDTLS_PSA_BUILTIN_CIPHER)
    return( mbedtls_psa_cipher_finish(
                operation, output, output_size, output_length ) );
#endif

    return( PSA_ERROR_NOT_SUPPORTED );
}

/*
 * opaque versions, to do
 */
psa_status_t mbedtls_test_opaque_cipher_encrypt(
    const psa_key_attributes_t *attributes,
    const uint8_t *key, size_t key_length,
    psa_algorithm_t alg,
    const uint8_t *iv, size_t iv_length,
    const uint8_t *input, size_t input_length,
    uint8_t *output, size_t output_size, size_t *output_length)
{
    (void) attributes;
    (void) key;
    (void) key_length;
    (void) alg;
    (void) iv;
    (void) iv_length;
    (void) input;
    (void) input_length;
    (void) output;
    (void) output_size;
    (void) output_length;
    return( PSA_ERROR_NOT_SUPPORTED );
}

psa_status_t mbedtls_test_opaque_cipher_decrypt(
    const psa_key_attributes_t *attributes,
    const uint8_t *key, size_t key_length,
    psa_algorithm_t alg,
    const uint8_t *input, size_t input_length,
    uint8_t *output, size_t output_size, size_t *output_length)
{
    (void) attributes;
    (void) key;
    (void) key_length;
    (void) alg;
    (void) input;
    (void) input_length;
    (void) output;
    (void) output_size;
    (void) output_length;
    return( PSA_ERROR_NOT_SUPPORTED );
}

psa_status_t mbedtls_test_opaque_cipher_encrypt_setup(
    mbedtls_opaque_test_driver_cipher_operation_t *operation,
    const psa_key_attributes_t *attributes,
    const uint8_t *key, size_t key_length,
    psa_algorithm_t alg)
{
    (void) operation;
    (void) attributes;
    (void) key;
    (void) key_length;
    (void) alg;
    return( PSA_ERROR_NOT_SUPPORTED );
}

psa_status_t mbedtls_test_opaque_cipher_decrypt_setup(
    mbedtls_opaque_test_driver_cipher_operation_t *operation,
    const psa_key_attributes_t *attributes,
    const uint8_t *key, size_t key_length,
    psa_algorithm_t alg)
{
    (void) operation;
    (void) attributes;
    (void) key;
    (void) key_length;
    (void) alg;
    return( PSA_ERROR_NOT_SUPPORTED );
}

psa_status_t mbedtls_test_opaque_cipher_abort(
    mbedtls_opaque_test_driver_cipher_operation_t *operation )
{
    (void) operation;
    return( PSA_ERROR_NOT_SUPPORTED );
}

psa_status_t mbedtls_test_opaque_cipher_set_iv(
    mbedtls_opaque_test_driver_cipher_operation_t *operation,
    const uint8_t *iv,
    size_t iv_length)
{
    (void) operation;
    (void) iv;
    (void) iv_length;
    return( PSA_ERROR_NOT_SUPPORTED );
}

psa_status_t mbedtls_test_opaque_cipher_update(
    mbedtls_opaque_test_driver_cipher_operation_t *operation,
    const uint8_t *input,
    size_t input_length,
    uint8_t *output,
    size_t output_size,
    size_t *output_length)
{
    (void) operation;
    (void) input;
    (void) input_length;
    (void) output;
    (void) output_size;
    (void) output_length;
    return( PSA_ERROR_NOT_SUPPORTED );
}

psa_status_t mbedtls_test_opaque_cipher_finish(
    mbedtls_opaque_test_driver_cipher_operation_t *operation,
    uint8_t *output,
    size_t output_size,
    size_t *output_length)
{
    (void) operation;
    (void) output;
    (void) output_size;
    (void) output_length;
    return( PSA_ERROR_NOT_SUPPORTED );
}
#endif /* MBEDTLS_PSA_CRYPTO_DRIVERS && PSA_CRYPTO_DRIVER_TEST */
