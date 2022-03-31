/*
 * Test driver for AEAD entry points.
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
#include "psa_crypto_aead.h"

#include "test/drivers/aead.h"

mbedtls_test_driver_aead_hooks_t
    mbedtls_test_driver_aead_hooks = MBEDTLS_TEST_DRIVER_AEAD_INIT;

psa_status_t mbedtls_test_transparent_aead_encrypt(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, size_t key_buffer_size,
    psa_algorithm_t alg,
    const uint8_t *nonce, size_t nonce_length,
    const uint8_t *additional_data, size_t additional_data_length,
    const uint8_t *plaintext, size_t plaintext_length,
    uint8_t *ciphertext, size_t ciphertext_size, size_t *ciphertext_length )
{
    mbedtls_test_driver_aead_hooks.hits++;

    if( mbedtls_test_driver_aead_hooks.forced_status != PSA_SUCCESS )
    {
         mbedtls_test_driver_aead_hooks.driver_status =
             mbedtls_test_driver_aead_hooks.forced_status;
    }
    else
    {
        mbedtls_test_driver_aead_hooks.driver_status =
            mbedtls_psa_aead_encrypt(
                attributes, key_buffer, key_buffer_size,
                alg,
                nonce, nonce_length,
                additional_data, additional_data_length,
                plaintext, plaintext_length,
                ciphertext, ciphertext_size, ciphertext_length );
    }

    return( mbedtls_test_driver_aead_hooks.driver_status );
}

psa_status_t mbedtls_test_transparent_aead_decrypt(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, size_t key_buffer_size,
    psa_algorithm_t alg,
    const uint8_t *nonce, size_t nonce_length,
    const uint8_t *additional_data, size_t additional_data_length,
    const uint8_t *ciphertext, size_t ciphertext_length,
    uint8_t *plaintext, size_t plaintext_size, size_t *plaintext_length )
{
    mbedtls_test_driver_aead_hooks.hits++;

    if( mbedtls_test_driver_aead_hooks.forced_status != PSA_SUCCESS )
    {
         mbedtls_test_driver_aead_hooks.driver_status =
             mbedtls_test_driver_aead_hooks.forced_status;
    }
    else
    {
        mbedtls_test_driver_aead_hooks.driver_status =
            mbedtls_psa_aead_decrypt(
                attributes, key_buffer, key_buffer_size,
                alg,
                nonce, nonce_length,
                additional_data, additional_data_length,
                ciphertext, ciphertext_length,
                plaintext, plaintext_size, plaintext_length );
    }

    return( mbedtls_test_driver_aead_hooks.driver_status );
}

#endif /* MBEDTLS_PSA_CRYPTO_DRIVERS && PSA_CRYPTO_DRIVER_TEST */
