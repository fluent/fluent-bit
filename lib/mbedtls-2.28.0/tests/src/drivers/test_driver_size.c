/*
 * Test driver for retrieving key context size.
 * Only used by opaque drivers.
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

#include "test/drivers/size.h"
#include "psa/crypto.h"

typedef struct {
    unsigned int context;
} test_driver_key_context_t;

/*
 * This macro returns the base size for the key context. It is the size of the
 * driver specific information stored in each key context.
 */
#define TEST_DRIVER_KEY_CONTEXT_BASE_SIZE sizeof( test_driver_key_context_t )

/*
 * Number of bytes included in every key context for a key pair.
 *
 * This pair size is for an ECC 256-bit private/public key pair.
 * Based on this value, the size of the private key can be derived by
 * subtracting the public key size below from this one.
 */
#define TEST_DRIVER_KEY_CONTEXT_KEY_PAIR_SIZE      65

/*
 * Number of bytes included in every key context for a public key.
 *
 * For ECC public keys, it needs 257 bits so 33 bytes.
 */
#define TEST_DRIVER_KEY_CONTEXT_PUBLIC_KEY_SIZE    33

/*
 * Every key context for a symmetric key includes this many times the key size.
 */
#define TEST_DRIVER_KEY_CONTEXT_SYMMETRIC_FACTOR   0

/*
 * If this is true for a key pair, the key context includes space for the public key.
 * If this is false, no additional space is added for the public key.
 *
 * For this instance, store the public key with the private one.
 */
#define TEST_DRIVER_KEY_CONTEXT_STORE_PUBLIC_KEY   1

size_t mbedtls_test_size_function(
    const psa_key_type_t key_type,
    const size_t key_bits )
{
    size_t key_buffer_size = 0;

    if( PSA_KEY_TYPE_IS_KEY_PAIR( key_type ) )
    {
        int public_key_overhead =
            ( ( TEST_DRIVER_KEY_CONTEXT_STORE_PUBLIC_KEY == 1 )
              ? PSA_EXPORT_KEY_OUTPUT_SIZE( key_type, key_bits ) : 0 );
        key_buffer_size = TEST_DRIVER_KEY_CONTEXT_BASE_SIZE +
                          TEST_DRIVER_KEY_CONTEXT_PUBLIC_KEY_SIZE +
                          public_key_overhead;
    }
    else if( PSA_KEY_TYPE_IS_PUBLIC_KEY( key_type ) )
    {
        key_buffer_size = TEST_DRIVER_KEY_CONTEXT_BASE_SIZE +
                          TEST_DRIVER_KEY_CONTEXT_PUBLIC_KEY_SIZE;
    }
    else if ( !PSA_KEY_TYPE_IS_KEY_PAIR( key_type ) &&
              !PSA_KEY_TYPE_IS_PUBLIC_KEY ( key_type ) )
    {
        key_buffer_size = TEST_DRIVER_KEY_CONTEXT_BASE_SIZE +
                          ( TEST_DRIVER_KEY_CONTEXT_SYMMETRIC_FACTOR *
                            ( ( key_bits + 7 ) / 8 ) );
    }

    return( key_buffer_size );
}
#endif /* MBEDTLS_PSA_CRYPTO_DRIVERS && PSA_CRYPTO_DRIVER_TEST */
