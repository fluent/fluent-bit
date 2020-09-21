/**
 * \file psa/crypto_platform.h
 *
 * \brief PSA cryptography module: Mbed TLS platform definitions
 *
 * \note This file may not be included directly. Applications must
 * include psa/crypto.h.
 *
 * This file contains platform-dependent type definitions.
 *
 * In implementations with isolation between the application and the
 * cryptography module, implementers should take care to ensure that
 * the definitions that are exposed to applications match what the
 * module implements.
 */
/*
 *  Copyright The Mbed TLS Contributors
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

#ifndef PSA_CRYPTO_PLATFORM_H
#define PSA_CRYPTO_PLATFORM_H

/* Include the Mbed TLS configuration file, the way Mbed TLS does it
 * in each of its header files. */
#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

/* PSA requires several types which C99 provides in stdint.h. */
#include <stdint.h>

/* Integral type representing a key handle. */
typedef uint16_t psa_key_handle_t;

/* This implementation distinguishes *application key identifiers*, which
 * are the key identifiers specified by the application, from
 * *key file identifiers*, which are the key identifiers that the library
 * sees internally. The two types can be different if there is a remote
 * call layer between the application and the library which supports
 * multiple client applications that do not have access to each others'
 * keys. The point of having different types is that the key file
 * identifier may encode not only the key identifier specified by the
 * application, but also the the identity of the application.
 *
 * Note that this is an internal concept of the library and the remote
 * call layer. The application itself never sees anything other than
 * #psa_app_key_id_t with its standard definition.
 */

/* The application key identifier is always what the application sees as
 * #psa_key_id_t. */
typedef uint32_t psa_app_key_id_t;

#if defined(MBEDTLS_PSA_CRYPTO_KEY_FILE_ID_ENCODES_OWNER)

#if defined(PSA_CRYPTO_SECURE)
/* Building for the PSA Crypto service on a PSA platform. */
/* A key owner is a PSA partition identifier. */
typedef int32_t psa_key_owner_id_t;
#endif

typedef struct
{
    uint32_t key_id;
    psa_key_owner_id_t owner;
} psa_key_file_id_t;
#define PSA_KEY_FILE_GET_KEY_ID( file_id ) ( ( file_id ).key_id )

/* Since crypto.h is used as part of the PSA Cryptography API specification,
 * it must use standard types for things like the argument of psa_open_key().
 * If it wasn't for that constraint, psa_open_key() would take a
 * `psa_key_file_id_t` argument. As a workaround, make `psa_key_id_t` an
 * alias for `psa_key_file_id_t` when building for a multi-client service. */
typedef psa_key_file_id_t psa_key_id_t;
#define PSA_KEY_ID_INIT {0, 0}

#else /* !MBEDTLS_PSA_CRYPTO_KEY_FILE_ID_ENCODES_OWNER */

/* By default, a key file identifier is just the application key identifier. */
typedef psa_app_key_id_t psa_key_file_id_t;
#define PSA_KEY_FILE_GET_KEY_ID( id ) ( id )

#endif /* !MBEDTLS_PSA_CRYPTO_KEY_FILE_ID_ENCODES_OWNER */

#endif /* PSA_CRYPTO_PLATFORM_H */
