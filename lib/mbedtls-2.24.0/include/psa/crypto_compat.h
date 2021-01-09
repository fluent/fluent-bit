/**
 * \file psa/crypto_compat.h
 *
 * \brief PSA cryptography module: Backward compatibility aliases
 *
 * This header declares alternative names for macro and functions.
 * New application code should not use these names.
 * These names may be removed in a future version of Mbed Crypto.
 *
 * \note This file may not be included directly. Applications must
 * include psa/crypto.h.
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

#ifndef PSA_CRYPTO_COMPAT_H
#define PSA_CRYPTO_COMPAT_H

#ifdef __cplusplus
extern "C" {
#endif

#if !defined(MBEDTLS_DEPRECATED_REMOVED)

/*
 * Mechanism for declaring deprecated values
 */
#if defined(MBEDTLS_DEPRECATED_WARNING) && !defined(MBEDTLS_PSA_DEPRECATED)
#define MBEDTLS_PSA_DEPRECATED __attribute__((deprecated))
#else
#define MBEDTLS_PSA_DEPRECATED
#endif

typedef MBEDTLS_PSA_DEPRECATED size_t mbedtls_deprecated_size_t;
typedef MBEDTLS_PSA_DEPRECATED psa_status_t mbedtls_deprecated_psa_status_t;
typedef MBEDTLS_PSA_DEPRECATED psa_key_usage_t mbedtls_deprecated_psa_key_usage_t;
typedef MBEDTLS_PSA_DEPRECATED psa_ecc_family_t mbedtls_deprecated_psa_ecc_family_t;
typedef MBEDTLS_PSA_DEPRECATED psa_dh_family_t mbedtls_deprecated_psa_dh_family_t;
typedef MBEDTLS_PSA_DEPRECATED psa_ecc_family_t psa_ecc_curve_t;
typedef MBEDTLS_PSA_DEPRECATED psa_dh_family_t psa_dh_group_t;

#define PSA_KEY_TYPE_GET_CURVE PSA_KEY_TYPE_ECC_GET_FAMILY
#define PSA_KEY_TYPE_GET_GROUP PSA_KEY_TYPE_DH_GET_FAMILY

#define MBEDTLS_DEPRECATED_CONSTANT( type, value )      \
    ( (mbedtls_deprecated_##type) ( value ) )

/*
 * Deprecated PSA Crypto error code definitions (PSA Crypto API  <= 1.0 beta2)
 */
#define PSA_ERROR_UNKNOWN_ERROR \
    MBEDTLS_DEPRECATED_CONSTANT( psa_status_t, PSA_ERROR_GENERIC_ERROR )
#define PSA_ERROR_OCCUPIED_SLOT \
    MBEDTLS_DEPRECATED_CONSTANT( psa_status_t, PSA_ERROR_ALREADY_EXISTS )
#define PSA_ERROR_EMPTY_SLOT \
    MBEDTLS_DEPRECATED_CONSTANT( psa_status_t, PSA_ERROR_DOES_NOT_EXIST )
#define PSA_ERROR_INSUFFICIENT_CAPACITY \
    MBEDTLS_DEPRECATED_CONSTANT( psa_status_t, PSA_ERROR_INSUFFICIENT_DATA )
#define PSA_ERROR_TAMPERING_DETECTED \
    MBEDTLS_DEPRECATED_CONSTANT( psa_status_t, PSA_ERROR_CORRUPTION_DETECTED )

/*
 * Deprecated PSA Crypto numerical encodings (PSA Crypto API  <= 1.0 beta3)
 */
#define PSA_KEY_USAGE_SIGN \
    MBEDTLS_DEPRECATED_CONSTANT( psa_key_usage_t, PSA_KEY_USAGE_SIGN_HASH )
#define PSA_KEY_USAGE_VERIFY \
    MBEDTLS_DEPRECATED_CONSTANT( psa_key_usage_t, PSA_KEY_USAGE_VERIFY_HASH )

/*
 * Deprecated PSA Crypto size calculation macros (PSA Crypto API  <= 1.0 beta3)
 */
#define PSA_ASYMMETRIC_SIGNATURE_MAX_SIZE \
    MBEDTLS_DEPRECATED_CONSTANT( size_t, PSA_SIGNATURE_MAX_SIZE )
#define PSA_ASYMMETRIC_SIGN_OUTPUT_SIZE( key_type, key_bits, alg ) \
    MBEDTLS_DEPRECATED_CONSTANT( size_t, PSA_SIGN_OUTPUT_SIZE( key_type, key_bits, alg ) )

/*
 * Deprecated PSA Crypto function names (PSA Crypto API  <= 1.0 beta3)
 */
MBEDTLS_PSA_DEPRECATED static inline psa_status_t psa_asymmetric_sign( psa_key_handle_t key,
                            psa_algorithm_t alg,
                            const uint8_t *hash,
                            size_t hash_length,
                            uint8_t *signature,
                            size_t signature_size,
                            size_t *signature_length )
{
    return psa_sign_hash( key, alg, hash, hash_length, signature, signature_size, signature_length );
}

MBEDTLS_PSA_DEPRECATED static inline psa_status_t psa_asymmetric_verify( psa_key_handle_t key,
                              psa_algorithm_t alg,
                              const uint8_t *hash,
                              size_t hash_length,
                              const uint8_t *signature,
                              size_t signature_length )
{
    return psa_verify_hash( key, alg, hash, hash_length, signature, signature_length );
}



#endif /* MBEDTLS_DEPRECATED_REMOVED */

/*
 * Size-specific elliptic curve families.
 */
#define PSA_ECC_CURVE_SECP160K1 \
    MBEDTLS_DEPRECATED_CONSTANT( psa_ecc_family_t, PSA_ECC_FAMILY_SECP_K1 )
#define PSA_ECC_CURVE_SECP192K1 \
    MBEDTLS_DEPRECATED_CONSTANT( psa_ecc_family_t, PSA_ECC_FAMILY_SECP_K1 )
#define PSA_ECC_CURVE_SECP224K1 \
    MBEDTLS_DEPRECATED_CONSTANT( psa_ecc_family_t, PSA_ECC_FAMILY_SECP_K1 )
#define PSA_ECC_CURVE_SECP256K1 \
    MBEDTLS_DEPRECATED_CONSTANT( psa_ecc_family_t, PSA_ECC_FAMILY_SECP_K1 )
#define PSA_ECC_CURVE_SECP160R1 \
    MBEDTLS_DEPRECATED_CONSTANT( psa_ecc_family_t, PSA_ECC_FAMILY_SECP_R1 )
#define PSA_ECC_CURVE_SECP192R1 \
    MBEDTLS_DEPRECATED_CONSTANT( psa_ecc_family_t, PSA_ECC_FAMILY_SECP_R1 )
#define PSA_ECC_CURVE_SECP224R1 \
    MBEDTLS_DEPRECATED_CONSTANT( psa_ecc_family_t, PSA_ECC_FAMILY_SECP_R1 )
#define PSA_ECC_CURVE_SECP256R1 \
    MBEDTLS_DEPRECATED_CONSTANT( psa_ecc_family_t, PSA_ECC_FAMILY_SECP_R1 )
#define PSA_ECC_CURVE_SECP384R1 \
    MBEDTLS_DEPRECATED_CONSTANT( psa_ecc_family_t, PSA_ECC_FAMILY_SECP_R1 )
#define PSA_ECC_CURVE_SECP521R1 \
    MBEDTLS_DEPRECATED_CONSTANT( psa_ecc_family_t, PSA_ECC_FAMILY_SECP_R1 )
#define PSA_ECC_CURVE_SECP160R2 \
    MBEDTLS_DEPRECATED_CONSTANT( psa_ecc_family_t, PSA_ECC_FAMILY_SECP_R2 )
#define PSA_ECC_CURVE_SECT163K1 \
    MBEDTLS_DEPRECATED_CONSTANT( psa_ecc_family_t, PSA_ECC_FAMILY_SECT_K1 )
#define PSA_ECC_CURVE_SECT233K1 \
    MBEDTLS_DEPRECATED_CONSTANT( psa_ecc_family_t, PSA_ECC_FAMILY_SECT_K1 )
#define PSA_ECC_CURVE_SECT239K1 \
    MBEDTLS_DEPRECATED_CONSTANT( psa_ecc_family_t, PSA_ECC_FAMILY_SECT_K1 )
#define PSA_ECC_CURVE_SECT283K1 \
    MBEDTLS_DEPRECATED_CONSTANT( psa_ecc_family_t, PSA_ECC_FAMILY_SECT_K1 )
#define PSA_ECC_CURVE_SECT409K1 \
    MBEDTLS_DEPRECATED_CONSTANT( psa_ecc_family_t, PSA_ECC_FAMILY_SECT_K1 )
#define PSA_ECC_CURVE_SECT571K1 \
    MBEDTLS_DEPRECATED_CONSTANT( psa_ecc_family_t, PSA_ECC_FAMILY_SECT_K1 )
#define PSA_ECC_CURVE_SECT163R1 \
    MBEDTLS_DEPRECATED_CONSTANT( psa_ecc_family_t, PSA_ECC_FAMILY_SECT_R1 )
#define PSA_ECC_CURVE_SECT193R1 \
    MBEDTLS_DEPRECATED_CONSTANT( psa_ecc_family_t, PSA_ECC_FAMILY_SECT_R1 )
#define PSA_ECC_CURVE_SECT233R1 \
    MBEDTLS_DEPRECATED_CONSTANT( psa_ecc_family_t, PSA_ECC_FAMILY_SECT_R1 )
#define PSA_ECC_CURVE_SECT283R1 \
    MBEDTLS_DEPRECATED_CONSTANT( psa_ecc_family_t, PSA_ECC_FAMILY_SECT_R1 )
#define PSA_ECC_CURVE_SECT409R1 \
    MBEDTLS_DEPRECATED_CONSTANT( psa_ecc_family_t, PSA_ECC_FAMILY_SECT_R1 )
#define PSA_ECC_CURVE_SECT571R1 \
    MBEDTLS_DEPRECATED_CONSTANT( psa_ecc_family_t, PSA_ECC_FAMILY_SECT_R1 )
#define PSA_ECC_CURVE_SECT163R2 \
    MBEDTLS_DEPRECATED_CONSTANT( psa_ecc_family_t, PSA_ECC_FAMILY_SECT_R2 )
#define PSA_ECC_CURVE_SECT193R2 \
    MBEDTLS_DEPRECATED_CONSTANT( psa_ecc_family_t, PSA_ECC_FAMILY_SECT_R2 )
#define PSA_ECC_CURVE_BRAINPOOL_P256R1 \
    MBEDTLS_DEPRECATED_CONSTANT( psa_ecc_family_t, PSA_ECC_FAMILY_BRAINPOOL_P_R1 )
#define PSA_ECC_CURVE_BRAINPOOL_P384R1 \
    MBEDTLS_DEPRECATED_CONSTANT( psa_ecc_family_t, PSA_ECC_FAMILY_BRAINPOOL_P_R1 )
#define PSA_ECC_CURVE_BRAINPOOL_P512R1 \
    MBEDTLS_DEPRECATED_CONSTANT( psa_ecc_family_t, PSA_ECC_FAMILY_BRAINPOOL_P_R1 )
#define PSA_ECC_CURVE_CURVE25519 \
    MBEDTLS_DEPRECATED_CONSTANT( psa_ecc_family_t, PSA_ECC_FAMILY_MONTGOMERY )
#define PSA_ECC_CURVE_CURVE448 \
    MBEDTLS_DEPRECATED_CONSTANT( psa_ecc_family_t, PSA_ECC_FAMILY_MONTGOMERY )

/*
 * Curves that changed name due to PSA specification.
 */
#define PSA_ECC_CURVE_SECP_K1 \
    MBEDTLS_DEPRECATED_CONSTANT( psa_ecc_family_t, PSA_ECC_FAMILY_SECP_K1 )
#define PSA_ECC_CURVE_SECP_R1 \
    MBEDTLS_DEPRECATED_CONSTANT( psa_ecc_family_t, PSA_ECC_FAMILY_SECP_R1 )
#define PSA_ECC_CURVE_SECP_R2 \
    MBEDTLS_DEPRECATED_CONSTANT( psa_ecc_family_t, PSA_ECC_FAMILY_SECP_R2 )
#define PSA_ECC_CURVE_SECT_K1 \
    MBEDTLS_DEPRECATED_CONSTANT( psa_ecc_family_t, PSA_ECC_FAMILY_SECT_K1 )
#define PSA_ECC_CURVE_SECT_R1 \
    MBEDTLS_DEPRECATED_CONSTANT( psa_ecc_family_t, PSA_ECC_FAMILY_SECT_R1 )
#define PSA_ECC_CURVE_SECT_R2 \
    MBEDTLS_DEPRECATED_CONSTANT( psa_ecc_family_t, PSA_ECC_FAMILY_SECT_R2 )
#define PSA_ECC_CURVE_BRAINPOOL_P_R1 \
    MBEDTLS_DEPRECATED_CONSTANT( psa_ecc_family_t, PSA_ECC_FAMILY_BRAINPOOL_P_R1 )
#define PSA_ECC_CURVE_MONTGOMERY \
    MBEDTLS_DEPRECATED_CONSTANT( psa_ecc_family_t, PSA_ECC_FAMILY_MONTGOMERY )

/*
 * Finite-field Diffie-Hellman families.
 */
#define PSA_DH_GROUP_FFDHE2048 \
    MBEDTLS_DEPRECATED_CONSTANT( psa_dh_family_t, PSA_DH_FAMILY_RFC7919 )
#define PSA_DH_GROUP_FFDHE3072 \
    MBEDTLS_DEPRECATED_CONSTANT( psa_dh_family_t, PSA_DH_FAMILY_RFC7919 )
#define PSA_DH_GROUP_FFDHE4096 \
    MBEDTLS_DEPRECATED_CONSTANT( psa_dh_family_t, PSA_DH_FAMILY_RFC7919 )
#define PSA_DH_GROUP_FFDHE6144 \
    MBEDTLS_DEPRECATED_CONSTANT( psa_dh_family_t, PSA_DH_FAMILY_RFC7919 )
#define PSA_DH_GROUP_FFDHE8192 \
    MBEDTLS_DEPRECATED_CONSTANT( psa_dh_family_t, PSA_DH_FAMILY_RFC7919 )

/*
 * Diffie-Hellman families that changed name due to PSA specification.
 */
#define PSA_DH_GROUP_RFC7919 \
    MBEDTLS_DEPRECATED_CONSTANT( psa_dh_family_t, PSA_DH_FAMILY_RFC7919 )
#define PSA_DH_GROUP_CUSTOM \
    MBEDTLS_DEPRECATED_CONSTANT( psa_dh_family_t, PSA_DH_FAMILY_CUSTOM )

#ifdef __cplusplus
}
#endif

#endif /* PSA_CRYPTO_COMPAT_H */
