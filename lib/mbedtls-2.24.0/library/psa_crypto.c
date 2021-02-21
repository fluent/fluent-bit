/*
 *  PSA crypto layer on top of Mbed TLS crypto
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

#include "common.h"

#if defined(MBEDTLS_PSA_CRYPTO_C)

#include "psa_crypto_service_integration.h"
#include "psa/crypto.h"

#include "psa_crypto_core.h"
#include "psa_crypto_invasive.h"
#if defined(MBEDTLS_PSA_CRYPTO_SE_C)
#include "psa_crypto_se.h"
#endif
#include "psa_crypto_slot_management.h"
/* Include internal declarations that are useful for implementing persistently
 * stored keys. */
#include "psa_crypto_storage.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include "mbedtls/platform.h"
#if !defined(MBEDTLS_PLATFORM_C)
#define mbedtls_calloc calloc
#define mbedtls_free   free
#endif

#include "mbedtls/arc4.h"
#include "mbedtls/asn1.h"
#include "mbedtls/asn1write.h"
#include "mbedtls/bignum.h"
#include "mbedtls/blowfish.h"
#include "mbedtls/camellia.h"
#include "mbedtls/chacha20.h"
#include "mbedtls/chachapoly.h"
#include "mbedtls/cipher.h"
#include "mbedtls/ccm.h"
#include "mbedtls/cmac.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/des.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/ecp.h"
#include "mbedtls/entropy.h"
#include "mbedtls/error.h"
#include "mbedtls/gcm.h"
#include "mbedtls/md2.h"
#include "mbedtls/md4.h"
#include "mbedtls/md5.h"
#include "mbedtls/md.h"
#include "mbedtls/md_internal.h"
#include "mbedtls/pk.h"
#include "mbedtls/pk_internal.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/error.h"
#include "mbedtls/ripemd160.h"
#include "mbedtls/rsa.h"
#include "mbedtls/sha1.h"
#include "mbedtls/sha256.h"
#include "mbedtls/sha512.h"
#include "mbedtls/xtea.h"

#define ARRAY_LENGTH( array ) ( sizeof( array ) / sizeof( *( array ) ) )

/* constant-time buffer comparison */
static inline int safer_memcmp( const uint8_t *a, const uint8_t *b, size_t n )
{
    size_t i;
    unsigned char diff = 0;

    for( i = 0; i < n; i++ )
        diff |= a[i] ^ b[i];

    return( diff );
}



/****************************************************************/
/* Global data, support functions and library management */
/****************************************************************/

static int key_type_is_raw_bytes( psa_key_type_t type )
{
    return( PSA_KEY_TYPE_IS_UNSTRUCTURED( type ) );
}

/* Values for psa_global_data_t::rng_state */
#define RNG_NOT_INITIALIZED 0
#define RNG_INITIALIZED 1
#define RNG_SEEDED 2

typedef struct
{
    void (* entropy_init )( mbedtls_entropy_context *ctx );
    void (* entropy_free )( mbedtls_entropy_context *ctx );
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    unsigned initialized : 1;
    unsigned rng_state : 2;
} psa_global_data_t;

static psa_global_data_t global_data;

#define GUARD_MODULE_INITIALIZED        \
    if( global_data.initialized == 0 )  \
        return( PSA_ERROR_BAD_STATE );

static psa_status_t mbedtls_to_psa_error( int ret )
{
    /* If there's both a high-level code and low-level code, dispatch on
     * the high-level code. */
    switch( ret < -0x7f ? - ( -ret & 0x7f80 ) : ret )
    {
        case 0:
            return( PSA_SUCCESS );

        case MBEDTLS_ERR_AES_INVALID_KEY_LENGTH:
        case MBEDTLS_ERR_AES_INVALID_INPUT_LENGTH:
        case MBEDTLS_ERR_AES_FEATURE_UNAVAILABLE:
            return( PSA_ERROR_NOT_SUPPORTED );
        case MBEDTLS_ERR_AES_HW_ACCEL_FAILED:
            return( PSA_ERROR_HARDWARE_FAILURE );

        case MBEDTLS_ERR_ARC4_HW_ACCEL_FAILED:
            return( PSA_ERROR_HARDWARE_FAILURE );

        case MBEDTLS_ERR_ASN1_OUT_OF_DATA:
        case MBEDTLS_ERR_ASN1_UNEXPECTED_TAG:
        case MBEDTLS_ERR_ASN1_INVALID_LENGTH:
        case MBEDTLS_ERR_ASN1_LENGTH_MISMATCH:
        case MBEDTLS_ERR_ASN1_INVALID_DATA:
            return( PSA_ERROR_INVALID_ARGUMENT );
        case MBEDTLS_ERR_ASN1_ALLOC_FAILED:
            return( PSA_ERROR_INSUFFICIENT_MEMORY );
        case MBEDTLS_ERR_ASN1_BUF_TOO_SMALL:
            return( PSA_ERROR_BUFFER_TOO_SMALL );

#if defined(MBEDTLS_ERR_BLOWFISH_BAD_INPUT_DATA)
        case MBEDTLS_ERR_BLOWFISH_BAD_INPUT_DATA:
#elif defined(MBEDTLS_ERR_BLOWFISH_INVALID_KEY_LENGTH)
        case MBEDTLS_ERR_BLOWFISH_INVALID_KEY_LENGTH:
#endif
        case MBEDTLS_ERR_BLOWFISH_INVALID_INPUT_LENGTH:
            return( PSA_ERROR_NOT_SUPPORTED );
        case MBEDTLS_ERR_BLOWFISH_HW_ACCEL_FAILED:
            return( PSA_ERROR_HARDWARE_FAILURE );

#if defined(MBEDTLS_ERR_CAMELLIA_BAD_INPUT_DATA)
        case MBEDTLS_ERR_CAMELLIA_BAD_INPUT_DATA:
#elif defined(MBEDTLS_ERR_CAMELLIA_INVALID_KEY_LENGTH)
        case MBEDTLS_ERR_CAMELLIA_INVALID_KEY_LENGTH:
#endif
        case MBEDTLS_ERR_CAMELLIA_INVALID_INPUT_LENGTH:
            return( PSA_ERROR_NOT_SUPPORTED );
        case MBEDTLS_ERR_CAMELLIA_HW_ACCEL_FAILED:
            return( PSA_ERROR_HARDWARE_FAILURE );

        case MBEDTLS_ERR_CCM_BAD_INPUT:
            return( PSA_ERROR_INVALID_ARGUMENT );
        case MBEDTLS_ERR_CCM_AUTH_FAILED:
            return( PSA_ERROR_INVALID_SIGNATURE );
        case MBEDTLS_ERR_CCM_HW_ACCEL_FAILED:
            return( PSA_ERROR_HARDWARE_FAILURE );

        case MBEDTLS_ERR_CHACHA20_BAD_INPUT_DATA:
            return( PSA_ERROR_INVALID_ARGUMENT );

        case MBEDTLS_ERR_CHACHAPOLY_BAD_STATE:
            return( PSA_ERROR_BAD_STATE );
        case MBEDTLS_ERR_CHACHAPOLY_AUTH_FAILED:
            return( PSA_ERROR_INVALID_SIGNATURE );

        case MBEDTLS_ERR_CIPHER_FEATURE_UNAVAILABLE:
            return( PSA_ERROR_NOT_SUPPORTED );
        case MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA:
            return( PSA_ERROR_INVALID_ARGUMENT );
        case MBEDTLS_ERR_CIPHER_ALLOC_FAILED:
            return( PSA_ERROR_INSUFFICIENT_MEMORY );
        case MBEDTLS_ERR_CIPHER_INVALID_PADDING:
            return( PSA_ERROR_INVALID_PADDING );
        case MBEDTLS_ERR_CIPHER_FULL_BLOCK_EXPECTED:
            return( PSA_ERROR_BAD_STATE );
        case MBEDTLS_ERR_CIPHER_AUTH_FAILED:
            return( PSA_ERROR_INVALID_SIGNATURE );
        case MBEDTLS_ERR_CIPHER_INVALID_CONTEXT:
            return( PSA_ERROR_CORRUPTION_DETECTED );
        case MBEDTLS_ERR_CIPHER_HW_ACCEL_FAILED:
            return( PSA_ERROR_HARDWARE_FAILURE );

        case MBEDTLS_ERR_CMAC_HW_ACCEL_FAILED:
            return( PSA_ERROR_HARDWARE_FAILURE );

        case MBEDTLS_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED:
            return( PSA_ERROR_INSUFFICIENT_ENTROPY );
        case MBEDTLS_ERR_CTR_DRBG_REQUEST_TOO_BIG:
        case MBEDTLS_ERR_CTR_DRBG_INPUT_TOO_BIG:
            return( PSA_ERROR_NOT_SUPPORTED );
        case MBEDTLS_ERR_CTR_DRBG_FILE_IO_ERROR:
            return( PSA_ERROR_INSUFFICIENT_ENTROPY );

        case MBEDTLS_ERR_DES_INVALID_INPUT_LENGTH:
            return( PSA_ERROR_NOT_SUPPORTED );
        case MBEDTLS_ERR_DES_HW_ACCEL_FAILED:
            return( PSA_ERROR_HARDWARE_FAILURE );

        case MBEDTLS_ERR_ENTROPY_NO_SOURCES_DEFINED:
        case MBEDTLS_ERR_ENTROPY_NO_STRONG_SOURCE:
        case MBEDTLS_ERR_ENTROPY_SOURCE_FAILED:
            return( PSA_ERROR_INSUFFICIENT_ENTROPY );

        case MBEDTLS_ERR_GCM_AUTH_FAILED:
            return( PSA_ERROR_INVALID_SIGNATURE );
        case MBEDTLS_ERR_GCM_BAD_INPUT:
            return( PSA_ERROR_INVALID_ARGUMENT );
        case MBEDTLS_ERR_GCM_HW_ACCEL_FAILED:
            return( PSA_ERROR_HARDWARE_FAILURE );

        case MBEDTLS_ERR_MD2_HW_ACCEL_FAILED:
        case MBEDTLS_ERR_MD4_HW_ACCEL_FAILED:
        case MBEDTLS_ERR_MD5_HW_ACCEL_FAILED:
            return( PSA_ERROR_HARDWARE_FAILURE );

        case MBEDTLS_ERR_MD_FEATURE_UNAVAILABLE:
            return( PSA_ERROR_NOT_SUPPORTED );
        case MBEDTLS_ERR_MD_BAD_INPUT_DATA:
            return( PSA_ERROR_INVALID_ARGUMENT );
        case MBEDTLS_ERR_MD_ALLOC_FAILED:
            return( PSA_ERROR_INSUFFICIENT_MEMORY );
        case MBEDTLS_ERR_MD_FILE_IO_ERROR:
            return( PSA_ERROR_STORAGE_FAILURE );
        case MBEDTLS_ERR_MD_HW_ACCEL_FAILED:
            return( PSA_ERROR_HARDWARE_FAILURE );

        case MBEDTLS_ERR_MPI_FILE_IO_ERROR:
            return( PSA_ERROR_STORAGE_FAILURE );
        case MBEDTLS_ERR_MPI_BAD_INPUT_DATA:
            return( PSA_ERROR_INVALID_ARGUMENT );
        case MBEDTLS_ERR_MPI_INVALID_CHARACTER:
            return( PSA_ERROR_INVALID_ARGUMENT );
        case MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL:
            return( PSA_ERROR_BUFFER_TOO_SMALL );
        case MBEDTLS_ERR_MPI_NEGATIVE_VALUE:
            return( PSA_ERROR_INVALID_ARGUMENT );
        case MBEDTLS_ERR_MPI_DIVISION_BY_ZERO:
            return( PSA_ERROR_INVALID_ARGUMENT );
        case MBEDTLS_ERR_MPI_NOT_ACCEPTABLE:
            return( PSA_ERROR_INVALID_ARGUMENT );
        case MBEDTLS_ERR_MPI_ALLOC_FAILED:
            return( PSA_ERROR_INSUFFICIENT_MEMORY );

        case MBEDTLS_ERR_PK_ALLOC_FAILED:
            return( PSA_ERROR_INSUFFICIENT_MEMORY );
        case MBEDTLS_ERR_PK_TYPE_MISMATCH:
        case MBEDTLS_ERR_PK_BAD_INPUT_DATA:
            return( PSA_ERROR_INVALID_ARGUMENT );
        case MBEDTLS_ERR_PK_FILE_IO_ERROR:
            return( PSA_ERROR_STORAGE_FAILURE );
        case MBEDTLS_ERR_PK_KEY_INVALID_VERSION:
        case MBEDTLS_ERR_PK_KEY_INVALID_FORMAT:
            return( PSA_ERROR_INVALID_ARGUMENT );
        case MBEDTLS_ERR_PK_UNKNOWN_PK_ALG:
            return( PSA_ERROR_NOT_SUPPORTED );
        case MBEDTLS_ERR_PK_PASSWORD_REQUIRED:
        case MBEDTLS_ERR_PK_PASSWORD_MISMATCH:
            return( PSA_ERROR_NOT_PERMITTED );
        case MBEDTLS_ERR_PK_INVALID_PUBKEY:
            return( PSA_ERROR_INVALID_ARGUMENT );
        case MBEDTLS_ERR_PK_INVALID_ALG:
        case MBEDTLS_ERR_PK_UNKNOWN_NAMED_CURVE:
        case MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE:
            return( PSA_ERROR_NOT_SUPPORTED );
        case MBEDTLS_ERR_PK_SIG_LEN_MISMATCH:
            return( PSA_ERROR_INVALID_SIGNATURE );
        case MBEDTLS_ERR_PK_HW_ACCEL_FAILED:
            return( PSA_ERROR_HARDWARE_FAILURE );

        case MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED:
            return( PSA_ERROR_HARDWARE_FAILURE );
        case MBEDTLS_ERR_PLATFORM_FEATURE_UNSUPPORTED:
            return( PSA_ERROR_NOT_SUPPORTED );

        case MBEDTLS_ERR_RIPEMD160_HW_ACCEL_FAILED:
            return( PSA_ERROR_HARDWARE_FAILURE );

        case MBEDTLS_ERR_RSA_BAD_INPUT_DATA:
            return( PSA_ERROR_INVALID_ARGUMENT );
        case MBEDTLS_ERR_RSA_INVALID_PADDING:
            return( PSA_ERROR_INVALID_PADDING );
        case MBEDTLS_ERR_RSA_KEY_GEN_FAILED:
            return( PSA_ERROR_HARDWARE_FAILURE );
        case MBEDTLS_ERR_RSA_KEY_CHECK_FAILED:
            return( PSA_ERROR_INVALID_ARGUMENT );
        case MBEDTLS_ERR_RSA_PUBLIC_FAILED:
        case MBEDTLS_ERR_RSA_PRIVATE_FAILED:
            return( PSA_ERROR_CORRUPTION_DETECTED );
        case MBEDTLS_ERR_RSA_VERIFY_FAILED:
            return( PSA_ERROR_INVALID_SIGNATURE );
        case MBEDTLS_ERR_RSA_OUTPUT_TOO_LARGE:
            return( PSA_ERROR_BUFFER_TOO_SMALL );
        case MBEDTLS_ERR_RSA_RNG_FAILED:
            return( PSA_ERROR_INSUFFICIENT_MEMORY );
        case MBEDTLS_ERR_RSA_UNSUPPORTED_OPERATION:
            return( PSA_ERROR_NOT_SUPPORTED );
        case MBEDTLS_ERR_RSA_HW_ACCEL_FAILED:
            return( PSA_ERROR_HARDWARE_FAILURE );

        case MBEDTLS_ERR_SHA1_HW_ACCEL_FAILED:
        case MBEDTLS_ERR_SHA256_HW_ACCEL_FAILED:
        case MBEDTLS_ERR_SHA512_HW_ACCEL_FAILED:
            return( PSA_ERROR_HARDWARE_FAILURE );

        case MBEDTLS_ERR_XTEA_INVALID_INPUT_LENGTH:
            return( PSA_ERROR_INVALID_ARGUMENT );
        case MBEDTLS_ERR_XTEA_HW_ACCEL_FAILED:
            return( PSA_ERROR_HARDWARE_FAILURE );

        case MBEDTLS_ERR_ECP_BAD_INPUT_DATA:
        case MBEDTLS_ERR_ECP_INVALID_KEY:
            return( PSA_ERROR_INVALID_ARGUMENT );
        case MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL:
            return( PSA_ERROR_BUFFER_TOO_SMALL );
        case MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE:
            return( PSA_ERROR_NOT_SUPPORTED );
        case MBEDTLS_ERR_ECP_SIG_LEN_MISMATCH:
        case MBEDTLS_ERR_ECP_VERIFY_FAILED:
            return( PSA_ERROR_INVALID_SIGNATURE );
        case MBEDTLS_ERR_ECP_ALLOC_FAILED:
            return( PSA_ERROR_INSUFFICIENT_MEMORY );
        case MBEDTLS_ERR_ECP_HW_ACCEL_FAILED:
            return( PSA_ERROR_HARDWARE_FAILURE );
        case MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED:
            return( PSA_ERROR_CORRUPTION_DETECTED );

        default:
            return( PSA_ERROR_GENERIC_ERROR );
    }
}




/****************************************************************/
/* Key management */
/****************************************************************/

#if defined(MBEDTLS_PSA_CRYPTO_SE_C)
static inline int psa_key_slot_is_external( const psa_key_slot_t *slot )
{
    return( psa_key_lifetime_is_external( slot->attr.lifetime ) );
}
#endif /* MBEDTLS_PSA_CRYPTO_SE_C */

#if defined(MBEDTLS_ECP_C)
mbedtls_ecp_group_id mbedtls_ecc_group_of_psa( psa_ecc_family_t curve,
                                               size_t byte_length )
{
    switch( curve )
    {
        case PSA_ECC_FAMILY_SECP_R1:
            switch( byte_length )
            {
                case PSA_BITS_TO_BYTES( 192 ):
                    return( MBEDTLS_ECP_DP_SECP192R1 );
                case PSA_BITS_TO_BYTES( 224 ):
                    return( MBEDTLS_ECP_DP_SECP224R1 );
                case PSA_BITS_TO_BYTES( 256 ):
                    return( MBEDTLS_ECP_DP_SECP256R1 );
                case PSA_BITS_TO_BYTES( 384 ):
                    return( MBEDTLS_ECP_DP_SECP384R1 );
                case PSA_BITS_TO_BYTES( 521 ):
                    return( MBEDTLS_ECP_DP_SECP521R1 );
                default:
                    return( MBEDTLS_ECP_DP_NONE );
            }
            break;

        case PSA_ECC_FAMILY_BRAINPOOL_P_R1:
            switch( byte_length )
            {
                case PSA_BITS_TO_BYTES( 256 ):
                    return( MBEDTLS_ECP_DP_BP256R1 );
                case PSA_BITS_TO_BYTES( 384 ):
                    return( MBEDTLS_ECP_DP_BP384R1 );
                case PSA_BITS_TO_BYTES( 512 ):
                    return( MBEDTLS_ECP_DP_BP512R1 );
                default:
                    return( MBEDTLS_ECP_DP_NONE );
            }
            break;

        case PSA_ECC_FAMILY_MONTGOMERY:
            switch( byte_length )
            {
                case PSA_BITS_TO_BYTES( 255 ):
                    return( MBEDTLS_ECP_DP_CURVE25519 );
                case PSA_BITS_TO_BYTES( 448 ):
                    return( MBEDTLS_ECP_DP_CURVE448 );
                default:
                    return( MBEDTLS_ECP_DP_NONE );
            }
            break;

        case PSA_ECC_FAMILY_SECP_K1:
            switch( byte_length )
            {
                case PSA_BITS_TO_BYTES( 192 ):
                    return( MBEDTLS_ECP_DP_SECP192K1 );
                case PSA_BITS_TO_BYTES( 224 ):
                    return( MBEDTLS_ECP_DP_SECP224K1 );
                case PSA_BITS_TO_BYTES( 256 ):
                    return( MBEDTLS_ECP_DP_SECP256K1 );
                default:
                    return( MBEDTLS_ECP_DP_NONE );
            }
            break;

        default:
            return( MBEDTLS_ECP_DP_NONE );
    }
}
#endif /* defined(MBEDTLS_ECP_C) */

static psa_status_t validate_unstructured_key_bit_size( psa_key_type_t type,
                                                        size_t bits )
{
    /* Check that the bit size is acceptable for the key type */
    switch( type )
    {
        case PSA_KEY_TYPE_RAW_DATA:
#if defined(MBEDTLS_MD_C)
        case PSA_KEY_TYPE_HMAC:
#endif
        case PSA_KEY_TYPE_DERIVE:
            break;
#if defined(MBEDTLS_AES_C)
        case PSA_KEY_TYPE_AES:
            if( bits != 128 && bits != 192 && bits != 256 )
                return( PSA_ERROR_INVALID_ARGUMENT );
            break;
#endif
#if defined(MBEDTLS_CAMELLIA_C)
        case PSA_KEY_TYPE_CAMELLIA:
            if( bits != 128 && bits != 192 && bits != 256 )
                return( PSA_ERROR_INVALID_ARGUMENT );
            break;
#endif
#if defined(MBEDTLS_DES_C)
        case PSA_KEY_TYPE_DES:
            if( bits != 64 && bits != 128 && bits != 192 )
                return( PSA_ERROR_INVALID_ARGUMENT );
            break;
#endif
#if defined(MBEDTLS_ARC4_C)
        case PSA_KEY_TYPE_ARC4:
            if( bits < 8 || bits > 2048 )
                return( PSA_ERROR_INVALID_ARGUMENT );
            break;
#endif
#if defined(MBEDTLS_CHACHA20_C)
        case PSA_KEY_TYPE_CHACHA20:
            if( bits != 256 )
                return( PSA_ERROR_INVALID_ARGUMENT );
            break;
#endif
        default:
            return( PSA_ERROR_NOT_SUPPORTED );
    }
    if( bits % 8 != 0 )
        return( PSA_ERROR_INVALID_ARGUMENT );

    return( PSA_SUCCESS );
}

#if defined(MBEDTLS_RSA_C)

#if defined(MBEDTLS_PK_PARSE_C)
/* Mbed TLS doesn't support non-byte-aligned key sizes (i.e. key sizes
 * that are not a multiple of 8) well. For example, there is only
 * mbedtls_rsa_get_len(), which returns a number of bytes, and no
 * way to return the exact bit size of a key.
 * To keep things simple, reject non-byte-aligned key sizes. */
static psa_status_t psa_check_rsa_key_byte_aligned(
    const mbedtls_rsa_context *rsa )
{
    mbedtls_mpi n;
    psa_status_t status;
    mbedtls_mpi_init( &n );
    status = mbedtls_to_psa_error(
        mbedtls_rsa_export( rsa, &n, NULL, NULL, NULL, NULL ) );
    if( status == PSA_SUCCESS )
    {
        if( mbedtls_mpi_bitlen( &n ) % 8 != 0 )
            status = PSA_ERROR_NOT_SUPPORTED;
    }
    mbedtls_mpi_free( &n );
    return( status );
}
#endif /* MBEDTLS_PK_PARSE_C */

/** Load the contents of a key buffer into an internal RSA representation
 *
 * \param[in] type          The type of key contained in \p data.
 * \param[in] data          The buffer from which to load the representation.
 * \param[in] data_length   The size in bytes of \p data.
 * \param[out] p_rsa        Returns a pointer to an RSA context on success.
 *                          The caller is responsible for freeing both the
 *                          contents of the context and the context itself
 *                          when done.
 */
static psa_status_t psa_load_rsa_representation( psa_key_type_t type,
                                                 const uint8_t *data,
                                                 size_t data_length,
                                                 mbedtls_rsa_context **p_rsa )
{
#if defined(MBEDTLS_PK_PARSE_C)
    psa_status_t status;
    mbedtls_pk_context ctx;
    size_t bits;
    mbedtls_pk_init( &ctx );

    /* Parse the data. */
    if( PSA_KEY_TYPE_IS_KEY_PAIR( type ) )
        status = mbedtls_to_psa_error(
            mbedtls_pk_parse_key( &ctx, data, data_length, NULL, 0 ) );
    else
        status = mbedtls_to_psa_error(
            mbedtls_pk_parse_public_key( &ctx, data, data_length ) );
    if( status != PSA_SUCCESS )
        goto exit;

    /* We have something that the pkparse module recognizes. If it is a
     * valid RSA key, store it. */
    if( mbedtls_pk_get_type( &ctx ) != MBEDTLS_PK_RSA )
    {
        status = PSA_ERROR_INVALID_ARGUMENT;
        goto exit;
    }

    /* The size of an RSA key doesn't have to be a multiple of 8. Mbed TLS
     * supports non-byte-aligned key sizes, but not well. For example,
     * mbedtls_rsa_get_len() returns the key size in bytes, not in bits. */
    bits = PSA_BYTES_TO_BITS( mbedtls_rsa_get_len( mbedtls_pk_rsa( ctx ) ) );
    if( bits > PSA_VENDOR_RSA_MAX_KEY_BITS )
    {
        status = PSA_ERROR_NOT_SUPPORTED;
        goto exit;
    }
    status = psa_check_rsa_key_byte_aligned( mbedtls_pk_rsa( ctx ) );
    if( status != PSA_SUCCESS )
        goto exit;

    /* Copy out the pointer to the RSA context, and reset the PK context
     * such that pk_free doesn't free the RSA context we just grabbed. */
    *p_rsa = mbedtls_pk_rsa( ctx );
    ctx.pk_info = NULL;

exit:
    mbedtls_pk_free( &ctx );
    return( status );
#else
    (void) data;
    (void) data_length;
    (void) type;
    (void) rsa;
    return( PSA_ERROR_NOT_SUPPORTED );
#endif /* MBEDTLS_PK_PARSE_C */
}

/** Export an RSA key to export representation
 *
 * \param[in] type          The type of key (public/private) to export
 * \param[in] rsa           The internal RSA representation from which to export
 * \param[out] data         The buffer to export to
 * \param[in] data_size     The length of the buffer to export to
 * \param[out] data_length  The amount of bytes written to \p data
 */
static psa_status_t psa_export_rsa_key( psa_key_type_t type,
                                        mbedtls_rsa_context *rsa,
                                        uint8_t *data,
                                        size_t data_size,
                                        size_t *data_length )
{
#if defined(MBEDTLS_PK_WRITE_C)
    int ret;
    mbedtls_pk_context pk;
    uint8_t *pos = data + data_size;

    mbedtls_pk_init( &pk );
    pk.pk_info = &mbedtls_rsa_info;
    pk.pk_ctx = rsa;

    /* PSA Crypto API defines the format of an RSA key as a DER-encoded
     * representation of the non-encrypted PKCS#1 RSAPrivateKey for a
     * private key and of the RFC3279 RSAPublicKey for a public key. */
    if( PSA_KEY_TYPE_IS_KEY_PAIR( type ) )
        ret = mbedtls_pk_write_key_der( &pk, data, data_size );
    else
        ret = mbedtls_pk_write_pubkey( &pos, data, &pk );

    if( ret < 0 )
    {
        /* Clean up in case pk_write failed halfway through. */
        memset( data, 0, data_size );
        return( mbedtls_to_psa_error( ret ) );
    }

    /* The mbedtls_pk_xxx functions write to the end of the buffer.
     * Move the data to the beginning and erase remaining data
     * at the original location. */
    if( 2 * (size_t) ret <= data_size )
    {
        memcpy( data, data + data_size - ret, ret );
        memset( data + data_size - ret, 0, ret );
    }
    else if( (size_t) ret < data_size )
    {
        memmove( data, data + data_size - ret, ret );
        memset( data + ret, 0, data_size - ret );
    }

    *data_length = ret;
    return( PSA_SUCCESS );
#else
    (void) type;
    (void) rsa;
    (void) data;
    (void) data_size;
    (void) data_length;
    return( PSA_ERROR_NOT_SUPPORTED );
#endif /* MBEDTLS_PK_WRITE_C */
}

/** Import an RSA key from import representation to a slot
 *
 * \param[in,out] slot      The slot where to store the export representation to
 * \param[in] data          The buffer containing the import representation
 * \param[in] data_length   The amount of bytes in \p data
 */
static psa_status_t psa_import_rsa_key( psa_key_slot_t *slot,
                                        const uint8_t *data,
                                        size_t data_length )
{
    psa_status_t status;
    uint8_t* output = NULL;
    mbedtls_rsa_context *rsa = NULL;

    /* Parse input */
    status = psa_load_rsa_representation( slot->attr.type,
                                          data,
                                          data_length,
                                          &rsa );
    if( status != PSA_SUCCESS )
        goto exit;

    slot->attr.bits = (psa_key_bits_t) PSA_BYTES_TO_BITS(
        mbedtls_rsa_get_len( rsa ) );

    /* Re-export the data to PSA export format, such that we can store export
     * representation in the key slot. Export representation in case of RSA is
     * the smallest representation that's allowed as input, so a straight-up
     * allocation of the same size as the input buffer will be large enough. */
    output = mbedtls_calloc( 1, data_length );
    if( output == NULL )
    {
        status = PSA_ERROR_INSUFFICIENT_MEMORY;
        goto exit;
    }

    status = psa_export_rsa_key( slot->attr.type,
                                 rsa,
                                 output,
                                 data_length,
                                 &data_length);
exit:
    /* Always free the RSA object */
    mbedtls_rsa_free( rsa );
    mbedtls_free( rsa );

    /* Free the allocated buffer only on error. */
    if( status != PSA_SUCCESS )
    {
        mbedtls_free( output );
        return( status );
    }

    /* On success, store the allocated export-formatted key. */
    slot->data.key.data = output;
    slot->data.key.bytes = data_length;

    return( PSA_SUCCESS );
}
#endif /* defined(MBEDTLS_RSA_C) */

#if defined(MBEDTLS_ECP_C)
/** Load the contents of a key buffer into an internal ECP representation
 *
 * \param[in] type          The type of key contained in \p data.
 * \param[in] data          The buffer from which to load the representation.
 * \param[in] data_length   The size in bytes of \p data.
 * \param[out] p_ecp        Returns a pointer to an ECP context on success.
 *                          The caller is responsible for freeing both the
 *                          contents of the context and the context itself
 *                          when done.
 */
static psa_status_t psa_load_ecp_representation( psa_key_type_t type,
                                                 const uint8_t *data,
                                                 size_t data_length,
                                                 mbedtls_ecp_keypair **p_ecp )
{
    mbedtls_ecp_group_id grp_id = MBEDTLS_ECP_DP_NONE;
    psa_status_t status;
    mbedtls_ecp_keypair *ecp = NULL;
    size_t curve_size = data_length;

    if( PSA_KEY_TYPE_IS_PUBLIC_KEY( type ) &&
        PSA_KEY_TYPE_ECC_GET_FAMILY( type ) != PSA_ECC_FAMILY_MONTGOMERY )
    {
        /* A Weierstrass public key is represented as:
         * - The byte 0x04;
         * - `x_P` as a `ceiling(m/8)`-byte string, big-endian;
         * - `y_P` as a `ceiling(m/8)`-byte string, big-endian.
         * So its data length is 2m+1 where n is the key size in bits.
         */
        if( ( data_length & 1 ) == 0 )
            return( PSA_ERROR_INVALID_ARGUMENT );
        curve_size = data_length / 2;

        /* Montgomery public keys are represented in compressed format, meaning
         * their curve_size is equal to the amount of input. */

        /* Private keys are represented in uncompressed private random integer
         * format, meaning their curve_size is equal to the amount of input. */
    }

    /* Allocate and initialize a key representation. */
    ecp = mbedtls_calloc( 1, sizeof( mbedtls_ecp_keypair ) );
    if( ecp == NULL )
        return( PSA_ERROR_INSUFFICIENT_MEMORY );
    mbedtls_ecp_keypair_init( ecp );

    /* Load the group. */
    grp_id = mbedtls_ecc_group_of_psa( PSA_KEY_TYPE_ECC_GET_FAMILY( type ),
                                       curve_size );
    if( grp_id == MBEDTLS_ECP_DP_NONE )
    {
        status = PSA_ERROR_INVALID_ARGUMENT;
        goto exit;
    }

    status = mbedtls_to_psa_error(
                mbedtls_ecp_group_load( &ecp->grp, grp_id ) );
    if( status != PSA_SUCCESS )
        goto exit;

    /* Load the key material. */
    if( PSA_KEY_TYPE_IS_PUBLIC_KEY( type ) )
    {
        /* Load the public value. */
        status = mbedtls_to_psa_error(
            mbedtls_ecp_point_read_binary( &ecp->grp, &ecp->Q,
                                           data,
                                           data_length ) );
        if( status != PSA_SUCCESS )
            goto exit;

        /* Check that the point is on the curve. */
        status = mbedtls_to_psa_error(
            mbedtls_ecp_check_pubkey( &ecp->grp, &ecp->Q ) );
        if( status != PSA_SUCCESS )
            goto exit;
    }
    else
    {
        /* Load and validate the secret value. */
        status = mbedtls_to_psa_error(
            mbedtls_ecp_read_key( ecp->grp.id,
                                  ecp,
                                  data,
                                  data_length ) );
        if( status != PSA_SUCCESS )
            goto exit;
    }

    *p_ecp = ecp;
exit:
    if( status != PSA_SUCCESS )
    {
        mbedtls_ecp_keypair_free( ecp );
        mbedtls_free( ecp );
    }

    return( status );
}

/** Export an ECP key to export representation
 *
 * \param[in] type          The type of key (public/private) to export
 * \param[in] ecp           The internal ECP representation from which to export
 * \param[out] data         The buffer to export to
 * \param[in] data_size     The length of the buffer to export to
 * \param[out] data_length  The amount of bytes written to \p data
 */
static psa_status_t psa_export_ecp_key( psa_key_type_t type,
                                        mbedtls_ecp_keypair *ecp,
                                        uint8_t *data,
                                        size_t data_size,
                                        size_t *data_length )
{
    psa_status_t status;

    if( PSA_KEY_TYPE_IS_PUBLIC_KEY( type ) )
    {
        /* Check whether the public part is loaded */
        if( mbedtls_ecp_is_zero( &ecp->Q ) )
        {
            /* Calculate the public key */
            status = mbedtls_to_psa_error(
                mbedtls_ecp_mul( &ecp->grp, &ecp->Q, &ecp->d, &ecp->grp.G,
                                 mbedtls_ctr_drbg_random, &global_data.ctr_drbg ) );
            if( status != PSA_SUCCESS )
                return( status );
        }

        status = mbedtls_to_psa_error(
                    mbedtls_ecp_point_write_binary( &ecp->grp, &ecp->Q,
                                                    MBEDTLS_ECP_PF_UNCOMPRESSED,
                                                    data_length,
                                                    data,
                                                    data_size ) );
        if( status != PSA_SUCCESS )
            memset( data, 0, data_size );

        return( status );
    }
    else
    {
        if( data_size < PSA_BITS_TO_BYTES( ecp->grp.nbits ) )
            return( PSA_ERROR_BUFFER_TOO_SMALL );

        status = mbedtls_to_psa_error(
                    mbedtls_ecp_write_key( ecp,
                                           data,
                                           PSA_BITS_TO_BYTES( ecp->grp.nbits ) ) );
        if( status == PSA_SUCCESS )
            *data_length = PSA_BITS_TO_BYTES( ecp->grp.nbits );
        else
            memset( data, 0, data_size );

        return( status );
    }
}

/** Import an ECP key from import representation to a slot
 *
 * \param[in,out] slot      The slot where to store the export representation to
 * \param[in] data          The buffer containing the import representation
 * \param[in] data_length   The amount of bytes in \p data
 */
static psa_status_t psa_import_ecp_key( psa_key_slot_t *slot,
                                        const uint8_t *data,
                                        size_t data_length )
{
    psa_status_t status;
    uint8_t* output = NULL;
    mbedtls_ecp_keypair *ecp = NULL;

    /* Parse input */
    status = psa_load_ecp_representation( slot->attr.type,
                                          data,
                                          data_length,
                                          &ecp );
    if( status != PSA_SUCCESS )
        goto exit;

    if( PSA_KEY_TYPE_ECC_GET_FAMILY( slot->attr.type ) == PSA_ECC_FAMILY_MONTGOMERY)
        slot->attr.bits = (psa_key_bits_t) ecp->grp.nbits + 1;
    else
        slot->attr.bits = (psa_key_bits_t) ecp->grp.nbits;

    /* Re-export the data to PSA export format. There is currently no support
     * for other input formats then the export format, so this is a 1-1
     * copy operation. */
    output = mbedtls_calloc( 1, data_length );
    if( output == NULL )
    {
        status = PSA_ERROR_INSUFFICIENT_MEMORY;
        goto exit;
    }

    status = psa_export_ecp_key( slot->attr.type,
                                 ecp,
                                 output,
                                 data_length,
                                 &data_length);
exit:
    /* Always free the PK object (will also free contained ECP context) */
    mbedtls_ecp_keypair_free( ecp );
    mbedtls_free( ecp );

    /* Free the allocated buffer only on error. */
    if( status != PSA_SUCCESS )
    {
        mbedtls_free( output );
        return( status );
    }

    /* On success, store the allocated export-formatted key. */
    slot->data.key.data = output;
    slot->data.key.bytes = data_length;

    return( PSA_SUCCESS );
}
#endif /* defined(MBEDTLS_ECP_C) */

/** Return the size of the key in the given slot, in bits.
 *
 * \param[in] slot      A key slot.
 *
 * \return The key size in bits, read from the metadata in the slot.
 */
static inline size_t psa_get_key_slot_bits( const psa_key_slot_t *slot )
{
    return( slot->attr.bits );
}

/** Try to allocate a buffer to an empty key slot.
 *
 * \param[in,out] slot          Key slot to attach buffer to.
 * \param[in] buffer_length     Requested size of the buffer.
 *
 * \retval #PSA_SUCCESS
 *         The buffer has been successfully allocated.
 * \retval #PSA_ERROR_INSUFFICIENT_MEMORY
 *         Not enough memory was available for allocation.
 * \retval #PSA_ERROR_ALREADY_EXISTS
 *         Trying to allocate a buffer to a non-empty key slot.
 */
static psa_status_t psa_allocate_buffer_to_slot( psa_key_slot_t *slot,
                                                 size_t buffer_length )
{
    if( slot->data.key.data != NULL )
        return( PSA_ERROR_ALREADY_EXISTS );

    slot->data.key.data = mbedtls_calloc( 1, buffer_length );
    if( slot->data.key.data == NULL )
        return( PSA_ERROR_INSUFFICIENT_MEMORY );

    slot->data.key.bytes = buffer_length;
    return( PSA_SUCCESS );
}

/** Import key data into a slot. `slot->attr.type` must have been set
 * previously. This function assumes that the slot does not contain
 * any key material yet. On failure, the slot content is unchanged. */
psa_status_t psa_import_key_into_slot( psa_key_slot_t *slot,
                                       const uint8_t *data,
                                       size_t data_length )
{
    psa_status_t status = PSA_SUCCESS;

    /* zero-length keys are never supported. */
    if( data_length == 0 )
        return( PSA_ERROR_NOT_SUPPORTED );

    if( key_type_is_raw_bytes( slot->attr.type ) )
    {
        size_t bit_size = PSA_BYTES_TO_BITS( data_length );

        /* Ensure that the bytes-to-bits conversion hasn't overflown. */
        if( data_length > SIZE_MAX / 8 )
            return( PSA_ERROR_NOT_SUPPORTED );

        /* Enforce a size limit, and in particular ensure that the bit
         * size fits in its representation type. */
        if( bit_size > PSA_MAX_KEY_BITS )
            return( PSA_ERROR_NOT_SUPPORTED );

        status = validate_unstructured_key_bit_size( slot->attr.type, bit_size );
        if( status != PSA_SUCCESS )
            return( status );

        /* Allocate memory for the key */
        status = psa_allocate_buffer_to_slot( slot, data_length );
        if( status != PSA_SUCCESS )
            return( status );

        /* copy key into allocated buffer */
        memcpy( slot->data.key.data, data, data_length );

        /* Write the actual key size to the slot.
         * psa_start_key_creation() wrote the size declared by the
         * caller, which may be 0 (meaning unspecified) or wrong. */
        slot->attr.bits = (psa_key_bits_t) bit_size;
    }
    else if( PSA_KEY_TYPE_IS_ECC( slot->attr.type ) )
    {
#if defined(MBEDTLS_ECP_C)
        status = psa_import_ecp_key( slot,
                                     data, data_length );
#else
        /* No drivers have been implemented yet, so without mbed TLS backing
         * there's no way to do ECP with the current library. */
        return( PSA_ERROR_NOT_SUPPORTED );
#endif /* defined(MBEDTLS_ECP_C) */
    }
    else if( PSA_KEY_TYPE_IS_RSA( slot->attr.type ) )
    {
#if defined(MBEDTLS_RSA_C)
        status = psa_import_rsa_key( slot,
                                     data, data_length );
#else
        /* No drivers have been implemented yet, so without mbed TLS backing
         * there's no way to do RSA with the current library. */
        status = PSA_ERROR_NOT_SUPPORTED;
#endif /* defined(MBEDTLS_RSA_C) */
    }
    else
    {
        /* Unknown key type */
        return( PSA_ERROR_NOT_SUPPORTED );
    }

    return( status );
}

/** Calculate the intersection of two algorithm usage policies.
 *
 * Return 0 (which allows no operation) on incompatibility.
 */
static psa_algorithm_t psa_key_policy_algorithm_intersection(
    psa_algorithm_t alg1,
    psa_algorithm_t alg2 )
{
    /* Common case: both sides actually specify the same policy. */
    if( alg1 == alg2 )
        return( alg1 );
    /* If the policies are from the same hash-and-sign family, check
     * if one is a wildcard. If so the other has the specific algorithm. */
    if( PSA_ALG_IS_HASH_AND_SIGN( alg1 ) &&
        PSA_ALG_IS_HASH_AND_SIGN( alg2 ) &&
        ( alg1 & ~PSA_ALG_HASH_MASK ) == ( alg2 & ~PSA_ALG_HASH_MASK ) )
    {
        if( PSA_ALG_SIGN_GET_HASH( alg1 ) == PSA_ALG_ANY_HASH )
            return( alg2 );
        if( PSA_ALG_SIGN_GET_HASH( alg2 ) == PSA_ALG_ANY_HASH )
            return( alg1 );
    }
    /* If the policies are incompatible, allow nothing. */
    return( 0 );
}

static int psa_key_algorithm_permits( psa_algorithm_t policy_alg,
                                      psa_algorithm_t requested_alg )
{
    /* Common case: the policy only allows requested_alg. */
    if( requested_alg == policy_alg )
        return( 1 );
    /* If policy_alg is a hash-and-sign with a wildcard for the hash,
     * and requested_alg is the same hash-and-sign family with any hash,
     * then requested_alg is compliant with policy_alg. */
    if( PSA_ALG_IS_HASH_AND_SIGN( requested_alg ) &&
        PSA_ALG_SIGN_GET_HASH( policy_alg ) == PSA_ALG_ANY_HASH )
    {
        return( ( policy_alg & ~PSA_ALG_HASH_MASK ) ==
                ( requested_alg & ~PSA_ALG_HASH_MASK ) );
    }
    /* If it isn't permitted, it's forbidden. */
    return( 0 );
}

/** Test whether a policy permits an algorithm.
 *
 * The caller must test usage flags separately.
 */
static int psa_key_policy_permits( const psa_key_policy_t *policy,
                                   psa_algorithm_t alg )
{
    return( psa_key_algorithm_permits( policy->alg, alg ) ||
            psa_key_algorithm_permits( policy->alg2, alg ) );
}

/** Restrict a key policy based on a constraint.
 *
 * \param[in,out] policy    The policy to restrict.
 * \param[in] constraint    The policy constraint to apply.
 *
 * \retval #PSA_SUCCESS
 *         \c *policy contains the intersection of the original value of
 *         \c *policy and \c *constraint.
 * \retval #PSA_ERROR_INVALID_ARGUMENT
 *         \c *policy and \c *constraint are incompatible.
 *         \c *policy is unchanged.
 */
static psa_status_t psa_restrict_key_policy(
    psa_key_policy_t *policy,
    const psa_key_policy_t *constraint )
{
    psa_algorithm_t intersection_alg =
        psa_key_policy_algorithm_intersection( policy->alg, constraint->alg );
    psa_algorithm_t intersection_alg2 =
        psa_key_policy_algorithm_intersection( policy->alg2, constraint->alg2 );
    if( intersection_alg == 0 && policy->alg != 0 && constraint->alg != 0 )
        return( PSA_ERROR_INVALID_ARGUMENT );
    if( intersection_alg2 == 0 && policy->alg2 != 0 && constraint->alg2 != 0 )
        return( PSA_ERROR_INVALID_ARGUMENT );
    policy->usage &= constraint->usage;
    policy->alg = intersection_alg;
    policy->alg2 = intersection_alg2;
    return( PSA_SUCCESS );
}

/** Retrieve a slot which must contain a key. The key must have allow all the
 * usage flags set in \p usage. If \p alg is nonzero, the key must allow
 * operations with this algorithm. */
static psa_status_t psa_get_key_from_slot( psa_key_handle_t handle,
                                           psa_key_slot_t **p_slot,
                                           psa_key_usage_t usage,
                                           psa_algorithm_t alg )
{
    psa_status_t status;
    psa_key_slot_t *slot = NULL;

    *p_slot = NULL;

    status = psa_get_key_slot( handle, &slot );
    if( status != PSA_SUCCESS )
        return( status );

    /* Enforce that usage policy for the key slot contains all the flags
     * required by the usage parameter. There is one exception: public
     * keys can always be exported, so we treat public key objects as
     * if they had the export flag. */
    if( PSA_KEY_TYPE_IS_PUBLIC_KEY( slot->attr.type ) )
        usage &= ~PSA_KEY_USAGE_EXPORT;
    if( ( slot->attr.policy.usage & usage ) != usage )
        return( PSA_ERROR_NOT_PERMITTED );

    /* Enforce that the usage policy permits the requested algortihm. */
    if( alg != 0 && ! psa_key_policy_permits( &slot->attr.policy, alg ) )
        return( PSA_ERROR_NOT_PERMITTED );

    *p_slot = slot;
    return( PSA_SUCCESS );
}

/** Retrieve a slot which must contain a transparent key.
 *
 * A transparent key is a key for which the key material is directly
 * available, as opposed to a key in a secure element.
 *
 * This is a temporary function to use instead of psa_get_key_from_slot()
 * until secure element support is fully implemented.
 */
#if defined(MBEDTLS_PSA_CRYPTO_SE_C)
static psa_status_t psa_get_transparent_key( psa_key_handle_t handle,
                                             psa_key_slot_t **p_slot,
                                             psa_key_usage_t usage,
                                             psa_algorithm_t alg )
{
    psa_status_t status = psa_get_key_from_slot( handle, p_slot, usage, alg );
    if( status != PSA_SUCCESS )
        return( status );
    if( psa_key_slot_is_external( *p_slot ) )
    {
        *p_slot = NULL;
        return( PSA_ERROR_NOT_SUPPORTED );
    }
    return( PSA_SUCCESS );
}
#else /* MBEDTLS_PSA_CRYPTO_SE_C */
/* With no secure element support, all keys are transparent. */
#define psa_get_transparent_key( handle, p_slot, usage, alg )   \
    psa_get_key_from_slot( handle, p_slot, usage, alg )
#endif /* MBEDTLS_PSA_CRYPTO_SE_C */

/** Wipe key data from a slot. Preserve metadata such as the policy. */
static psa_status_t psa_remove_key_data_from_memory( psa_key_slot_t *slot )
{
#if defined(MBEDTLS_PSA_CRYPTO_SE_C)
    if( psa_key_slot_is_external( slot ) )
    {
        /* No key material to clean. */
    }
    else
#endif /* MBEDTLS_PSA_CRYPTO_SE_C */
    {
        /* Data pointer will always be either a valid pointer or NULL in an
         * initialized slot, so we can just free it. */
        if( slot->data.key.data != NULL )
            mbedtls_platform_zeroize( slot->data.key.data, slot->data.key.bytes);
        mbedtls_free( slot->data.key.data );
        slot->data.key.data = NULL;
        slot->data.key.bytes = 0;
    }

    return( PSA_SUCCESS );
}

/** Completely wipe a slot in memory, including its policy.
 * Persistent storage is not affected. */
psa_status_t psa_wipe_key_slot( psa_key_slot_t *slot )
{
    psa_status_t status = psa_remove_key_data_from_memory( slot );
    /* Multipart operations may still be using the key. This is safe
     * because all multipart operation objects are independent from
     * the key slot: if they need to access the key after the setup
     * phase, they have a copy of the key. Note that this means that
     * key material can linger until all operations are completed. */
    /* At this point, key material and other type-specific content has
     * been wiped. Clear remaining metadata. We can call memset and not
     * zeroize because the metadata is not particularly sensitive. */
    memset( slot, 0, sizeof( *slot ) );
    return( status );
}

psa_status_t psa_destroy_key( psa_key_handle_t handle )
{
    psa_key_slot_t *slot;
    psa_status_t status; /* status of the last operation */
    psa_status_t overall_status = PSA_SUCCESS;
#if defined(MBEDTLS_PSA_CRYPTO_SE_C)
    psa_se_drv_table_entry_t *driver;
#endif /* MBEDTLS_PSA_CRYPTO_SE_C */

    if( handle == 0 )
        return( PSA_SUCCESS );

    status = psa_get_key_slot( handle, &slot );
    if( status != PSA_SUCCESS )
        return( status );

#if defined(MBEDTLS_PSA_CRYPTO_SE_C)
    driver = psa_get_se_driver_entry( slot->attr.lifetime );
    if( driver != NULL )
    {
        /* For a key in a secure element, we need to do three things:
         * remove the key file in internal storage, destroy the
         * key inside the secure element, and update the driver's
         * persistent data. Start a transaction that will encompass these
         * three actions. */
        psa_crypto_prepare_transaction( PSA_CRYPTO_TRANSACTION_DESTROY_KEY );
        psa_crypto_transaction.key.lifetime = slot->attr.lifetime;
        psa_crypto_transaction.key.slot = slot->data.se.slot_number;
        psa_crypto_transaction.key.id = slot->attr.id;
        status = psa_crypto_save_transaction( );
        if( status != PSA_SUCCESS )
        {
            (void) psa_crypto_stop_transaction( );
            /* We should still try to destroy the key in the secure
             * element and the key metadata in storage. This is especially
             * important if the error is that the storage is full.
             * But how to do it exactly without risking an inconsistent
             * state after a reset?
             * https://github.com/ARMmbed/mbed-crypto/issues/215
             */
            overall_status = status;
            goto exit;
        }

        status = psa_destroy_se_key( driver, slot->data.se.slot_number );
        if( overall_status == PSA_SUCCESS )
            overall_status = status;
    }
#endif /* MBEDTLS_PSA_CRYPTO_SE_C */

#if defined(MBEDTLS_PSA_CRYPTO_STORAGE_C)
    if( slot->attr.lifetime != PSA_KEY_LIFETIME_VOLATILE )
    {
        status = psa_destroy_persistent_key( slot->attr.id );
        if( overall_status == PSA_SUCCESS )
            overall_status = status;

        /* TODO: other slots may have a copy of the same key. We should
         * invalidate them.
         * https://github.com/ARMmbed/mbed-crypto/issues/214
         */
    }
#endif /* defined(MBEDTLS_PSA_CRYPTO_STORAGE_C) */

#if defined(MBEDTLS_PSA_CRYPTO_SE_C)
    if( driver != NULL )
    {
        status = psa_save_se_persistent_data( driver );
        if( overall_status == PSA_SUCCESS )
            overall_status = status;
        status = psa_crypto_stop_transaction( );
        if( overall_status == PSA_SUCCESS )
            overall_status = status;
    }
#endif /* MBEDTLS_PSA_CRYPTO_SE_C */

#if defined(MBEDTLS_PSA_CRYPTO_SE_C)
exit:
#endif /* MBEDTLS_PSA_CRYPTO_SE_C */
    status = psa_wipe_key_slot( slot );
    /* Prioritize CORRUPTION_DETECTED from wiping over a storage error */
    if( overall_status == PSA_SUCCESS )
        overall_status = status;
    return( overall_status );
}

void psa_reset_key_attributes( psa_key_attributes_t *attributes )
{
    mbedtls_free( attributes->domain_parameters );
    memset( attributes, 0, sizeof( *attributes ) );
}

psa_status_t psa_set_key_domain_parameters( psa_key_attributes_t *attributes,
                                            psa_key_type_t type,
                                            const uint8_t *data,
                                            size_t data_length )
{
    uint8_t *copy = NULL;

    if( data_length != 0 )
    {
        copy = mbedtls_calloc( 1, data_length );
        if( copy == NULL )
            return( PSA_ERROR_INSUFFICIENT_MEMORY );
        memcpy( copy, data, data_length );
    }
    /* After this point, this function is guaranteed to succeed, so it
     * can start modifying `*attributes`. */

    if( attributes->domain_parameters != NULL )
    {
        mbedtls_free( attributes->domain_parameters );
        attributes->domain_parameters = NULL;
        attributes->domain_parameters_size = 0;
    }

    attributes->domain_parameters = copy;
    attributes->domain_parameters_size = data_length;
    attributes->core.type = type;
    return( PSA_SUCCESS );
}

psa_status_t psa_get_key_domain_parameters(
    const psa_key_attributes_t *attributes,
    uint8_t *data, size_t data_size, size_t *data_length )
{
    if( attributes->domain_parameters_size > data_size )
        return( PSA_ERROR_BUFFER_TOO_SMALL );
    *data_length = attributes->domain_parameters_size;
    if( attributes->domain_parameters_size != 0 )
        memcpy( data, attributes->domain_parameters,
                attributes->domain_parameters_size );
    return( PSA_SUCCESS );
}

#if defined(MBEDTLS_RSA_C)
static psa_status_t psa_get_rsa_public_exponent(
    const mbedtls_rsa_context *rsa,
    psa_key_attributes_t *attributes )
{
    mbedtls_mpi mpi;
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    uint8_t *buffer = NULL;
    size_t buflen;
    mbedtls_mpi_init( &mpi );

    ret = mbedtls_rsa_export( rsa, NULL, NULL, NULL, NULL, &mpi );
    if( ret != 0 )
        goto exit;
    if( mbedtls_mpi_cmp_int( &mpi, 65537 ) == 0 )
    {
        /* It's the default value, which is reported as an empty string,
         * so there's nothing to do. */
        goto exit;
    }

    buflen = mbedtls_mpi_size( &mpi );
    buffer = mbedtls_calloc( 1, buflen );
    if( buffer == NULL )
    {
        ret = MBEDTLS_ERR_MPI_ALLOC_FAILED;
        goto exit;
    }
    ret = mbedtls_mpi_write_binary( &mpi, buffer, buflen );
    if( ret != 0 )
        goto exit;
    attributes->domain_parameters = buffer;
    attributes->domain_parameters_size = buflen;

exit:
    mbedtls_mpi_free( &mpi );
    if( ret != 0 )
        mbedtls_free( buffer );
    return( mbedtls_to_psa_error( ret ) );
}
#endif /* MBEDTLS_RSA_C */

/** Retrieve all the publicly-accessible attributes of a key.
 */
psa_status_t psa_get_key_attributes( psa_key_handle_t handle,
                                     psa_key_attributes_t *attributes )
{
    psa_key_slot_t *slot;
    psa_status_t status;

    psa_reset_key_attributes( attributes );

    status = psa_get_key_from_slot( handle, &slot, 0, 0 );
    if( status != PSA_SUCCESS )
        return( status );

    attributes->core = slot->attr;
    attributes->core.flags &= ( MBEDTLS_PSA_KA_MASK_EXTERNAL_ONLY |
                                MBEDTLS_PSA_KA_MASK_DUAL_USE );

#if defined(MBEDTLS_PSA_CRYPTO_SE_C)
    if( psa_key_slot_is_external( slot ) )
        psa_set_key_slot_number( attributes, slot->data.se.slot_number );
#endif /* MBEDTLS_PSA_CRYPTO_SE_C */

    switch( slot->attr.type )
    {
#if defined(MBEDTLS_RSA_C)
        case PSA_KEY_TYPE_RSA_KEY_PAIR:
        case PSA_KEY_TYPE_RSA_PUBLIC_KEY:
#if defined(MBEDTLS_PSA_CRYPTO_SE_C)
            /* TODO: reporting the public exponent for opaque keys
             * is not yet implemented.
             * https://github.com/ARMmbed/mbed-crypto/issues/216
             */
            if( psa_key_slot_is_external( slot ) )
                break;
#endif /* MBEDTLS_PSA_CRYPTO_SE_C */
            {
                mbedtls_rsa_context *rsa = NULL;

                status = psa_load_rsa_representation( slot->attr.type,
                                                      slot->data.key.data,
                                                      slot->data.key.bytes,
                                                      &rsa );
                if( status != PSA_SUCCESS )
                    break;

                status = psa_get_rsa_public_exponent( rsa,
                                                      attributes );
                mbedtls_rsa_free( rsa );
                mbedtls_free( rsa );
            }
            break;
#endif /* MBEDTLS_RSA_C */
        default:
            /* Nothing else to do. */
            break;
    }

    if( status != PSA_SUCCESS )
        psa_reset_key_attributes( attributes );
    return( status );
}

#if defined(MBEDTLS_PSA_CRYPTO_SE_C)
psa_status_t psa_get_key_slot_number(
    const psa_key_attributes_t *attributes,
    psa_key_slot_number_t *slot_number )
{
    if( attributes->core.flags & MBEDTLS_PSA_KA_FLAG_HAS_SLOT_NUMBER )
    {
        *slot_number = attributes->slot_number;
        return( PSA_SUCCESS );
    }
    else
        return( PSA_ERROR_INVALID_ARGUMENT );
}
#endif /* MBEDTLS_PSA_CRYPTO_SE_C */

static psa_status_t psa_internal_export_key_buffer( const psa_key_slot_t *slot,
                                                    uint8_t *data,
                                                    size_t data_size,
                                                    size_t *data_length )
{
    if( slot->data.key.bytes > data_size )
        return( PSA_ERROR_BUFFER_TOO_SMALL );
    memcpy( data, slot->data.key.data, slot->data.key.bytes );
    memset( data + slot->data.key.bytes, 0,
            data_size - slot->data.key.bytes );
    *data_length = slot->data.key.bytes;
    return( PSA_SUCCESS );
}

static psa_status_t psa_internal_export_key( const psa_key_slot_t *slot,
                                             uint8_t *data,
                                             size_t data_size,
                                             size_t *data_length,
                                             int export_public_key )
{
#if defined(MBEDTLS_PSA_CRYPTO_SE_C)
    const psa_drv_se_t *drv;
    psa_drv_se_context_t *drv_context;
#endif /* MBEDTLS_PSA_CRYPTO_SE_C */

    *data_length = 0;

    if( export_public_key && ! PSA_KEY_TYPE_IS_ASYMMETRIC( slot->attr.type ) )
        return( PSA_ERROR_INVALID_ARGUMENT );

    /* Reject a zero-length output buffer now, since this can never be a
     * valid key representation. This way we know that data must be a valid
     * pointer and we can do things like memset(data, ..., data_size). */
    if( data_size == 0 )
        return( PSA_ERROR_BUFFER_TOO_SMALL );

#if defined(MBEDTLS_PSA_CRYPTO_SE_C)
    if( psa_get_se_driver( slot->attr.lifetime, &drv, &drv_context ) )
    {
        psa_drv_se_export_key_t method;
        if( drv->key_management == NULL )
            return( PSA_ERROR_NOT_SUPPORTED );
        method = ( export_public_key ?
                   drv->key_management->p_export_public :
                   drv->key_management->p_export );
        if( method == NULL )
            return( PSA_ERROR_NOT_SUPPORTED );
        return( method( drv_context,
                        slot->data.se.slot_number,
                        data, data_size, data_length ) );
    }
#endif /* MBEDTLS_PSA_CRYPTO_SE_C */

    if( key_type_is_raw_bytes( slot->attr.type ) )
    {
        return( psa_internal_export_key_buffer( slot, data, data_size, data_length ) );
    }
    else if( PSA_KEY_TYPE_IS_RSA( slot->attr.type ) ||
             PSA_KEY_TYPE_IS_ECC( slot->attr.type ) )
    {
        if( PSA_KEY_TYPE_IS_PUBLIC_KEY( slot->attr.type ) )
        {
            /* Exporting public -> public */
            return( psa_internal_export_key_buffer( slot, data, data_size, data_length ) );
        }
        else if( !export_public_key )
        {
            /* Exporting private -> private */
            return( psa_internal_export_key_buffer( slot, data, data_size, data_length ) );
        }
        /* Need to export the public part of a private key,
         * so conversion is needed */
        if( PSA_KEY_TYPE_IS_RSA( slot->attr.type ) )
        {
#if defined(MBEDTLS_RSA_C)
            mbedtls_rsa_context *rsa = NULL;
            psa_status_t status = psa_load_rsa_representation(
                                    slot->attr.type,
                                    slot->data.key.data,
                                    slot->data.key.bytes,
                                    &rsa );
            if( status != PSA_SUCCESS )
                return( status );

            status = psa_export_rsa_key( PSA_KEY_TYPE_RSA_PUBLIC_KEY,
                                         rsa,
                                         data,
                                         data_size,
                                         data_length );

            mbedtls_rsa_free( rsa );
            mbedtls_free( rsa );

            return( status );
#else
            /* We don't know how to convert a private RSA key to public. */
            return( PSA_ERROR_NOT_SUPPORTED );
#endif
        }
        else
        {
#if defined(MBEDTLS_ECP_C)
            mbedtls_ecp_keypair *ecp = NULL;
            psa_status_t status = psa_load_ecp_representation(
                                    slot->attr.type,
                                    slot->data.key.data,
                                    slot->data.key.bytes,
                                    &ecp );
            if( status != PSA_SUCCESS )
                return( status );

            status = psa_export_ecp_key( PSA_KEY_TYPE_ECC_PUBLIC_KEY(
                                            PSA_KEY_TYPE_ECC_GET_FAMILY(
                                                slot->attr.type ) ),
                                         ecp,
                                         data,
                                         data_size,
                                         data_length );

            mbedtls_ecp_keypair_free( ecp );
            mbedtls_free( ecp );
            return( status );
#else
            /* We don't know how to convert a private ECC key to public */
            return( PSA_ERROR_NOT_SUPPORTED );
#endif
        }
    }
    else
    {
        /* This shouldn't happen in the reference implementation, but
           it is valid for a special-purpose implementation to omit
           support for exporting certain key types. */
        return( PSA_ERROR_NOT_SUPPORTED );
    }
}

psa_status_t psa_export_key( psa_key_handle_t handle,
                             uint8_t *data,
                             size_t data_size,
                             size_t *data_length )
{
    psa_key_slot_t *slot;
    psa_status_t status;

    /* Set the key to empty now, so that even when there are errors, we always
     * set data_length to a value between 0 and data_size. On error, setting
     * the key to empty is a good choice because an empty key representation is
     * unlikely to be accepted anywhere. */
    *data_length = 0;

    /* Export requires the EXPORT flag. There is an exception for public keys,
     * which don't require any flag, but psa_get_key_from_slot takes
     * care of this. */
    status = psa_get_key_from_slot( handle, &slot, PSA_KEY_USAGE_EXPORT, 0 );
    if( status != PSA_SUCCESS )
        return( status );
    return( psa_internal_export_key( slot, data, data_size,
                                     data_length, 0 ) );
}

psa_status_t psa_export_public_key( psa_key_handle_t handle,
                                    uint8_t *data,
                                    size_t data_size,
                                    size_t *data_length )
{
    psa_key_slot_t *slot;
    psa_status_t status;

    /* Set the key to empty now, so that even when there are errors, we always
     * set data_length to a value between 0 and data_size. On error, setting
     * the key to empty is a good choice because an empty key representation is
     * unlikely to be accepted anywhere. */
    *data_length = 0;

    /* Exporting a public key doesn't require a usage flag. */
    status = psa_get_key_from_slot( handle, &slot, 0, 0 );
    if( status != PSA_SUCCESS )
        return( status );
    return( psa_internal_export_key( slot, data, data_size,
                                     data_length, 1 ) );
}

#if defined(static_assert)
static_assert( ( MBEDTLS_PSA_KA_MASK_EXTERNAL_ONLY & MBEDTLS_PSA_KA_MASK_DUAL_USE ) == 0,
               "One or more key attribute flag is listed as both external-only and dual-use" );
static_assert( ( PSA_KA_MASK_INTERNAL_ONLY & MBEDTLS_PSA_KA_MASK_DUAL_USE ) == 0,
               "One or more key attribute flag is listed as both internal-only and dual-use" );
static_assert( ( PSA_KA_MASK_INTERNAL_ONLY & MBEDTLS_PSA_KA_MASK_EXTERNAL_ONLY ) == 0,
               "One or more key attribute flag is listed as both internal-only and external-only" );
#endif

/** Validate that a key policy is internally well-formed.
 *
 * This function only rejects invalid policies. It does not validate the
 * consistency of the policy with respect to other attributes of the key
 * such as the key type.
 */
static psa_status_t psa_validate_key_policy( const psa_key_policy_t *policy )
{
    if( ( policy->usage & ~( PSA_KEY_USAGE_EXPORT |
                             PSA_KEY_USAGE_COPY |
                             PSA_KEY_USAGE_ENCRYPT |
                             PSA_KEY_USAGE_DECRYPT |
                             PSA_KEY_USAGE_SIGN_HASH |
                             PSA_KEY_USAGE_VERIFY_HASH |
                             PSA_KEY_USAGE_DERIVE ) ) != 0 )
        return( PSA_ERROR_INVALID_ARGUMENT );

    return( PSA_SUCCESS );
}

/** Validate the internal consistency of key attributes.
 *
 * This function only rejects invalid attribute values. If does not
 * validate the consistency of the attributes with any key data that may
 * be involved in the creation of the key.
 *
 * Call this function early in the key creation process.
 *
 * \param[in] attributes    Key attributes for the new key.
 * \param[out] p_drv        On any return, the driver for the key, if any.
 *                          NULL for a transparent key.
 *
 */
static psa_status_t psa_validate_key_attributes(
    const psa_key_attributes_t *attributes,
    psa_se_drv_table_entry_t **p_drv )
{
    psa_status_t status = PSA_ERROR_INVALID_ARGUMENT;

    status = psa_validate_key_location( psa_get_key_lifetime( attributes ),
                                        p_drv );
    if( status != PSA_SUCCESS )
        return( status );

    status = psa_validate_key_persistence( psa_get_key_lifetime( attributes ),
                                           psa_get_key_id( attributes ) );
    if( status != PSA_SUCCESS )
        return( status );

    status = psa_validate_key_policy( &attributes->core.policy );
    if( status != PSA_SUCCESS )
        return( status );

    /* Refuse to create overly large keys.
     * Note that this doesn't trigger on import if the attributes don't
     * explicitly specify a size (so psa_get_key_bits returns 0), so
     * psa_import_key() needs its own checks. */
    if( psa_get_key_bits( attributes ) > PSA_MAX_KEY_BITS )
        return( PSA_ERROR_NOT_SUPPORTED );

    /* Reject invalid flags. These should not be reachable through the API. */
    if( attributes->core.flags & ~ ( MBEDTLS_PSA_KA_MASK_EXTERNAL_ONLY |
                                     MBEDTLS_PSA_KA_MASK_DUAL_USE ) )
        return( PSA_ERROR_INVALID_ARGUMENT );

    return( PSA_SUCCESS );
}

/** Prepare a key slot to receive key material.
 *
 * This function allocates a key slot and sets its metadata.
 *
 * If this function fails, call psa_fail_key_creation().
 *
 * This function is intended to be used as follows:
 * -# Call psa_start_key_creation() to allocate a key slot, prepare
 *    it with the specified attributes, and assign it a handle.
 * -# Populate the slot with the key material.
 * -# Call psa_finish_key_creation() to finalize the creation of the slot.
 * In case of failure at any step, stop the sequence and call
 * psa_fail_key_creation().
 *
 * \param method            An identification of the calling function.
 * \param[in] attributes    Key attributes for the new key.
 * \param[out] handle       On success, a handle for the allocated slot.
 * \param[out] p_slot       On success, a pointer to the prepared slot.
 * \param[out] p_drv        On any return, the driver for the key, if any.
 *                          NULL for a transparent key.
 *
 * \retval #PSA_SUCCESS
 *         The key slot is ready to receive key material.
 * \return If this function fails, the key slot is an invalid state.
 *         You must call psa_fail_key_creation() to wipe and free the slot.
 */
static psa_status_t psa_start_key_creation(
    psa_key_creation_method_t method,
    const psa_key_attributes_t *attributes,
    psa_key_handle_t *handle,
    psa_key_slot_t **p_slot,
    psa_se_drv_table_entry_t **p_drv )
{
    psa_status_t status;
    psa_key_slot_t *slot;

    (void) method;
    *p_drv = NULL;

    status = psa_validate_key_attributes( attributes, p_drv );
    if( status != PSA_SUCCESS )
        return( status );

    status = psa_get_empty_key_slot( handle, p_slot );
    if( status != PSA_SUCCESS )
        return( status );
    slot = *p_slot;

    /* We're storing the declared bit-size of the key. It's up to each
     * creation mechanism to verify that this information is correct.
     * It's automatically correct for mechanisms that use the bit-size as
     * an input (generate, device) but not for those where the bit-size
     * is optional (import, copy). */

    slot->attr = attributes->core;

    /* Erase external-only flags from the internal copy. To access
     * external-only flags, query `attributes`. Thanks to the check
     * in psa_validate_key_attributes(), this leaves the dual-use
     * flags and any internal flag that psa_get_empty_key_slot()
     * may have set. */
    slot->attr.flags &= ~MBEDTLS_PSA_KA_MASK_EXTERNAL_ONLY;

#if defined(MBEDTLS_PSA_CRYPTO_SE_C)
    /* For a key in a secure element, we need to do three things
     * when creating or registering a persistent key:
     * create the key file in internal storage, create the
     * key inside the secure element, and update the driver's
     * persistent data. This is done by starting a transaction that will
     * encompass these three actions.
     * For registering a volatile key, we just need to find an appropriate
     * slot number inside the SE. Since the key is designated volatile, creating
     * a transaction is not required. */
    /* The first thing to do is to find a slot number for the new key.
     * We save the slot number in persistent storage as part of the
     * transaction data. It will be needed to recover if the power
     * fails during the key creation process, to clean up on the secure
     * element side after restarting. Obtaining a slot number from the
     * secure element driver updates its persistent state, but we do not yet
     * save the driver's persistent state, so that if the power fails,
     * we can roll back to a state where the key doesn't exist. */
    if( *p_drv != NULL )
    {
        status = psa_find_se_slot_for_key( attributes, method, *p_drv,
                                           &slot->data.se.slot_number );
        if( status != PSA_SUCCESS )
            return( status );

        if( ! PSA_KEY_LIFETIME_IS_VOLATILE( attributes->core.lifetime ) )
        {
            psa_crypto_prepare_transaction( PSA_CRYPTO_TRANSACTION_CREATE_KEY );
            psa_crypto_transaction.key.lifetime = slot->attr.lifetime;
            psa_crypto_transaction.key.slot = slot->data.se.slot_number;
            psa_crypto_transaction.key.id = slot->attr.id;
            status = psa_crypto_save_transaction( );
            if( status != PSA_SUCCESS )
            {
                (void) psa_crypto_stop_transaction( );
                return( status );
            }
        }
    }

    if( *p_drv == NULL && method == PSA_KEY_CREATION_REGISTER )
    {
        /* Key registration only makes sense with a secure element. */
        return( PSA_ERROR_INVALID_ARGUMENT );
    }
#endif /* MBEDTLS_PSA_CRYPTO_SE_C */

    return( status );
}

/** Finalize the creation of a key once its key material has been set.
 *
 * This entails writing the key to persistent storage.
 *
 * If this function fails, call psa_fail_key_creation().
 * See the documentation of psa_start_key_creation() for the intended use
 * of this function.
 *
 * \param[in,out] slot  Pointer to the slot with key material.
 * \param[in] driver    The secure element driver for the key,
 *                      or NULL for a transparent key.
 *
 * \retval #PSA_SUCCESS
 *         The key was successfully created. The handle is now valid.
 * \return If this function fails, the key slot is an invalid state.
 *         You must call psa_fail_key_creation() to wipe and free the slot.
 */
static psa_status_t psa_finish_key_creation(
    psa_key_slot_t *slot,
    psa_se_drv_table_entry_t *driver )
{
    psa_status_t status = PSA_SUCCESS;
    (void) slot;
    (void) driver;

#if defined(MBEDTLS_PSA_CRYPTO_STORAGE_C)
    if( ! PSA_KEY_LIFETIME_IS_VOLATILE( slot->attr.lifetime ) )
    {
#if defined(MBEDTLS_PSA_CRYPTO_SE_C)
        if( driver != NULL )
        {
            psa_se_key_data_storage_t data;
#if defined(static_assert)
            static_assert( sizeof( slot->data.se.slot_number ) ==
                           sizeof( data.slot_number ),
                           "Slot number size does not match psa_se_key_data_storage_t" );
            static_assert( sizeof( slot->attr.bits ) == sizeof( data.bits ),
                           "Bit-size size does not match psa_se_key_data_storage_t" );
#endif
            memcpy( &data.slot_number, &slot->data.se.slot_number,
                    sizeof( slot->data.se.slot_number ) );
            memcpy( &data.bits, &slot->attr.bits,
                    sizeof( slot->attr.bits ) );
            status = psa_save_persistent_key( &slot->attr,
                                              (uint8_t*) &data,
                                              sizeof( data ) );
        }
        else
#endif /* MBEDTLS_PSA_CRYPTO_SE_C */
        {
            size_t buffer_size =
                PSA_KEY_EXPORT_MAX_SIZE( slot->attr.type,
                                         slot->attr.bits );
            uint8_t *buffer = mbedtls_calloc( 1, buffer_size );
            size_t length = 0;
            if( buffer == NULL )
                return( PSA_ERROR_INSUFFICIENT_MEMORY );
            status = psa_internal_export_key( slot,
                                              buffer, buffer_size, &length,
                                              0 );
            if( status == PSA_SUCCESS )
                status = psa_save_persistent_key( &slot->attr,
                                                  buffer, length );

            mbedtls_platform_zeroize( buffer, buffer_size );
            mbedtls_free( buffer );
        }
    }
#endif /* defined(MBEDTLS_PSA_CRYPTO_STORAGE_C) */

#if defined(MBEDTLS_PSA_CRYPTO_SE_C)
    /* Finish the transaction for a key creation. This does not
     * happen when registering an existing key. Detect this case
     * by checking whether a transaction is in progress (actual
     * creation of a persistent key in a secure element requires a transaction,
     * but registration or volatile key creation doesn't use one). */
    if( driver != NULL &&
        psa_crypto_transaction.unknown.type == PSA_CRYPTO_TRANSACTION_CREATE_KEY )
    {
        status = psa_save_se_persistent_data( driver );
        if( status != PSA_SUCCESS )
        {
            psa_destroy_persistent_key( slot->attr.id );
            return( status );
        }
        status = psa_crypto_stop_transaction( );
        if( status != PSA_SUCCESS )
            return( status );
    }
#endif /* MBEDTLS_PSA_CRYPTO_SE_C */

    return( status );
}

/** Abort the creation of a key.
 *
 * You may call this function after calling psa_start_key_creation(),
 * or after psa_finish_key_creation() fails. In other circumstances, this
 * function may not clean up persistent storage.
 * See the documentation of psa_start_key_creation() for the intended use
 * of this function.
 *
 * \param[in,out] slot  Pointer to the slot with key material.
 * \param[in] driver    The secure element driver for the key,
 *                      or NULL for a transparent key.
 */
static void psa_fail_key_creation( psa_key_slot_t *slot,
                                   psa_se_drv_table_entry_t *driver )
{
    (void) driver;

    if( slot == NULL )
        return;

#if defined(MBEDTLS_PSA_CRYPTO_SE_C)
    /* TODO: If the key has already been created in the secure
     * element, and the failure happened later (when saving metadata
     * to internal storage), we need to destroy the key in the secure
     * element.
     * https://github.com/ARMmbed/mbed-crypto/issues/217
     */

    /* Abort the ongoing transaction if any (there may not be one if
     * the creation process failed before starting one, or if the
     * key creation is a registration of a key in a secure element).
     * Earlier functions must already have done what it takes to undo any
     * partial creation. All that's left is to update the transaction data
     * itself. */
    (void) psa_crypto_stop_transaction( );
#endif /* MBEDTLS_PSA_CRYPTO_SE_C */

    psa_wipe_key_slot( slot );
}

/** Validate optional attributes during key creation.
 *
 * Some key attributes are optional during key creation. If they are
 * specified in the attributes structure, check that they are consistent
 * with the data in the slot.
 *
 * This function should be called near the end of key creation, after
 * the slot in memory is fully populated but before saving persistent data.
 */
static psa_status_t psa_validate_optional_attributes(
    const psa_key_slot_t *slot,
    const psa_key_attributes_t *attributes )
{
    if( attributes->core.type != 0 )
    {
        if( attributes->core.type != slot->attr.type )
            return( PSA_ERROR_INVALID_ARGUMENT );
    }

    if( attributes->domain_parameters_size != 0 )
    {
#if defined(MBEDTLS_RSA_C)
        if( PSA_KEY_TYPE_IS_RSA( slot->attr.type ) )
        {
            mbedtls_rsa_context *rsa = NULL;
            mbedtls_mpi actual, required;
            int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

            psa_status_t status = psa_load_rsa_representation(
                                    slot->attr.type,
                                    slot->data.key.data,
                                    slot->data.key.bytes,
                                    &rsa );
            if( status != PSA_SUCCESS )
                return( status );

            mbedtls_mpi_init( &actual );
            mbedtls_mpi_init( &required );
            ret = mbedtls_rsa_export( rsa,
                                      NULL, NULL, NULL, NULL, &actual );
            mbedtls_rsa_free( rsa );
            mbedtls_free( rsa );
            if( ret != 0 )
                goto rsa_exit;
            ret = mbedtls_mpi_read_binary( &required,
                                           attributes->domain_parameters,
                                           attributes->domain_parameters_size );
            if( ret != 0 )
                goto rsa_exit;
            if( mbedtls_mpi_cmp_mpi( &actual, &required ) != 0 )
                ret = MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
        rsa_exit:
            mbedtls_mpi_free( &actual );
            mbedtls_mpi_free( &required );
            if( ret != 0)
                return( mbedtls_to_psa_error( ret ) );
        }
        else
#endif
        {
            return( PSA_ERROR_INVALID_ARGUMENT );
        }
    }

    if( attributes->core.bits != 0 )
    {
        if( attributes->core.bits != slot->attr.bits )
            return( PSA_ERROR_INVALID_ARGUMENT );
    }

    return( PSA_SUCCESS );
}

psa_status_t psa_import_key( const psa_key_attributes_t *attributes,
                             const uint8_t *data,
                             size_t data_length,
                             psa_key_handle_t *handle )
{
    psa_status_t status;
    psa_key_slot_t *slot = NULL;
    psa_se_drv_table_entry_t *driver = NULL;

    /* Reject zero-length symmetric keys (including raw data key objects).
     * This also rejects any key which might be encoded as an empty string,
     * which is never valid. */
    if( data_length == 0 )
        return( PSA_ERROR_INVALID_ARGUMENT );

    status = psa_start_key_creation( PSA_KEY_CREATION_IMPORT, attributes,
                                     handle, &slot, &driver );
    if( status != PSA_SUCCESS )
        goto exit;

#if defined(MBEDTLS_PSA_CRYPTO_SE_C)
    if( driver != NULL )
    {
        const psa_drv_se_t *drv = psa_get_se_driver_methods( driver );
        /* The driver should set the number of key bits, however in
         * case it doesn't, we initialize bits to an invalid value. */
        size_t bits = PSA_MAX_KEY_BITS + 1;
        if( drv->key_management == NULL ||
            drv->key_management->p_import == NULL )
        {
            status = PSA_ERROR_NOT_SUPPORTED;
            goto exit;
        }
        status = drv->key_management->p_import(
            psa_get_se_driver_context( driver ),
            slot->data.se.slot_number, attributes, data, data_length,
            &bits );
        if( status != PSA_SUCCESS )
            goto exit;
        if( bits > PSA_MAX_KEY_BITS )
        {
            status = PSA_ERROR_NOT_SUPPORTED;
            goto exit;
        }
        slot->attr.bits = (psa_key_bits_t) bits;
    }
    else
#endif /* MBEDTLS_PSA_CRYPTO_SE_C */
    {
        status = psa_import_key_into_slot( slot, data, data_length );
        if( status != PSA_SUCCESS )
            goto exit;
    }
    status = psa_validate_optional_attributes( slot, attributes );
    if( status != PSA_SUCCESS )
        goto exit;

    status = psa_finish_key_creation( slot, driver );
exit:
    if( status != PSA_SUCCESS )
    {
        psa_fail_key_creation( slot, driver );
        *handle = 0;
    }
    return( status );
}

#if defined(MBEDTLS_PSA_CRYPTO_SE_C)
psa_status_t mbedtls_psa_register_se_key(
    const psa_key_attributes_t *attributes )
{
    psa_status_t status;
    psa_key_slot_t *slot = NULL;
    psa_se_drv_table_entry_t *driver = NULL;
    psa_key_handle_t handle = 0;

    /* Leaving attributes unspecified is not currently supported.
     * It could make sense to query the key type and size from the
     * secure element, but not all secure elements support this
     * and the driver HAL doesn't currently support it. */
    if( psa_get_key_type( attributes ) == PSA_KEY_TYPE_NONE )
        return( PSA_ERROR_NOT_SUPPORTED );
    if( psa_get_key_bits( attributes ) == 0 )
        return( PSA_ERROR_NOT_SUPPORTED );

    status = psa_start_key_creation( PSA_KEY_CREATION_REGISTER, attributes,
                                     &handle, &slot, &driver );
    if( status != PSA_SUCCESS )
        goto exit;

    status = psa_finish_key_creation( slot, driver );

exit:
    if( status != PSA_SUCCESS )
    {
        psa_fail_key_creation( slot, driver );
    }
    /* Registration doesn't keep the key in RAM. */
    psa_close_key( handle );
    return( status );
}
#endif /* MBEDTLS_PSA_CRYPTO_SE_C */

static psa_status_t psa_copy_key_material( const psa_key_slot_t *source,
                                           psa_key_slot_t *target )
{
    psa_status_t status;
    uint8_t *buffer = NULL;
    size_t buffer_size = 0;
    size_t length;

    buffer_size = PSA_KEY_EXPORT_MAX_SIZE( source->attr.type,
                                           psa_get_key_slot_bits( source ) );
    buffer = mbedtls_calloc( 1, buffer_size );
    if( buffer == NULL )
        return( PSA_ERROR_INSUFFICIENT_MEMORY );
    status = psa_internal_export_key( source, buffer, buffer_size, &length, 0 );
    if( status != PSA_SUCCESS )
        goto exit;
    target->attr.type = source->attr.type;
    status = psa_import_key_into_slot( target, buffer, length );

exit:
    mbedtls_platform_zeroize( buffer, buffer_size );
    mbedtls_free( buffer );
    return( status );
}

psa_status_t psa_copy_key( psa_key_handle_t source_handle,
                           const psa_key_attributes_t *specified_attributes,
                           psa_key_handle_t *target_handle )
{
    psa_status_t status;
    psa_key_slot_t *source_slot = NULL;
    psa_key_slot_t *target_slot = NULL;
    psa_key_attributes_t actual_attributes = *specified_attributes;
    psa_se_drv_table_entry_t *driver = NULL;

    status = psa_get_transparent_key( source_handle, &source_slot,
                                      PSA_KEY_USAGE_COPY, 0 );
    if( status != PSA_SUCCESS )
        goto exit;

    status = psa_validate_optional_attributes( source_slot,
                                               specified_attributes );
    if( status != PSA_SUCCESS )
        goto exit;

    status = psa_restrict_key_policy( &actual_attributes.core.policy,
                                      &source_slot->attr.policy );
    if( status != PSA_SUCCESS )
        goto exit;

    status = psa_start_key_creation( PSA_KEY_CREATION_COPY,
                                     &actual_attributes,
                                     target_handle, &target_slot, &driver );
    if( status != PSA_SUCCESS )
        goto exit;

#if defined(MBEDTLS_PSA_CRYPTO_SE_C)
    if( driver != NULL )
    {
        /* Copying to a secure element is not implemented yet. */
        status = PSA_ERROR_NOT_SUPPORTED;
        goto exit;
    }
#endif /* MBEDTLS_PSA_CRYPTO_SE_C */

    status = psa_copy_key_material( source_slot, target_slot );
    if( status != PSA_SUCCESS )
        goto exit;

    status = psa_finish_key_creation( target_slot, driver );
exit:
    if( status != PSA_SUCCESS )
    {
        psa_fail_key_creation( target_slot, driver );
        *target_handle = 0;
    }
    return( status );
}



/****************************************************************/
/* Message digests */
/****************************************************************/

#if defined(MBEDTLS_RSA_C) || defined(MBEDTLS_ECDSA_DETERMINISTIC)
static const mbedtls_md_info_t *mbedtls_md_info_from_psa( psa_algorithm_t alg )
{
    switch( alg )
    {
#if defined(MBEDTLS_MD2_C)
        case PSA_ALG_MD2:
            return( &mbedtls_md2_info );
#endif
#if defined(MBEDTLS_MD4_C)
        case PSA_ALG_MD4:
            return( &mbedtls_md4_info );
#endif
#if defined(MBEDTLS_MD5_C)
        case PSA_ALG_MD5:
            return( &mbedtls_md5_info );
#endif
#if defined(MBEDTLS_RIPEMD160_C)
        case PSA_ALG_RIPEMD160:
            return( &mbedtls_ripemd160_info );
#endif
#if defined(MBEDTLS_SHA1_C)
        case PSA_ALG_SHA_1:
            return( &mbedtls_sha1_info );
#endif
#if defined(MBEDTLS_SHA256_C)
        case PSA_ALG_SHA_224:
            return( &mbedtls_sha224_info );
        case PSA_ALG_SHA_256:
            return( &mbedtls_sha256_info );
#endif
#if defined(MBEDTLS_SHA512_C)
#if !defined(MBEDTLS_SHA512_NO_SHA384)
        case PSA_ALG_SHA_384:
            return( &mbedtls_sha384_info );
#endif
        case PSA_ALG_SHA_512:
            return( &mbedtls_sha512_info );
#endif
        default:
            return( NULL );
    }
}
#endif

psa_status_t psa_hash_abort( psa_hash_operation_t *operation )
{
    switch( operation->alg )
    {
        case 0:
            /* The object has (apparently) been initialized but it is not
             * in use. It's ok to call abort on such an object, and there's
             * nothing to do. */
            break;
#if defined(MBEDTLS_MD2_C)
        case PSA_ALG_MD2:
            mbedtls_md2_free( &operation->ctx.md2 );
            break;
#endif
#if defined(MBEDTLS_MD4_C)
        case PSA_ALG_MD4:
            mbedtls_md4_free( &operation->ctx.md4 );
            break;
#endif
#if defined(MBEDTLS_MD5_C)
        case PSA_ALG_MD5:
            mbedtls_md5_free( &operation->ctx.md5 );
            break;
#endif
#if defined(MBEDTLS_RIPEMD160_C)
        case PSA_ALG_RIPEMD160:
            mbedtls_ripemd160_free( &operation->ctx.ripemd160 );
            break;
#endif
#if defined(MBEDTLS_SHA1_C)
        case PSA_ALG_SHA_1:
            mbedtls_sha1_free( &operation->ctx.sha1 );
            break;
#endif
#if defined(MBEDTLS_SHA256_C)
        case PSA_ALG_SHA_224:
        case PSA_ALG_SHA_256:
            mbedtls_sha256_free( &operation->ctx.sha256 );
            break;
#endif
#if defined(MBEDTLS_SHA512_C)
#if !defined(MBEDTLS_SHA512_NO_SHA384)
        case PSA_ALG_SHA_384:
#endif
        case PSA_ALG_SHA_512:
            mbedtls_sha512_free( &operation->ctx.sha512 );
            break;
#endif
        default:
            return( PSA_ERROR_BAD_STATE );
    }
    operation->alg = 0;
    return( PSA_SUCCESS );
}

psa_status_t psa_hash_setup( psa_hash_operation_t *operation,
                             psa_algorithm_t alg )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    /* A context must be freshly initialized before it can be set up. */
    if( operation->alg != 0 )
    {
        return( PSA_ERROR_BAD_STATE );
    }

    switch( alg )
    {
#if defined(MBEDTLS_MD2_C)
        case PSA_ALG_MD2:
            mbedtls_md2_init( &operation->ctx.md2 );
            ret = mbedtls_md2_starts_ret( &operation->ctx.md2 );
            break;
#endif
#if defined(MBEDTLS_MD4_C)
        case PSA_ALG_MD4:
            mbedtls_md4_init( &operation->ctx.md4 );
            ret = mbedtls_md4_starts_ret( &operation->ctx.md4 );
            break;
#endif
#if defined(MBEDTLS_MD5_C)
        case PSA_ALG_MD5:
            mbedtls_md5_init( &operation->ctx.md5 );
            ret = mbedtls_md5_starts_ret( &operation->ctx.md5 );
            break;
#endif
#if defined(MBEDTLS_RIPEMD160_C)
        case PSA_ALG_RIPEMD160:
            mbedtls_ripemd160_init( &operation->ctx.ripemd160 );
            ret = mbedtls_ripemd160_starts_ret( &operation->ctx.ripemd160 );
            break;
#endif
#if defined(MBEDTLS_SHA1_C)
        case PSA_ALG_SHA_1:
            mbedtls_sha1_init( &operation->ctx.sha1 );
            ret = mbedtls_sha1_starts_ret( &operation->ctx.sha1 );
            break;
#endif
#if defined(MBEDTLS_SHA256_C)
        case PSA_ALG_SHA_224:
            mbedtls_sha256_init( &operation->ctx.sha256 );
            ret = mbedtls_sha256_starts_ret( &operation->ctx.sha256, 1 );
            break;
        case PSA_ALG_SHA_256:
            mbedtls_sha256_init( &operation->ctx.sha256 );
            ret = mbedtls_sha256_starts_ret( &operation->ctx.sha256, 0 );
            break;
#endif
#if defined(MBEDTLS_SHA512_C)
#if !defined(MBEDTLS_SHA512_NO_SHA384)
        case PSA_ALG_SHA_384:
            mbedtls_sha512_init( &operation->ctx.sha512 );
            ret = mbedtls_sha512_starts_ret( &operation->ctx.sha512, 1 );
            break;
#endif
        case PSA_ALG_SHA_512:
            mbedtls_sha512_init( &operation->ctx.sha512 );
            ret = mbedtls_sha512_starts_ret( &operation->ctx.sha512, 0 );
            break;
#endif
        default:
            return( PSA_ALG_IS_HASH( alg ) ?
                    PSA_ERROR_NOT_SUPPORTED :
                    PSA_ERROR_INVALID_ARGUMENT );
    }
    if( ret == 0 )
        operation->alg = alg;
    else
        psa_hash_abort( operation );
    return( mbedtls_to_psa_error( ret ) );
}

psa_status_t psa_hash_update( psa_hash_operation_t *operation,
                              const uint8_t *input,
                              size_t input_length )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    /* Don't require hash implementations to behave correctly on a
     * zero-length input, which may have an invalid pointer. */
    if( input_length == 0 )
        return( PSA_SUCCESS );

    switch( operation->alg )
    {
#if defined(MBEDTLS_MD2_C)
        case PSA_ALG_MD2:
            ret = mbedtls_md2_update_ret( &operation->ctx.md2,
                                          input, input_length );
            break;
#endif
#if defined(MBEDTLS_MD4_C)
        case PSA_ALG_MD4:
            ret = mbedtls_md4_update_ret( &operation->ctx.md4,
                                          input, input_length );
            break;
#endif
#if defined(MBEDTLS_MD5_C)
        case PSA_ALG_MD5:
            ret = mbedtls_md5_update_ret( &operation->ctx.md5,
                                          input, input_length );
            break;
#endif
#if defined(MBEDTLS_RIPEMD160_C)
        case PSA_ALG_RIPEMD160:
            ret = mbedtls_ripemd160_update_ret( &operation->ctx.ripemd160,
                                                input, input_length );
            break;
#endif
#if defined(MBEDTLS_SHA1_C)
        case PSA_ALG_SHA_1:
            ret = mbedtls_sha1_update_ret( &operation->ctx.sha1,
                                           input, input_length );
            break;
#endif
#if defined(MBEDTLS_SHA256_C)
        case PSA_ALG_SHA_224:
        case PSA_ALG_SHA_256:
            ret = mbedtls_sha256_update_ret( &operation->ctx.sha256,
                                             input, input_length );
            break;
#endif
#if defined(MBEDTLS_SHA512_C)
#if !defined(MBEDTLS_SHA512_NO_SHA384)
        case PSA_ALG_SHA_384:
#endif
        case PSA_ALG_SHA_512:
            ret = mbedtls_sha512_update_ret( &operation->ctx.sha512,
                                             input, input_length );
            break;
#endif
        default:
            return( PSA_ERROR_BAD_STATE );
    }

    if( ret != 0 )
        psa_hash_abort( operation );
    return( mbedtls_to_psa_error( ret ) );
}

psa_status_t psa_hash_finish( psa_hash_operation_t *operation,
                              uint8_t *hash,
                              size_t hash_size,
                              size_t *hash_length )
{
    psa_status_t status;
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t actual_hash_length = PSA_HASH_SIZE( operation->alg );

    /* Fill the output buffer with something that isn't a valid hash
     * (barring an attack on the hash and deliberately-crafted input),
     * in case the caller doesn't check the return status properly. */
    *hash_length = hash_size;
    /* If hash_size is 0 then hash may be NULL and then the
     * call to memset would have undefined behavior. */
    if( hash_size != 0 )
        memset( hash, '!', hash_size );

    if( hash_size < actual_hash_length )
    {
        status = PSA_ERROR_BUFFER_TOO_SMALL;
        goto exit;
    }

    switch( operation->alg )
    {
#if defined(MBEDTLS_MD2_C)
        case PSA_ALG_MD2:
            ret = mbedtls_md2_finish_ret( &operation->ctx.md2, hash );
            break;
#endif
#if defined(MBEDTLS_MD4_C)
        case PSA_ALG_MD4:
            ret = mbedtls_md4_finish_ret( &operation->ctx.md4, hash );
            break;
#endif
#if defined(MBEDTLS_MD5_C)
        case PSA_ALG_MD5:
            ret = mbedtls_md5_finish_ret( &operation->ctx.md5, hash );
            break;
#endif
#if defined(MBEDTLS_RIPEMD160_C)
        case PSA_ALG_RIPEMD160:
            ret = mbedtls_ripemd160_finish_ret( &operation->ctx.ripemd160, hash );
            break;
#endif
#if defined(MBEDTLS_SHA1_C)
        case PSA_ALG_SHA_1:
            ret = mbedtls_sha1_finish_ret( &operation->ctx.sha1, hash );
            break;
#endif
#if defined(MBEDTLS_SHA256_C)
        case PSA_ALG_SHA_224:
        case PSA_ALG_SHA_256:
            ret = mbedtls_sha256_finish_ret( &operation->ctx.sha256, hash );
            break;
#endif
#if defined(MBEDTLS_SHA512_C)
#if !defined(MBEDTLS_SHA512_NO_SHA384)
        case PSA_ALG_SHA_384:
#endif
        case PSA_ALG_SHA_512:
            ret = mbedtls_sha512_finish_ret( &operation->ctx.sha512, hash );
            break;
#endif
        default:
            return( PSA_ERROR_BAD_STATE );
    }
    status = mbedtls_to_psa_error( ret );

exit:
    if( status == PSA_SUCCESS )
    {
        *hash_length = actual_hash_length;
        return( psa_hash_abort( operation ) );
    }
    else
    {
        psa_hash_abort( operation );
        return( status );
    }
}

psa_status_t psa_hash_verify( psa_hash_operation_t *operation,
                              const uint8_t *hash,
                              size_t hash_length )
{
    uint8_t actual_hash[MBEDTLS_MD_MAX_SIZE];
    size_t actual_hash_length;
    psa_status_t status = psa_hash_finish( operation,
                                           actual_hash, sizeof( actual_hash ),
                                           &actual_hash_length );
    if( status != PSA_SUCCESS )
        return( status );
    if( actual_hash_length != hash_length )
        return( PSA_ERROR_INVALID_SIGNATURE );
    if( safer_memcmp( hash, actual_hash, actual_hash_length ) != 0 )
        return( PSA_ERROR_INVALID_SIGNATURE );
    return( PSA_SUCCESS );
}

psa_status_t psa_hash_compute( psa_algorithm_t alg,
                               const uint8_t *input, size_t input_length,
                               uint8_t *hash, size_t hash_size,
                               size_t *hash_length )
{
    psa_hash_operation_t operation = PSA_HASH_OPERATION_INIT;
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;

    *hash_length = hash_size;
    status = psa_hash_setup( &operation, alg );
    if( status != PSA_SUCCESS )
        goto exit;
    status = psa_hash_update( &operation, input, input_length );
    if( status != PSA_SUCCESS )
        goto exit;
    status = psa_hash_finish( &operation, hash, hash_size, hash_length );
    if( status != PSA_SUCCESS )
        goto exit;

exit:
    if( status == PSA_SUCCESS )
        status = psa_hash_abort( &operation );
    else
        psa_hash_abort( &operation );
    return( status );
}

psa_status_t psa_hash_compare( psa_algorithm_t alg,
                               const uint8_t *input, size_t input_length,
                               const uint8_t *hash, size_t hash_length )
{
    psa_hash_operation_t operation = PSA_HASH_OPERATION_INIT;
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;

    status = psa_hash_setup( &operation, alg );
    if( status != PSA_SUCCESS )
        goto exit;
    status = psa_hash_update( &operation, input, input_length );
    if( status != PSA_SUCCESS )
        goto exit;
    status = psa_hash_verify( &operation, hash, hash_length );
    if( status != PSA_SUCCESS )
        goto exit;

exit:
    if( status == PSA_SUCCESS )
        status = psa_hash_abort( &operation );
    else
        psa_hash_abort( &operation );
    return( status );
}

psa_status_t psa_hash_clone( const psa_hash_operation_t *source_operation,
                             psa_hash_operation_t *target_operation )
{
    if( target_operation->alg != 0 )
        return( PSA_ERROR_BAD_STATE );

    switch( source_operation->alg )
    {
        case 0:
            return( PSA_ERROR_BAD_STATE );
#if defined(MBEDTLS_MD2_C)
        case PSA_ALG_MD2:
            mbedtls_md2_clone( &target_operation->ctx.md2,
                               &source_operation->ctx.md2 );
            break;
#endif
#if defined(MBEDTLS_MD4_C)
        case PSA_ALG_MD4:
            mbedtls_md4_clone( &target_operation->ctx.md4,
                               &source_operation->ctx.md4 );
            break;
#endif
#if defined(MBEDTLS_MD5_C)
        case PSA_ALG_MD5:
            mbedtls_md5_clone( &target_operation->ctx.md5,
                               &source_operation->ctx.md5 );
            break;
#endif
#if defined(MBEDTLS_RIPEMD160_C)
        case PSA_ALG_RIPEMD160:
            mbedtls_ripemd160_clone( &target_operation->ctx.ripemd160,
                                     &source_operation->ctx.ripemd160 );
            break;
#endif
#if defined(MBEDTLS_SHA1_C)
        case PSA_ALG_SHA_1:
            mbedtls_sha1_clone( &target_operation->ctx.sha1,
                                &source_operation->ctx.sha1 );
            break;
#endif
#if defined(MBEDTLS_SHA256_C)
        case PSA_ALG_SHA_224:
        case PSA_ALG_SHA_256:
            mbedtls_sha256_clone( &target_operation->ctx.sha256,
                                  &source_operation->ctx.sha256 );
            break;
#endif
#if defined(MBEDTLS_SHA512_C)
#if !defined(MBEDTLS_SHA512_NO_SHA384)
        case PSA_ALG_SHA_384:
#endif
        case PSA_ALG_SHA_512:
            mbedtls_sha512_clone( &target_operation->ctx.sha512,
                                  &source_operation->ctx.sha512 );
            break;
#endif
        default:
            return( PSA_ERROR_NOT_SUPPORTED );
    }

    target_operation->alg = source_operation->alg;
    return( PSA_SUCCESS );
}


/****************************************************************/
/* MAC */
/****************************************************************/

static const mbedtls_cipher_info_t *mbedtls_cipher_info_from_psa(
    psa_algorithm_t alg,
    psa_key_type_t key_type,
    size_t key_bits,
    mbedtls_cipher_id_t* cipher_id )
{
    mbedtls_cipher_mode_t mode;
    mbedtls_cipher_id_t cipher_id_tmp;

    if( PSA_ALG_IS_AEAD( alg ) )
        alg = PSA_ALG_AEAD_WITH_TAG_LENGTH( alg, 0 );

    if( PSA_ALG_IS_CIPHER( alg ) || PSA_ALG_IS_AEAD( alg ) )
    {
        switch( alg )
        {
            case PSA_ALG_ARC4:
            case PSA_ALG_CHACHA20:
                mode = MBEDTLS_MODE_STREAM;
                break;
            case PSA_ALG_CTR:
                mode = MBEDTLS_MODE_CTR;
                break;
            case PSA_ALG_CFB:
                mode = MBEDTLS_MODE_CFB;
                break;
            case PSA_ALG_OFB:
                mode = MBEDTLS_MODE_OFB;
                break;
            case PSA_ALG_CBC_NO_PADDING:
                mode = MBEDTLS_MODE_CBC;
                break;
            case PSA_ALG_CBC_PKCS7:
                mode = MBEDTLS_MODE_CBC;
                break;
            case PSA_ALG_AEAD_WITH_TAG_LENGTH( PSA_ALG_CCM, 0 ):
                mode = MBEDTLS_MODE_CCM;
                break;
            case PSA_ALG_AEAD_WITH_TAG_LENGTH( PSA_ALG_GCM, 0 ):
                mode = MBEDTLS_MODE_GCM;
                break;
            case PSA_ALG_AEAD_WITH_TAG_LENGTH( PSA_ALG_CHACHA20_POLY1305, 0 ):
                mode = MBEDTLS_MODE_CHACHAPOLY;
                break;
            default:
                return( NULL );
        }
    }
    else if( alg == PSA_ALG_CMAC )
        mode = MBEDTLS_MODE_ECB;
    else
        return( NULL );

    switch( key_type )
    {
        case PSA_KEY_TYPE_AES:
            cipher_id_tmp = MBEDTLS_CIPHER_ID_AES;
            break;
        case PSA_KEY_TYPE_DES:
            /* key_bits is 64 for Single-DES, 128 for two-key Triple-DES,
             * and 192 for three-key Triple-DES. */
            if( key_bits == 64 )
                cipher_id_tmp = MBEDTLS_CIPHER_ID_DES;
            else
                cipher_id_tmp = MBEDTLS_CIPHER_ID_3DES;
            /* mbedtls doesn't recognize two-key Triple-DES as an algorithm,
             * but two-key Triple-DES is functionally three-key Triple-DES
             * with K1=K3, so that's how we present it to mbedtls. */
            if( key_bits == 128 )
                key_bits = 192;
            break;
        case PSA_KEY_TYPE_CAMELLIA:
            cipher_id_tmp = MBEDTLS_CIPHER_ID_CAMELLIA;
            break;
        case PSA_KEY_TYPE_ARC4:
            cipher_id_tmp = MBEDTLS_CIPHER_ID_ARC4;
            break;
        case PSA_KEY_TYPE_CHACHA20:
            cipher_id_tmp = MBEDTLS_CIPHER_ID_CHACHA20;
            break;
        default:
            return( NULL );
    }
    if( cipher_id != NULL )
        *cipher_id = cipher_id_tmp;

    return( mbedtls_cipher_info_from_values( cipher_id_tmp,
                                             (int) key_bits, mode ) );
}

#if defined(MBEDTLS_MD_C)
static size_t psa_get_hash_block_size( psa_algorithm_t alg )
{
    switch( alg )
    {
        case PSA_ALG_MD2:
            return( 16 );
        case PSA_ALG_MD4:
            return( 64 );
        case PSA_ALG_MD5:
            return( 64 );
        case PSA_ALG_RIPEMD160:
            return( 64 );
        case PSA_ALG_SHA_1:
            return( 64 );
        case PSA_ALG_SHA_224:
            return( 64 );
        case PSA_ALG_SHA_256:
            return( 64 );
        case PSA_ALG_SHA_384:
            return( 128 );
        case PSA_ALG_SHA_512:
            return( 128 );
        default:
            return( 0 );
    }
}
#endif /* MBEDTLS_MD_C */

/* Initialize the MAC operation structure. Once this function has been
 * called, psa_mac_abort can run and will do the right thing. */
static psa_status_t psa_mac_init( psa_mac_operation_t *operation,
                                  psa_algorithm_t alg )
{
    psa_status_t status = PSA_ERROR_NOT_SUPPORTED;

    operation->alg = alg;
    operation->key_set = 0;
    operation->iv_set = 0;
    operation->iv_required = 0;
    operation->has_input = 0;
    operation->is_sign = 0;

#if defined(MBEDTLS_CMAC_C)
    if( alg == PSA_ALG_CMAC )
    {
        operation->iv_required = 0;
        mbedtls_cipher_init( &operation->ctx.cmac );
        status = PSA_SUCCESS;
    }
    else
#endif /* MBEDTLS_CMAC_C */
#if defined(MBEDTLS_MD_C)
    if( PSA_ALG_IS_HMAC( operation->alg ) )
    {
        /* We'll set up the hash operation later in psa_hmac_setup_internal. */
        operation->ctx.hmac.hash_ctx.alg = 0;
        status = PSA_SUCCESS;
    }
    else
#endif /* MBEDTLS_MD_C */
    {
        if( ! PSA_ALG_IS_MAC( alg ) )
            status = PSA_ERROR_INVALID_ARGUMENT;
    }

    if( status != PSA_SUCCESS )
        memset( operation, 0, sizeof( *operation ) );
    return( status );
}

#if defined(MBEDTLS_MD_C)
static psa_status_t psa_hmac_abort_internal( psa_hmac_internal_data *hmac )
{
    mbedtls_platform_zeroize( hmac->opad, sizeof( hmac->opad ) );
    return( psa_hash_abort( &hmac->hash_ctx ) );
}
#endif /* MBEDTLS_MD_C */

psa_status_t psa_mac_abort( psa_mac_operation_t *operation )
{
    if( operation->alg == 0 )
    {
        /* The object has (apparently) been initialized but it is not
         * in use. It's ok to call abort on such an object, and there's
         * nothing to do. */
        return( PSA_SUCCESS );
    }
    else
#if defined(MBEDTLS_CMAC_C)
    if( operation->alg == PSA_ALG_CMAC )
    {
        mbedtls_cipher_free( &operation->ctx.cmac );
    }
    else
#endif /* MBEDTLS_CMAC_C */
#if defined(MBEDTLS_MD_C)
    if( PSA_ALG_IS_HMAC( operation->alg ) )
    {
        psa_hmac_abort_internal( &operation->ctx.hmac );
    }
    else
#endif /* MBEDTLS_MD_C */
    {
        /* Sanity check (shouldn't happen: operation->alg should
         * always have been initialized to a valid value). */
        goto bad_state;
    }

    operation->alg = 0;
    operation->key_set = 0;
    operation->iv_set = 0;
    operation->iv_required = 0;
    operation->has_input = 0;
    operation->is_sign = 0;

    return( PSA_SUCCESS );

bad_state:
    /* If abort is called on an uninitialized object, we can't trust
     * anything. Wipe the object in case it contains confidential data.
     * This may result in a memory leak if a pointer gets overwritten,
     * but it's too late to do anything about this. */
    memset( operation, 0, sizeof( *operation ) );
    return( PSA_ERROR_BAD_STATE );
}

#if defined(MBEDTLS_CMAC_C)
static int psa_cmac_setup( psa_mac_operation_t *operation,
                           size_t key_bits,
                           psa_key_slot_t *slot,
                           const mbedtls_cipher_info_t *cipher_info )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    operation->mac_size = cipher_info->block_size;

    ret = mbedtls_cipher_setup( &operation->ctx.cmac, cipher_info );
    if( ret != 0 )
        return( ret );

    ret = mbedtls_cipher_cmac_starts( &operation->ctx.cmac,
                                      slot->data.key.data,
                                      key_bits );
    return( ret );
}
#endif /* MBEDTLS_CMAC_C */

#if defined(MBEDTLS_MD_C)
static psa_status_t psa_hmac_setup_internal( psa_hmac_internal_data *hmac,
                                             const uint8_t *key,
                                             size_t key_length,
                                             psa_algorithm_t hash_alg )
{
    uint8_t ipad[PSA_HMAC_MAX_HASH_BLOCK_SIZE];
    size_t i;
    size_t hash_size = PSA_HASH_SIZE( hash_alg );
    size_t block_size = psa_get_hash_block_size( hash_alg );
    psa_status_t status;

    /* Sanity checks on block_size, to guarantee that there won't be a buffer
     * overflow below. This should never trigger if the hash algorithm
     * is implemented correctly. */
    /* The size checks against the ipad and opad buffers cannot be written
     * `block_size > sizeof( ipad ) || block_size > sizeof( hmac->opad )`
     * because that triggers -Wlogical-op on GCC 7.3. */
    if( block_size > sizeof( ipad ) )
        return( PSA_ERROR_NOT_SUPPORTED );
    if( block_size > sizeof( hmac->opad ) )
        return( PSA_ERROR_NOT_SUPPORTED );
    if( block_size < hash_size )
        return( PSA_ERROR_NOT_SUPPORTED );

    if( key_length > block_size )
    {
        status = psa_hash_compute( hash_alg, key, key_length,
                                   ipad, sizeof( ipad ), &key_length );
        if( status != PSA_SUCCESS )
            goto cleanup;
    }
    /* A 0-length key is not commonly used in HMAC when used as a MAC,
     * but it is permitted. It is common when HMAC is used in HKDF, for
     * example. Don't call `memcpy` in the 0-length because `key` could be
     * an invalid pointer which would make the behavior undefined. */
    else if( key_length != 0 )
        memcpy( ipad, key, key_length );

    /* ipad contains the key followed by garbage. Xor and fill with 0x36
     * to create the ipad value. */
    for( i = 0; i < key_length; i++ )
        ipad[i] ^= 0x36;
    memset( ipad + key_length, 0x36, block_size - key_length );

    /* Copy the key material from ipad to opad, flipping the requisite bits,
     * and filling the rest of opad with the requisite constant. */
    for( i = 0; i < key_length; i++ )
        hmac->opad[i] = ipad[i] ^ 0x36 ^ 0x5C;
    memset( hmac->opad + key_length, 0x5C, block_size - key_length );

    status = psa_hash_setup( &hmac->hash_ctx, hash_alg );
    if( status != PSA_SUCCESS )
        goto cleanup;

    status = psa_hash_update( &hmac->hash_ctx, ipad, block_size );

cleanup:
    mbedtls_platform_zeroize( ipad, sizeof( ipad ) );

    return( status );
}
#endif /* MBEDTLS_MD_C */

static psa_status_t psa_mac_setup( psa_mac_operation_t *operation,
                                   psa_key_handle_t handle,
                                   psa_algorithm_t alg,
                                   int is_sign )
{
    psa_status_t status;
    psa_key_slot_t *slot;
    size_t key_bits;
    psa_key_usage_t usage =
        is_sign ? PSA_KEY_USAGE_SIGN_HASH : PSA_KEY_USAGE_VERIFY_HASH;
    uint8_t truncated = PSA_MAC_TRUNCATED_LENGTH( alg );
    psa_algorithm_t full_length_alg = PSA_ALG_FULL_LENGTH_MAC( alg );

    /* A context must be freshly initialized before it can be set up. */
    if( operation->alg != 0 )
    {
        return( PSA_ERROR_BAD_STATE );
    }

    status = psa_mac_init( operation, full_length_alg );
    if( status != PSA_SUCCESS )
        return( status );
    if( is_sign )
        operation->is_sign = 1;

    status = psa_get_transparent_key( handle, &slot, usage, alg );
    if( status != PSA_SUCCESS )
        goto exit;
    key_bits = psa_get_key_slot_bits( slot );

#if defined(MBEDTLS_CMAC_C)
    if( full_length_alg == PSA_ALG_CMAC )
    {
        const mbedtls_cipher_info_t *cipher_info =
            mbedtls_cipher_info_from_psa( full_length_alg,
                                          slot->attr.type, key_bits, NULL );
        int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
        if( cipher_info == NULL )
        {
            status = PSA_ERROR_NOT_SUPPORTED;
            goto exit;
        }
        operation->mac_size = cipher_info->block_size;
        ret = psa_cmac_setup( operation, key_bits, slot, cipher_info );
        status = mbedtls_to_psa_error( ret );
    }
    else
#endif /* MBEDTLS_CMAC_C */
#if defined(MBEDTLS_MD_C)
    if( PSA_ALG_IS_HMAC( full_length_alg ) )
    {
        psa_algorithm_t hash_alg = PSA_ALG_HMAC_GET_HASH( alg );
        if( hash_alg == 0 )
        {
            status = PSA_ERROR_NOT_SUPPORTED;
            goto exit;
        }

        operation->mac_size = PSA_HASH_SIZE( hash_alg );
        /* Sanity check. This shouldn't fail on a valid configuration. */
        if( operation->mac_size == 0 ||
            operation->mac_size > sizeof( operation->ctx.hmac.opad ) )
        {
            status = PSA_ERROR_NOT_SUPPORTED;
            goto exit;
        }

        if( slot->attr.type != PSA_KEY_TYPE_HMAC )
        {
            status = PSA_ERROR_INVALID_ARGUMENT;
            goto exit;
        }

        status = psa_hmac_setup_internal( &operation->ctx.hmac,
                                          slot->data.key.data,
                                          slot->data.key.bytes,
                                          hash_alg );
    }
    else
#endif /* MBEDTLS_MD_C */
    {
        (void) key_bits;
        status = PSA_ERROR_NOT_SUPPORTED;
    }

    if( truncated == 0 )
    {
        /* The "normal" case: untruncated algorithm. Nothing to do. */
    }
    else if( truncated < 4 )
    {
        /* A very short MAC is too short for security since it can be
         * brute-forced. Ancient protocols with 32-bit MACs do exist,
         * so we make this our minimum, even though 32 bits is still
         * too small for security. */
        status = PSA_ERROR_NOT_SUPPORTED;
    }
    else if( truncated > operation->mac_size )
    {
        /* It's impossible to "truncate" to a larger length. */
        status = PSA_ERROR_INVALID_ARGUMENT;
    }
    else
        operation->mac_size = truncated;

exit:
    if( status != PSA_SUCCESS )
    {
        psa_mac_abort( operation );
    }
    else
    {
        operation->key_set = 1;
    }
    return( status );
}

psa_status_t psa_mac_sign_setup( psa_mac_operation_t *operation,
                                 psa_key_handle_t handle,
                                 psa_algorithm_t alg )
{
    return( psa_mac_setup( operation, handle, alg, 1 ) );
}

psa_status_t psa_mac_verify_setup( psa_mac_operation_t *operation,
                                   psa_key_handle_t handle,
                                   psa_algorithm_t alg )
{
    return( psa_mac_setup( operation, handle, alg, 0 ) );
}

psa_status_t psa_mac_update( psa_mac_operation_t *operation,
                             const uint8_t *input,
                             size_t input_length )
{
    psa_status_t status = PSA_ERROR_BAD_STATE;
    if( ! operation->key_set )
        return( PSA_ERROR_BAD_STATE );
    if( operation->iv_required && ! operation->iv_set )
        return( PSA_ERROR_BAD_STATE );
    operation->has_input = 1;

#if defined(MBEDTLS_CMAC_C)
    if( operation->alg == PSA_ALG_CMAC )
    {
        int ret = mbedtls_cipher_cmac_update( &operation->ctx.cmac,
                                              input, input_length );
        status = mbedtls_to_psa_error( ret );
    }
    else
#endif /* MBEDTLS_CMAC_C */
#if defined(MBEDTLS_MD_C)
    if( PSA_ALG_IS_HMAC( operation->alg ) )
    {
        status = psa_hash_update( &operation->ctx.hmac.hash_ctx, input,
                                  input_length );
    }
    else
#endif /* MBEDTLS_MD_C */
    {
        /* This shouldn't happen if `operation` was initialized by
         * a setup function. */
        return( PSA_ERROR_BAD_STATE );
    }

    if( status != PSA_SUCCESS )
        psa_mac_abort( operation );
    return( status );
}

#if defined(MBEDTLS_MD_C)
static psa_status_t psa_hmac_finish_internal( psa_hmac_internal_data *hmac,
                                              uint8_t *mac,
                                              size_t mac_size )
{
    uint8_t tmp[MBEDTLS_MD_MAX_SIZE];
    psa_algorithm_t hash_alg = hmac->hash_ctx.alg;
    size_t hash_size = 0;
    size_t block_size = psa_get_hash_block_size( hash_alg );
    psa_status_t status;

    status = psa_hash_finish( &hmac->hash_ctx, tmp, sizeof( tmp ), &hash_size );
    if( status != PSA_SUCCESS )
        return( status );
    /* From here on, tmp needs to be wiped. */

    status = psa_hash_setup( &hmac->hash_ctx, hash_alg );
    if( status != PSA_SUCCESS )
        goto exit;

    status = psa_hash_update( &hmac->hash_ctx, hmac->opad, block_size );
    if( status != PSA_SUCCESS )
        goto exit;

    status = psa_hash_update( &hmac->hash_ctx, tmp, hash_size );
    if( status != PSA_SUCCESS )
        goto exit;

    status = psa_hash_finish( &hmac->hash_ctx, tmp, sizeof( tmp ), &hash_size );
    if( status != PSA_SUCCESS )
        goto exit;

    memcpy( mac, tmp, mac_size );

exit:
    mbedtls_platform_zeroize( tmp, hash_size );
    return( status );
}
#endif /* MBEDTLS_MD_C */

static psa_status_t psa_mac_finish_internal( psa_mac_operation_t *operation,
                                             uint8_t *mac,
                                             size_t mac_size )
{
    if( ! operation->key_set )
        return( PSA_ERROR_BAD_STATE );
    if( operation->iv_required && ! operation->iv_set )
        return( PSA_ERROR_BAD_STATE );

    if( mac_size < operation->mac_size )
        return( PSA_ERROR_BUFFER_TOO_SMALL );

#if defined(MBEDTLS_CMAC_C)
    if( operation->alg == PSA_ALG_CMAC )
    {
        uint8_t tmp[PSA_MAX_BLOCK_CIPHER_BLOCK_SIZE];
        int ret = mbedtls_cipher_cmac_finish( &operation->ctx.cmac, tmp );
        if( ret == 0 )
            memcpy( mac, tmp, operation->mac_size );
        mbedtls_platform_zeroize( tmp, sizeof( tmp ) );
        return( mbedtls_to_psa_error( ret ) );
    }
    else
#endif /* MBEDTLS_CMAC_C */
#if defined(MBEDTLS_MD_C)
    if( PSA_ALG_IS_HMAC( operation->alg ) )
    {
        return( psa_hmac_finish_internal( &operation->ctx.hmac,
                                          mac, operation->mac_size ) );
    }
    else
#endif /* MBEDTLS_MD_C */
    {
        /* This shouldn't happen if `operation` was initialized by
         * a setup function. */
        return( PSA_ERROR_BAD_STATE );
    }
}

psa_status_t psa_mac_sign_finish( psa_mac_operation_t *operation,
                                  uint8_t *mac,
                                  size_t mac_size,
                                  size_t *mac_length )
{
    psa_status_t status;

    if( operation->alg == 0 )
    {
        return( PSA_ERROR_BAD_STATE );
    }

    /* Fill the output buffer with something that isn't a valid mac
     * (barring an attack on the mac and deliberately-crafted input),
     * in case the caller doesn't check the return status properly. */
    *mac_length = mac_size;
    /* If mac_size is 0 then mac may be NULL and then the
     * call to memset would have undefined behavior. */
    if( mac_size != 0 )
        memset( mac, '!', mac_size );

    if( ! operation->is_sign )
    {
        return( PSA_ERROR_BAD_STATE );
    }

    status = psa_mac_finish_internal( operation, mac, mac_size );

    if( status == PSA_SUCCESS )
    {
        status = psa_mac_abort( operation );
        if( status == PSA_SUCCESS )
            *mac_length = operation->mac_size;
        else
            memset( mac, '!', mac_size );
    }
    else
        psa_mac_abort( operation );
    return( status );
}

psa_status_t psa_mac_verify_finish( psa_mac_operation_t *operation,
                                    const uint8_t *mac,
                                    size_t mac_length )
{
    uint8_t actual_mac[PSA_MAC_MAX_SIZE];
    psa_status_t status;

    if( operation->alg == 0 )
    {
        return( PSA_ERROR_BAD_STATE );
    }

    if( operation->is_sign )
    {
        return( PSA_ERROR_BAD_STATE );
    }
    if( operation->mac_size != mac_length )
    {
        status = PSA_ERROR_INVALID_SIGNATURE;
        goto cleanup;
    }

    status = psa_mac_finish_internal( operation,
                                      actual_mac, sizeof( actual_mac ) );
    if( status != PSA_SUCCESS )
        goto cleanup;

    if( safer_memcmp( mac, actual_mac, mac_length ) != 0 )
        status = PSA_ERROR_INVALID_SIGNATURE;

cleanup:
    if( status == PSA_SUCCESS )
        status = psa_mac_abort( operation );
    else
        psa_mac_abort( operation );

    mbedtls_platform_zeroize( actual_mac, sizeof( actual_mac ) );

    return( status );
}



/****************************************************************/
/* Asymmetric cryptography */
/****************************************************************/

#if defined(MBEDTLS_RSA_C)
/* Decode the hash algorithm from alg and store the mbedtls encoding in
 * md_alg. Verify that the hash length is acceptable. */
static psa_status_t psa_rsa_decode_md_type( psa_algorithm_t alg,
                                            size_t hash_length,
                                            mbedtls_md_type_t *md_alg )
{
    psa_algorithm_t hash_alg = PSA_ALG_SIGN_GET_HASH( alg );
    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_psa( hash_alg );
    *md_alg = mbedtls_md_get_type( md_info );

    /* The Mbed TLS RSA module uses an unsigned int for hash length
     * parameters. Validate that it fits so that we don't risk an
     * overflow later. */
#if SIZE_MAX > UINT_MAX
    if( hash_length > UINT_MAX )
        return( PSA_ERROR_INVALID_ARGUMENT );
#endif

#if defined(MBEDTLS_PKCS1_V15)
    /* For PKCS#1 v1.5 signature, if using a hash, the hash length
     * must be correct. */
    if( PSA_ALG_IS_RSA_PKCS1V15_SIGN( alg ) &&
        alg != PSA_ALG_RSA_PKCS1V15_SIGN_RAW )
    {
        if( md_info == NULL )
            return( PSA_ERROR_NOT_SUPPORTED );
        if( mbedtls_md_get_size( md_info ) != hash_length )
            return( PSA_ERROR_INVALID_ARGUMENT );
    }
#endif /* MBEDTLS_PKCS1_V15 */

#if defined(MBEDTLS_PKCS1_V21)
    /* PSS requires a hash internally. */
    if( PSA_ALG_IS_RSA_PSS( alg ) )
    {
        if( md_info == NULL )
            return( PSA_ERROR_NOT_SUPPORTED );
    }
#endif /* MBEDTLS_PKCS1_V21 */

    return( PSA_SUCCESS );
}

static psa_status_t psa_rsa_sign( mbedtls_rsa_context *rsa,
                                  psa_algorithm_t alg,
                                  const uint8_t *hash,
                                  size_t hash_length,
                                  uint8_t *signature,
                                  size_t signature_size,
                                  size_t *signature_length )
{
    psa_status_t status;
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_md_type_t md_alg;

    status = psa_rsa_decode_md_type( alg, hash_length, &md_alg );
    if( status != PSA_SUCCESS )
        return( status );

    if( signature_size < mbedtls_rsa_get_len( rsa ) )
        return( PSA_ERROR_BUFFER_TOO_SMALL );

#if defined(MBEDTLS_PKCS1_V15)
    if( PSA_ALG_IS_RSA_PKCS1V15_SIGN( alg ) )
    {
        mbedtls_rsa_set_padding( rsa, MBEDTLS_RSA_PKCS_V15,
                                 MBEDTLS_MD_NONE );
        ret = mbedtls_rsa_pkcs1_sign( rsa,
                                      mbedtls_ctr_drbg_random,
                                      &global_data.ctr_drbg,
                                      MBEDTLS_RSA_PRIVATE,
                                      md_alg,
                                      (unsigned int) hash_length,
                                      hash,
                                      signature );
    }
    else
#endif /* MBEDTLS_PKCS1_V15 */
#if defined(MBEDTLS_PKCS1_V21)
    if( PSA_ALG_IS_RSA_PSS( alg ) )
    {
        mbedtls_rsa_set_padding( rsa, MBEDTLS_RSA_PKCS_V21, md_alg );
        ret = mbedtls_rsa_rsassa_pss_sign( rsa,
                                           mbedtls_ctr_drbg_random,
                                           &global_data.ctr_drbg,
                                           MBEDTLS_RSA_PRIVATE,
                                           MBEDTLS_MD_NONE,
                                           (unsigned int) hash_length,
                                           hash,
                                           signature );
    }
    else
#endif /* MBEDTLS_PKCS1_V21 */
    {
        return( PSA_ERROR_INVALID_ARGUMENT );
    }

    if( ret == 0 )
        *signature_length = mbedtls_rsa_get_len( rsa );
    return( mbedtls_to_psa_error( ret ) );
}

static psa_status_t psa_rsa_verify( mbedtls_rsa_context *rsa,
                                    psa_algorithm_t alg,
                                    const uint8_t *hash,
                                    size_t hash_length,
                                    const uint8_t *signature,
                                    size_t signature_length )
{
    psa_status_t status;
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_md_type_t md_alg;

    status = psa_rsa_decode_md_type( alg, hash_length, &md_alg );
    if( status != PSA_SUCCESS )
        return( status );

    if( signature_length != mbedtls_rsa_get_len( rsa ) )
        return( PSA_ERROR_INVALID_SIGNATURE );

#if defined(MBEDTLS_PKCS1_V15)
    if( PSA_ALG_IS_RSA_PKCS1V15_SIGN( alg ) )
    {
        mbedtls_rsa_set_padding( rsa, MBEDTLS_RSA_PKCS_V15,
                                 MBEDTLS_MD_NONE );
        ret = mbedtls_rsa_pkcs1_verify( rsa,
                                        mbedtls_ctr_drbg_random,
                                        &global_data.ctr_drbg,
                                        MBEDTLS_RSA_PUBLIC,
                                        md_alg,
                                        (unsigned int) hash_length,
                                        hash,
                                        signature );
    }
    else
#endif /* MBEDTLS_PKCS1_V15 */
#if defined(MBEDTLS_PKCS1_V21)
    if( PSA_ALG_IS_RSA_PSS( alg ) )
    {
        mbedtls_rsa_set_padding( rsa, MBEDTLS_RSA_PKCS_V21, md_alg );
        ret = mbedtls_rsa_rsassa_pss_verify( rsa,
                                             mbedtls_ctr_drbg_random,
                                             &global_data.ctr_drbg,
                                             MBEDTLS_RSA_PUBLIC,
                                             MBEDTLS_MD_NONE,
                                             (unsigned int) hash_length,
                                             hash,
                                             signature );
    }
    else
#endif /* MBEDTLS_PKCS1_V21 */
    {
        return( PSA_ERROR_INVALID_ARGUMENT );
    }

    /* Mbed TLS distinguishes "invalid padding" from "valid padding but
     * the rest of the signature is invalid". This has little use in
     * practice and PSA doesn't report this distinction. */
    if( ret == MBEDTLS_ERR_RSA_INVALID_PADDING )
        return( PSA_ERROR_INVALID_SIGNATURE );
    return( mbedtls_to_psa_error( ret ) );
}
#endif /* MBEDTLS_RSA_C */

#if defined(MBEDTLS_ECDSA_C)
/* `ecp` cannot be const because `ecp->grp` needs to be non-const
 * for mbedtls_ecdsa_sign() and mbedtls_ecdsa_sign_det()
 * (even though these functions don't modify it). */
static psa_status_t psa_ecdsa_sign( mbedtls_ecp_keypair *ecp,
                                    psa_algorithm_t alg,
                                    const uint8_t *hash,
                                    size_t hash_length,
                                    uint8_t *signature,
                                    size_t signature_size,
                                    size_t *signature_length )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_mpi r, s;
    size_t curve_bytes = PSA_BITS_TO_BYTES( ecp->grp.pbits );
    mbedtls_mpi_init( &r );
    mbedtls_mpi_init( &s );

    if( signature_size < 2 * curve_bytes )
    {
        ret = MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL;
        goto cleanup;
    }

#if defined(MBEDTLS_ECDSA_DETERMINISTIC)
    if( PSA_ALG_DSA_IS_DETERMINISTIC( alg ) )
    {
        psa_algorithm_t hash_alg = PSA_ALG_SIGN_GET_HASH( alg );
        const mbedtls_md_info_t *md_info = mbedtls_md_info_from_psa( hash_alg );
        mbedtls_md_type_t md_alg = mbedtls_md_get_type( md_info );
        MBEDTLS_MPI_CHK( mbedtls_ecdsa_sign_det_ext( &ecp->grp, &r, &s,
                                                     &ecp->d, hash,
                                                     hash_length, md_alg,
                                                     mbedtls_ctr_drbg_random,
                                                     &global_data.ctr_drbg ) );
    }
    else
#endif /* MBEDTLS_ECDSA_DETERMINISTIC */
    {
        (void) alg;
        MBEDTLS_MPI_CHK( mbedtls_ecdsa_sign( &ecp->grp, &r, &s, &ecp->d,
                                             hash, hash_length,
                                             mbedtls_ctr_drbg_random,
                                             &global_data.ctr_drbg ) );
    }

    MBEDTLS_MPI_CHK( mbedtls_mpi_write_binary( &r,
                                               signature,
                                               curve_bytes ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_write_binary( &s,
                                               signature + curve_bytes,
                                               curve_bytes ) );

cleanup:
    mbedtls_mpi_free( &r );
    mbedtls_mpi_free( &s );
    if( ret == 0 )
        *signature_length = 2 * curve_bytes;
    return( mbedtls_to_psa_error( ret ) );
}

static psa_status_t psa_ecdsa_verify( mbedtls_ecp_keypair *ecp,
                                      const uint8_t *hash,
                                      size_t hash_length,
                                      const uint8_t *signature,
                                      size_t signature_length )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_mpi r, s;
    size_t curve_bytes = PSA_BITS_TO_BYTES( ecp->grp.pbits );
    mbedtls_mpi_init( &r );
    mbedtls_mpi_init( &s );

    if( signature_length != 2 * curve_bytes )
        return( PSA_ERROR_INVALID_SIGNATURE );

    MBEDTLS_MPI_CHK( mbedtls_mpi_read_binary( &r,
                                              signature,
                                              curve_bytes ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_read_binary( &s,
                                              signature + curve_bytes,
                                              curve_bytes ) );

    /* Check whether the public part is loaded. If not, load it. */
    if( mbedtls_ecp_is_zero( &ecp->Q ) )
    {
        MBEDTLS_MPI_CHK(
            mbedtls_ecp_mul( &ecp->grp, &ecp->Q, &ecp->d, &ecp->grp.G,
                             mbedtls_ctr_drbg_random, &global_data.ctr_drbg ) );
    }

    ret = mbedtls_ecdsa_verify( &ecp->grp, hash, hash_length,
                                &ecp->Q, &r, &s );

cleanup:
    mbedtls_mpi_free( &r );
    mbedtls_mpi_free( &s );
    return( mbedtls_to_psa_error( ret ) );
}
#endif /* MBEDTLS_ECDSA_C */

psa_status_t psa_sign_hash( psa_key_handle_t handle,
                            psa_algorithm_t alg,
                            const uint8_t *hash,
                            size_t hash_length,
                            uint8_t *signature,
                            size_t signature_size,
                            size_t *signature_length )
{
    psa_key_slot_t *slot;
    psa_status_t status;
#if defined(MBEDTLS_PSA_CRYPTO_SE_C)
    const psa_drv_se_t *drv;
    psa_drv_se_context_t *drv_context;
#endif /* MBEDTLS_PSA_CRYPTO_SE_C */

    *signature_length = signature_size;
    /* Immediately reject a zero-length signature buffer. This guarantees
     * that signature must be a valid pointer. (On the other hand, the hash
     * buffer can in principle be empty since it doesn't actually have
     * to be a hash.) */
    if( signature_size == 0 )
        return( PSA_ERROR_BUFFER_TOO_SMALL );

    status = psa_get_key_from_slot( handle, &slot, PSA_KEY_USAGE_SIGN_HASH, alg );
    if( status != PSA_SUCCESS )
        goto exit;
    if( ! PSA_KEY_TYPE_IS_KEY_PAIR( slot->attr.type ) )
    {
        status = PSA_ERROR_INVALID_ARGUMENT;
        goto exit;
    }

#if defined(MBEDTLS_PSA_CRYPTO_SE_C)
    if( psa_get_se_driver( slot->attr.lifetime, &drv, &drv_context ) )
    {
        if( drv->asymmetric == NULL ||
            drv->asymmetric->p_sign == NULL )
        {
            status = PSA_ERROR_NOT_SUPPORTED;
            goto exit;
        }
        status = drv->asymmetric->p_sign( drv_context,
                                          slot->data.se.slot_number,
                                          alg,
                                          hash, hash_length,
                                          signature, signature_size,
                                          signature_length );
    }
    else
#endif /* MBEDTLS_PSA_CRYPTO_SE_C */
#if defined(MBEDTLS_RSA_C)
    if( slot->attr.type == PSA_KEY_TYPE_RSA_KEY_PAIR )
    {
        mbedtls_rsa_context *rsa = NULL;

        status = psa_load_rsa_representation( slot->attr.type,
                                              slot->data.key.data,
                                              slot->data.key.bytes,
                                              &rsa );
        if( status != PSA_SUCCESS )
            goto exit;

        status = psa_rsa_sign( rsa,
                               alg,
                               hash, hash_length,
                               signature, signature_size,
                               signature_length );

        mbedtls_rsa_free( rsa );
        mbedtls_free( rsa );
    }
    else
#endif /* defined(MBEDTLS_RSA_C) */
#if defined(MBEDTLS_ECP_C)
    if( PSA_KEY_TYPE_IS_ECC( slot->attr.type ) )
    {
#if defined(MBEDTLS_ECDSA_C)
        if(
#if defined(MBEDTLS_ECDSA_DETERMINISTIC)
            PSA_ALG_IS_ECDSA( alg )
#else
            PSA_ALG_IS_RANDOMIZED_ECDSA( alg )
#endif
            )
        {
            mbedtls_ecp_keypair *ecp = NULL;
            status = psa_load_ecp_representation( slot->attr.type,
                                                  slot->data.key.data,
                                                  slot->data.key.bytes,
                                                  &ecp );
            if( status != PSA_SUCCESS )
                goto exit;
            status = psa_ecdsa_sign( ecp,
                                     alg,
                                     hash, hash_length,
                                     signature, signature_size,
                                     signature_length );
            mbedtls_ecp_keypair_free( ecp );
            mbedtls_free( ecp );
        }
        else
#endif /* defined(MBEDTLS_ECDSA_C) */
        {
            status = PSA_ERROR_INVALID_ARGUMENT;
        }
    }
    else
#endif /* defined(MBEDTLS_ECP_C) */
    {
        status = PSA_ERROR_NOT_SUPPORTED;
    }

exit:
    /* Fill the unused part of the output buffer (the whole buffer on error,
     * the trailing part on success) with something that isn't a valid mac
     * (barring an attack on the mac and deliberately-crafted input),
     * in case the caller doesn't check the return status properly. */
    if( status == PSA_SUCCESS )
        memset( signature + *signature_length, '!',
                signature_size - *signature_length );
    else
        memset( signature, '!', signature_size );
    /* If signature_size is 0 then we have nothing to do. We must not call
     * memset because signature may be NULL in this case. */
    return( status );
}

psa_status_t psa_verify_hash( psa_key_handle_t handle,
                              psa_algorithm_t alg,
                              const uint8_t *hash,
                              size_t hash_length,
                              const uint8_t *signature,
                              size_t signature_length )
{
    psa_key_slot_t *slot;
    psa_status_t status;
#if defined(MBEDTLS_PSA_CRYPTO_SE_C)
    const psa_drv_se_t *drv;
    psa_drv_se_context_t *drv_context;
#endif /* MBEDTLS_PSA_CRYPTO_SE_C */

    status = psa_get_key_from_slot( handle, &slot, PSA_KEY_USAGE_VERIFY_HASH, alg );
    if( status != PSA_SUCCESS )
        return( status );

#if defined(MBEDTLS_PSA_CRYPTO_SE_C)
    if( psa_get_se_driver( slot->attr.lifetime, &drv, &drv_context ) )
    {
        if( drv->asymmetric == NULL ||
            drv->asymmetric->p_verify == NULL )
            return( PSA_ERROR_NOT_SUPPORTED );
        return( drv->asymmetric->p_verify( drv_context,
                                           slot->data.se.slot_number,
                                           alg,
                                           hash, hash_length,
                                           signature, signature_length ) );
    }
    else
#endif /* MBEDTLS_PSA_CRYPTO_SE_C */
#if defined(MBEDTLS_RSA_C)
    if( PSA_KEY_TYPE_IS_RSA( slot->attr.type ) )
    {
        mbedtls_rsa_context *rsa = NULL;

        status = psa_load_rsa_representation( slot->attr.type,
                                              slot->data.key.data,
                                              slot->data.key.bytes,
                                              &rsa );
        if( status != PSA_SUCCESS )
            return( status );

        status = psa_rsa_verify( rsa,
                                 alg,
                                 hash, hash_length,
                                 signature, signature_length );
        mbedtls_rsa_free( rsa );
        mbedtls_free( rsa );
        return( status );
    }
    else
#endif /* defined(MBEDTLS_RSA_C) */
#if defined(MBEDTLS_ECP_C)
    if( PSA_KEY_TYPE_IS_ECC( slot->attr.type ) )
    {
#if defined(MBEDTLS_ECDSA_C)
        if( PSA_ALG_IS_ECDSA( alg ) )
        {
            mbedtls_ecp_keypair *ecp = NULL;
            status = psa_load_ecp_representation( slot->attr.type,
                                                  slot->data.key.data,
                                                  slot->data.key.bytes,
                                                  &ecp );
            if( status != PSA_SUCCESS )
                return( status );
            status = psa_ecdsa_verify( ecp,
                                       hash, hash_length,
                                       signature, signature_length );
            mbedtls_ecp_keypair_free( ecp );
            mbedtls_free( ecp );
            return( status );
        }
        else
#endif /* defined(MBEDTLS_ECDSA_C) */
        {
            return( PSA_ERROR_INVALID_ARGUMENT );
        }
    }
    else
#endif /* defined(MBEDTLS_ECP_C) */
    {
        return( PSA_ERROR_NOT_SUPPORTED );
    }
}

#if defined(MBEDTLS_RSA_C) && defined(MBEDTLS_PKCS1_V21)
static void psa_rsa_oaep_set_padding_mode( psa_algorithm_t alg,
                                           mbedtls_rsa_context *rsa )
{
    psa_algorithm_t hash_alg = PSA_ALG_RSA_OAEP_GET_HASH( alg );
    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_psa( hash_alg );
    mbedtls_md_type_t md_alg = mbedtls_md_get_type( md_info );
    mbedtls_rsa_set_padding( rsa, MBEDTLS_RSA_PKCS_V21, md_alg );
}
#endif /* defined(MBEDTLS_RSA_C) && defined(MBEDTLS_PKCS1_V21) */

psa_status_t psa_asymmetric_encrypt( psa_key_handle_t handle,
                                     psa_algorithm_t alg,
                                     const uint8_t *input,
                                     size_t input_length,
                                     const uint8_t *salt,
                                     size_t salt_length,
                                     uint8_t *output,
                                     size_t output_size,
                                     size_t *output_length )
{
    psa_key_slot_t *slot;
    psa_status_t status;

    (void) input;
    (void) input_length;
    (void) salt;
    (void) output;
    (void) output_size;

    *output_length = 0;

    if( ! PSA_ALG_IS_RSA_OAEP( alg ) && salt_length != 0 )
        return( PSA_ERROR_INVALID_ARGUMENT );

    status = psa_get_transparent_key( handle, &slot, PSA_KEY_USAGE_ENCRYPT, alg );
    if( status != PSA_SUCCESS )
        return( status );
    if( ! ( PSA_KEY_TYPE_IS_PUBLIC_KEY( slot->attr.type ) ||
            PSA_KEY_TYPE_IS_KEY_PAIR( slot->attr.type ) ) )
        return( PSA_ERROR_INVALID_ARGUMENT );

#if defined(MBEDTLS_RSA_C)
    if( PSA_KEY_TYPE_IS_RSA( slot->attr.type ) )
    {
        mbedtls_rsa_context *rsa = NULL;
        status = psa_load_rsa_representation( slot->attr.type,
                                              slot->data.key.data,
                                              slot->data.key.bytes,
                                              &rsa );
        if( status != PSA_SUCCESS )
            goto rsa_exit;

        if( output_size < mbedtls_rsa_get_len( rsa ) )
        {
            status = PSA_ERROR_BUFFER_TOO_SMALL;
            goto rsa_exit;
        }
#if defined(MBEDTLS_PKCS1_V15)
        if( alg == PSA_ALG_RSA_PKCS1V15_CRYPT )
        {
            status = mbedtls_to_psa_error(
                    mbedtls_rsa_pkcs1_encrypt( rsa,
                                               mbedtls_ctr_drbg_random,
                                               &global_data.ctr_drbg,
                                               MBEDTLS_RSA_PUBLIC,
                                               input_length,
                                               input,
                                               output ) );
        }
        else
#endif /* MBEDTLS_PKCS1_V15 */
#if defined(MBEDTLS_PKCS1_V21)
        if( PSA_ALG_IS_RSA_OAEP( alg ) )
        {
            psa_rsa_oaep_set_padding_mode( alg, rsa );
            status = mbedtls_to_psa_error(
                mbedtls_rsa_rsaes_oaep_encrypt( rsa,
                                                mbedtls_ctr_drbg_random,
                                                &global_data.ctr_drbg,
                                                MBEDTLS_RSA_PUBLIC,
                                                salt, salt_length,
                                                input_length,
                                                input,
                                                output ) );
        }
        else
#endif /* MBEDTLS_PKCS1_V21 */
        {
            status = PSA_ERROR_INVALID_ARGUMENT;
            goto rsa_exit;
        }
rsa_exit:
        if( status == PSA_SUCCESS )
            *output_length = mbedtls_rsa_get_len( rsa );

        mbedtls_rsa_free( rsa );
        mbedtls_free( rsa );
        return( status );
    }
    else
#endif /* defined(MBEDTLS_RSA_C) */
    {
        return( PSA_ERROR_NOT_SUPPORTED );
    }
}

psa_status_t psa_asymmetric_decrypt( psa_key_handle_t handle,
                                     psa_algorithm_t alg,
                                     const uint8_t *input,
                                     size_t input_length,
                                     const uint8_t *salt,
                                     size_t salt_length,
                                     uint8_t *output,
                                     size_t output_size,
                                     size_t *output_length )
{
    psa_key_slot_t *slot;
    psa_status_t status;

    (void) input;
    (void) input_length;
    (void) salt;
    (void) output;
    (void) output_size;

    *output_length = 0;

    if( ! PSA_ALG_IS_RSA_OAEP( alg ) && salt_length != 0 )
        return( PSA_ERROR_INVALID_ARGUMENT );

    status = psa_get_transparent_key( handle, &slot, PSA_KEY_USAGE_DECRYPT, alg );
    if( status != PSA_SUCCESS )
        return( status );
    if( ! PSA_KEY_TYPE_IS_KEY_PAIR( slot->attr.type ) )
        return( PSA_ERROR_INVALID_ARGUMENT );

#if defined(MBEDTLS_RSA_C)
    if( slot->attr.type == PSA_KEY_TYPE_RSA_KEY_PAIR )
    {
        mbedtls_rsa_context *rsa = NULL;
        status = psa_load_rsa_representation( slot->attr.type,
                                              slot->data.key.data,
                                              slot->data.key.bytes,
                                              &rsa );
        if( status != PSA_SUCCESS )
            return( status );

        if( input_length != mbedtls_rsa_get_len( rsa ) )
        {
            status = PSA_ERROR_INVALID_ARGUMENT;
            goto rsa_exit;
        }

#if defined(MBEDTLS_PKCS1_V15)
        if( alg == PSA_ALG_RSA_PKCS1V15_CRYPT )
        {
            status = mbedtls_to_psa_error(
                mbedtls_rsa_pkcs1_decrypt( rsa,
                                           mbedtls_ctr_drbg_random,
                                           &global_data.ctr_drbg,
                                           MBEDTLS_RSA_PRIVATE,
                                           output_length,
                                           input,
                                           output,
                                           output_size ) );
        }
        else
#endif /* MBEDTLS_PKCS1_V15 */
#if defined(MBEDTLS_PKCS1_V21)
        if( PSA_ALG_IS_RSA_OAEP( alg ) )
        {
            psa_rsa_oaep_set_padding_mode( alg, rsa );
            status = mbedtls_to_psa_error(
                mbedtls_rsa_rsaes_oaep_decrypt( rsa,
                                                mbedtls_ctr_drbg_random,
                                                &global_data.ctr_drbg,
                                                MBEDTLS_RSA_PRIVATE,
                                                salt, salt_length,
                                                output_length,
                                                input,
                                                output,
                                                output_size ) );
        }
        else
#endif /* MBEDTLS_PKCS1_V21 */
        {
            status = PSA_ERROR_INVALID_ARGUMENT;
        }

rsa_exit:
        mbedtls_rsa_free( rsa );
        mbedtls_free( rsa );
        return( status );
    }
    else
#endif /* defined(MBEDTLS_RSA_C) */
    {
        return( PSA_ERROR_NOT_SUPPORTED );
    }
}



/****************************************************************/
/* Symmetric cryptography */
/****************************************************************/

/* Initialize the cipher operation structure. Once this function has been
 * called, psa_cipher_abort can run and will do the right thing. */
static psa_status_t psa_cipher_init( psa_cipher_operation_t *operation,
                                     psa_algorithm_t alg )
{
    if( ! PSA_ALG_IS_CIPHER( alg ) )
    {
        memset( operation, 0, sizeof( *operation ) );
        return( PSA_ERROR_INVALID_ARGUMENT );
    }

    operation->alg = alg;
    operation->key_set = 0;
    operation->iv_set = 0;
    operation->iv_required = 1;
    operation->iv_size = 0;
    operation->block_size = 0;
    mbedtls_cipher_init( &operation->ctx.cipher );
    return( PSA_SUCCESS );
}

static psa_status_t psa_cipher_setup( psa_cipher_operation_t *operation,
                                      psa_key_handle_t handle,
                                      psa_algorithm_t alg,
                                      mbedtls_operation_t cipher_operation )
{
    int ret = 0;
    psa_status_t status = PSA_ERROR_GENERIC_ERROR;
    psa_key_slot_t *slot;
    size_t key_bits;
    const mbedtls_cipher_info_t *cipher_info = NULL;
    psa_key_usage_t usage = ( cipher_operation == MBEDTLS_ENCRYPT ?
                              PSA_KEY_USAGE_ENCRYPT :
                              PSA_KEY_USAGE_DECRYPT );

    /* A context must be freshly initialized before it can be set up. */
    if( operation->alg != 0 )
    {
        return( PSA_ERROR_BAD_STATE );
    }

    status = psa_cipher_init( operation, alg );
    if( status != PSA_SUCCESS )
        return( status );

    status = psa_get_transparent_key( handle, &slot, usage, alg);
    if( status != PSA_SUCCESS )
        goto exit;
    key_bits = psa_get_key_slot_bits( slot );

    cipher_info = mbedtls_cipher_info_from_psa( alg, slot->attr.type, key_bits, NULL );
    if( cipher_info == NULL )
    {
        status = PSA_ERROR_NOT_SUPPORTED;
        goto exit;
    }

    ret = mbedtls_cipher_setup( &operation->ctx.cipher, cipher_info );
    if( ret != 0 )
        goto exit;

#if defined(MBEDTLS_DES_C)
    if( slot->attr.type == PSA_KEY_TYPE_DES && key_bits == 128 )
    {
        /* Two-key Triple-DES is 3-key Triple-DES with K1=K3 */
        uint8_t keys[24];
        memcpy( keys, slot->data.key.data, 16 );
        memcpy( keys + 16, slot->data.key.data, 8 );
        ret = mbedtls_cipher_setkey( &operation->ctx.cipher,
                                     keys,
                                     192, cipher_operation );
    }
    else
#endif
    {
        ret = mbedtls_cipher_setkey( &operation->ctx.cipher,
                                     slot->data.key.data,
                                     (int) key_bits, cipher_operation );
    }
    if( ret != 0 )
        goto exit;

#if defined(MBEDTLS_CIPHER_MODE_WITH_PADDING)
    switch( alg )
    {
        case PSA_ALG_CBC_NO_PADDING:
            ret = mbedtls_cipher_set_padding_mode( &operation->ctx.cipher,
                                                   MBEDTLS_PADDING_NONE );
            break;
        case PSA_ALG_CBC_PKCS7:
            ret = mbedtls_cipher_set_padding_mode( &operation->ctx.cipher,
                                                   MBEDTLS_PADDING_PKCS7 );
            break;
        default:
            /* The algorithm doesn't involve padding. */
            ret = 0;
            break;
    }
    if( ret != 0 )
        goto exit;
#endif //MBEDTLS_CIPHER_MODE_WITH_PADDING

    operation->key_set = 1;
    operation->block_size = ( PSA_ALG_IS_STREAM_CIPHER( alg ) ? 1 :
                              PSA_BLOCK_CIPHER_BLOCK_SIZE( slot->attr.type ) );
    if( alg & PSA_ALG_CIPHER_FROM_BLOCK_FLAG )
    {
        operation->iv_size = PSA_BLOCK_CIPHER_BLOCK_SIZE( slot->attr.type );
    }
#if defined(MBEDTLS_CHACHA20_C)
    else
    if( alg == PSA_ALG_CHACHA20 )
        operation->iv_size = 12;
#endif

exit:
    if( status == 0 )
        status = mbedtls_to_psa_error( ret );
    if( status != 0 )
        psa_cipher_abort( operation );
    return( status );
}

psa_status_t psa_cipher_encrypt_setup( psa_cipher_operation_t *operation,
                                       psa_key_handle_t handle,
                                       psa_algorithm_t alg )
{
    return( psa_cipher_setup( operation, handle, alg, MBEDTLS_ENCRYPT ) );
}

psa_status_t psa_cipher_decrypt_setup( psa_cipher_operation_t *operation,
                                       psa_key_handle_t handle,
                                       psa_algorithm_t alg )
{
    return( psa_cipher_setup( operation, handle, alg, MBEDTLS_DECRYPT ) );
}

psa_status_t psa_cipher_generate_iv( psa_cipher_operation_t *operation,
                                     uint8_t *iv,
                                     size_t iv_size,
                                     size_t *iv_length )
{
    psa_status_t status;
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    if( operation->iv_set || ! operation->iv_required )
    {
        return( PSA_ERROR_BAD_STATE );
    }
    if( iv_size < operation->iv_size )
    {
        status = PSA_ERROR_BUFFER_TOO_SMALL;
        goto exit;
    }
    ret = mbedtls_ctr_drbg_random( &global_data.ctr_drbg,
                                   iv, operation->iv_size );
    if( ret != 0 )
    {
        status = mbedtls_to_psa_error( ret );
        goto exit;
    }

    *iv_length = operation->iv_size;
    status = psa_cipher_set_iv( operation, iv, *iv_length );

exit:
    if( status != PSA_SUCCESS )
        psa_cipher_abort( operation );
    return( status );
}

psa_status_t psa_cipher_set_iv( psa_cipher_operation_t *operation,
                                const uint8_t *iv,
                                size_t iv_length )
{
    psa_status_t status;
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    if( operation->iv_set || ! operation->iv_required )
    {
        return( PSA_ERROR_BAD_STATE );
    }
    if( iv_length != operation->iv_size )
    {
        status = PSA_ERROR_INVALID_ARGUMENT;
        goto exit;
    }
    ret = mbedtls_cipher_set_iv( &operation->ctx.cipher, iv, iv_length );
    status = mbedtls_to_psa_error( ret );
exit:
    if( status == PSA_SUCCESS )
        operation->iv_set = 1;
    else
        psa_cipher_abort( operation );
    return( status );
}

psa_status_t psa_cipher_update( psa_cipher_operation_t *operation,
                                const uint8_t *input,
                                size_t input_length,
                                uint8_t *output,
                                size_t output_size,
                                size_t *output_length )
{
    psa_status_t status;
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t expected_output_size;

    if( operation->alg == 0 )
    {
        return( PSA_ERROR_BAD_STATE );
    }

    if( ! PSA_ALG_IS_STREAM_CIPHER( operation->alg ) )
    {
        /* Take the unprocessed partial block left over from previous
         * update calls, if any, plus the input to this call. Remove
         * the last partial block, if any. You get the data that will be
         * output in this call. */
        expected_output_size =
            ( operation->ctx.cipher.unprocessed_len + input_length )
            / operation->block_size * operation->block_size;
    }
    else
    {
        expected_output_size = input_length;
    }

    if( output_size < expected_output_size )
    {
        status = PSA_ERROR_BUFFER_TOO_SMALL;
        goto exit;
    }

    ret = mbedtls_cipher_update( &operation->ctx.cipher, input,
                                 input_length, output, output_length );
    status = mbedtls_to_psa_error( ret );
exit:
    if( status != PSA_SUCCESS )
        psa_cipher_abort( operation );
    return( status );
}

psa_status_t psa_cipher_finish( psa_cipher_operation_t *operation,
                                uint8_t *output,
                                size_t output_size,
                                size_t *output_length )
{
    psa_status_t status = PSA_ERROR_GENERIC_ERROR;
    int cipher_ret = MBEDTLS_ERR_CIPHER_FEATURE_UNAVAILABLE;
    uint8_t temp_output_buffer[MBEDTLS_MAX_BLOCK_LENGTH];

    if( ! operation->key_set )
    {
        return( PSA_ERROR_BAD_STATE );
    }
    if( operation->iv_required && ! operation->iv_set )
    {
        return( PSA_ERROR_BAD_STATE );
    }

    if( operation->ctx.cipher.operation == MBEDTLS_ENCRYPT &&
        operation->alg == PSA_ALG_CBC_NO_PADDING &&
        operation->ctx.cipher.unprocessed_len != 0 )
    {
            status = PSA_ERROR_INVALID_ARGUMENT;
            goto error;
    }

    cipher_ret = mbedtls_cipher_finish( &operation->ctx.cipher,
                                        temp_output_buffer,
                                        output_length );
    if( cipher_ret != 0 )
    {
        status = mbedtls_to_psa_error( cipher_ret );
        goto error;
    }

    if( *output_length == 0 )
        ; /* Nothing to copy. Note that output may be NULL in this case. */
    else if( output_size >= *output_length )
        memcpy( output, temp_output_buffer, *output_length );
    else
    {
        status = PSA_ERROR_BUFFER_TOO_SMALL;
        goto error;
    }

    mbedtls_platform_zeroize( temp_output_buffer, sizeof( temp_output_buffer ) );
    status = psa_cipher_abort( operation );

    return( status );

error:

    *output_length = 0;

    mbedtls_platform_zeroize( temp_output_buffer, sizeof( temp_output_buffer ) );
    (void) psa_cipher_abort( operation );

    return( status );
}

psa_status_t psa_cipher_abort( psa_cipher_operation_t *operation )
{
    if( operation->alg == 0 )
    {
        /* The object has (apparently) been initialized but it is not
         * in use. It's ok to call abort on such an object, and there's
         * nothing to do. */
        return( PSA_SUCCESS );
    }

    /* Sanity check (shouldn't happen: operation->alg should
     * always have been initialized to a valid value). */
    if( ! PSA_ALG_IS_CIPHER( operation->alg ) )
        return( PSA_ERROR_BAD_STATE );

    mbedtls_cipher_free( &operation->ctx.cipher );

    operation->alg = 0;
    operation->key_set = 0;
    operation->iv_set = 0;
    operation->iv_size = 0;
    operation->block_size = 0;
    operation->iv_required = 0;

    return( PSA_SUCCESS );
}




/****************************************************************/
/* AEAD */
/****************************************************************/

typedef struct
{
    psa_key_slot_t *slot;
    const mbedtls_cipher_info_t *cipher_info;
    union
    {
#if defined(MBEDTLS_CCM_C)
        mbedtls_ccm_context ccm;
#endif /* MBEDTLS_CCM_C */
#if defined(MBEDTLS_GCM_C)
        mbedtls_gcm_context gcm;
#endif /* MBEDTLS_GCM_C */
#if defined(MBEDTLS_CHACHAPOLY_C)
        mbedtls_chachapoly_context chachapoly;
#endif /* MBEDTLS_CHACHAPOLY_C */
    } ctx;
    psa_algorithm_t core_alg;
    uint8_t full_tag_length;
    uint8_t tag_length;
} aead_operation_t;

static void psa_aead_abort_internal( aead_operation_t *operation )
{
    switch( operation->core_alg )
    {
#if defined(MBEDTLS_CCM_C)
        case PSA_ALG_CCM:
            mbedtls_ccm_free( &operation->ctx.ccm );
            break;
#endif /* MBEDTLS_CCM_C */
#if defined(MBEDTLS_GCM_C)
        case PSA_ALG_GCM:
            mbedtls_gcm_free( &operation->ctx.gcm );
            break;
#endif /* MBEDTLS_GCM_C */
    }
}

static psa_status_t psa_aead_setup( aead_operation_t *operation,
                                    psa_key_handle_t handle,
                                    psa_key_usage_t usage,
                                    psa_algorithm_t alg )
{
    psa_status_t status;
    size_t key_bits;
    mbedtls_cipher_id_t cipher_id;

    status = psa_get_transparent_key( handle, &operation->slot, usage, alg );
    if( status != PSA_SUCCESS )
        return( status );

    key_bits = psa_get_key_slot_bits( operation->slot );

    operation->cipher_info =
        mbedtls_cipher_info_from_psa( alg, operation->slot->attr.type, key_bits,
                                      &cipher_id );
    if( operation->cipher_info == NULL )
        return( PSA_ERROR_NOT_SUPPORTED );

    switch( PSA_ALG_AEAD_WITH_TAG_LENGTH( alg, 0 ) )
    {
#if defined(MBEDTLS_CCM_C)
        case PSA_ALG_AEAD_WITH_TAG_LENGTH( PSA_ALG_CCM, 0 ):
            operation->core_alg = PSA_ALG_CCM;
            operation->full_tag_length = 16;
            /* CCM allows the following tag lengths: 4, 6, 8, 10, 12, 14, 16.
             * The call to mbedtls_ccm_encrypt_and_tag or
             * mbedtls_ccm_auth_decrypt will validate the tag length. */
            if( PSA_BLOCK_CIPHER_BLOCK_SIZE( operation->slot->attr.type ) != 16 )
                return( PSA_ERROR_INVALID_ARGUMENT );
            mbedtls_ccm_init( &operation->ctx.ccm );
            status = mbedtls_to_psa_error(
                mbedtls_ccm_setkey( &operation->ctx.ccm, cipher_id,
                                    operation->slot->data.key.data,
                                    (unsigned int) key_bits ) );
            if( status != 0 )
                goto cleanup;
            break;
#endif /* MBEDTLS_CCM_C */

#if defined(MBEDTLS_GCM_C)
        case PSA_ALG_AEAD_WITH_TAG_LENGTH( PSA_ALG_GCM, 0 ):
            operation->core_alg = PSA_ALG_GCM;
            operation->full_tag_length = 16;
            /* GCM allows the following tag lengths: 4, 8, 12, 13, 14, 15, 16.
             * The call to mbedtls_gcm_crypt_and_tag or
             * mbedtls_gcm_auth_decrypt will validate the tag length. */
            if( PSA_BLOCK_CIPHER_BLOCK_SIZE( operation->slot->attr.type ) != 16 )
                return( PSA_ERROR_INVALID_ARGUMENT );
            mbedtls_gcm_init( &operation->ctx.gcm );
            status = mbedtls_to_psa_error(
                mbedtls_gcm_setkey( &operation->ctx.gcm, cipher_id,
                                    operation->slot->data.key.data,
                                    (unsigned int) key_bits ) );
            if( status != 0 )
                goto cleanup;
            break;
#endif /* MBEDTLS_GCM_C */

#if defined(MBEDTLS_CHACHAPOLY_C)
        case PSA_ALG_AEAD_WITH_TAG_LENGTH( PSA_ALG_CHACHA20_POLY1305, 0 ):
            operation->core_alg = PSA_ALG_CHACHA20_POLY1305;
            operation->full_tag_length = 16;
            /* We only support the default tag length. */
            if( alg != PSA_ALG_CHACHA20_POLY1305 )
                return( PSA_ERROR_NOT_SUPPORTED );
            mbedtls_chachapoly_init( &operation->ctx.chachapoly );
            status = mbedtls_to_psa_error(
                mbedtls_chachapoly_setkey( &operation->ctx.chachapoly,
                                           operation->slot->data.key.data ) );
            if( status != 0 )
                goto cleanup;
            break;
#endif /* MBEDTLS_CHACHAPOLY_C */

        default:
            return( PSA_ERROR_NOT_SUPPORTED );
    }

    if( PSA_AEAD_TAG_LENGTH( alg ) > operation->full_tag_length )
    {
        status = PSA_ERROR_INVALID_ARGUMENT;
        goto cleanup;
    }
    operation->tag_length = PSA_AEAD_TAG_LENGTH( alg );

    return( PSA_SUCCESS );

cleanup:
    psa_aead_abort_internal( operation );
    return( status );
}

psa_status_t psa_aead_encrypt( psa_key_handle_t handle,
                               psa_algorithm_t alg,
                               const uint8_t *nonce,
                               size_t nonce_length,
                               const uint8_t *additional_data,
                               size_t additional_data_length,
                               const uint8_t *plaintext,
                               size_t plaintext_length,
                               uint8_t *ciphertext,
                               size_t ciphertext_size,
                               size_t *ciphertext_length )
{
    psa_status_t status;
    aead_operation_t operation;
    uint8_t *tag;

    *ciphertext_length = 0;

    status = psa_aead_setup( &operation, handle, PSA_KEY_USAGE_ENCRYPT, alg );
    if( status != PSA_SUCCESS )
        return( status );

    /* For all currently supported modes, the tag is at the end of the
     * ciphertext. */
    if( ciphertext_size < ( plaintext_length + operation.tag_length ) )
    {
        status = PSA_ERROR_BUFFER_TOO_SMALL;
        goto exit;
    }
    tag = ciphertext + plaintext_length;

#if defined(MBEDTLS_GCM_C)
    if( operation.core_alg == PSA_ALG_GCM )
    {
        status = mbedtls_to_psa_error(
            mbedtls_gcm_crypt_and_tag( &operation.ctx.gcm,
                                       MBEDTLS_GCM_ENCRYPT,
                                       plaintext_length,
                                       nonce, nonce_length,
                                       additional_data, additional_data_length,
                                       plaintext, ciphertext,
                                       operation.tag_length, tag ) );
    }
    else
#endif /* MBEDTLS_GCM_C */
#if defined(MBEDTLS_CCM_C)
    if( operation.core_alg == PSA_ALG_CCM )
    {
        status = mbedtls_to_psa_error(
            mbedtls_ccm_encrypt_and_tag( &operation.ctx.ccm,
                                         plaintext_length,
                                         nonce, nonce_length,
                                         additional_data,
                                         additional_data_length,
                                         plaintext, ciphertext,
                                         tag, operation.tag_length ) );
    }
    else
#endif /* MBEDTLS_CCM_C */
#if defined(MBEDTLS_CHACHAPOLY_C)
    if( operation.core_alg == PSA_ALG_CHACHA20_POLY1305 )
    {
        if( nonce_length != 12 || operation.tag_length != 16 )
        {
            status = PSA_ERROR_NOT_SUPPORTED;
            goto exit;
        }
        status = mbedtls_to_psa_error(
            mbedtls_chachapoly_encrypt_and_tag( &operation.ctx.chachapoly,
                                                plaintext_length,
                                                nonce,
                                                additional_data,
                                                additional_data_length,
                                                plaintext,
                                                ciphertext,
                                                tag ) );
    }
    else
#endif /* MBEDTLS_CHACHAPOLY_C */
    {
        return( PSA_ERROR_NOT_SUPPORTED );
    }

    if( status != PSA_SUCCESS && ciphertext_size != 0 )
        memset( ciphertext, 0, ciphertext_size );

exit:
    psa_aead_abort_internal( &operation );
    if( status == PSA_SUCCESS )
        *ciphertext_length = plaintext_length + operation.tag_length;
    return( status );
}

/* Locate the tag in a ciphertext buffer containing the encrypted data
 * followed by the tag. Return the length of the part preceding the tag in
 * *plaintext_length. This is the size of the plaintext in modes where
 * the encrypted data has the same size as the plaintext, such as
 * CCM and GCM. */
static psa_status_t psa_aead_unpadded_locate_tag( size_t tag_length,
                                                  const uint8_t *ciphertext,
                                                  size_t ciphertext_length,
                                                  size_t plaintext_size,
                                                  const uint8_t **p_tag )
{
    size_t payload_length;
    if( tag_length > ciphertext_length )
        return( PSA_ERROR_INVALID_ARGUMENT );
    payload_length = ciphertext_length - tag_length;
    if( payload_length > plaintext_size )
        return( PSA_ERROR_BUFFER_TOO_SMALL );
    *p_tag = ciphertext + payload_length;
    return( PSA_SUCCESS );
}

psa_status_t psa_aead_decrypt( psa_key_handle_t handle,
                               psa_algorithm_t alg,
                               const uint8_t *nonce,
                               size_t nonce_length,
                               const uint8_t *additional_data,
                               size_t additional_data_length,
                               const uint8_t *ciphertext,
                               size_t ciphertext_length,
                               uint8_t *plaintext,
                               size_t plaintext_size,
                               size_t *plaintext_length )
{
    psa_status_t status;
    aead_operation_t operation;
    const uint8_t *tag = NULL;

    *plaintext_length = 0;

    status = psa_aead_setup( &operation, handle, PSA_KEY_USAGE_DECRYPT, alg );
    if( status != PSA_SUCCESS )
        return( status );

    status = psa_aead_unpadded_locate_tag( operation.tag_length,
                                           ciphertext, ciphertext_length,
                                           plaintext_size, &tag );
    if( status != PSA_SUCCESS )
        goto exit;

#if defined(MBEDTLS_GCM_C)
    if( operation.core_alg == PSA_ALG_GCM )
    {
        status = mbedtls_to_psa_error(
            mbedtls_gcm_auth_decrypt( &operation.ctx.gcm,
                                      ciphertext_length - operation.tag_length,
                                      nonce, nonce_length,
                                      additional_data,
                                      additional_data_length,
                                      tag, operation.tag_length,
                                      ciphertext, plaintext ) );
    }
    else
#endif /* MBEDTLS_GCM_C */
#if defined(MBEDTLS_CCM_C)
    if( operation.core_alg == PSA_ALG_CCM )
    {
        status = mbedtls_to_psa_error(
            mbedtls_ccm_auth_decrypt( &operation.ctx.ccm,
                                      ciphertext_length - operation.tag_length,
                                      nonce, nonce_length,
                                      additional_data,
                                      additional_data_length,
                                      ciphertext, plaintext,
                                      tag, operation.tag_length ) );
    }
    else
#endif /* MBEDTLS_CCM_C */
#if defined(MBEDTLS_CHACHAPOLY_C)
    if( operation.core_alg == PSA_ALG_CHACHA20_POLY1305 )
    {
        if( nonce_length != 12 || operation.tag_length != 16 )
        {
            status = PSA_ERROR_NOT_SUPPORTED;
            goto exit;
        }
        status = mbedtls_to_psa_error(
            mbedtls_chachapoly_auth_decrypt( &operation.ctx.chachapoly,
                                             ciphertext_length - operation.tag_length,
                                             nonce,
                                             additional_data,
                                             additional_data_length,
                                             tag,
                                             ciphertext,
                                             plaintext ) );
    }
    else
#endif /* MBEDTLS_CHACHAPOLY_C */
    {
        return( PSA_ERROR_NOT_SUPPORTED );
    }

    if( status != PSA_SUCCESS && plaintext_size != 0 )
        memset( plaintext, 0, plaintext_size );

exit:
    psa_aead_abort_internal( &operation );
    if( status == PSA_SUCCESS )
        *plaintext_length = ciphertext_length - operation.tag_length;
    return( status );
}



/****************************************************************/
/* Generators */
/****************************************************************/

#define HKDF_STATE_INIT 0 /* no input yet */
#define HKDF_STATE_STARTED 1 /* got salt */
#define HKDF_STATE_KEYED 2 /* got key */
#define HKDF_STATE_OUTPUT 3 /* output started */

static psa_algorithm_t psa_key_derivation_get_kdf_alg(
    const psa_key_derivation_operation_t *operation )
{
    if ( PSA_ALG_IS_KEY_AGREEMENT( operation->alg ) )
        return( PSA_ALG_KEY_AGREEMENT_GET_KDF( operation->alg ) );
    else
        return( operation->alg );
}


psa_status_t psa_key_derivation_abort( psa_key_derivation_operation_t *operation )
{
    psa_status_t status = PSA_SUCCESS;
    psa_algorithm_t kdf_alg = psa_key_derivation_get_kdf_alg( operation );
    if( kdf_alg == 0 )
    {
        /* The object has (apparently) been initialized but it is not
         * in use. It's ok to call abort on such an object, and there's
         * nothing to do. */
    }
    else
#if defined(MBEDTLS_MD_C)
    if( PSA_ALG_IS_HKDF( kdf_alg ) )
    {
        mbedtls_free( operation->ctx.hkdf.info );
        status = psa_hmac_abort_internal( &operation->ctx.hkdf.hmac );
    }
    else if( PSA_ALG_IS_TLS12_PRF( kdf_alg ) ||
             /* TLS-1.2 PSK-to-MS KDF uses the same core as TLS-1.2 PRF */
             PSA_ALG_IS_TLS12_PSK_TO_MS( kdf_alg ) )
    {
        if( operation->ctx.tls12_prf.seed != NULL )
        {
            mbedtls_platform_zeroize( operation->ctx.tls12_prf.seed,
                                      operation->ctx.tls12_prf.seed_length );
            mbedtls_free( operation->ctx.tls12_prf.seed );
        }

        if( operation->ctx.tls12_prf.label != NULL )
        {
            mbedtls_platform_zeroize( operation->ctx.tls12_prf.label,
                                      operation->ctx.tls12_prf.label_length );
            mbedtls_free( operation->ctx.tls12_prf.label );
        }

        status = psa_hmac_abort_internal( &operation->ctx.tls12_prf.hmac );

        /* We leave the fields Ai and output_block to be erased safely by the
         * mbedtls_platform_zeroize() in the end of this function. */
    }
    else
#endif /* MBEDTLS_MD_C */
    {
        status = PSA_ERROR_BAD_STATE;
    }
    mbedtls_platform_zeroize( operation, sizeof( *operation ) );
    return( status );
}

psa_status_t psa_key_derivation_get_capacity(const psa_key_derivation_operation_t *operation,
                                        size_t *capacity)
{
    if( operation->alg == 0 )
    {
        /* This is a blank key derivation operation. */
        return( PSA_ERROR_BAD_STATE );
    }

    *capacity = operation->capacity;
    return( PSA_SUCCESS );
}

psa_status_t psa_key_derivation_set_capacity( psa_key_derivation_operation_t *operation,
                                         size_t capacity )
{
    if( operation->alg == 0 )
        return( PSA_ERROR_BAD_STATE );
    if( capacity > operation->capacity )
        return( PSA_ERROR_INVALID_ARGUMENT );
    operation->capacity = capacity;
    return( PSA_SUCCESS );
}

#if defined(MBEDTLS_MD_C)
/* Read some bytes from an HKDF-based operation. This performs a chunk
 * of the expand phase of the HKDF algorithm. */
static psa_status_t psa_key_derivation_hkdf_read( psa_hkdf_key_derivation_t *hkdf,
                                             psa_algorithm_t hash_alg,
                                             uint8_t *output,
                                             size_t output_length )
{
    uint8_t hash_length = PSA_HASH_SIZE( hash_alg );
    psa_status_t status;

    if( hkdf->state < HKDF_STATE_KEYED || ! hkdf->info_set )
        return( PSA_ERROR_BAD_STATE );
    hkdf->state = HKDF_STATE_OUTPUT;

    while( output_length != 0 )
    {
        /* Copy what remains of the current block */
        uint8_t n = hash_length - hkdf->offset_in_block;
        if( n > output_length )
            n = (uint8_t) output_length;
        memcpy( output, hkdf->output_block + hkdf->offset_in_block, n );
        output += n;
        output_length -= n;
        hkdf->offset_in_block += n;
        if( output_length == 0 )
            break;
        /* We can't be wanting more output after block 0xff, otherwise
         * the capacity check in psa_key_derivation_output_bytes() would have
         * prevented this call. It could happen only if the operation
         * object was corrupted or if this function is called directly
         * inside the library. */
        if( hkdf->block_number == 0xff )
            return( PSA_ERROR_BAD_STATE );

        /* We need a new block */
        ++hkdf->block_number;
        hkdf->offset_in_block = 0;
        status = psa_hmac_setup_internal( &hkdf->hmac,
                                          hkdf->prk, hash_length,
                                          hash_alg );
        if( status != PSA_SUCCESS )
            return( status );
        if( hkdf->block_number != 1 )
        {
            status = psa_hash_update( &hkdf->hmac.hash_ctx,
                                      hkdf->output_block,
                                      hash_length );
            if( status != PSA_SUCCESS )
                return( status );
        }
        status = psa_hash_update( &hkdf->hmac.hash_ctx,
                                  hkdf->info,
                                  hkdf->info_length );
        if( status != PSA_SUCCESS )
            return( status );
        status = psa_hash_update( &hkdf->hmac.hash_ctx,
                                  &hkdf->block_number, 1 );
        if( status != PSA_SUCCESS )
            return( status );
        status = psa_hmac_finish_internal( &hkdf->hmac,
                                           hkdf->output_block,
                                           sizeof( hkdf->output_block ) );
        if( status != PSA_SUCCESS )
            return( status );
    }

    return( PSA_SUCCESS );
}

static psa_status_t psa_key_derivation_tls12_prf_generate_next_block(
    psa_tls12_prf_key_derivation_t *tls12_prf,
    psa_algorithm_t alg )
{
    psa_algorithm_t hash_alg = PSA_ALG_HKDF_GET_HASH( alg );
    uint8_t hash_length = PSA_HASH_SIZE( hash_alg );
    psa_hash_operation_t backup = PSA_HASH_OPERATION_INIT;
    psa_status_t status, cleanup_status;

    /* We can't be wanting more output after block 0xff, otherwise
     * the capacity check in psa_key_derivation_output_bytes() would have
     * prevented this call. It could happen only if the operation
     * object was corrupted or if this function is called directly
     * inside the library. */
    if( tls12_prf->block_number == 0xff )
        return( PSA_ERROR_CORRUPTION_DETECTED );

    /* We need a new block */
    ++tls12_prf->block_number;
    tls12_prf->left_in_block = hash_length;

    /* Recall the definition of the TLS-1.2-PRF from RFC 5246:
     *
     * PRF(secret, label, seed) = P_<hash>(secret, label + seed)
     *
     * P_hash(secret, seed) = HMAC_hash(secret, A(1) + seed) +
     *                        HMAC_hash(secret, A(2) + seed) +
     *                        HMAC_hash(secret, A(3) + seed) + ...
     *
     * A(0) = seed
     * A(i) = HMAC_hash(secret, A(i-1))
     *
     * The `psa_tls12_prf_key_derivation` structure saves the block
     * `HMAC_hash(secret, A(i) + seed)` from which the output
     * is currently extracted as `output_block` and where i is
     * `block_number`.
     */

    /* Save the hash context before using it, to preserve the hash state with
     * only the inner padding in it. We need this, because inner padding depends
     * on the key (secret in the RFC's terminology). */
    status = psa_hash_clone( &tls12_prf->hmac.hash_ctx, &backup );
    if( status != PSA_SUCCESS )
        goto cleanup;

    /* Calculate A(i) where i = tls12_prf->block_number. */
    if( tls12_prf->block_number == 1 )
    {
        /* A(1) = HMAC_hash(secret, A(0)), where A(0) = seed. (The RFC overloads
         * the variable seed and in this instance means it in the context of the
         * P_hash function, where seed = label + seed.) */
        status = psa_hash_update( &tls12_prf->hmac.hash_ctx,
                                  tls12_prf->label, tls12_prf->label_length );
        if( status != PSA_SUCCESS )
            goto cleanup;
        status = psa_hash_update( &tls12_prf->hmac.hash_ctx,
                                  tls12_prf->seed, tls12_prf->seed_length );
        if( status != PSA_SUCCESS )
            goto cleanup;
    }
    else
    {
        /* A(i) = HMAC_hash(secret, A(i-1)) */
        status = psa_hash_update( &tls12_prf->hmac.hash_ctx,
                                  tls12_prf->Ai, hash_length );
        if( status != PSA_SUCCESS )
            goto cleanup;
    }

    status = psa_hmac_finish_internal( &tls12_prf->hmac,
                                       tls12_prf->Ai, hash_length );
    if( status != PSA_SUCCESS )
        goto cleanup;
    status = psa_hash_clone( &backup, &tls12_prf->hmac.hash_ctx );
    if( status != PSA_SUCCESS )
        goto cleanup;

    /* Calculate HMAC_hash(secret, A(i) + label + seed). */
    status = psa_hash_update( &tls12_prf->hmac.hash_ctx,
                              tls12_prf->Ai, hash_length );
    if( status != PSA_SUCCESS )
        goto cleanup;
    status = psa_hash_update( &tls12_prf->hmac.hash_ctx,
                              tls12_prf->label, tls12_prf->label_length );
    if( status != PSA_SUCCESS )
        goto cleanup;
    status = psa_hash_update( &tls12_prf->hmac.hash_ctx,
                              tls12_prf->seed, tls12_prf->seed_length );
    if( status != PSA_SUCCESS )
        goto cleanup;
    status = psa_hmac_finish_internal( &tls12_prf->hmac,
                                       tls12_prf->output_block, hash_length );
    if( status != PSA_SUCCESS )
        goto cleanup;
    status = psa_hash_clone( &backup, &tls12_prf->hmac.hash_ctx );
    if( status != PSA_SUCCESS )
        goto cleanup;


cleanup:

    cleanup_status = psa_hash_abort( &backup );
    if( status == PSA_SUCCESS && cleanup_status != PSA_SUCCESS )
        status = cleanup_status;

    return( status );
}

static psa_status_t psa_key_derivation_tls12_prf_read(
    psa_tls12_prf_key_derivation_t *tls12_prf,
    psa_algorithm_t alg,
    uint8_t *output,
    size_t output_length )
{
    psa_algorithm_t hash_alg = PSA_ALG_TLS12_PRF_GET_HASH( alg );
    uint8_t hash_length = PSA_HASH_SIZE( hash_alg );
    psa_status_t status;
    uint8_t offset, length;

    while( output_length != 0 )
    {
        /* Check if we have fully processed the current block. */
        if( tls12_prf->left_in_block == 0 )
        {
            status = psa_key_derivation_tls12_prf_generate_next_block( tls12_prf,
                                                                       alg );
            if( status != PSA_SUCCESS )
                return( status );

            continue;
        }

        if( tls12_prf->left_in_block > output_length )
            length = (uint8_t) output_length;
        else
            length = tls12_prf->left_in_block;

        offset = hash_length - tls12_prf->left_in_block;
        memcpy( output, tls12_prf->output_block + offset, length );
        output += length;
        output_length -= length;
        tls12_prf->left_in_block -= length;
    }

    return( PSA_SUCCESS );
}
#endif /* MBEDTLS_MD_C */

psa_status_t psa_key_derivation_output_bytes(
    psa_key_derivation_operation_t *operation,
    uint8_t *output,
    size_t output_length )
{
    psa_status_t status;
    psa_algorithm_t kdf_alg = psa_key_derivation_get_kdf_alg( operation );

    if( operation->alg == 0 )
    {
        /* This is a blank operation. */
        return( PSA_ERROR_BAD_STATE );
    }

    if( output_length > operation->capacity )
    {
        operation->capacity = 0;
        /* Go through the error path to wipe all confidential data now
         * that the operation object is useless. */
        status = PSA_ERROR_INSUFFICIENT_DATA;
        goto exit;
    }
    if( output_length == 0 && operation->capacity == 0 )
    {
        /* Edge case: this is a finished operation, and 0 bytes
         * were requested. The right error in this case could
         * be either INSUFFICIENT_CAPACITY or BAD_STATE. Return
         * INSUFFICIENT_CAPACITY, which is right for a finished
         * operation, for consistency with the case when
         * output_length > 0. */
        return( PSA_ERROR_INSUFFICIENT_DATA );
    }
    operation->capacity -= output_length;

#if defined(MBEDTLS_MD_C)
    if( PSA_ALG_IS_HKDF( kdf_alg ) )
    {
        psa_algorithm_t hash_alg = PSA_ALG_HKDF_GET_HASH( kdf_alg );
        status = psa_key_derivation_hkdf_read( &operation->ctx.hkdf, hash_alg,
                                          output, output_length );
    }
    else
    if( PSA_ALG_IS_TLS12_PRF( kdf_alg ) ||
             PSA_ALG_IS_TLS12_PSK_TO_MS( kdf_alg ) )
    {
        status = psa_key_derivation_tls12_prf_read( &operation->ctx.tls12_prf,
                                               kdf_alg, output,
                                               output_length );
    }
    else
#endif /* MBEDTLS_MD_C */
    {
        return( PSA_ERROR_BAD_STATE );
    }

exit:
    if( status != PSA_SUCCESS )
    {
        /* Preserve the algorithm upon errors, but clear all sensitive state.
         * This allows us to differentiate between exhausted operations and
         * blank operations, so we can return PSA_ERROR_BAD_STATE on blank
         * operations. */
        psa_algorithm_t alg = operation->alg;
        psa_key_derivation_abort( operation );
        operation->alg = alg;
        memset( output, '!', output_length );
    }
    return( status );
}

#if defined(MBEDTLS_DES_C)
static void psa_des_set_key_parity( uint8_t *data, size_t data_size )
{
    if( data_size >= 8 )
        mbedtls_des_key_set_parity( data );
    if( data_size >= 16 )
        mbedtls_des_key_set_parity( data + 8 );
    if( data_size >= 24 )
        mbedtls_des_key_set_parity( data + 16 );
}
#endif /* MBEDTLS_DES_C */

static psa_status_t psa_generate_derived_key_internal(
    psa_key_slot_t *slot,
    size_t bits,
    psa_key_derivation_operation_t *operation )
{
    uint8_t *data = NULL;
    size_t bytes = PSA_BITS_TO_BYTES( bits );
    psa_status_t status;

    if( ! key_type_is_raw_bytes( slot->attr.type ) )
        return( PSA_ERROR_INVALID_ARGUMENT );
    if( bits % 8 != 0 )
        return( PSA_ERROR_INVALID_ARGUMENT );
    data = mbedtls_calloc( 1, bytes );
    if( data == NULL )
        return( PSA_ERROR_INSUFFICIENT_MEMORY );

    status = psa_key_derivation_output_bytes( operation, data, bytes );
    if( status != PSA_SUCCESS )
        goto exit;
#if defined(MBEDTLS_DES_C)
    if( slot->attr.type == PSA_KEY_TYPE_DES )
        psa_des_set_key_parity( data, bytes );
#endif /* MBEDTLS_DES_C */
    status = psa_import_key_into_slot( slot, data, bytes );

exit:
    mbedtls_free( data );
    return( status );
}

psa_status_t psa_key_derivation_output_key( const psa_key_attributes_t *attributes,
                                       psa_key_derivation_operation_t *operation,
                                       psa_key_handle_t *handle )
{
    psa_status_t status;
    psa_key_slot_t *slot = NULL;
    psa_se_drv_table_entry_t *driver = NULL;

    /* Reject any attempt to create a zero-length key so that we don't
     * risk tripping up later, e.g. on a malloc(0) that returns NULL. */
    if( psa_get_key_bits( attributes ) == 0 )
        return( PSA_ERROR_INVALID_ARGUMENT );

    if( ! operation->can_output_key )
        return( PSA_ERROR_NOT_PERMITTED );

    status = psa_start_key_creation( PSA_KEY_CREATION_DERIVE,
                                     attributes, handle, &slot, &driver );
#if defined(MBEDTLS_PSA_CRYPTO_SE_C)
    if( driver != NULL )
    {
        /* Deriving a key in a secure element is not implemented yet. */
        status = PSA_ERROR_NOT_SUPPORTED;
    }
#endif /* MBEDTLS_PSA_CRYPTO_SE_C */
    if( status == PSA_SUCCESS )
    {
        status = psa_generate_derived_key_internal( slot,
                                                    attributes->core.bits,
                                                    operation );
    }
    if( status == PSA_SUCCESS )
        status = psa_finish_key_creation( slot, driver );
    if( status != PSA_SUCCESS )
    {
        psa_fail_key_creation( slot, driver );
        *handle = 0;
    }
    return( status );
}



/****************************************************************/
/* Key derivation */
/****************************************************************/

static psa_status_t psa_key_derivation_setup_kdf(
    psa_key_derivation_operation_t *operation,
    psa_algorithm_t kdf_alg )
{
    /* Make sure that operation->ctx is properly zero-initialised. (Macro
     * initialisers for this union leave some bytes unspecified.) */
    memset( &operation->ctx, 0, sizeof( operation->ctx ) );

    /* Make sure that kdf_alg is a supported key derivation algorithm. */
#if defined(MBEDTLS_MD_C)
    if( PSA_ALG_IS_HKDF( kdf_alg ) ||
        PSA_ALG_IS_TLS12_PRF( kdf_alg ) ||
        PSA_ALG_IS_TLS12_PSK_TO_MS( kdf_alg ) )
    {
        psa_algorithm_t hash_alg = PSA_ALG_HKDF_GET_HASH( kdf_alg );
        size_t hash_size = PSA_HASH_SIZE( hash_alg );
        if( hash_size == 0 )
            return( PSA_ERROR_NOT_SUPPORTED );
        if( ( PSA_ALG_IS_TLS12_PRF( kdf_alg ) ||
              PSA_ALG_IS_TLS12_PSK_TO_MS( kdf_alg ) ) &&
            ! ( hash_alg == PSA_ALG_SHA_256 || hash_alg == PSA_ALG_SHA_384 ) )
        {
            return( PSA_ERROR_NOT_SUPPORTED );
        }
        operation->capacity = 255 * hash_size;
        return( PSA_SUCCESS );
    }
#endif /* MBEDTLS_MD_C */
    else
        return( PSA_ERROR_NOT_SUPPORTED );
}

psa_status_t psa_key_derivation_setup( psa_key_derivation_operation_t *operation,
                                       psa_algorithm_t alg )
{
    psa_status_t status;

    if( operation->alg != 0 )
        return( PSA_ERROR_BAD_STATE );

    if( PSA_ALG_IS_RAW_KEY_AGREEMENT( alg ) )
        return( PSA_ERROR_INVALID_ARGUMENT );
    else if( PSA_ALG_IS_KEY_AGREEMENT( alg ) )
    {
        psa_algorithm_t kdf_alg = PSA_ALG_KEY_AGREEMENT_GET_KDF( alg );
        status = psa_key_derivation_setup_kdf( operation, kdf_alg );
    }
    else if( PSA_ALG_IS_KEY_DERIVATION( alg ) )
    {
        status = psa_key_derivation_setup_kdf( operation, alg );
    }
    else
        return( PSA_ERROR_INVALID_ARGUMENT );

    if( status == PSA_SUCCESS )
        operation->alg = alg;
    return( status );
}

#if defined(MBEDTLS_MD_C)
static psa_status_t psa_hkdf_input( psa_hkdf_key_derivation_t *hkdf,
                                    psa_algorithm_t hash_alg,
                                    psa_key_derivation_step_t step,
                                    const uint8_t *data,
                                    size_t data_length )
{
    psa_status_t status;
    switch( step )
    {
        case PSA_KEY_DERIVATION_INPUT_SALT:
            if( hkdf->state != HKDF_STATE_INIT )
                return( PSA_ERROR_BAD_STATE );
            status = psa_hmac_setup_internal( &hkdf->hmac,
                                              data, data_length,
                                              hash_alg );
            if( status != PSA_SUCCESS )
                return( status );
            hkdf->state = HKDF_STATE_STARTED;
            return( PSA_SUCCESS );
        case PSA_KEY_DERIVATION_INPUT_SECRET:
            /* If no salt was provided, use an empty salt. */
            if( hkdf->state == HKDF_STATE_INIT )
            {
                status = psa_hmac_setup_internal( &hkdf->hmac,
                                                  NULL, 0,
                                                  hash_alg );
                if( status != PSA_SUCCESS )
                    return( status );
                hkdf->state = HKDF_STATE_STARTED;
            }
            if( hkdf->state != HKDF_STATE_STARTED )
                return( PSA_ERROR_BAD_STATE );
            status = psa_hash_update( &hkdf->hmac.hash_ctx,
                                      data, data_length );
            if( status != PSA_SUCCESS )
                return( status );
            status = psa_hmac_finish_internal( &hkdf->hmac,
                                               hkdf->prk,
                                               sizeof( hkdf->prk ) );
            if( status != PSA_SUCCESS )
                return( status );
            hkdf->offset_in_block = PSA_HASH_SIZE( hash_alg );
            hkdf->block_number = 0;
            hkdf->state = HKDF_STATE_KEYED;
            return( PSA_SUCCESS );
        case PSA_KEY_DERIVATION_INPUT_INFO:
            if( hkdf->state == HKDF_STATE_OUTPUT )
                return( PSA_ERROR_BAD_STATE );
            if( hkdf->info_set )
                return( PSA_ERROR_BAD_STATE );
            hkdf->info_length = data_length;
            if( data_length != 0 )
            {
                hkdf->info = mbedtls_calloc( 1, data_length );
                if( hkdf->info == NULL )
                    return( PSA_ERROR_INSUFFICIENT_MEMORY );
                memcpy( hkdf->info, data, data_length );
            }
            hkdf->info_set = 1;
            return( PSA_SUCCESS );
        default:
            return( PSA_ERROR_INVALID_ARGUMENT );
    }
}

static psa_status_t psa_tls12_prf_set_seed( psa_tls12_prf_key_derivation_t *prf,
                                            const uint8_t *data,
                                            size_t data_length )
{
    if( prf->state != TLS12_PRF_STATE_INIT )
        return( PSA_ERROR_BAD_STATE );

    if( data_length != 0 )
    {
        prf->seed = mbedtls_calloc( 1, data_length );
        if( prf->seed == NULL )
            return( PSA_ERROR_INSUFFICIENT_MEMORY );

        memcpy( prf->seed, data, data_length );
        prf->seed_length = data_length;
    }

    prf->state = TLS12_PRF_STATE_SEED_SET;

    return( PSA_SUCCESS );
}

static psa_status_t psa_tls12_prf_set_key( psa_tls12_prf_key_derivation_t *prf,
                                           psa_algorithm_t hash_alg,
                                           const uint8_t *data,
                                           size_t data_length )
{
    psa_status_t status;
    if( prf->state != TLS12_PRF_STATE_SEED_SET )
        return( PSA_ERROR_BAD_STATE );

    status = psa_hmac_setup_internal( &prf->hmac, data, data_length, hash_alg );
    if( status != PSA_SUCCESS )
        return( status );

    prf->state = TLS12_PRF_STATE_KEY_SET;

    return( PSA_SUCCESS );
}

static psa_status_t psa_tls12_prf_psk_to_ms_set_key(
    psa_tls12_prf_key_derivation_t *prf,
    psa_algorithm_t hash_alg,
    const uint8_t *data,
    size_t data_length )
{
    psa_status_t status;
    uint8_t pms[ 4 + 2 * PSA_ALG_TLS12_PSK_TO_MS_MAX_PSK_LEN ];
    uint8_t *cur = pms;

    if( data_length > PSA_ALG_TLS12_PSK_TO_MS_MAX_PSK_LEN )
        return( PSA_ERROR_INVALID_ARGUMENT );

    /* Quoting RFC 4279, Section 2:
     *
     * The premaster secret is formed as follows: if the PSK is N octets
     * long, concatenate a uint16 with the value N, N zero octets, a second
     * uint16 with the value N, and the PSK itself.
     */

    *cur++ = ( data_length >> 8 ) & 0xff;
    *cur++ = ( data_length >> 0 ) & 0xff;
    memset( cur, 0, data_length );
    cur += data_length;
    *cur++ = pms[0];
    *cur++ = pms[1];
    memcpy( cur, data, data_length );
    cur += data_length;

    status = psa_tls12_prf_set_key( prf, hash_alg, pms, cur - pms );

    mbedtls_platform_zeroize( pms, sizeof( pms ) );
    return( status );
}

static psa_status_t psa_tls12_prf_set_label( psa_tls12_prf_key_derivation_t *prf,
                                             const uint8_t *data,
                                             size_t data_length )
{
    if( prf->state != TLS12_PRF_STATE_KEY_SET )
        return( PSA_ERROR_BAD_STATE );

    if( data_length != 0 )
    {
        prf->label = mbedtls_calloc( 1, data_length );
        if( prf->label == NULL )
            return( PSA_ERROR_INSUFFICIENT_MEMORY );

        memcpy( prf->label, data, data_length );
        prf->label_length = data_length;
    }

    prf->state = TLS12_PRF_STATE_LABEL_SET;

    return( PSA_SUCCESS );
}

static psa_status_t psa_tls12_prf_input( psa_tls12_prf_key_derivation_t *prf,
                                         psa_algorithm_t hash_alg,
                                         psa_key_derivation_step_t step,
                                         const uint8_t *data,
                                         size_t data_length )
{
    switch( step )
    {
        case PSA_KEY_DERIVATION_INPUT_SEED:
            return( psa_tls12_prf_set_seed( prf, data, data_length ) );
        case PSA_KEY_DERIVATION_INPUT_SECRET:
            return( psa_tls12_prf_set_key( prf, hash_alg, data, data_length ) );
        case PSA_KEY_DERIVATION_INPUT_LABEL:
            return( psa_tls12_prf_set_label( prf, data, data_length ) );
        default:
            return( PSA_ERROR_INVALID_ARGUMENT );
    }
}

static psa_status_t psa_tls12_prf_psk_to_ms_input(
    psa_tls12_prf_key_derivation_t *prf,
    psa_algorithm_t hash_alg,
    psa_key_derivation_step_t step,
    const uint8_t *data,
    size_t data_length )
{
    if( step == PSA_KEY_DERIVATION_INPUT_SECRET )
    {
        return( psa_tls12_prf_psk_to_ms_set_key( prf, hash_alg,
                                                 data, data_length ) );
    }

    return( psa_tls12_prf_input( prf, hash_alg, step, data, data_length ) );
}
#endif /* MBEDTLS_MD_C */

/** Check whether the given key type is acceptable for the given
 * input step of a key derivation.
 *
 * Secret inputs must have the type #PSA_KEY_TYPE_DERIVE.
 * Non-secret inputs must have the type #PSA_KEY_TYPE_RAW_DATA.
 * Both secret and non-secret inputs can alternatively have the type
 * #PSA_KEY_TYPE_NONE, which is never the type of a key object, meaning
 * that the input was passed as a buffer rather than via a key object.
 */
static int psa_key_derivation_check_input_type(
    psa_key_derivation_step_t step,
    psa_key_type_t key_type )
{
    switch( step )
    {
        case PSA_KEY_DERIVATION_INPUT_SECRET:
            if( key_type == PSA_KEY_TYPE_DERIVE )
                return( PSA_SUCCESS );
            if( key_type == PSA_KEY_TYPE_NONE )
                return( PSA_SUCCESS );
            break;
        case PSA_KEY_DERIVATION_INPUT_LABEL:
        case PSA_KEY_DERIVATION_INPUT_SALT:
        case PSA_KEY_DERIVATION_INPUT_INFO:
        case PSA_KEY_DERIVATION_INPUT_SEED:
            if( key_type == PSA_KEY_TYPE_RAW_DATA )
                return( PSA_SUCCESS );
            if( key_type == PSA_KEY_TYPE_NONE )
                return( PSA_SUCCESS );
            break;
    }
    return( PSA_ERROR_INVALID_ARGUMENT );
}

static psa_status_t psa_key_derivation_input_internal(
    psa_key_derivation_operation_t *operation,
    psa_key_derivation_step_t step,
    psa_key_type_t key_type,
    const uint8_t *data,
    size_t data_length )
{
    psa_status_t status;
    psa_algorithm_t kdf_alg = psa_key_derivation_get_kdf_alg( operation );

    status = psa_key_derivation_check_input_type( step, key_type );
    if( status != PSA_SUCCESS )
        goto exit;

#if defined(MBEDTLS_MD_C)
    if( PSA_ALG_IS_HKDF( kdf_alg ) )
    {
        status = psa_hkdf_input( &operation->ctx.hkdf,
                                 PSA_ALG_HKDF_GET_HASH( kdf_alg ),
                                 step, data, data_length );
    }
    else if( PSA_ALG_IS_TLS12_PRF( kdf_alg ) )
    {
        status = psa_tls12_prf_input( &operation->ctx.tls12_prf,
                                      PSA_ALG_HKDF_GET_HASH( kdf_alg ),
                                      step, data, data_length );
    }
    else if( PSA_ALG_IS_TLS12_PSK_TO_MS( kdf_alg ) )
    {
        status = psa_tls12_prf_psk_to_ms_input( &operation->ctx.tls12_prf,
                                                PSA_ALG_HKDF_GET_HASH( kdf_alg ),
                                                step, data, data_length );
    }
    else
#endif /* MBEDTLS_MD_C */
    {
        /* This can't happen unless the operation object was not initialized */
        return( PSA_ERROR_BAD_STATE );
    }

exit:
    if( status != PSA_SUCCESS )
        psa_key_derivation_abort( operation );
    return( status );
}

psa_status_t psa_key_derivation_input_bytes(
    psa_key_derivation_operation_t *operation,
    psa_key_derivation_step_t step,
    const uint8_t *data,
    size_t data_length )
{
    return( psa_key_derivation_input_internal( operation, step,
                                               PSA_KEY_TYPE_NONE,
                                               data, data_length ) );
}

psa_status_t psa_key_derivation_input_key(
    psa_key_derivation_operation_t *operation,
    psa_key_derivation_step_t step,
    psa_key_handle_t handle )
{
    psa_key_slot_t *slot;
    psa_status_t status;

    status = psa_get_transparent_key( handle, &slot,
                                      PSA_KEY_USAGE_DERIVE,
                                      operation->alg );
    if( status != PSA_SUCCESS )
    {
        psa_key_derivation_abort( operation );
        return( status );
    }

    /* Passing a key object as a SECRET input unlocks the permission
     * to output to a key object. */
    if( step == PSA_KEY_DERIVATION_INPUT_SECRET )
        operation->can_output_key = 1;

    return( psa_key_derivation_input_internal( operation,
                                               step, slot->attr.type,
                                               slot->data.key.data,
                                               slot->data.key.bytes ) );
}



/****************************************************************/
/* Key agreement */
/****************************************************************/

#if defined(MBEDTLS_ECDH_C)
static psa_status_t psa_key_agreement_ecdh( const uint8_t *peer_key,
                                            size_t peer_key_length,
                                            const mbedtls_ecp_keypair *our_key,
                                            uint8_t *shared_secret,
                                            size_t shared_secret_size,
                                            size_t *shared_secret_length )
{
    mbedtls_ecp_keypair *their_key = NULL;
    mbedtls_ecdh_context ecdh;
    psa_status_t status;
    size_t bits = 0;
    psa_ecc_family_t curve = mbedtls_ecc_group_to_psa( our_key->grp.id, &bits );
    mbedtls_ecdh_init( &ecdh );

    status = psa_load_ecp_representation( PSA_KEY_TYPE_ECC_PUBLIC_KEY(curve),
                                          peer_key,
                                          peer_key_length,
                                          &their_key );
    if( status != PSA_SUCCESS )
        goto exit;

    status = mbedtls_to_psa_error(
        mbedtls_ecdh_get_params( &ecdh, their_key, MBEDTLS_ECDH_THEIRS ) );
    if( status != PSA_SUCCESS )
        goto exit;
    status = mbedtls_to_psa_error(
        mbedtls_ecdh_get_params( &ecdh, our_key, MBEDTLS_ECDH_OURS ) );
    if( status != PSA_SUCCESS )
        goto exit;

    status = mbedtls_to_psa_error(
        mbedtls_ecdh_calc_secret( &ecdh,
                                  shared_secret_length,
                                  shared_secret, shared_secret_size,
                                  mbedtls_ctr_drbg_random,
                                  &global_data.ctr_drbg ) );
    if( status != PSA_SUCCESS )
        goto exit;
    if( PSA_BITS_TO_BYTES( bits ) != *shared_secret_length )
        status = PSA_ERROR_CORRUPTION_DETECTED;

exit:
    if( status != PSA_SUCCESS )
        mbedtls_platform_zeroize( shared_secret, shared_secret_size );
    mbedtls_ecdh_free( &ecdh );
    mbedtls_ecp_keypair_free( their_key );
    mbedtls_free( their_key );

    return( status );
}
#endif /* MBEDTLS_ECDH_C */

#define PSA_KEY_AGREEMENT_MAX_SHARED_SECRET_SIZE MBEDTLS_ECP_MAX_BYTES

static psa_status_t psa_key_agreement_raw_internal( psa_algorithm_t alg,
                                                    psa_key_slot_t *private_key,
                                                    const uint8_t *peer_key,
                                                    size_t peer_key_length,
                                                    uint8_t *shared_secret,
                                                    size_t shared_secret_size,
                                                    size_t *shared_secret_length )
{
    switch( alg )
    {
#if defined(MBEDTLS_ECDH_C)
        case PSA_ALG_ECDH:
            if( ! PSA_KEY_TYPE_IS_ECC_KEY_PAIR( private_key->attr.type ) )
                return( PSA_ERROR_INVALID_ARGUMENT );
            mbedtls_ecp_keypair *ecp = NULL;
            psa_status_t status = psa_load_ecp_representation(
                                    private_key->attr.type,
                                    private_key->data.key.data,
                                    private_key->data.key.bytes,
                                    &ecp );
            if( status != PSA_SUCCESS )
                return( status );
            status = psa_key_agreement_ecdh( peer_key, peer_key_length,
                                             ecp,
                                             shared_secret, shared_secret_size,
                                             shared_secret_length );
            mbedtls_ecp_keypair_free( ecp );
            mbedtls_free( ecp );
            return( status );
#endif /* MBEDTLS_ECDH_C */
        default:
            (void) private_key;
            (void) peer_key;
            (void) peer_key_length;
            (void) shared_secret;
            (void) shared_secret_size;
            (void) shared_secret_length;
            return( PSA_ERROR_NOT_SUPPORTED );
    }
}

/* Note that if this function fails, you must call psa_key_derivation_abort()
 * to potentially free embedded data structures and wipe confidential data.
 */
static psa_status_t psa_key_agreement_internal( psa_key_derivation_operation_t *operation,
                                                psa_key_derivation_step_t step,
                                                psa_key_slot_t *private_key,
                                                const uint8_t *peer_key,
                                                size_t peer_key_length )
{
    psa_status_t status;
    uint8_t shared_secret[PSA_KEY_AGREEMENT_MAX_SHARED_SECRET_SIZE];
    size_t shared_secret_length = 0;
    psa_algorithm_t ka_alg = PSA_ALG_KEY_AGREEMENT_GET_BASE( operation->alg );

    /* Step 1: run the secret agreement algorithm to generate the shared
     * secret. */
    status = psa_key_agreement_raw_internal( ka_alg,
                                             private_key,
                                             peer_key, peer_key_length,
                                             shared_secret,
                                             sizeof( shared_secret ),
                                             &shared_secret_length );
    if( status != PSA_SUCCESS )
        goto exit;

    /* Step 2: set up the key derivation to generate key material from
     * the shared secret. A shared secret is permitted wherever a key
     * of type DERIVE is permitted. */
    status = psa_key_derivation_input_internal( operation, step,
                                                PSA_KEY_TYPE_DERIVE,
                                                shared_secret,
                                                shared_secret_length );

exit:
    mbedtls_platform_zeroize( shared_secret, shared_secret_length );
    return( status );
}

psa_status_t psa_key_derivation_key_agreement( psa_key_derivation_operation_t *operation,
                                               psa_key_derivation_step_t step,
                                               psa_key_handle_t private_key,
                                               const uint8_t *peer_key,
                                               size_t peer_key_length )
{
    psa_key_slot_t *slot;
    psa_status_t status;
    if( ! PSA_ALG_IS_KEY_AGREEMENT( operation->alg ) )
        return( PSA_ERROR_INVALID_ARGUMENT );
    status = psa_get_transparent_key( private_key, &slot,
                                      PSA_KEY_USAGE_DERIVE, operation->alg );
    if( status != PSA_SUCCESS )
        return( status );
    status = psa_key_agreement_internal( operation, step,
                                         slot,
                                         peer_key, peer_key_length );
    if( status != PSA_SUCCESS )
        psa_key_derivation_abort( operation );
    return( status );
}

psa_status_t psa_raw_key_agreement( psa_algorithm_t alg,
                                    psa_key_handle_t private_key,
                                    const uint8_t *peer_key,
                                    size_t peer_key_length,
                                    uint8_t *output,
                                    size_t output_size,
                                    size_t *output_length )
{
    psa_key_slot_t *slot;
    psa_status_t status;

    if( ! PSA_ALG_IS_KEY_AGREEMENT( alg ) )
    {
        status = PSA_ERROR_INVALID_ARGUMENT;
        goto exit;
    }
    status = psa_get_transparent_key( private_key, &slot,
                                      PSA_KEY_USAGE_DERIVE, alg );
    if( status != PSA_SUCCESS )
        goto exit;

    status = psa_key_agreement_raw_internal( alg, slot,
                                             peer_key, peer_key_length,
                                             output, output_size,
                                             output_length );

exit:
    if( status != PSA_SUCCESS )
    {
        /* If an error happens and is not handled properly, the output
         * may be used as a key to protect sensitive data. Arrange for such
         * a key to be random, which is likely to result in decryption or
         * verification errors. This is better than filling the buffer with
         * some constant data such as zeros, which would result in the data
         * being protected with a reproducible, easily knowable key.
         */
        psa_generate_random( output, output_size );
        *output_length = output_size;
    }
    return( status );
}


/****************************************************************/
/* Random generation */
/****************************************************************/

psa_status_t psa_generate_random( uint8_t *output,
                                  size_t output_size )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    GUARD_MODULE_INITIALIZED;

    while( output_size > MBEDTLS_CTR_DRBG_MAX_REQUEST )
    {
        ret = mbedtls_ctr_drbg_random( &global_data.ctr_drbg,
                                       output,
                                       MBEDTLS_CTR_DRBG_MAX_REQUEST );
        if( ret != 0 )
            return( mbedtls_to_psa_error( ret ) );
        output += MBEDTLS_CTR_DRBG_MAX_REQUEST;
        output_size -= MBEDTLS_CTR_DRBG_MAX_REQUEST;
    }

    ret = mbedtls_ctr_drbg_random( &global_data.ctr_drbg, output, output_size );
    return( mbedtls_to_psa_error( ret ) );
}

#if defined(MBEDTLS_PSA_INJECT_ENTROPY)
#include "mbedtls/entropy_poll.h"

psa_status_t mbedtls_psa_inject_entropy( const uint8_t *seed,
                                         size_t seed_size )
{
    if( global_data.initialized )
        return( PSA_ERROR_NOT_PERMITTED );

    if( ( ( seed_size < MBEDTLS_ENTROPY_MIN_PLATFORM ) ||
          ( seed_size < MBEDTLS_ENTROPY_BLOCK_SIZE ) ) ||
          ( seed_size > MBEDTLS_ENTROPY_MAX_SEED_SIZE ) )
            return( PSA_ERROR_INVALID_ARGUMENT );

    return( mbedtls_psa_storage_inject_entropy( seed, seed_size ) );
}
#endif /* MBEDTLS_PSA_INJECT_ENTROPY */

#if defined(MBEDTLS_RSA_C) && defined(MBEDTLS_GENPRIME)
static psa_status_t psa_read_rsa_exponent( const uint8_t *domain_parameters,
                                           size_t domain_parameters_size,
                                           int *exponent )
{
    size_t i;
    uint32_t acc = 0;

    if( domain_parameters_size == 0 )
    {
        *exponent = 65537;
        return( PSA_SUCCESS );
    }

    /* Mbed TLS encodes the public exponent as an int. For simplicity, only
     * support values that fit in a 32-bit integer, which is larger than
     * int on just about every platform anyway. */
    if( domain_parameters_size > sizeof( acc ) )
        return( PSA_ERROR_NOT_SUPPORTED );
    for( i = 0; i < domain_parameters_size; i++ )
        acc = ( acc << 8 ) | domain_parameters[i];
    if( acc > INT_MAX )
        return( PSA_ERROR_NOT_SUPPORTED );
    *exponent = acc;
    return( PSA_SUCCESS );
}
#endif /* MBEDTLS_RSA_C && MBEDTLS_GENPRIME */

static psa_status_t psa_generate_key_internal(
    psa_key_slot_t *slot, size_t bits,
    const uint8_t *domain_parameters, size_t domain_parameters_size )
{
    psa_key_type_t type = slot->attr.type;

    if( domain_parameters == NULL && domain_parameters_size != 0 )
        return( PSA_ERROR_INVALID_ARGUMENT );

    if( key_type_is_raw_bytes( type ) )
    {
        psa_status_t status;

        status = validate_unstructured_key_bit_size( slot->attr.type, bits );
        if( status != PSA_SUCCESS )
            return( status );

        /* Allocate memory for the key */
        status = psa_allocate_buffer_to_slot( slot, PSA_BITS_TO_BYTES( bits ) );
        if( status != PSA_SUCCESS )
            return( status );

        status = psa_generate_random( slot->data.key.data,
                                      slot->data.key.bytes );
        if( status != PSA_SUCCESS )
            return( status );

        slot->attr.bits = (psa_key_bits_t) bits;
#if defined(MBEDTLS_DES_C)
        if( type == PSA_KEY_TYPE_DES )
            psa_des_set_key_parity( slot->data.key.data,
                                    slot->data.key.bytes );
#endif /* MBEDTLS_DES_C */
    }
    else

#if defined(MBEDTLS_RSA_C) && defined(MBEDTLS_GENPRIME)
    if ( type == PSA_KEY_TYPE_RSA_KEY_PAIR )
    {
        mbedtls_rsa_context rsa;
        int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
        int exponent;
        psa_status_t status;
        if( bits > PSA_VENDOR_RSA_MAX_KEY_BITS )
            return( PSA_ERROR_NOT_SUPPORTED );
        /* Accept only byte-aligned keys, for the same reasons as
         * in psa_import_rsa_key(). */
        if( bits % 8 != 0 )
            return( PSA_ERROR_NOT_SUPPORTED );
        status = psa_read_rsa_exponent( domain_parameters,
                                        domain_parameters_size,
                                        &exponent );
        if( status != PSA_SUCCESS )
            return( status );
        mbedtls_rsa_init( &rsa, MBEDTLS_RSA_PKCS_V15, MBEDTLS_MD_NONE );
        ret = mbedtls_rsa_gen_key( &rsa,
                                   mbedtls_ctr_drbg_random,
                                   &global_data.ctr_drbg,
                                   (unsigned int) bits,
                                   exponent );
        if( ret != 0 )
            return( mbedtls_to_psa_error( ret ) );

        /* Make sure to always have an export representation available */
        size_t bytes = PSA_KEY_EXPORT_RSA_KEY_PAIR_MAX_SIZE( bits );

        status = psa_allocate_buffer_to_slot( slot, bytes );
        if( status != PSA_SUCCESS )
        {
            mbedtls_rsa_free( &rsa );
            return( status );
        }

        status = psa_export_rsa_key( type,
                                     &rsa,
                                     slot->data.key.data,
                                     bytes,
                                     &slot->data.key.bytes );
        mbedtls_rsa_free( &rsa );
        if( status != PSA_SUCCESS )
            psa_remove_key_data_from_memory( slot );
        return( status );
    }
    else
#endif /* MBEDTLS_RSA_C && MBEDTLS_GENPRIME */

#if defined(MBEDTLS_ECP_C)
    if ( PSA_KEY_TYPE_IS_ECC( type ) && PSA_KEY_TYPE_IS_KEY_PAIR( type ) )
    {
        psa_ecc_family_t curve = PSA_KEY_TYPE_ECC_GET_FAMILY( type );
        mbedtls_ecp_group_id grp_id =
            mbedtls_ecc_group_of_psa( curve, PSA_BITS_TO_BYTES( bits ) );
        const mbedtls_ecp_curve_info *curve_info =
            mbedtls_ecp_curve_info_from_grp_id( grp_id );
        mbedtls_ecp_keypair ecp;
        int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
        if( domain_parameters_size != 0 )
            return( PSA_ERROR_NOT_SUPPORTED );
        if( grp_id == MBEDTLS_ECP_DP_NONE || curve_info == NULL )
            return( PSA_ERROR_NOT_SUPPORTED );
        if( curve_info->bit_size != bits )
            return( PSA_ERROR_INVALID_ARGUMENT );
        mbedtls_ecp_keypair_init( &ecp );
        ret = mbedtls_ecp_gen_key( grp_id, &ecp,
                                   mbedtls_ctr_drbg_random,
                                   &global_data.ctr_drbg );
        if( ret != 0 )
        {
            mbedtls_ecp_keypair_free( &ecp );
            return( mbedtls_to_psa_error( ret ) );
        }


        /* Make sure to always have an export representation available */
        size_t bytes = PSA_BITS_TO_BYTES( bits );
        psa_status_t status = psa_allocate_buffer_to_slot( slot, bytes );
        if( status != PSA_SUCCESS )
        {
            mbedtls_ecp_keypair_free( &ecp );
            return( status );
        }

        status = mbedtls_to_psa_error(
            mbedtls_ecp_write_key( &ecp, slot->data.key.data, bytes ) );

        mbedtls_ecp_keypair_free( &ecp );
        if( status != PSA_SUCCESS ) {
            memset( slot->data.key.data, 0, bytes );
            psa_remove_key_data_from_memory( slot );
        }
        return( status );
    }
    else
#endif /* MBEDTLS_ECP_C */
    {
        return( PSA_ERROR_NOT_SUPPORTED );
    }

    return( PSA_SUCCESS );
}

psa_status_t psa_generate_key( const psa_key_attributes_t *attributes,
                               psa_key_handle_t *handle )
{
    psa_status_t status;
    psa_key_slot_t *slot = NULL;
    psa_se_drv_table_entry_t *driver = NULL;

    /* Reject any attempt to create a zero-length key so that we don't
     * risk tripping up later, e.g. on a malloc(0) that returns NULL. */
    if( psa_get_key_bits( attributes ) == 0 )
        return( PSA_ERROR_INVALID_ARGUMENT );

    status = psa_start_key_creation( PSA_KEY_CREATION_GENERATE,
                                     attributes, handle, &slot, &driver );
    if( status != PSA_SUCCESS )
        goto exit;

#if defined(MBEDTLS_PSA_CRYPTO_SE_C)
    if( driver != NULL )
    {
        const psa_drv_se_t *drv = psa_get_se_driver_methods( driver );
        size_t pubkey_length = 0; /* We don't support this feature yet */
        if( drv->key_management == NULL ||
            drv->key_management->p_generate == NULL )
        {
            status = PSA_ERROR_NOT_SUPPORTED;
            goto exit;
        }
        status = drv->key_management->p_generate(
            psa_get_se_driver_context( driver ),
            slot->data.se.slot_number, attributes,
            NULL, 0, &pubkey_length );
    }
    else
#endif /* MBEDTLS_PSA_CRYPTO_SE_C */
    {
        status = psa_generate_key_internal(
            slot, attributes->core.bits,
            attributes->domain_parameters, attributes->domain_parameters_size );
    }

exit:
    if( status == PSA_SUCCESS )
        status = psa_finish_key_creation( slot, driver );
    if( status != PSA_SUCCESS )
    {
        psa_fail_key_creation( slot, driver );
        *handle = 0;
    }
    return( status );
}



/****************************************************************/
/* Module setup */
/****************************************************************/

psa_status_t mbedtls_psa_crypto_configure_entropy_sources(
    void (* entropy_init )( mbedtls_entropy_context *ctx ),
    void (* entropy_free )( mbedtls_entropy_context *ctx ) )
{
    if( global_data.rng_state != RNG_NOT_INITIALIZED )
        return( PSA_ERROR_BAD_STATE );
    global_data.entropy_init = entropy_init;
    global_data.entropy_free = entropy_free;
    return( PSA_SUCCESS );
}

void mbedtls_psa_crypto_free( void )
{
    psa_wipe_all_key_slots( );
    if( global_data.rng_state != RNG_NOT_INITIALIZED )
    {
        mbedtls_ctr_drbg_free( &global_data.ctr_drbg );
        global_data.entropy_free( &global_data.entropy );
    }
    /* Wipe all remaining data, including configuration.
     * In particular, this sets all state indicator to the value
     * indicating "uninitialized". */
    mbedtls_platform_zeroize( &global_data, sizeof( global_data ) );
#if defined(MBEDTLS_PSA_CRYPTO_SE_C)
    /* Unregister all secure element drivers, so that we restart from
     * a pristine state. */
    psa_unregister_all_se_drivers( );
#endif /* MBEDTLS_PSA_CRYPTO_SE_C */
}

#if defined(PSA_CRYPTO_STORAGE_HAS_TRANSACTIONS)
/** Recover a transaction that was interrupted by a power failure.
 *
 * This function is called during initialization, before psa_crypto_init()
 * returns. If this function returns a failure status, the initialization
 * fails.
 */
static psa_status_t psa_crypto_recover_transaction(
    const psa_crypto_transaction_t *transaction )
{
    switch( transaction->unknown.type )
    {
        case PSA_CRYPTO_TRANSACTION_CREATE_KEY:
        case PSA_CRYPTO_TRANSACTION_DESTROY_KEY:
            /* TODO - fall through to the failure case until this
             * is implemented.
             * https://github.com/ARMmbed/mbed-crypto/issues/218
             */
        default:
            /* We found an unsupported transaction in the storage.
             * We don't know what state the storage is in. Give up. */
            return( PSA_ERROR_STORAGE_FAILURE );
    }
}
#endif /* PSA_CRYPTO_STORAGE_HAS_TRANSACTIONS */

psa_status_t psa_crypto_init( void )
{
    psa_status_t status;
    const unsigned char drbg_seed[] = "PSA";

    /* Double initialization is explicitly allowed. */
    if( global_data.initialized != 0 )
        return( PSA_SUCCESS );

    /* Set default configuration if
     * mbedtls_psa_crypto_configure_entropy_sources() hasn't been called. */
    if( global_data.entropy_init == NULL )
        global_data.entropy_init = mbedtls_entropy_init;
    if( global_data.entropy_free == NULL )
        global_data.entropy_free = mbedtls_entropy_free;

    /* Initialize the random generator. */
    global_data.entropy_init( &global_data.entropy );
#if defined(MBEDTLS_PSA_INJECT_ENTROPY) && \
    defined(MBEDTLS_NO_DEFAULT_ENTROPY_SOURCES)
    /* The PSA entropy injection feature depends on using NV seed as an entropy
     * source. Add NV seed as an entropy source for PSA entropy injection. */
    mbedtls_entropy_add_source( &global_data.entropy,
                                mbedtls_nv_seed_poll, NULL,
                                MBEDTLS_ENTROPY_BLOCK_SIZE,
                                MBEDTLS_ENTROPY_SOURCE_STRONG );
#endif
    mbedtls_ctr_drbg_init( &global_data.ctr_drbg );
    global_data.rng_state = RNG_INITIALIZED;
    status = mbedtls_to_psa_error(
        mbedtls_ctr_drbg_seed( &global_data.ctr_drbg,
                               mbedtls_entropy_func,
                               &global_data.entropy,
                               drbg_seed, sizeof( drbg_seed ) - 1 ) );
    if( status != PSA_SUCCESS )
        goto exit;
    global_data.rng_state = RNG_SEEDED;

    status = psa_initialize_key_slots( );
    if( status != PSA_SUCCESS )
        goto exit;

#if defined(MBEDTLS_PSA_CRYPTO_SE_C)
    status = psa_init_all_se_drivers( );
    if( status != PSA_SUCCESS )
        goto exit;
#endif /* MBEDTLS_PSA_CRYPTO_SE_C */

#if defined(PSA_CRYPTO_STORAGE_HAS_TRANSACTIONS)
    status = psa_crypto_load_transaction( );
    if( status == PSA_SUCCESS )
    {
        status = psa_crypto_recover_transaction( &psa_crypto_transaction );
        if( status != PSA_SUCCESS )
            goto exit;
        status = psa_crypto_stop_transaction( );
    }
    else if( status == PSA_ERROR_DOES_NOT_EXIST )
    {
        /* There's no transaction to complete. It's all good. */
        status = PSA_SUCCESS;
    }
#endif /* PSA_CRYPTO_STORAGE_HAS_TRANSACTIONS */

    /* All done. */
    global_data.initialized = 1;

exit:
    if( status != PSA_SUCCESS )
        mbedtls_psa_crypto_free( );
    return( status );
}

#endif /* MBEDTLS_PSA_CRYPTO_C */
