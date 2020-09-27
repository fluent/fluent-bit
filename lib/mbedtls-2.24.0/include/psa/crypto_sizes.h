/**
 * \file psa/crypto_sizes.h
 *
 * \brief PSA cryptography module: Mbed TLS buffer size macros
 *
 * \note This file may not be included directly. Applications must
 * include psa/crypto.h.
 *
 * This file contains the definitions of macros that are useful to
 * compute buffer sizes. The signatures and semantics of these macros
 * are standardized, but the definitions are not, because they depend on
 * the available algorithms and, in some cases, on permitted tolerances
 * on buffer sizes.
 *
 * In implementations with isolation between the application and the
 * cryptography module, implementers should take care to ensure that
 * the definitions that are exposed to applications match what the
 * module implements.
 *
 * Macros that compute sizes whose values do not depend on the
 * implementation are in crypto.h.
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

#ifndef PSA_CRYPTO_SIZES_H
#define PSA_CRYPTO_SIZES_H

/* Include the Mbed TLS configuration file, the way Mbed TLS does it
 * in each of its header files. */
#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#define PSA_BITS_TO_BYTES(bits) (((bits) + 7) / 8)
#define PSA_BYTES_TO_BITS(bytes) ((bytes) * 8)

#define PSA_ROUND_UP_TO_MULTIPLE(block_size, length) \
    (((length) + (block_size) - 1) / (block_size) * (block_size))

/** The size of the output of psa_hash_finish(), in bytes.
 *
 * This is also the hash size that psa_hash_verify() expects.
 *
 * \param alg   A hash algorithm (\c PSA_ALG_XXX value such that
 *              #PSA_ALG_IS_HASH(\p alg) is true), or an HMAC algorithm
 *              (#PSA_ALG_HMAC(\c hash_alg) where \c hash_alg is a
 *              hash algorithm).
 *
 * \return The hash size for the specified hash algorithm.
 *         If the hash algorithm is not recognized, return 0.
 *         An implementation may return either 0 or the correct size
 *         for a hash algorithm that it recognizes, but does not support.
 */
#define PSA_HASH_SIZE(alg)                                      \
    (                                                           \
        PSA_ALG_HMAC_GET_HASH(alg) == PSA_ALG_MD2 ? 16 :            \
        PSA_ALG_HMAC_GET_HASH(alg) == PSA_ALG_MD4 ? 16 :            \
        PSA_ALG_HMAC_GET_HASH(alg) == PSA_ALG_MD5 ? 16 :            \
        PSA_ALG_HMAC_GET_HASH(alg) == PSA_ALG_RIPEMD160 ? 20 :      \
        PSA_ALG_HMAC_GET_HASH(alg) == PSA_ALG_SHA_1 ? 20 :          \
        PSA_ALG_HMAC_GET_HASH(alg) == PSA_ALG_SHA_224 ? 28 :        \
        PSA_ALG_HMAC_GET_HASH(alg) == PSA_ALG_SHA_256 ? 32 :        \
        PSA_ALG_HMAC_GET_HASH(alg) == PSA_ALG_SHA_384 ? 48 :        \
        PSA_ALG_HMAC_GET_HASH(alg) == PSA_ALG_SHA_512 ? 64 :        \
        PSA_ALG_HMAC_GET_HASH(alg) == PSA_ALG_SHA_512_224 ? 28 :    \
        PSA_ALG_HMAC_GET_HASH(alg) == PSA_ALG_SHA_512_256 ? 32 :    \
        PSA_ALG_HMAC_GET_HASH(alg) == PSA_ALG_SHA3_224 ? 28 :       \
        PSA_ALG_HMAC_GET_HASH(alg) == PSA_ALG_SHA3_256 ? 32 :       \
        PSA_ALG_HMAC_GET_HASH(alg) == PSA_ALG_SHA3_384 ? 48 :       \
        PSA_ALG_HMAC_GET_HASH(alg) == PSA_ALG_SHA3_512 ? 64 :       \
        0)

/** \def PSA_HASH_MAX_SIZE
 *
 * Maximum size of a hash.
 *
 * This macro must expand to a compile-time constant integer. This value
 * should be the maximum size of a hash supported by the implementation,
 * in bytes, and must be no smaller than this maximum.
 */
/* Note: for HMAC-SHA-3, the block size is 144 bytes for HMAC-SHA3-226,
 * 136 bytes for HMAC-SHA3-256, 104 bytes for SHA3-384, 72 bytes for
 * HMAC-SHA3-512. */
#if defined(MBEDTLS_SHA512_C)
#define PSA_HASH_MAX_SIZE 64
#define PSA_HMAC_MAX_HASH_BLOCK_SIZE 128
#else
#define PSA_HASH_MAX_SIZE 32
#define PSA_HMAC_MAX_HASH_BLOCK_SIZE 64
#endif

/** \def PSA_MAC_MAX_SIZE
 *
 * Maximum size of a MAC.
 *
 * This macro must expand to a compile-time constant integer. This value
 * should be the maximum size of a MAC supported by the implementation,
 * in bytes, and must be no smaller than this maximum.
 */
/* All non-HMAC MACs have a maximum size that's smaller than the
 * minimum possible value of PSA_HASH_MAX_SIZE in this implementation. */
/* Note that the encoding of truncated MAC algorithms limits this value
 * to 64 bytes.
 */
#define PSA_MAC_MAX_SIZE PSA_HASH_MAX_SIZE

/** The tag size for an AEAD algorithm, in bytes.
 *
 * \param alg                 An AEAD algorithm
 *                            (\c PSA_ALG_XXX value such that
 *                            #PSA_ALG_IS_AEAD(\p alg) is true).
 *
 * \return                    The tag size for the specified algorithm.
 *                            If the AEAD algorithm does not have an identified
 *                            tag that can be distinguished from the rest of
 *                            the ciphertext, return 0.
 *                            If the AEAD algorithm is not recognized, return 0.
 *                            An implementation may return either 0 or a
 *                            correct size for an AEAD algorithm that it
 *                            recognizes, but does not support.
 */
#define PSA_AEAD_TAG_LENGTH(alg)                                        \
    (PSA_ALG_IS_AEAD(alg) ?                                             \
     (((alg) & PSA_ALG_AEAD_TAG_LENGTH_MASK) >> PSA_AEAD_TAG_LENGTH_OFFSET) : \
     0)

/* The maximum size of an RSA key on this implementation, in bits.
 * This is a vendor-specific macro.
 *
 * Mbed TLS does not set a hard limit on the size of RSA keys: any key
 * whose parameters fit in a bignum is accepted. However large keys can
 * induce a large memory usage and long computation times. Unlike other
 * auxiliary macros in this file and in crypto.h, which reflect how the
 * library is configured, this macro defines how the library is
 * configured. This implementation refuses to import or generate an
 * RSA key whose size is larger than the value defined here.
 *
 * Note that an implementation may set different size limits for different
 * operations, and does not need to accept all key sizes up to the limit. */
#define PSA_VENDOR_RSA_MAX_KEY_BITS 4096

/* The maximum size of an ECC key on this implementation, in bits.
 * This is a vendor-specific macro. */
#if defined(MBEDTLS_ECP_DP_SECP521R1_ENABLED)
#define PSA_VENDOR_ECC_MAX_CURVE_BITS 521
#elif defined(MBEDTLS_ECP_DP_BP512R1_ENABLED)
#define PSA_VENDOR_ECC_MAX_CURVE_BITS 512
#elif defined(MBEDTLS_ECP_DP_CURVE448_ENABLED)
#define PSA_VENDOR_ECC_MAX_CURVE_BITS 448
#elif defined(MBEDTLS_ECP_DP_SECP384R1_ENABLED)
#define PSA_VENDOR_ECC_MAX_CURVE_BITS 384
#elif defined(MBEDTLS_ECP_DP_BP384R1_ENABLED)
#define PSA_VENDOR_ECC_MAX_CURVE_BITS 384
#elif defined(MBEDTLS_ECP_DP_SECP256R1_ENABLED)
#define PSA_VENDOR_ECC_MAX_CURVE_BITS 256
#elif defined(MBEDTLS_ECP_DP_SECP256K1_ENABLED)
#define PSA_VENDOR_ECC_MAX_CURVE_BITS 256
#elif defined(MBEDTLS_ECP_DP_BP256R1_ENABLED)
#define PSA_VENDOR_ECC_MAX_CURVE_BITS 256
#elif defined(MBEDTLS_ECP_DP_CURVE25519_ENABLED)
#define PSA_VENDOR_ECC_MAX_CURVE_BITS 255
#elif defined(MBEDTLS_ECP_DP_SECP224R1_ENABLED)
#define PSA_VENDOR_ECC_MAX_CURVE_BITS 224
#elif defined(MBEDTLS_ECP_DP_SECP224K1_ENABLED)
#define PSA_VENDOR_ECC_MAX_CURVE_BITS 224
#elif defined(MBEDTLS_ECP_DP_SECP192R1_ENABLED)
#define PSA_VENDOR_ECC_MAX_CURVE_BITS 192
#elif defined(MBEDTLS_ECP_DP_SECP192K1_ENABLED)
#define PSA_VENDOR_ECC_MAX_CURVE_BITS 192
#else
#define PSA_VENDOR_ECC_MAX_CURVE_BITS 0
#endif

/** \def PSA_ALG_TLS12_PSK_TO_MS_MAX_PSK_LEN
 *
 * This macro returns the maximum length of the PSK supported
 * by the TLS-1.2 PSK-to-MS key derivation.
 *
 * Quoting RFC 4279, Sect 5.3:
 * TLS implementations supporting these ciphersuites MUST support
 * arbitrary PSK identities up to 128 octets in length, and arbitrary
 * PSKs up to 64 octets in length.  Supporting longer identities and
 * keys is RECOMMENDED.
 *
 * Therefore, no implementation should define a value smaller than 64
 * for #PSA_ALG_TLS12_PSK_TO_MS_MAX_PSK_LEN.
 */
#define PSA_ALG_TLS12_PSK_TO_MS_MAX_PSK_LEN 128

/** The maximum size of a block cipher supported by the implementation. */
#define PSA_MAX_BLOCK_CIPHER_BLOCK_SIZE 16

/** The size of the output of psa_mac_sign_finish(), in bytes.
 *
 * This is also the MAC size that psa_mac_verify_finish() expects.
 *
 * \param key_type      The type of the MAC key.
 * \param key_bits      The size of the MAC key in bits.
 * \param alg           A MAC algorithm (\c PSA_ALG_XXX value such that
 *                      #PSA_ALG_IS_MAC(\p alg) is true).
 *
 * \return              The MAC size for the specified algorithm with
 *                      the specified key parameters.
 * \return              0 if the MAC algorithm is not recognized.
 * \return              Either 0 or the correct size for a MAC algorithm that
 *                      the implementation recognizes, but does not support.
 * \return              Unspecified if the key parameters are not consistent
 *                      with the algorithm.
 */
#define PSA_MAC_FINAL_SIZE(key_type, key_bits, alg)                     \
    ((alg) & PSA_ALG_MAC_TRUNCATION_MASK ? PSA_MAC_TRUNCATED_LENGTH(alg) : \
     PSA_ALG_IS_HMAC(alg) ? PSA_HASH_SIZE(PSA_ALG_HMAC_GET_HASH(alg)) : \
     PSA_ALG_IS_BLOCK_CIPHER_MAC(alg) ? PSA_BLOCK_CIPHER_BLOCK_SIZE(key_type) : \
     ((void)(key_type), (void)(key_bits), 0))

/** The maximum size of the output of psa_aead_encrypt(), in bytes.
 *
 * If the size of the ciphertext buffer is at least this large, it is
 * guaranteed that psa_aead_encrypt() will not fail due to an
 * insufficient buffer size. Depending on the algorithm, the actual size of
 * the ciphertext may be smaller.
 *
 * \param alg                 An AEAD algorithm
 *                            (\c PSA_ALG_XXX value such that
 *                            #PSA_ALG_IS_AEAD(\p alg) is true).
 * \param plaintext_length    Size of the plaintext in bytes.
 *
 * \return                    The AEAD ciphertext size for the specified
 *                            algorithm.
 *                            If the AEAD algorithm is not recognized, return 0.
 *                            An implementation may return either 0 or a
 *                            correct size for an AEAD algorithm that it
 *                            recognizes, but does not support.
 */
#define PSA_AEAD_ENCRYPT_OUTPUT_SIZE(alg, plaintext_length)       \
    (PSA_AEAD_TAG_LENGTH(alg) != 0 ?                              \
     (plaintext_length) + PSA_AEAD_TAG_LENGTH(alg) :              \
     0)

/** The maximum size of the output of psa_aead_decrypt(), in bytes.
 *
 * If the size of the plaintext buffer is at least this large, it is
 * guaranteed that psa_aead_decrypt() will not fail due to an
 * insufficient buffer size. Depending on the algorithm, the actual size of
 * the plaintext may be smaller.
 *
 * \param alg                 An AEAD algorithm
 *                            (\c PSA_ALG_XXX value such that
 *                            #PSA_ALG_IS_AEAD(\p alg) is true).
 * \param ciphertext_length   Size of the plaintext in bytes.
 *
 * \return                    The AEAD ciphertext size for the specified
 *                            algorithm.
 *                            If the AEAD algorithm is not recognized, return 0.
 *                            An implementation may return either 0 or a
 *                            correct size for an AEAD algorithm that it
 *                            recognizes, but does not support.
 */
#define PSA_AEAD_DECRYPT_OUTPUT_SIZE(alg, ciphertext_length)      \
    (PSA_AEAD_TAG_LENGTH(alg) != 0 ?                              \
     (ciphertext_length) - PSA_AEAD_TAG_LENGTH(alg) :             \
     0)

/** A sufficient output buffer size for psa_aead_update().
 *
 * If the size of the output buffer is at least this large, it is
 * guaranteed that psa_aead_update() will not fail due to an
 * insufficient buffer size. The actual size of the output may be smaller
 * in any given call.
 *
 * \param alg                 An AEAD algorithm
 *                            (\c PSA_ALG_XXX value such that
 *                            #PSA_ALG_IS_AEAD(\p alg) is true).
 * \param input_length        Size of the input in bytes.
 *
 * \return                    A sufficient output buffer size for the specified
 *                            algorithm.
 *                            If the AEAD algorithm is not recognized, return 0.
 *                            An implementation may return either 0 or a
 *                            correct size for an AEAD algorithm that it
 *                            recognizes, but does not support.
 */
/* For all the AEAD modes defined in this specification, it is possible
 * to emit output without delay. However, hardware may not always be
 * capable of this. So for modes based on a block cipher, allow the
 * implementation to delay the output until it has a full block. */
#define PSA_AEAD_UPDATE_OUTPUT_SIZE(alg, input_length)                  \
    (PSA_ALG_IS_AEAD_ON_BLOCK_CIPHER(alg) ?                             \
     PSA_ROUND_UP_TO_MULTIPLE(PSA_MAX_BLOCK_CIPHER_BLOCK_SIZE, (input_length)) : \
     (input_length))

/** A sufficient ciphertext buffer size for psa_aead_finish().
 *
 * If the size of the ciphertext buffer is at least this large, it is
 * guaranteed that psa_aead_finish() will not fail due to an
 * insufficient ciphertext buffer size. The actual size of the output may
 * be smaller in any given call.
 *
 * \param alg                 An AEAD algorithm
 *                            (\c PSA_ALG_XXX value such that
 *                            #PSA_ALG_IS_AEAD(\p alg) is true).
 *
 * \return                    A sufficient ciphertext buffer size for the
 *                            specified algorithm.
 *                            If the AEAD algorithm is not recognized, return 0.
 *                            An implementation may return either 0 or a
 *                            correct size for an AEAD algorithm that it
 *                            recognizes, but does not support.
 */
#define PSA_AEAD_FINISH_OUTPUT_SIZE(alg)                                \
    (PSA_ALG_IS_AEAD_ON_BLOCK_CIPHER(alg) ?                             \
     PSA_MAX_BLOCK_CIPHER_BLOCK_SIZE :                                  \
     0)

/** A sufficient plaintext buffer size for psa_aead_verify().
 *
 * If the size of the plaintext buffer is at least this large, it is
 * guaranteed that psa_aead_verify() will not fail due to an
 * insufficient plaintext buffer size. The actual size of the output may
 * be smaller in any given call.
 *
 * \param alg                 An AEAD algorithm
 *                            (\c PSA_ALG_XXX value such that
 *                            #PSA_ALG_IS_AEAD(\p alg) is true).
 *
 * \return                    A sufficient plaintext buffer size for the
 *                            specified algorithm.
 *                            If the AEAD algorithm is not recognized, return 0.
 *                            An implementation may return either 0 or a
 *                            correct size for an AEAD algorithm that it
 *                            recognizes, but does not support.
 */
#define PSA_AEAD_VERIFY_OUTPUT_SIZE(alg)                                \
    (PSA_ALG_IS_AEAD_ON_BLOCK_CIPHER(alg) ?                             \
     PSA_MAX_BLOCK_CIPHER_BLOCK_SIZE :                                  \
     0)

#define PSA_RSA_MINIMUM_PADDING_SIZE(alg)                         \
    (PSA_ALG_IS_RSA_OAEP(alg) ?                                   \
     2 * PSA_HASH_SIZE(PSA_ALG_RSA_OAEP_GET_HASH(alg)) + 1 :      \
     11 /*PKCS#1v1.5*/)

/**
 * \brief ECDSA signature size for a given curve bit size
 *
 * \param curve_bits    Curve size in bits.
 * \return              Signature size in bytes.
 *
 * \note This macro returns a compile-time constant if its argument is one.
 */
#define PSA_ECDSA_SIGNATURE_SIZE(curve_bits)    \
    (PSA_BITS_TO_BYTES(curve_bits) * 2)

/** Sufficient signature buffer size for psa_sign_hash().
 *
 * This macro returns a sufficient buffer size for a signature using a key
 * of the specified type and size, with the specified algorithm.
 * Note that the actual size of the signature may be smaller
 * (some algorithms produce a variable-size signature).
 *
 * \warning This function may call its arguments multiple times or
 *          zero times, so you should not pass arguments that contain
 *          side effects.
 *
 * \param key_type  An asymmetric key type (this may indifferently be a
 *                  key pair type or a public key type).
 * \param key_bits  The size of the key in bits.
 * \param alg       The signature algorithm.
 *
 * \return If the parameters are valid and supported, return
 *         a buffer size in bytes that guarantees that
 *         psa_sign_hash() will not fail with
 *         #PSA_ERROR_BUFFER_TOO_SMALL.
 *         If the parameters are a valid combination that is not supported
 *         by the implementation, this macro shall return either a
 *         sensible size or 0.
 *         If the parameters are not valid, the
 *         return value is unspecified.
 */
#define PSA_SIGN_OUTPUT_SIZE(key_type, key_bits, alg)        \
    (PSA_KEY_TYPE_IS_RSA(key_type) ? ((void)alg, PSA_BITS_TO_BYTES(key_bits)) : \
     PSA_KEY_TYPE_IS_ECC(key_type) ? PSA_ECDSA_SIGNATURE_SIZE(key_bits) : \
     ((void)alg, 0))

#define PSA_VENDOR_ECDSA_SIGNATURE_MAX_SIZE     \
    PSA_ECDSA_SIGNATURE_SIZE(PSA_VENDOR_ECC_MAX_CURVE_BITS)

/** \def PSA_SIGNATURE_MAX_SIZE
 *
 * Maximum size of an asymmetric signature.
 *
 * This macro must expand to a compile-time constant integer. This value
 * should be the maximum size of a signature supported by the implementation,
 * in bytes, and must be no smaller than this maximum.
 */
#define PSA_SIGNATURE_MAX_SIZE                               \
    (PSA_BITS_TO_BYTES(PSA_VENDOR_RSA_MAX_KEY_BITS) > PSA_VENDOR_ECDSA_SIGNATURE_MAX_SIZE ? \
     PSA_BITS_TO_BYTES(PSA_VENDOR_RSA_MAX_KEY_BITS) :                   \
     PSA_VENDOR_ECDSA_SIGNATURE_MAX_SIZE)

/** Sufficient output buffer size for psa_asymmetric_encrypt().
 *
 * This macro returns a sufficient buffer size for a ciphertext produced using
 * a key of the specified type and size, with the specified algorithm.
 * Note that the actual size of the ciphertext may be smaller, depending
 * on the algorithm.
 *
 * \warning This function may call its arguments multiple times or
 *          zero times, so you should not pass arguments that contain
 *          side effects.
 *
 * \param key_type  An asymmetric key type (this may indifferently be a
 *                  key pair type or a public key type).
 * \param key_bits  The size of the key in bits.
 * \param alg       The asymmetric encryption algorithm.
 *
 * \return If the parameters are valid and supported, return
 *         a buffer size in bytes that guarantees that
 *         psa_asymmetric_encrypt() will not fail with
 *         #PSA_ERROR_BUFFER_TOO_SMALL.
 *         If the parameters are a valid combination that is not supported
 *         by the implementation, this macro shall return either a
 *         sensible size or 0.
 *         If the parameters are not valid, the
 *         return value is unspecified.
 */
#define PSA_ASYMMETRIC_ENCRYPT_OUTPUT_SIZE(key_type, key_bits, alg)     \
    (PSA_KEY_TYPE_IS_RSA(key_type) ?                                    \
     ((void)alg, PSA_BITS_TO_BYTES(key_bits)) :                         \
     0)

/** Sufficient output buffer size for psa_asymmetric_decrypt().
 *
 * This macro returns a sufficient buffer size for a plaintext produced using
 * a key of the specified type and size, with the specified algorithm.
 * Note that the actual size of the plaintext may be smaller, depending
 * on the algorithm.
 *
 * \warning This function may call its arguments multiple times or
 *          zero times, so you should not pass arguments that contain
 *          side effects.
 *
 * \param key_type  An asymmetric key type (this may indifferently be a
 *                  key pair type or a public key type).
 * \param key_bits  The size of the key in bits.
 * \param alg       The asymmetric encryption algorithm.
 *
 * \return If the parameters are valid and supported, return
 *         a buffer size in bytes that guarantees that
 *         psa_asymmetric_decrypt() will not fail with
 *         #PSA_ERROR_BUFFER_TOO_SMALL.
 *         If the parameters are a valid combination that is not supported
 *         by the implementation, this macro shall return either a
 *         sensible size or 0.
 *         If the parameters are not valid, the
 *         return value is unspecified.
 */
#define PSA_ASYMMETRIC_DECRYPT_OUTPUT_SIZE(key_type, key_bits, alg)     \
    (PSA_KEY_TYPE_IS_RSA(key_type) ?                                    \
     PSA_BITS_TO_BYTES(key_bits) - PSA_RSA_MINIMUM_PADDING_SIZE(alg) :  \
     0)

/* Maximum size of the ASN.1 encoding of an INTEGER with the specified
 * number of bits.
 *
 * This definition assumes that bits <= 2^19 - 9 so that the length field
 * is at most 3 bytes. The length of the encoding is the length of the
 * bit string padded to a whole number of bytes plus:
 * - 1 type byte;
 * - 1 to 3 length bytes;
 * - 0 to 1 bytes of leading 0 due to the sign bit.
 */
#define PSA_KEY_EXPORT_ASN1_INTEGER_MAX_SIZE(bits)      \
    ((bits) / 8 + 5)

/* Maximum size of the export encoding of an RSA public key.
 * Assumes that the public exponent is less than 2^32.
 *
 * RSAPublicKey  ::=  SEQUENCE  {
 *    modulus            INTEGER,    -- n
 *    publicExponent     INTEGER  }  -- e
 *
 * - 4 bytes of SEQUENCE overhead;
 * - n : INTEGER;
 * - 7 bytes for the public exponent.
 */
#define PSA_KEY_EXPORT_RSA_PUBLIC_KEY_MAX_SIZE(key_bits)        \
    (PSA_KEY_EXPORT_ASN1_INTEGER_MAX_SIZE(key_bits) + 11)

/* Maximum size of the export encoding of an RSA key pair.
 * Assumes thatthe public exponent is less than 2^32 and that the size
 * difference between the two primes is at most 1 bit.
 *
 * RSAPrivateKey ::= SEQUENCE {
 *     version           Version,  -- 0
 *     modulus           INTEGER,  -- N-bit
 *     publicExponent    INTEGER,  -- 32-bit
 *     privateExponent   INTEGER,  -- N-bit
 *     prime1            INTEGER,  -- N/2-bit
 *     prime2            INTEGER,  -- N/2-bit
 *     exponent1         INTEGER,  -- N/2-bit
 *     exponent2         INTEGER,  -- N/2-bit
 *     coefficient       INTEGER,  -- N/2-bit
 * }
 *
 * - 4 bytes of SEQUENCE overhead;
 * - 3 bytes of version;
 * - 7 half-size INTEGERs plus 2 full-size INTEGERs,
 *   overapproximated as 9 half-size INTEGERS;
 * - 7 bytes for the public exponent.
 */
#define PSA_KEY_EXPORT_RSA_KEY_PAIR_MAX_SIZE(key_bits)   \
    (9 * PSA_KEY_EXPORT_ASN1_INTEGER_MAX_SIZE((key_bits) / 2 + 1) + 14)

/* Maximum size of the export encoding of a DSA public key.
 *
 * SubjectPublicKeyInfo  ::=  SEQUENCE  {
 *      algorithm            AlgorithmIdentifier,
 *      subjectPublicKey     BIT STRING  } -- contains DSAPublicKey
 * AlgorithmIdentifier  ::=  SEQUENCE  {
 *      algorithm               OBJECT IDENTIFIER,
 *      parameters              Dss-Parms  } -- SEQUENCE of 3 INTEGERs
 * DSAPublicKey  ::=  INTEGER -- public key, Y
 *
 * - 3 * 4 bytes of SEQUENCE overhead;
 * - 1 + 1 + 7 bytes of algorithm (DSA OID);
 * - 4 bytes of BIT STRING overhead;
 * - 3 full-size INTEGERs (p, g, y);
 * - 1 + 1 + 32 bytes for 1 sub-size INTEGER (q <= 256 bits).
 */
#define PSA_KEY_EXPORT_DSA_PUBLIC_KEY_MAX_SIZE(key_bits)        \
    (PSA_KEY_EXPORT_ASN1_INTEGER_MAX_SIZE(key_bits) * 3 + 59)

/* Maximum size of the export encoding of a DSA key pair.
 *
 * DSAPrivateKey ::= SEQUENCE {
 *     version             Version,  -- 0
 *     prime               INTEGER,  -- p
 *     subprime            INTEGER,  -- q
 *     generator           INTEGER,  -- g
 *     public              INTEGER,  -- y
 *     private             INTEGER,  -- x
 * }
 *
 * - 4 bytes of SEQUENCE overhead;
 * - 3 bytes of version;
 * - 3 full-size INTEGERs (p, g, y);
 * - 2 * (1 + 1 + 32) bytes for 2 sub-size INTEGERs (q, x <= 256 bits).
 */
#define PSA_KEY_EXPORT_DSA_KEY_PAIR_MAX_SIZE(key_bits)   \
    (PSA_KEY_EXPORT_ASN1_INTEGER_MAX_SIZE(key_bits) * 3 + 75)

/* Maximum size of the export encoding of an ECC public key.
 *
 * The representation of an ECC public key is:
 *      - The byte 0x04;
 *      - `x_P` as a `ceiling(m/8)`-byte string, big-endian;
 *      - `y_P` as a `ceiling(m/8)`-byte string, big-endian;
 *      - where m is the bit size associated with the curve.
 *
 * - 1 byte + 2 * point size.
 */
#define PSA_KEY_EXPORT_ECC_PUBLIC_KEY_MAX_SIZE(key_bits)        \
    (2 * PSA_BITS_TO_BYTES(key_bits) + 1)

/* Maximum size of the export encoding of an ECC key pair.
 *
 * An ECC key pair is represented by the secret value.
 */
#define PSA_KEY_EXPORT_ECC_KEY_PAIR_MAX_SIZE(key_bits)   \
    (PSA_BITS_TO_BYTES(key_bits))

/** Sufficient output buffer size for psa_export_key() or psa_export_public_key().
 *
 * This macro returns a compile-time constant if its arguments are
 * compile-time constants.
 *
 * \warning This function may call its arguments multiple times or
 *          zero times, so you should not pass arguments that contain
 *          side effects.
 *
 * The following code illustrates how to allocate enough memory to export
 * a key by querying the key type and size at runtime.
 * \code{c}
 * psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
 * psa_status_t status;
 * status = psa_get_key_attributes(key, &attributes);
 * if (status != PSA_SUCCESS) handle_error(...);
 * psa_key_type_t key_type = psa_get_key_type(&attributes);
 * size_t key_bits = psa_get_key_bits(&attributes);
 * size_t buffer_size = PSA_KEY_EXPORT_MAX_SIZE(key_type, key_bits);
 * psa_reset_key_attributes(&attributes);
 * uint8_t *buffer = malloc(buffer_size);
 * if (buffer == NULL) handle_error(...);
 * size_t buffer_length;
 * status = psa_export_key(key, buffer, buffer_size, &buffer_length);
 * if (status != PSA_SUCCESS) handle_error(...);
 * \endcode
 *
 * For psa_export_public_key(), calculate the buffer size from the
 * public key type. You can use the macro #PSA_KEY_TYPE_PUBLIC_KEY_OF_KEY_PAIR
 * to convert a key pair type to the corresponding public key type.
 * \code{c}
 * psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
 * psa_status_t status;
 * status = psa_get_key_attributes(key, &attributes);
 * if (status != PSA_SUCCESS) handle_error(...);
 * psa_key_type_t key_type = psa_get_key_type(&attributes);
 * psa_key_type_t public_key_type = PSA_KEY_TYPE_PUBLIC_KEY_OF_KEY_PAIR(key_type);
 * size_t key_bits = psa_get_key_bits(&attributes);
 * size_t buffer_size = PSA_KEY_EXPORT_MAX_SIZE(public_key_type, key_bits);
 * psa_reset_key_attributes(&attributes);
 * uint8_t *buffer = malloc(buffer_size);
 * if (buffer == NULL) handle_error(...);
 * size_t buffer_length;
 * status = psa_export_public_key(key, buffer, buffer_size, &buffer_length);
 * if (status != PSA_SUCCESS) handle_error(...);
 * \endcode
 *
 * \param key_type  A supported key type.
 * \param key_bits  The size of the key in bits.
 *
 * \return If the parameters are valid and supported, return
 *         a buffer size in bytes that guarantees that
 *         psa_sign_hash() will not fail with
 *         #PSA_ERROR_BUFFER_TOO_SMALL.
 *         If the parameters are a valid combination that is not supported
 *         by the implementation, this macro shall return either a
 *         sensible size or 0.
 *         If the parameters are not valid, the
 *         return value is unspecified.
 */
#define PSA_KEY_EXPORT_MAX_SIZE(key_type, key_bits)                     \
    (PSA_KEY_TYPE_IS_UNSTRUCTURED(key_type) ? PSA_BITS_TO_BYTES(key_bits) : \
     (key_type) == PSA_KEY_TYPE_RSA_KEY_PAIR ? PSA_KEY_EXPORT_RSA_KEY_PAIR_MAX_SIZE(key_bits) : \
     (key_type) == PSA_KEY_TYPE_RSA_PUBLIC_KEY ? PSA_KEY_EXPORT_RSA_PUBLIC_KEY_MAX_SIZE(key_bits) : \
     (key_type) == PSA_KEY_TYPE_DSA_KEY_PAIR ? PSA_KEY_EXPORT_DSA_KEY_PAIR_MAX_SIZE(key_bits) : \
     (key_type) == PSA_KEY_TYPE_DSA_PUBLIC_KEY ? PSA_KEY_EXPORT_DSA_PUBLIC_KEY_MAX_SIZE(key_bits) : \
     PSA_KEY_TYPE_IS_ECC_KEY_PAIR(key_type) ? PSA_KEY_EXPORT_ECC_KEY_PAIR_MAX_SIZE(key_bits) : \
     PSA_KEY_TYPE_IS_ECC_PUBLIC_KEY(key_type) ? PSA_KEY_EXPORT_ECC_PUBLIC_KEY_MAX_SIZE(key_bits) : \
     0)

#endif /* PSA_CRYPTO_SIZES_H */
