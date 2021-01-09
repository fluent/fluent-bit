/**
 * \file psa/crypto_accel_driver.h
 * \brief PSA cryptography accelerator driver module
 *
 * This header declares types and function signatures for cryptography
 * drivers that access key material directly. This is meant for
 * on-chip cryptography accelerators.
 *
 * This file is part of the PSA Crypto Driver Model, containing functions for
 * driver developers to implement to enable hardware to be called in a
 * standardized way by a PSA Cryptographic API implementation. The functions
 * comprising the driver model, which driver authors implement, are not
 * intended to be called by application developers.
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
#ifndef PSA_CRYPTO_ACCEL_DRIVER_H
#define PSA_CRYPTO_ACCEL_DRIVER_H

#include "crypto_driver_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/** \defgroup driver_digest Hardware-Accelerated Message Digests
 *
 * Generation and authentication of Message Digests (aka hashes) must be done
 * in parts using the following sequence:
 * - `psa_drv_hash_setup_t`
 * - `psa_drv_hash_update_t`
 * - `psa_drv_hash_update_t`
 * - ...
 * - `psa_drv_hash_finish_t`
 *
 * If a previously started Message Digest operation needs to be terminated
 * before the `psa_drv_hash_finish_t` operation is complete, it should be aborted
 * by the `psa_drv_hash_abort_t`. Failure to do so may result in allocated
 * resources not being freed or in other undefined behavior.
 */
/**@{*/

/** \brief The hardware-specific hash context structure
 *
 * The contents of this structure are implementation dependent and are
 * therefore not described here
 */
typedef struct psa_drv_hash_context_s psa_drv_hash_context_t;

/** \brief The function prototype for the start operation of a hash (message
 * digest) operation
 *
 *  Functions that implement this prototype should be named in the following
 * convention:
 * ~~~~~~~~~~~~~{.c}
 * psa_drv_hash_<ALGO>_setup
 * ~~~~~~~~~~~~~
 * Where `ALGO` is the name of the underlying hash function
 *
 * \param[in,out] p_context     A structure that will contain the
 * hardware-specific hash context
 *
 * \retval  PSA_SUCCESS     Success.
 */
typedef psa_status_t (*psa_drv_hash_setup_t)(psa_drv_hash_context_t *p_context);

/** \brief The function prototype for the update operation of a hash (message
 * digest) operation
 *
 * Functions that implement this prototype should be named in the following
 * convention:
 * ~~~~~~~~~~~~~{.c}
 * psa_drv_hash_<ALGO>_update
 * ~~~~~~~~~~~~~
 * Where `ALGO` is the name of the underlying algorithm
 *
 * \param[in,out] p_context     A hardware-specific structure for the
 *                              previously-established hash operation to be
 *                              continued
 * \param[in] p_input           A buffer containing the message to be appended
 *                              to the hash operation
 * \param[in] input_length      The size in bytes of the input message buffer
 */
typedef psa_status_t (*psa_drv_hash_update_t)(psa_drv_hash_context_t *p_context,
                                              const uint8_t *p_input,
                                              size_t input_length);

/** \brief  The function prototype for the finish operation of a hash (message
 * digest) operation
 *
 * Functions that implement this prototype should be named in the following
 * convention:
 * ~~~~~~~~~~~~~{.c}
 * psa_drv_hash_<ALGO>_finish
 * ~~~~~~~~~~~~~
 * Where `ALGO` is the name of the underlying algorithm
 *
 * \param[in,out] p_context     A hardware-specific structure for the
 *                              previously started hash operation to be
 *                              fiinished
 * \param[out] p_output         A buffer where the generated digest will be
 *                              placed
 * \param[in] output_size       The size in bytes of the buffer that has been
 *                              allocated for the `p_output` buffer
 * \param[out] p_output_length  The number of bytes placed in `p_output` after
 *                              success
 *
 * \retval PSA_SUCCESS
 *          Success.
 */
typedef psa_status_t (*psa_drv_hash_finish_t)(psa_drv_hash_context_t *p_context,
                                              uint8_t *p_output,
                                              size_t output_size,
                                              size_t *p_output_length);

/** \brief The function prototype for the abort operation of a hash (message
 * digest) operation
 *
 * Functions that implement this prototype should be named in the following
 * convention:
 * ~~~~~~~~~~~~~{.c}
 * psa_drv_hash_<ALGO>_abort
 * ~~~~~~~~~~~~~
 * Where `ALGO` is the name of the underlying algorithm
 *
 * \param[in,out] p_context A hardware-specific structure for the previously
 *                          started hash operation to be aborted
 */
typedef void (*psa_drv_hash_abort_t)(psa_drv_hash_context_t *p_context);

/**@}*/

/** \defgroup accel_mac Hardware-Accelerated Message Authentication Code
 * Generation and authentication of Message Authentication Codes (MACs) using
 * cryptographic accelerators can be done either as a single function call (via the
 * `psa_drv_accel_mac_generate_t` or `psa_drv_accel_mac_verify_t`
 * functions), or in parts using the following sequence:
 * - `psa_drv_accel_mac_setup_t`
 * - `psa_drv_accel_mac_update_t`
 * - `psa_drv_accel_mac_update_t`
 * - ...
 * - `psa_drv_accel_mac_finish_t` or `psa_drv_accel_mac_finish_verify_t`
 *
 * If a previously started MAC operation needs to be terminated, it
 * should be done so by the `psa_drv_accel_mac_abort_t`. Failure to do so may
 * result in allocated resources not being freed or in other undefined
 * behavior.
 *
 */
/**@{*/

/** \brief The hardware-accelerator-specific MAC context structure
 *
 * The contents of this structure are implementation dependent and are
 * therefore not described here.
 */
typedef struct psa_drv_accel_mac_context_s psa_drv_accel_mac_context_t;

/** \brief The function prototype for the setup operation of a
 * hardware-accelerated MAC operation
 *
 *  Functions that implement this prototype should be named in the following
 * convention:
 * ~~~~~~~~~~~~~{.c}
 * psa_drv_accel_mac_<ALGO>_<MAC_VARIANT>_setup
 * ~~~~~~~~~~~~~
 * Where `ALGO` is the name of the underlying primitive, and `MAC_VARIANT`
 * is the specific variant of a MAC operation (such as HMAC or CMAC)
 *
 * \param[in,out] p_context     A structure that will contain the
 *                              hardware-specific MAC context
 * \param[in] p_key             A buffer containing the cleartext key material
 *                              to be used in the operation
 * \param[in] key_length        The size in bytes of the key material
 *
 * \retval  PSA_SUCCESS
 *          Success.
 */
typedef psa_status_t (*psa_drv_accel_mac_setup_t)(psa_drv_accel_mac_context_t *p_context,
                                                  const uint8_t *p_key,
                                                  size_t key_length);

/** \brief The function prototype for the update operation of a
 * hardware-accelerated MAC operation
 *
 * Functions that implement this prototype should be named in the following
 * convention:
 * ~~~~~~~~~~~~~{.c}
 * psa_drv_accel_mac_<ALGO>_<MAC_VARIANT>_update
 * ~~~~~~~~~~~~~
 * Where `ALGO` is the name of the underlying algorithm, and `MAC_VARIANT`
 * is the specific variant of a MAC operation (such as HMAC or CMAC)
 *
 * \param[in,out] p_context     A hardware-specific structure for the
 *                              previously-established MAC operation to be
 *                              continued
 * \param[in] p_input           A buffer containing the message to be appended
 *                              to the MAC operation
 * \param[in] input_length      The size in bytes of the input message buffer
 */
typedef psa_status_t (*psa_drv_accel_mac_update_t)(psa_drv_accel_mac_context_t *p_context,
                                                   const uint8_t *p_input,
                                                   size_t input_length);

/** \brief  The function prototype for the finish operation of a
 * hardware-accelerated MAC operation
 *
 * Functions that implement this prototype should be named in the following
 *  convention:
 * ~~~~~~~~~~~~~{.c}
 * psa_drv_accel_mac_<ALGO>_<MAC_VARIANT>_finish
 * ~~~~~~~~~~~~~
 * Where `ALGO` is the name of the underlying algorithm, and `MAC_VARIANT` is
 * the specific variant of a MAC operation (such as HMAC or CMAC)
 *
 * \param[in,out] p_context     A hardware-specific structure for the
 *                              previously started MAC operation to be
 *                              finished
 * \param[out] p_mac            A buffer where the generated MAC will be placed
 * \param[in] mac_length        The size in bytes of the buffer that has been
 *                              allocated for the `p_mac` buffer
 *
 * \retval PSA_SUCCESS
 *          Success.
 */
typedef psa_status_t (*psa_drv_accel_mac_finish_t)(psa_drv_accel_mac_context_t *p_context,
                                                   uint8_t *p_mac,
                                                   size_t mac_length);

/** \brief The function prototype for the finish and verify operation of a
 * hardware-accelerated MAC operation
 *
 * Functions that implement this prototype should be named in the following
 * convention:
 * ~~~~~~~~~~~~~{.c}
 * psa_drv_accel_mac_<ALGO>_<MAC_VARIANT>_finish_verify
 * ~~~~~~~~~~~~~
 * Where `ALGO` is the name of the underlying algorithm, and `MAC_VARIANT` is
 * the specific variant of a MAC operation (such as HMAC or CMAC)
 *
 * \param[in,out] p_context     A hardware-specific structure for the
 *                              previously started MAC operation to be
 *                              verified and finished
 * \param[in] p_mac             A buffer containing the MAC that will be used
 *                              for verification
 * \param[in] mac_length        The size in bytes of the data in the `p_mac`
 *                              buffer
 *
 * \retval PSA_SUCCESS
 *          The operation completed successfully and the comparison matched
 */
typedef psa_status_t (*psa_drv_accel_mac_finish_verify_t)(psa_drv_accel_mac_context_t *p_context,
                                                          const uint8_t *p_mac,
                                                          size_t mac_length);

/** \brief The function prototype for the abort operation for a previously
 * started hardware-accelerated MAC operation
 *
 * Functions that implement this prototype should be named in the following
 * convention:
 * ~~~~~~~~~~~~~{.c}
 * psa_drv_accel_mac_<ALGO>_<MAC_VARIANT>_abort
 * ~~~~~~~~~~~~~
 * Where `ALGO` is the name of the underlying algorithm, and `MAC_VARIANT` is
 * the specific variant of a MAC operation (such as HMAC or CMAC)
 *
 * \param[in,out] p_context     A hardware-specific structure for the
 *                              previously started MAC operation to be
 *                              aborted
 *
 */
typedef psa_status_t (*psa_drv_accel_mac_abort_t)(psa_drv_accel_mac_context_t *p_context);

/** \brief The function prototype for the one-shot operation of a
 * hardware-accelerated MAC operation
 *
 * Functions that implement this prototype should be named in the following
 * convention:
 * ~~~~~~~~~~~~~{.c}
 * psa_drv_accel_mac_<ALGO>_<MAC_VARIANT>
 * ~~~~~~~~~~~~~
 * Where `ALGO` is the name of the underlying algorithm, and `MAC_VARIANT` is
 * the specific variant of a MAC operation (such as HMAC or CMAC)
 *
 * \param[in] p_input        A buffer containing the data to be MACed
 * \param[in] input_length   The length in bytes of the `p_input` data
 * \param[in] p_key          A buffer containing the key material to be used
 *                           for the MAC operation
 * \param[in] key_length     The length in bytes of the `p_key` data
 * \param[in] alg            The algorithm to be performed
 * \param[out] p_mac         The buffer where the resulting MAC will be placed
 *                           upon success
 * \param[in] mac_length     The length in bytes of the `p_mac` buffer
 */
typedef psa_status_t (*psa_drv_accel_mac_t)(const uint8_t *p_input,
                                            size_t input_length,
                                            const uint8_t *p_key,
                                            size_t key_length,
                                            psa_algorithm_t alg,
                                            uint8_t *p_mac,
                                            size_t mac_length);

/** \brief The function prototype for the one-shot hardware-accelerated MAC
 * Verify operation
 *
 * Functions that implement this prototype should be named in the following
 * convention:
 * ~~~~~~~~~~~~~{.c}
 * psa_drv_accel_mac_<ALGO>_<MAC_VARIANT>_verify
 * ~~~~~~~~~~~~~
 * Where `ALGO` is the name of the underlying algorithm, and `MAC_VARIANT` is
 * the specific variant of a MAC operation (such as HMAC or CMAC)
 *
 * \param[in] p_input        A buffer containing the data to be MACed
 * \param[in] input_length   The length in bytes of the `p_input` data
 * \param[in] p_key          A buffer containing the key material to be used
 *                           for the MAC operation
 * \param[in] key_length     The length in bytes of the `p_key` data
 * \param[in] alg            The algorithm to be performed
 * \param[in] p_mac          The MAC data to be compared
 * \param[in] mac_length     The length in bytes of the `p_mac` buffer
 *
 * \retval PSA_SUCCESS
 *  The operation completed successfully and the comparison matched
 */
typedef psa_status_t (*psa_drv_accel_mac_verify_t)(const uint8_t *p_input,
                                                   size_t input_length,
                                                   const uint8_t *p_key,
                                                   size_t key_length,
                                                   psa_algorithm_t alg,
                                                   const uint8_t *p_mac,
                                                   size_t mac_length);
/**@}*/

/** \defgroup accel_cipher Hardware-Accelerated Block Ciphers
 * Encryption and Decryption using hardware-acceleration in block modes other
 * than ECB must be done in multiple parts, using the following flow:
 * - `psa_drv_accel_ciphersetup_t`
 * - `psa_drv_accel_cipher_set_iv_t` (optional depending upon block mode)
 * - `psa_drv_accel_cipher_update_t`
 * - `psa_drv_accel_cipher_update_t`
 * - ...
 * - `psa_drv_accel_cipher_finish_t`
 *
 * If a previously started hardware-accelerated Cipher operation needs to be
 * terminated, it should be done so by the `psa_drv_accel_cipher_abort_t`.
 * Failure to do so may result in allocated resources not being freed or in
 * other undefined behavior.
 */
/**@{*/

/** \brief The hardware-accelerator-specific cipher context structure
 *
 * The contents of this structure are implementation dependent and are
 * therefore not described here.
 */
typedef struct psa_drv_accel_cipher_context_s psa_drv_accel_cipher_context_t;

/** \brief The function prototype for the setup operation of
 * hardware-accelerated block cipher operations.
 *  Functions that implement this prototype should be named in the following
 * conventions:
 * ~~~~~~~~~~~~~{.c}
 * psa_drv_accel_cipher_setup_<CIPHER_NAME>_<MODE>
 * ~~~~~~~~~~~~~
 * Where
 * - `CIPHER_NAME` is the name of the underlying block cipher (i.e. AES or DES)
 * - `MODE` is the block mode of the cipher operation (i.e. CBC or CTR)
 *
 * For stream ciphers:
 * ~~~~~~~~~~~~~{.c}
 * psa_drv_accel_cipher_setup_<CIPHER_NAME>
 * ~~~~~~~~~~~~~
 * Where `CIPHER_NAME` is the name of a stream cipher (i.e. RC4)
 *
 * \param[in,out] p_context     A structure that will contain the
 *                              hardware-specific cipher context
 * \param[in] direction         Indicates if the operation is an encrypt or a
 *                              decrypt
 * \param[in] p_key_data        A buffer containing the cleartext key material
 *                              to be used in the operation
 * \param[in] key_data_size     The size in bytes of the key material
 *
 * \retval PSA_SUCCESS
 */
typedef psa_status_t (*psa_drv_accel_cipher_setup_t)(psa_drv_accel_cipher_context_t *p_context,
                                                     psa_encrypt_or_decrypt_t direction,
                                                     const uint8_t *p_key_data,
                                                     size_t key_data_size);

/** \brief The function prototype for the set initialization vector operation
 * of hardware-accelerated block cipher operations
 * Functions that implement this prototype should be named in the following
 * convention:
 * ~~~~~~~~~~~~~{.c}
 * psa_drv_accel_cipher_set_iv_<CIPHER_NAME>_<MODE>
 * ~~~~~~~~~~~~~
 * Where
 * - `CIPHER_NAME` is the name of the underlying block cipher (i.e. AES or DES)
 * - `MODE` is the block mode of the cipher operation (i.e. CBC or CTR)
 *
 * \param[in,out] p_context     A structure that contains the previously setup
 *                              hardware-specific cipher context
 * \param[in] p_iv              A buffer containing the initialization vecotr
 * \param[in] iv_length         The size in bytes of the contents of `p_iv`
 *
 * \retval PSA_SUCCESS
 */
typedef psa_status_t (*psa_drv_accel_cipher_set_iv_t)(psa_drv_accel_cipher_context_t *p_context,
                                                      const uint8_t *p_iv,
                                                      size_t iv_length);

/** \brief The function prototype for the update operation of
 * hardware-accelerated block cipher operations.
 *
 *  Functions that implement this prototype should be named in the following
 * convention:
 * ~~~~~~~~~~~~~{.c}
 * psa_drv_accel_cipher_update_<CIPHER_NAME>_<MODE>
 * ~~~~~~~~~~~~~
 * Where
 * - `CIPHER_NAME` is the name of the underlying block cipher (i.e. AES or DES)
 * - `MODE` is the block mode of the cipher operation (i.e. CBC or CTR)
 *
 * \param[in,out] p_context         A hardware-specific structure for the
 *                                  previously started cipher operation
 * \param[in] p_input               A buffer containing the data to be
 *                                  encrypted or decrypted
 * \param[in] input_size            The size in bytes of the `p_input` buffer
 * \param[out] p_output             A caller-allocated buffer where the
 *                                  generated output will be placed
 * \param[in] output_size           The size in bytes of the `p_output` buffer
 * \param[out] p_output_length      After completion, will contain the number
 *                                  of bytes placed in the `p_output` buffer
 *
 * \retval PSA_SUCCESS
 */
typedef psa_status_t (*psa_drv_accel_cipher_update_t)(psa_drv_accel_cipher_context_t *p_context,
                                                      const uint8_t *p_input,
                                                      size_t input_size,
                                                      uint8_t *p_output,
                                                      size_t output_size,
                                                      size_t *p_output_length);

/** \brief The function prototype for the finish operation of
 * hardware-accelerated block cipher operations.
 *
 *  Functions that implement this prototype should be named in the following
 * convention:
 * ~~~~~~~~~~~~~{.c}
 * psa_drv_accel_cipher_finish_<CIPHER_NAME>_<MODE>
 * ~~~~~~~~~~~~~
 * Where
 * - `CIPHER_NAME` is the name of the underlying block cipher (i.e. AES or DES)
 * - `MODE` is the block mode of the cipher operation (i.e. CBC or CTR)
 *
 * \param[in,out] p_context     A hardware-specific structure for the
 *                              previously started cipher operation
 * \param[out] p_output         A caller-allocated buffer where the generated
 *                              output will be placed
 * \param[in] output_size       The size in bytes of the `p_output` buffer
 * \param[out] p_output_length  After completion, will contain the number of
 *                              bytes placed in the `p_output` buffer
 *
 * \retval PSA_SUCCESS
 */
typedef psa_status_t (*psa_drv_accel_cipher_finish_t)(psa_drv_accel_cipher_context_t *p_context,
                                                      uint8_t *p_output,
                                                      size_t output_size,
                                                      size_t *p_output_length);

/** \brief The function prototype for the abort operation of
 * hardware-accelerated block cipher operations.
 *
 *  Functions that implement the following prototype should be named in the
 * following convention:
 * ~~~~~~~~~~~~~{.c}
 * psa_drv_accel_cipher_abort_<CIPHER_NAME>_<MODE>
 * ~~~~~~~~~~~~~
 * Where
 * - `CIPHER_NAME` is the name of the underlying block cipher (i.e. AES or DES)
 * - `MODE` is the block mode of the cipher operation (i.e. CBC or CTR)
 *
 * \param[in,out] p_context     A hardware-specific structure for the
 *                              previously started cipher operation
 *
 * \retval PSA_SUCCESS
 */
typedef psa_status_t (*psa_drv_accel_cipher_abort_t)(psa_drv_accel_cipher_context_t *p_context);

/**@}*/

/** \defgroup accel_aead Hardware-Accelerated Authenticated Encryption with Additional Data
 *
 * Hardware-accelerated Authenticated Encryption with Additional Data (AEAD)
 * operations must be done in one function call. While this creates a burden
 * for implementers as there must be sufficient space in memory for the entire
 * message, it prevents decrypted data from being made available before the
 * authentication operation is complete and the data is known to be authentic.
 */
/**@{*/

/** \brief The function prototype for the hardware-accelerated authenticated
 * encryption operation.
 *
 * Functions that implement this prototype should be named in the following
 * convention:
 * ~~~~~~~~~~~~~{.c}
 * psa_drv_accel_aead_<ALGO>_encrypt
 * ~~~~~~~~~~~~~
 * Where `ALGO` is the name of the AEAD algorithm
 *
 * \param[in] p_key                     A pointer to the key material
 * \param[in] key_length                The size in bytes of the key material
 * \param[in] alg                       The AEAD algorithm to compute
 *                                      (\c PSA_ALG_XXX value such that
 *                                      #PSA_ALG_IS_AEAD(`alg`) is true)
 * \param[in] nonce                     Nonce or IV to use
 * \param[in] nonce_length              Size of the `nonce` buffer in bytes
 * \param[in] additional_data           Additional data that will be MACed
 *                                      but not encrypted.
 * \param[in] additional_data_length    Size of `additional_data` in bytes
 * \param[in] plaintext                 Data that will be MACed and
 *                                      encrypted.
 * \param[in] plaintext_length          Size of `plaintext` in bytes
 * \param[out] ciphertext               Output buffer for the authenticated and
 *                                      encrypted data. The additional data is
 *                                      not part of this output. For algorithms
 *                                      where the encrypted data and the
 *                                      authentication tag are defined as
 *                                      separate outputs, the authentication
 *                                      tag is appended to the encrypted data.
 * \param[in] ciphertext_size           Size of the `ciphertext` buffer in
 *                                      bytes
 *                                      This must be at least
 *                                      #PSA_AEAD_ENCRYPT_OUTPUT_SIZE(`alg`,
 *                                      `plaintext_length`).
 * \param[out] ciphertext_length        On success, the size of the output in
 *                                      the `ciphertext` buffer
 *
 * \retval #PSA_SUCCESS
 *
 */
typedef psa_status_t (*psa_drv_accel_aead_encrypt_t)(const uint8_t *p_key,
                                                     size_t key_length,
                                                     psa_algorithm_t alg,
                                                     const uint8_t *nonce,
                                                     size_t nonce_length,
                                                     const uint8_t *additional_data,
                                                     size_t additional_data_length,
                                                     const uint8_t *plaintext,
                                                     size_t plaintext_length,
                                                     uint8_t *ciphertext,
                                                     size_t ciphertext_size,
                                                     size_t *ciphertext_length);

/** \brief The function prototype for the hardware-accelerated authenticated
 * decryption operation.
 *
 * Functions that implement this prototype should be named in the following
 * convention:
 * ~~~~~~~~~~~~~{.c}
 * psa_drv_accel_aead_<ALGO>_decrypt
 * ~~~~~~~~~~~~~
 * Where `ALGO` is the name of the AEAD algorithm
 * \param[in] p_key                     A pointer to the key material
 * \param[in] key_length                The size in bytes of the key material
 * \param[in] alg                       The AEAD algorithm to compute
 *                                      (\c PSA_ALG_XXX value such that
 *                                      #PSA_ALG_IS_AEAD(`alg`) is true)
 * \param[in] nonce                     Nonce or IV to use
 * \param[in] nonce_length              Size of the `nonce` buffer in bytes
 * \param[in] additional_data           Additional data that has been MACed
 *                                      but not encrypted
 * \param[in] additional_data_length    Size of `additional_data` in bytes
 * \param[in] ciphertext                Data that has been MACed and
 *                                      encrypted
 *                                      For algorithms where the encrypted data
 *                                      and the authentication tag are defined
 *                                      as separate inputs, the buffer must
 *                                      contain the encrypted data followed by
 *                                      the authentication tag.
 * \param[in] ciphertext_length         Size of `ciphertext` in bytes
 * \param[out] plaintext                Output buffer for the decrypted data
 * \param[in] plaintext_size            Size of the `plaintext` buffer in
 *                                      bytes
 *                                      This must be at least
 *                                      #PSA_AEAD_DECRYPT_OUTPUT_SIZE(`alg`,
 *                                      `ciphertext_length`).
 * \param[out] plaintext_length         On success, the size of the output
 *                                      in the \b plaintext buffer
 *
 * \retval #PSA_SUCCESS
 *         Success.
 */
typedef psa_status_t (*psa_drv_accel_aead_decrypt_t)(const uint8_t *p_key,
                                                     size_t key_length,
                                                     psa_algorithm_t alg,
                                                     const uint8_t *nonce,
                                                     size_t nonce_length,
                                                     const uint8_t *additional_data,
                                                     size_t additional_data_length,
                                                     const uint8_t *ciphertext,
                                                     size_t ciphertext_length,
                                                     uint8_t *plaintext,
                                                     size_t plaintext_size,
                                                     size_t *plaintext_length);

/**@}*/

/** \defgroup accel_asymmetric Hardware-Accelerated Asymmetric Cryptography
 *
 * Since the amount of data that can (or should) be encrypted or signed using
 * asymmetric keys is limited by the key size, hardware-accelerated asymmetric
 * key operations must be done in single function calls.
 */
/**@{*/


/**
 * \brief The function prototype for the hardware-accelerated asymmetric sign
 * operation.
 *
 * Functions that implement this prototype should be named in the following
 * convention:
 * ~~~~~~~~~~~~~{.c}
 * psa_drv_accel_asymmetric_<ALGO>_sign
 * ~~~~~~~~~~~~~
 * Where `ALGO` is the name of the signing algorithm
 *
 * This function supports any asymmetric-key output from psa_export_key() as
 * the buffer in \p p_key. Refer to the documentation of \ref
 * psa_export_key() for the formats.
 *
 * \param[in] p_key                 A buffer containing the private key
 *                                  material
 * \param[in] key_size              The size in bytes of the `p_key` data
 * \param[in] alg                   A signature algorithm that is compatible
 *                                  with the type of `p_key`
 * \param[in] p_hash                The hash or message to sign
 * \param[in] hash_length           Size of the `p_hash` buffer in bytes
 * \param[out] p_signature          Buffer where the signature is to be written
 * \param[in] signature_size        Size of the `p_signature` buffer in bytes
 * \param[out] p_signature_length   On success, the number of bytes
 *                                  that make up the returned signature value
 *
 * \retval PSA_SUCCESS
 */
typedef psa_status_t (*psa_drv_accel_asymmetric_sign_t)(const uint8_t *p_key,
                                                        size_t key_size,
                                                        psa_algorithm_t alg,
                                                        psa_key_type_t key_type,
                                                        const uint8_t *p_hash,
                                                        size_t hash_length,
                                                        uint8_t *p_signature,
                                                        size_t signature_size,
                                                        size_t *p_signature_length);

/**
 * \brief The function prototype for the hardware-accelerated signature verify
 * operation
 *
 * Functions that implement this prototype should be named in the following
 * convention:
 * ~~~~~~~~~~~~~{.c}
 * psa_drv_accel_asymmetric_<ALGO>_verify
 * ~~~~~~~~~~~~~
 * Where `ALGO` is the name of the signing algorithm
 *
 * This function supports any output from \ref psa_export_public_key() as the
 * buffer in \p p_key. Refer to the documentation of \ref
 * psa_export_public_key() for the format of public keys and to the
 * documentation of \ref psa_export_key() for the format for other key types.
 *
 * \param[in] p_key             A buffer containing the public key material
 * \param[in] key_size          The size in bytes of the `p_key` data
 * \param[in] alg               A signature algorithm that is compatible with
 *                              the type of `key`
 * \param[in] p_hash            The hash or message whose signature is to be
 *                              verified
 * \param[in] hash_length       Size of the `p_hash` buffer in bytes
 * \param[in] p_signature       Buffer containing the signature to verify
 * \param[in] signature_length  Size of the `p_signature` buffer in bytes
 *
 * \retval PSA_SUCCESS
 *         The signature is valid.
 */
typedef psa_status_t (*psa_drv_accel_asymmetric_verify_t)(const uint8_t *p_key,
                                                          size_t key_size,
                                                          psa_algorithm_t alg,
                                                          psa_key_type_t key_type,
                                                          const uint8_t *p_hash,
                                                          size_t hash_length,
                                                          const uint8_t *p_signature,
                                                          size_t signature_length);

/**
 * \brief The function prototype for the hardware-accelerated asymmetric
 * encrypt operation
 *
 * Functions that implement this prototype should be named in the following
 * convention:
 * ~~~~~~~~~~~~~{.c}
 * psa_drv_accel_asymmetric_<ALGO>_encrypt
 * ~~~~~~~~~~~~~
 * Where `ALGO` is the name of the encryption algorithm
 *
 * This function supports any output from \ref psa_export_public_key() as the
 * buffer in \p p_key. Refer to the documentation of \ref
 * psa_export_public_key() for the format of public keys and to the
 * documentation of \ref psa_export_key() for the format for other key types.
 *
 * \param[in] p_key             A buffer containing the public key material
 * \param[in] key_size          The size in bytes of the `p_key` data
 * \param[in] alg               An asymmetric encryption algorithm that is
 *                              compatible with the type of `key`
 * \param[in] p_input           The message to encrypt
 * \param[in] input_length      Size of the `p_input` buffer in bytes
 * \param[in] p_salt            A salt or label, if supported by the
 *                              encryption algorithm
 *                              If the algorithm does not support a
 *                              salt, pass `NULL`
 *                              If the algorithm supports an optional
 *                              salt and you do not want to pass a salt,
 *                              pass `NULL`.
 *                              For #PSA_ALG_RSA_PKCS1V15_CRYPT, no salt is
 *                              supported.
 * \param[in] salt_length       Size of the `p_salt` buffer in bytes
 *                              If `p_salt` is `NULL`, pass 0.
 * \param[out] p_output         Buffer where the encrypted message is to
 *                              be written
 * \param[in] output_size       Size of the `p_output` buffer in bytes
 * \param[out] p_output_length  On success, the number of bytes
 *                              that make up the returned output
 *
 * \retval PSA_SUCCESS
 */
typedef psa_status_t (*psa_drv_accel_asymmetric_encrypt_t)(const uint8_t *p_key,
                                                           size_t key_size,
                                                           psa_algorithm_t alg,
                                                           psa_key_type_t key_type,
                                                           const uint8_t *p_input,
                                                           size_t input_length,
                                                           const uint8_t *p_salt,
                                                           size_t salt_length,
                                                           uint8_t *p_output,
                                                           size_t output_size,
                                                           size_t *p_output_length);

/**
 * \brief The function prototype for the hardware=acce;erated asymmetric
 * decrypt operation
 *
 * Functions that implement this prototype should be named in the following
 * convention:
 * ~~~~~~~~~~~~~{.c}
 * psa_drv_accel_asymmetric_<ALGO>_decrypt
 * ~~~~~~~~~~~~~
 * Where `ALGO` is the name of the encryption algorithm
 *
 * This function supports any asymmetric-key output from psa_export_key() as
 * the buffer in \p p_key. Refer to the documentation of \ref
 * psa_export_key() for the formats.
 *
 * \param[in] p_key             A buffer containing the private key material
 * \param[in] key_size          The size in bytes of the `p_key` data
 * \param[in] alg               An asymmetric encryption algorithm that is
 *                              compatible with the type of `key`
 * \param[in] p_input           The message to decrypt
 * \param[in] input_length      Size of the `p_input` buffer in bytes
 * \param[in] p_salt            A salt or label, if supported by the
 *                              encryption algorithm
 *                              If the algorithm does not support a
 *                              salt, pass `NULL`.
 *                              If the algorithm supports an optional
 *                              salt and you do not want to pass a salt,
 *                              pass `NULL`.
 *                              For #PSA_ALG_RSA_PKCS1V15_CRYPT, no salt is
 *                              supported
 * \param[in] salt_length       Size of the `p_salt` buffer in bytes
 *                              If `p_salt` is `NULL`, pass 0
 * \param[out] p_output         Buffer where the decrypted message is to
 *                              be written
 * \param[in] output_size       Size of the `p_output` buffer in bytes
 * \param[out] p_output_length  On success, the number of bytes
 *                              that make up the returned output
 *
 * \retval PSA_SUCCESS
 */
typedef psa_status_t (*psa_drv_accel_asymmetric_decrypt_t)(const uint8_t *p_key,
                                                           size_t key_size,
                                                           psa_algorithm_t alg,
                                                           psa_key_type_t key_type,
                                                           const uint8_t *p_input,
                                                           size_t input_length,
                                                           const uint8_t *p_salt,
                                                           size_t salt_length,
                                                           uint8_t *p_output,
                                                           size_t output_size,
                                                           size_t *p_output_length);

/**@}*/

#ifdef __cplusplus
}
#endif

#endif /* PSA_CRYPTO_ACCEL_DRIVER_H */
