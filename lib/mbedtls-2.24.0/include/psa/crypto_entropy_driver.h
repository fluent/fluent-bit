/**
 * \file psa/crypto_entropy_driver.h
 * \brief PSA entropy source driver module
 *
 * This header declares types and function signatures for entropy sources.
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
#ifndef PSA_CRYPTO_ENTROPY_DRIVER_H
#define PSA_CRYPTO_ENTROPY_DRIVER_H

#include "crypto_driver_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/** \defgroup driver_rng Entropy Generation
 */
/**@{*/

/** \brief Initialize an entropy driver
 *
 *
 * \param[in,out] p_context             A hardware-specific structure
 *                                      containing any context information for
 *                                      the implementation
 *
 * \retval PSA_SUCCESS
 */
typedef psa_status_t (*psa_drv_entropy_init_t)(void *p_context);

/** \brief Get a specified number of bits from the entropy source
 *
 * It retrives `buffer_size` bytes of data from the entropy source. The entropy
 * source will always fill the provided buffer to its full size, however, most
 * entropy sources have biases, and the actual amount of entropy contained in
 * the buffer will be less than the number of bytes.
 * The driver will return the actual number of bytes of entropy placed in the
 * buffer in `p_received_entropy_bytes`.
 * A PSA Crypto API implementation will likely feed the output of this function
 * into a Digital Random Bit Generator (DRBG), and typically has a minimum
 * amount of entropy that it needs.
 * To accomplish this, the PSA Crypto implementation should be designed to call
 * this function multiple times until it has received the required amount of
 * entropy from the entropy source.
 *
 * \param[in,out] p_context                 A hardware-specific structure
 *                                          containing any context information
 *                                          for the implementation
 * \param[out] p_buffer                     A caller-allocated buffer for the
 *                                          retrieved entropy to be placed in
 * \param[in] buffer_size                   The allocated size of `p_buffer`
 * \param[out] p_received_entropy_bits      The amount of entropy (in bits)
 *                                          actually provided in `p_buffer`
 *
 * \retval PSA_SUCCESS
 */
typedef psa_status_t (*psa_drv_entropy_get_bits_t)(void *p_context,
                                                   uint8_t *p_buffer,
                                                   uint32_t buffer_size,
                                                   uint32_t *p_received_entropy_bits);

/**
 * \brief A struct containing all of the function pointers needed to interface
 * to an entropy source
 *
 * PSA Crypto API implementations should populate instances of the table as
 * appropriate upon startup.
 *
 * If one of the functions is not implemented, it should be set to NULL.
 */
typedef struct {
    /** The driver-specific size of the entropy context */
    const size_t                context_size;
    /** Function that performs initialization for the entropy source */
    psa_drv_entropy_init_t      p_init;
    /** Function that performs the get_bits operation for the entropy source */
    psa_drv_entropy_get_bits_t  p_get_bits;
} psa_drv_entropy_t;
/**@}*/

#ifdef __cplusplus
}
#endif

#endif /* PSA_CRYPTO_ENTROPY_DRIVER_H */
