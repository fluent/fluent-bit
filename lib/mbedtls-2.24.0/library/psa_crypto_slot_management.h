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

#ifndef PSA_CRYPTO_SLOT_MANAGEMENT_H
#define PSA_CRYPTO_SLOT_MANAGEMENT_H

#include "psa/crypto.h"
#include "psa_crypto_se.h"

/* Number of key slots (plus one because 0 is not used).
 * The value is a compile-time constant for now, for simplicity. */
#define PSA_KEY_SLOT_COUNT 32

/** Access a key slot at the given handle.
 *
 * \param handle        Key handle to query.
 * \param[out] p_slot   On success, `*p_slot` contains a pointer to the
 *                      key slot in memory designated by \p handle.
 *
 * \retval PSA_SUCCESS
 *         Success: \p handle is a handle to `*p_slot`. Note that `*p_slot`
 *         may be empty or occupied.
 * \retval PSA_ERROR_INVALID_HANDLE
 *         \p handle is out of range or is not in use.
 * \retval PSA_ERROR_BAD_STATE
 *         The library has not been initialized.
 */
psa_status_t psa_get_key_slot( psa_key_handle_t handle,
                               psa_key_slot_t **p_slot );

/** Initialize the key slot structures.
 *
 * \retval PSA_SUCCESS
 *         Currently this function always succeeds.
 */
psa_status_t psa_initialize_key_slots( void );

/** Delete all data from key slots in memory.
 *
 * This does not affect persistent storage. */
void psa_wipe_all_key_slots( void );

/** Find a free key slot.
 *
 * This function returns a key slot that is available for use and is in its
 * ground state (all-bits-zero).
 *
 * \param[out] handle   On success, a slot number that can be used as a
 *                      handle to the slot.
 * \param[out] p_slot   On success, a pointer to the slot.
 *
 * \retval #PSA_SUCCESS
 * \retval #PSA_ERROR_INSUFFICIENT_MEMORY
 * \retval #PSA_ERROR_BAD_STATE
 */
psa_status_t psa_get_empty_key_slot( psa_key_handle_t *handle,
                                     psa_key_slot_t **p_slot );

/** Test whether a lifetime designates a key in an external cryptoprocessor.
 *
 * \param lifetime      The lifetime to test.
 *
 * \retval 1
 *         The lifetime designates an external key. There should be a
 *         registered driver for this lifetime, otherwise the key cannot
 *         be created or manipulated.
 * \retval 0
 *         The lifetime designates a key that is volatile or in internal
 *         storage.
 */
static inline int psa_key_lifetime_is_external( psa_key_lifetime_t lifetime )
{
    return( PSA_KEY_LIFETIME_GET_LOCATION( lifetime )
                != PSA_KEY_LOCATION_LOCAL_STORAGE );
}

/** Validate a key's location.
 *
 * This function checks whether the key's attributes point to a location that
 * is known to the PSA Core, and returns the driver function table if the key
 * is to be found in an external location.
 *
 * \param[in] lifetime      The key lifetime attribute.
 * \param[out] p_drv        On success, when a key is located in external
 *                          storage, returns a pointer to the driver table
 *                          associated with the key's storage location.
 *
 * \retval #PSA_SUCCESS
 * \retval #PSA_ERROR_INVALID_ARGUMENT
 */
psa_status_t psa_validate_key_location( psa_key_lifetime_t lifetime,
                                        psa_se_drv_table_entry_t **p_drv );

/** Validate that a key's persistence attributes are valid.
 *
 * This function checks whether a key's declared persistence level and key ID
 * attributes are valid and known to the PSA Core in its actual configuration.
 *
 * \param[in] lifetime    The key lifetime attribute.
 * \param[in] key_id      The key ID attribute
 *
 * \retval #PSA_SUCCESS
 * \retval #PSA_ERROR_INVALID_ARGUMENT
 */
psa_status_t psa_validate_key_persistence( psa_key_lifetime_t lifetime,
                                           psa_key_id_t key_id );


#endif /* PSA_CRYPTO_SLOT_MANAGEMENT_H */
