/**
 * \file
 * Functions and types for CRC checks.
 *
 * Generated on Wed Mar 18 12:41:20 2020
 * by pycrc v0.9.2, https://pycrc.org
 * using the configuration:
 *  - Width         = 32
 *  - Poly          = 0x04c11db7
 *  - XorIn         = 0xffffffff
 *  - ReflectIn     = True
 *  - XorOut        = 0xffffffff
 *  - ReflectOut    = True
 *  - Algorithm     = table-driven
 *  - SliceBy       = 8
 *
 * This file defines the functions crc_init(), crc_update() and crc_finalize().
 *
 * The crc_init() function returns the inital \c crc value and must be called
 * before the first call to crc_update().
 * Similarly, the crc_finalize() function must be called after the last call
 * to crc_update(), before the \c crc is being used.
 * is being used.
 *
 * The crc_update() function can be called any number of times (including zero
 * times) in between the crc_init() and crc_finalize() calls.
 *
 * This pseudo-code shows an example usage of the API:
 * \code{.c}
 * crc_t crc;
 * unsigned char data[MAX_DATA_LEN];
 * size_t data_len;
 *
 * crc = crc_init();
 * while ((data_len = read_data(data, MAX_DATA_LEN)) > 0) {
 *     crc = crc_update(crc, data, data_len);
 * }
 * crc = crc_finalize(crc);
 * \endcode
 */
#ifndef CRC32_H
#define CRC32_H

#include <stdlib.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif


/**
 * The definition of the used algorithm.
 *
 * This is not used anywhere in the generated code, but it may be used by the
 * application code to call algorithm-specific code, if desired.
 */
#define CRC_ALGO_TABLE_DRIVEN 1


/**
 * The type of the CRC values.
 *
 * This type must be big enough to contain at least 32 bits.
 */
typedef uint_fast32_t crc_t;


/**
 * Calculate the initial crc value.
 *
 * \return     The initial crc value.
 */
static inline crc_t crc_init(void)
{
    return 0xffffffff;
}


/**
 * Update the crc value with new data.
 *
 * \param[in] crc      The current crc value.
 * \param[in] data     Pointer to a buffer of \a data_len bytes.
 * \param[in] data_len Number of bytes in the \a data buffer.
 * \return             The updated crc value.
 */
crc_t crc_update(crc_t crc, const void *data, size_t data_len);


/* Patch by Fluent Bit Authors */

/**
 * crc_update() picks a hardware accelerated kernel at runtime when the CPU
 * has one (see crc32_dispatch.c). All kernels return the same value.
 */
#define CRC_ALGO_RUNTIME_DISPATCH 1

/**
 * Update the crc value with new data using the portable table-driven code,
 * regardless of what the CPU supports. Same contract as crc_update().
 */
crc_t crc_update_table(crc_t crc, const void *data, size_t data_len);

/**
 * Name of the kernel crc_update() runs on this machine: "table", "pclmul",
 * "avx512-vpclmulqdq", "armv8-crc32" or "armv8-crc32-pmull".
 */
const char *crc_backend(void);

/**
 * The value crc_update() returned on big-endian hosts before it was fixed to
 * compute the standard CRC-32 there. Not a CRC-32, and dependent on the
 * address of \a data modulo 8. Only for recognizing checksums stored by
 * those builds; returns the same value on any host.
 */
crc_t crc_update_legacy_big_endian(crc_t crc, const void *data,
                                   size_t data_len);


/**
 * Calculate the final crc value.
 *
 * \param[in] crc  The current crc value.
 * \return     The final crc value.
 */
static inline crc_t crc_finalize(crc_t crc)
{
    return crc ^ 0xffffffff;
}


#ifdef __cplusplus
}           /* closing brace for extern "C" */
#endif

#endif      /* CRC32_H */
