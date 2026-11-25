/*
 * librd - Rapid Development C library
 *
 * Copyright (c) 2012-2022, Magnus Edenhill
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef _RDRAND_H_
#define _RDRAND_H_

#if WITH_SSL
#include <openssl/crypto.h>
#if OPENSSL_VERSION_NUMBER >= 0x10101000L
#define HAVE_OSSL_SECURE_RAND_BYTES 1
#define HAVE_SECURE_RAND_BYTES      1
#endif
#endif
#ifndef HAVE_OSSL_SECURE_RAND_BYTES
#if HAVE_GETENTROPY || defined(_WIN32)
#define HAVE_SECURE_RAND_BYTES 1
#else
#define HAVE_SECURE_RAND_BYTES 0
#endif
#endif

/**
 * Returns a (non-secure) random seed for a pseudo-random number generator.
 */
unsigned int rd_seed();

/**
 * Fills \p buf with \p num cryptographically secure random bytes.
 *
 * @param buf Buffer to fill.
 * @param num Number of bytes to generate.
 *
 * @return rd_true on success, rd_false on failure.
 */
rd_bool_t rd_rand_bytes(unsigned char *buf, unsigned int num);

/**
 * Returns a random (using rand(3)) number between 'low'..'high' (inclusive).
 */
int rd_jitter(int low, int high);

/**
 * Shuffles (randomizes) an array using the modern Fisher-Yates algorithm.
 */
void rd_array_shuffle(void *base, size_t nmemb, size_t entry_size);

#endif /* _RDRAND_H_ */
