/* crc32_simd.h
 *
 * Copyright 2017 The Chromium Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in LICENSE.chromium.
 *
 * Adapted for Chunk I/O by the Fluent Bit Authors. crc32_simd.c is a copy of
 * chromium/src/third_party/zlib/crc32_simd.c (main, November 2026) with one
 * marked fix in crc32_avx512_simd_(); this header replaces the original one
 * so the kernels build without the rest of zlib:
 *
 *  - the zconf.h, zutil.h and deflate.h includes are gone, the three names
 *    crc32_simd.c takes from them are defined here instead.
 *  - the exported symbols carry a cio_ prefix so they cannot collide with a
 *    zlib that ships the same file.
 *
 * Callers must go through crc_update() in crc32_dispatch.c, which checks the
 * CPU at runtime and honors the length constraints documented below.
 */
#ifndef CIO_CRC32_SIMD_H
#define CIO_CRC32_SIMD_H

#include <stddef.h>
#include <stdint.h>

#define ZLIB_INTERNAL
typedef size_t z_size_t;

#if defined(_MSC_VER) && !defined(__clang__)
#define zalign(x) __declspec(align(x))
#else
#define zalign(x) __attribute__((aligned(x)))
#endif

#if defined(__APPLE__) && defined(__aarch64__)
#define ARMV8_OS_MACOS
#endif

#define crc32_sse42_simd_         cio_crc32_sse42_simd_
#define crc32_avx512_simd_        cio_crc32_avx512_simd_
#define armv8_crc32_little        cio_armv8_crc32_little
#define armv8_crc32_pmull_little  cio_armv8_crc32_pmull_little

/*
 * crc32_sse42_simd_(): compute the crc32 of the buffer, where the buffer
 * length must be at least 64, and a multiple of 16. Takes and returns the
 * un-finalized crc.
 */
uint32_t ZLIB_INTERNAL crc32_sse42_simd_(const unsigned char* buf,
                                         z_size_t len,
                                         uint32_t crc);

/*
 * crc32_avx512_simd_(): same contract, the buffer length must be at least
 * 256, and a multiple of 64.
 */
uint32_t ZLIB_INTERNAL crc32_avx512_simd_(const unsigned char* buf,
                                          z_size_t len,
                                          uint32_t crc);

#define Z_CRC32_SSE42_MINIMUM_LENGTH 64
#define Z_CRC32_SSE42_CHUNKSIZE_MASK 15
#define Z_CRC32_AVX512_MINIMUM_LENGTH 256
#define Z_CRC32_AVX512_CHUNKSIZE_MASK 63

/*
 * CRC32 checksums using ARMv8-a crypto instructions. Any length. Unlike the
 * other kernels this one takes and returns the *finalized* crc: it inverts
 * the value on the way in and on the way out.
 */
uint32_t ZLIB_INTERNAL armv8_crc32_little(const unsigned char* buf,
                                          z_size_t len,
                                          uint32_t crc);

/* aarch64 specific code. */
#if defined(__aarch64__)

/* 128 is the sweet spot at the time of coding (late 2020). */
#define Z_CRC32_PMULL_MINIMUM_LENGTH 128
#define Z_CRC32_PMULL_CHUNKSIZE_MASK 15

/*
 * CRC32 checksums using ARMv8-a PMULL instructions, where the buffer
 * length must be at least 64, and a multiple of 16. Takes and returns the
 * un-finalized crc.
 */
uint32_t ZLIB_INTERNAL armv8_crc32_pmull_little(const unsigned char* buf,
                                                z_size_t len,
                                                uint32_t crc);

#endif

#endif
