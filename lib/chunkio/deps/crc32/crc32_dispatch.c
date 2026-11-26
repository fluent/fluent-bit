/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Chunk I/O
 *  =========
 *  Copyright 2026 The Fluent Bit Authors
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

/*
 * Runtime selection of the CRC32 kernel behind crc_update().
 *
 * Every kernel computes the same CRC-32 (IEEE 802.3) the table code in
 * crc32.c does and works on the same un-finalized state, so the value stored
 * in a chunk does not depend on which one ran. The build decides which
 * kernels exist (see CMakeLists.txt), the CPU decides which one is used, and
 * a self-test against the table code has the last word: a kernel that
 * disagrees with it is never selected.
 */

#include "crc32.h"

#if defined(CRC32_SIMD_SSE42_PCLMUL) || defined(CRC32_SIMD_AVX512_PCLMUL) || \
    defined(CRC32_ARMV8_CRC32)
#define CRC_HAVE_SIMD
#include "crc32_simd.h"
#endif

typedef crc_t (*crc_update_fn)(crc_t crc, const void *data, size_t data_len);

static crc_t crc_update_resolve(crc_t crc, const void *data, size_t data_len);

/*
 * Concurrent first calls may all run the resolver; they all store the same
 * pointer, so the outcome does not depend on who wins. The accesses are
 * atomic so that is not a data race; a relaxed load costs the same as a plain
 * one. MSVC has no such builtin, there an aligned pointer access is atomic
 * on every supported target.
 */
static crc_update_fn crc_update_ptr = crc_update_resolve;

#if defined(__GNUC__) || defined(__clang__)
#define crc_ptr_load()    __atomic_load_n(&crc_update_ptr, __ATOMIC_RELAXED)
#define crc_ptr_store(fn) __atomic_store_n(&crc_update_ptr, fn, __ATOMIC_RELAXED)
#else
#define crc_ptr_load()    (crc_update_ptr)
#define crc_ptr_store(fn) (crc_update_ptr = (fn))
#endif

#if defined(CRC32_SIMD_SSE42_PCLMUL)

#if defined(_MSC_VER) && !defined(__clang__)
#include <intrin.h>
#include <immintrin.h>

static void x86_cpuid(int leaf, int subleaf, unsigned int *regs)
{
    int out[4];

    __cpuidex(out, leaf, subleaf);
    regs[0] = (unsigned int) out[0];
    regs[1] = (unsigned int) out[1];
    regs[2] = (unsigned int) out[2];
    regs[3] = (unsigned int) out[3];
}

static uint64_t x86_xgetbv(void)
{
    return _xgetbv(0);
}
#else
#include <cpuid.h>

static void x86_cpuid(int leaf, int subleaf, unsigned int *regs)
{
    __cpuid_count(leaf, subleaf, regs[0], regs[1], regs[2], regs[3]);
}

static uint64_t x86_xgetbv(void)
{
    unsigned int eax;
    unsigned int edx;

    /* xgetbv, spelled in bytes for assemblers that do not know it */
    __asm__(".byte 0x0f, 0x01, 0xd0" : "=a" (eax), "=d" (edx) : "c" (0));

    return ((uint64_t) edx << 32) | eax;
}
#endif

#define X86_PCLMUL   1
#define X86_AVX512   2

static int x86_features(void)
{
    int features = 0;
    unsigned int max_leaf;
    unsigned int regs[4];

    x86_cpuid(0, 0, regs);
    max_leaf = regs[0];
    if (max_leaf < 1) {
        return 0;
    }

    /* ecx: pclmulqdq (1), sse4.1 (19), sse4.2 (20), osxsave (27) */
    x86_cpuid(1, 0, regs);
    if ((regs[2] & (1u << 1)) && (regs[2] & (1u << 19)) &&
        (regs[2] & (1u << 20))) {
        features |= X86_PCLMUL;
    }

    if (!(features & X86_PCLMUL) || !(regs[2] & (1u << 27)) || max_leaf < 7) {
        return features;
    }

    /* The OS must save xmm, ymm, opmask and zmm state */
    if ((x86_xgetbv() & 0xe6) != 0xe6) {
        return features;
    }

    /* ebx: avx512f (16), ecx: vpclmulqdq (10) */
    x86_cpuid(7, 0, regs);
    if ((regs[1] & (1u << 16)) && (regs[2] & (1u << 10))) {
        features |= X86_AVX512;
    }

    return features;
}

static crc_t crc_update_pclmul(crc_t crc, const void *data, size_t data_len)
{
    size_t chunk;
    uint32_t state = (uint32_t) crc;
    const unsigned char *buf = (const unsigned char *) data;

    if (data_len >= Z_CRC32_SSE42_MINIMUM_LENGTH) {
        chunk = data_len & ~(size_t) Z_CRC32_SSE42_CHUNKSIZE_MASK;
        state = crc32_sse42_simd_(buf, chunk, state);
        buf += chunk;
        data_len -= chunk;
    }

    if (data_len == 0) {
        return state;
    }

    return crc_update_table(state, buf, data_len);
}

#if defined(CRC32_SIMD_AVX512_PCLMUL)
static crc_t crc_update_avx512(crc_t crc, const void *data, size_t data_len)
{
    size_t chunk;
    uint32_t state = (uint32_t) crc;
    const unsigned char *buf = (const unsigned char *) data;

    if (data_len >= Z_CRC32_AVX512_MINIMUM_LENGTH) {
        chunk = data_len & ~(size_t) Z_CRC32_AVX512_CHUNKSIZE_MASK;
        state = crc32_avx512_simd_(buf, chunk, state);
        buf += chunk;
        data_len -= chunk;
    }

    if (data_len == 0) {
        return state;
    }

    return crc_update_pclmul(state, buf, data_len);
}
#endif

#endif /* CRC32_SIMD_SSE42_PCLMUL */

#if defined(CRC32_ARMV8_CRC32)

#if defined(__linux__)
#include <sys/auxv.h>
#include <asm/hwcap.h>
#endif

#define ARM_CRC32   1
#define ARM_PMULL   2

static int arm_features(void)
{
#if defined(__APPLE__)
    /* Every Apple silicon core has both */
    return ARM_CRC32 | ARM_PMULL;
#elif defined(__linux__)
    int features = 0;
    unsigned long hwcap = getauxval(AT_HWCAP);

    if (hwcap & HWCAP_CRC32) {
        features |= ARM_CRC32;
    }

    if (hwcap & HWCAP_PMULL) {
        features |= ARM_PMULL;
    }

    return features;
#else
    return 0;
#endif
}

static crc_t crc_update_armv8(crc_t crc, const void *data, size_t data_len)
{
    uint32_t state = (uint32_t) crc;

    /* This kernel inverts on entry and on exit, undo both */
    return ~armv8_crc32_little((const unsigned char *) data, data_len,
                               ~state) & 0xffffffff;
}

static crc_t crc_update_armv8_pmull(crc_t crc, const void *data,
                                    size_t data_len)
{
    size_t chunk;
    uint32_t state = (uint32_t) crc;
    const unsigned char *buf = (const unsigned char *) data;

    if (data_len > Z_CRC32_PMULL_MINIMUM_LENGTH) {
        chunk = data_len & ~(size_t) Z_CRC32_PMULL_CHUNKSIZE_MASK;
        state = armv8_crc32_pmull_little(buf, chunk, state);
        buf += chunk;
        data_len -= chunk;
    }

    return crc_update_armv8(state, buf, data_len);
}

#endif /* CRC32_ARMV8_CRC32 */

#ifdef CRC_HAVE_SIMD
/*
 * Compare a kernel with the table code over lengths that cross every size
 * threshold of the kernels above, on an unaligned buffer and from a state
 * that is not the initial one.
 */
static int crc_self_test(crc_update_fn fn)
{
    static const size_t lengths[] = {1, 15, 16, 63, 64, 65, 127, 128, 129,
                                     255, 256, 257, 511, 777, 1031};
    size_t i;
    crc_t state = 0x5a17c0de;
    uint32_t seed = 0x2545f491;
    unsigned char buf[1032];

    for (i = 0; i < sizeof(buf); i++) {
        seed = seed * 1664525u + 1013904223u;
        buf[i] = (unsigned char) (seed >> 24);
    }

    for (i = 0; i < sizeof(lengths) / sizeof(lengths[0]); i++) {
        if (fn(state, buf + 1, lengths[i]) !=
            crc_update_table(state, buf + 1, lengths[i])) {
            return 0;
        }
    }

    return 1;
}
#endif

static crc_t crc_update_resolve(crc_t crc, const void *data, size_t data_len)
{
    crc_update_fn fn = crc_update_table;

#if defined(CRC32_SIMD_SSE42_PCLMUL)
    int features = x86_features();

    if (features & X86_PCLMUL) {
        fn = crc_update_pclmul;
    }

#if defined(CRC32_SIMD_AVX512_PCLMUL)
    if (features & X86_AVX512) {
        fn = crc_update_avx512;
    }
#endif

#elif defined(CRC32_ARMV8_CRC32)
    int features = arm_features();

    if (features & ARM_CRC32) {
        fn = crc_update_armv8;

        if (features & ARM_PMULL) {
            fn = crc_update_armv8_pmull;
        }
    }
#endif

#ifdef CRC_HAVE_SIMD
    if (fn != crc_update_table && !crc_self_test(fn)) {
        fn = crc_update_table;
    }
#endif

    crc_ptr_store(fn);

    return fn(crc, data, data_len);
}

crc_t crc_update(crc_t crc, const void *data, size_t data_len)
{
    crc_update_fn fn = crc_ptr_load();

    return fn(crc, data, data_len);
}

const char *crc_backend(void)
{
    crc_update_fn fn = crc_ptr_load();

    if (fn == crc_update_resolve) {
        crc_update(crc_init(), NULL, 0);
        fn = crc_ptr_load();
    }

#if defined(CRC32_SIMD_SSE42_PCLMUL)
    if (fn == crc_update_pclmul) {
        return "pclmul";
    }
#if defined(CRC32_SIMD_AVX512_PCLMUL)
    if (fn == crc_update_avx512) {
        return "avx512-vpclmulqdq";
    }
#endif
#elif defined(CRC32_ARMV8_CRC32)
    if (fn == crc_update_armv8) {
        return "armv8-crc32";
    }
    if (fn == crc_update_armv8_pmull) {
        return "armv8-crc32-pmull";
    }
#endif

    return "table";
}
