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
 * CRC32 benchmark. Build against a Release library:
 *
 *   cmake -S . -B /tmp/cio-release -DCMAKE_BUILD_TYPE=Release
 *   cmake --build /tmp/cio-release -j8
 *   cc -O3 -Iinclude -Ideps -Ideps/monkey/include -I/tmp/cio-release/include \
 *     tools/cio_bench_crc32.c /tmp/cio-release/src/libchunkio-static.a \
 *     /tmp/cio-release/deps/crc32/libcio-crc32.a -o /tmp/cio-bench-crc32
 *
 *   cio_bench_crc32 micro           compare checksum kernels by buffer size
 *   cio_bench_crc32 e2e [chunks] [bytes] [append]
 *                                   cost of CIO_CHECKSUM in write and load
 *
 * Every kernel in the "compatible" group computes the very same CRC-32
 * (IEEE 802.3, reflected polynomial 0xedb88320) that ChunkIO stores on disk,
 * and works on the un-finalized state so it can replace crc_update() one to
 * one. Before any timing the tool proves that by cross-checking each of them
 * against a bit-by-bit reference; a mismatch aborts the run. The "library"
 * row is cio_crc32_update() of whatever library the tool is linked against,
 * so linking the same source against two builds gives a before and after.
 *
 * Kernels in the "incompatible" group use a different function. Their numbers
 * are only there to show what a format change would buy.
 */
#define _GNU_SOURCE
#define _XOPEN_SOURCE 700
#include <assert.h>
#include <ftw.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <chunkio/chunkio.h>
#include <chunkio/cio_crc32.h>
#include <chunkio/cio_meta.h>

#if defined(__x86_64__) && (defined(__GNUC__) || defined(__clang__))
#define BENCH_X86_64 1
#include <immintrin.h>
#endif

#if defined(__aarch64__) && (defined(__GNUC__) || defined(__clang__))
#define BENCH_AARCH64 1
#include <arm_acle.h>
#if defined(__linux__)
#include <sys/auxv.h>
#include <asm/hwcap.h>
#endif
#endif

#define CRC32_POLY_REFLECTED   0xedb88320u
#define CRC32C_POLY_REFLECTED  0x82f63b78u

typedef uint32_t (*crc_fn)(uint32_t state, const unsigned char *data,
                           size_t len);

static uint32_t table[16][256];
static uint32_t table_c[256];

static double seconds(void)
{
    struct timespec now;

    clock_gettime(CLOCK_MONOTONIC, &now);

    return now.tv_sec + now.tv_nsec / 1e9;
}

static inline uint32_t load_le32(const unsigned char *p)
{
    return ((uint32_t) p[0]) | ((uint32_t) p[1] << 8) |
           ((uint32_t) p[2] << 16) | ((uint32_t) p[3] << 24);
}

static void tables_init(void)
{
    int bit;
    int slice;
    uint32_t i;
    uint32_t crc;
    uint32_t crc_c;

    for (i = 0; i < 256; i++) {
        crc = i;
        crc_c = i;
        for (bit = 0; bit < 8; bit++) {
            crc = (crc >> 1) ^ ((crc & 1) ? CRC32_POLY_REFLECTED : 0);
            crc_c = (crc_c >> 1) ^ ((crc_c & 1) ? CRC32C_POLY_REFLECTED : 0);
        }
        table[0][i] = crc;
        table_c[i] = crc_c;
    }

    for (slice = 1; slice < 16; slice++) {
        for (i = 0; i < 256; i++) {
            crc = table[slice - 1][i];
            table[slice][i] = (crc >> 8) ^ table[0][crc & 0xff];
        }
    }
}

/* Reference: one bit at a time, no tables. Only used to verify the others. */
static uint32_t crc32_bitwise(uint32_t crc, const unsigned char *data,
                              size_t len)
{
    int bit;

    while (len--) {
        crc ^= *data++;
        for (bit = 0; bit < 8; bit++) {
            crc = (crc >> 1) ^ ((crc & 1) ? CRC32_POLY_REFLECTED : 0);
        }
    }

    return crc;
}

/* Sarwate: one table lookup per byte */
static uint32_t crc32_bytewise(uint32_t crc, const unsigned char *data,
                               size_t len)
{
    while (len--) {
        crc = table[0][(crc ^ *data++) & 0xff] ^ (crc >> 8);
    }

    return crc;
}

/* Whatever the linked library does behind cio_crc32_update() */
static uint32_t crc32_library(uint32_t crc, const unsigned char *data,
                              size_t len)
{
    return (uint32_t) cio_crc32_update(crc, data, len);
}

/* Portable upgrade: slice-by-16, no alignment prologue */
static uint32_t crc32_slice16(uint32_t crc, const unsigned char *data,
                              size_t len)
{
    uint32_t a;
    uint32_t b;
    uint32_t c;
    uint32_t d;

    while (len >= 16) {
        a = load_le32(data) ^ crc;
        b = load_le32(data + 4);
        c = load_le32(data + 8);
        d = load_le32(data + 12);

        crc = table[15][a & 0xff] ^ table[14][(a >> 8) & 0xff] ^
              table[13][(a >> 16) & 0xff] ^ table[12][a >> 24] ^
              table[11][b & 0xff] ^ table[10][(b >> 8) & 0xff] ^
              table[9][(b >> 16) & 0xff] ^ table[8][b >> 24] ^
              table[7][c & 0xff] ^ table[6][(c >> 8) & 0xff] ^
              table[5][(c >> 16) & 0xff] ^ table[4][c >> 24] ^
              table[3][d & 0xff] ^ table[2][(d >> 8) & 0xff] ^
              table[1][(d >> 16) & 0xff] ^ table[0][d >> 24];

        data += 16;
        len -= 16;
    }

    return crc32_bytewise(crc, data, len);
}

#ifdef BENCH_X86_64
/*
 * Carry-less multiplication folding, after "Fast CRC Computation for Generic
 * Polynomials Using PCLMULQDQ Instruction" (Gopal et al., Intel, 2009). The
 * constants are x^n mod P for the bit-reflected IEEE polynomial; this is the
 * same scheme zlib-ng, Chromium's zlib and the Linux kernel use.
 *
 * It consumes 64 bytes per iteration in four independent 128-bit lanes, then
 * collapses the lanes and Barrett-reduces to 32 bits. Anything shorter than
 * 64 bytes and the sub-16-byte tail go through the table code.
 */
#define FOLD(lane, k, next)                                                 \
    _mm_xor_si128(_mm_xor_si128(_mm_clmulepi64_si128(lane, k, 0x00),        \
                                _mm_clmulepi64_si128(lane, k, 0x11)), next)

__attribute__((target("pclmul,sse4.1")))
static uint32_t crc32_pclmul(uint32_t crc, const unsigned char *data,
                             size_t len)
{
    const __m128i fold_512 = _mm_set_epi64x(0x01c6e41596, 0x0154442bd4);
    const __m128i fold_128 = _mm_set_epi64x(0x00ccaa009e, 0x01751997d0);
    const __m128i fold_64 = _mm_set_epi64x(0, 0x0163cd6124);
    const __m128i barrett = _mm_set_epi64x(0x01f7011641, 0x01db710641);
    const __m128i low_32 = _mm_setr_epi32(~0, 0, ~0, 0);
    __m128i x0;
    __m128i x1;
    __m128i x2;
    __m128i x3;
    __m128i tmp;

    if (len < 64) {
        return crc32_slice16(crc, data, len);
    }

    x0 = _mm_loadu_si128((const __m128i *) (data + 0));
    x1 = _mm_loadu_si128((const __m128i *) (data + 16));
    x2 = _mm_loadu_si128((const __m128i *) (data + 32));
    x3 = _mm_loadu_si128((const __m128i *) (data + 48));
    x0 = _mm_xor_si128(x0, _mm_cvtsi32_si128((int) crc));
    data += 64;
    len -= 64;

    while (len >= 64) {
        x0 = FOLD(x0, fold_512, _mm_loadu_si128((const __m128i *) (data + 0)));
        x1 = FOLD(x1, fold_512, _mm_loadu_si128((const __m128i *) (data + 16)));
        x2 = FOLD(x2, fold_512, _mm_loadu_si128((const __m128i *) (data + 32)));
        x3 = FOLD(x3, fold_512, _mm_loadu_si128((const __m128i *) (data + 48)));
        data += 64;
        len -= 64;
    }

    /* Four lanes into one */
    x0 = FOLD(x0, fold_128, x1);
    x0 = FOLD(x0, fold_128, x2);
    x0 = FOLD(x0, fold_128, x3);

    while (len >= 16) {
        x0 = FOLD(x0, fold_128, _mm_loadu_si128((const __m128i *) data));
        data += 16;
        len -= 16;
    }

    /* 128 -> 64 bits */
    tmp = _mm_clmulepi64_si128(x0, fold_128, 0x10);
    x0 = _mm_xor_si128(_mm_srli_si128(x0, 8), tmp);
    tmp = _mm_srli_si128(x0, 4);
    x0 = _mm_clmulepi64_si128(_mm_and_si128(x0, low_32), fold_64, 0x00);
    x0 = _mm_xor_si128(x0, tmp);

    /* Barrett reduction, 64 -> 32 bits */
    tmp = _mm_and_si128(x0, low_32);
    tmp = _mm_clmulepi64_si128(tmp, barrett, 0x10);
    tmp = _mm_and_si128(tmp, low_32);
    tmp = _mm_clmulepi64_si128(tmp, barrett, 0x00);
    x0 = _mm_xor_si128(x0, tmp);

    crc = (uint32_t) _mm_extract_epi32(x0, 1);

    return crc32_bytewise(crc, data, len);
}

/* CRC-32C (Castagnoli) through the SSE4.2 instruction: NOT the same checksum */
__attribute__((target("sse4.2")))
static uint32_t crc32c_sse42(uint32_t crc, const unsigned char *data,
                             size_t len)
{
    uint64_t wide = crc;
    uint64_t word;

    while (len >= 8) {
        memcpy(&word, data, 8);
        wide = _mm_crc32_u64(wide, word);
        data += 8;
        len -= 8;
    }

    crc = (uint32_t) wide;
    while (len--) {
        crc = _mm_crc32_u8(crc, *data++);
    }

    return crc;
}

static uint32_t crc32c_bytewise(uint32_t crc, const unsigned char *data,
                                size_t len)
{
    while (len--) {
        crc = table_c[(crc ^ *data++) & 0xff] ^ (crc >> 8);
    }

    return crc;
}
#endif

#ifdef BENCH_AARCH64
/*
 * ARMv8 CRC extension. Unlike x86, the ARM instruction set carries the IEEE
 * polynomial natively (crc32b/h/w/x), so this is format compatible.
 */
__attribute__((target("+crc")))
static uint32_t crc32_armv8(uint32_t crc, const unsigned char *data,
                            size_t len)
{
    uint64_t word;

    while (len >= 8) {
        memcpy(&word, data, 8);
        crc = __crc32d(crc, word);
        data += 8;
        len -= 8;
    }

    while (len--) {
        crc = __crc32b(crc, *data++);
    }

    return crc;
}
#endif

struct kernel {
    const char *name;
    const char *note;
    crc_fn fn;
    int compatible;
};

static struct kernel kernels[8];
static int kernel_count;

static void kernel_add(const char *name, const char *note, crc_fn fn,
                       int compatible)
{
    kernels[kernel_count].name = name;
    kernels[kernel_count].note = note;
    kernels[kernel_count].fn = fn;
    kernels[kernel_count].compatible = compatible;
    kernel_count++;
}

static void kernels_init(void)
{
    kernel_add("bytewise", "1 table, portable", crc32_bytewise, 1);
#ifdef CRC_ALGO_RUNTIME_DISPATCH
    kernel_add("library", crc_backend(), crc32_library, 1);
#else
    kernel_add("library", "table (slice-by-8)", crc32_library, 1);
#endif
    kernel_add("slice16", "16 tables, portable", crc32_slice16, 1);

#ifdef BENCH_X86_64
    __builtin_cpu_init();
    if (__builtin_cpu_supports("pclmul") &&
        __builtin_cpu_supports("sse4.1")) {
        kernel_add("pclmul", "x86-64 carry-less multiply", crc32_pclmul, 1);
    }

    if (__builtin_cpu_supports("sse4.2")) {
        kernel_add("crc32c-sse42", "different polynomial", crc32c_sse42, 0);
    }
#endif

#ifdef BENCH_AARCH64
#if defined(__linux__)
    if (getauxval(AT_HWCAP) & HWCAP_CRC32) {
        kernel_add("armv8-crc", "ARMv8 CRC extension", crc32_armv8, 1);
    }
#elif defined(__APPLE__)
    kernel_add("armv8-crc", "ARMv8 CRC extension", crc32_armv8, 1);
#endif
#endif
}

static uint64_t rng_state = 0x9e3779b97f4a7c15ull;

static uint64_t rng(void)
{
    rng_state ^= rng_state << 13;
    rng_state ^= rng_state >> 7;
    rng_state ^= rng_state << 17;

    return rng_state;
}

static void fill_random(unsigned char *buf, size_t len)
{
    size_t i;

    for (i = 0; i < len; i++) {
        buf[i] = (unsigned char) (rng() >> 32);
    }
}

/*
 * Compatible kernels must match the bit-by-bit reference for any start state,
 * any alignment, any length, and when the same data is fed in pieces: ChunkIO
 * keeps a running un-finalized state per chunk and extends it on every append.
 */
static void verify(void)
{
    int k;
    int round;
    size_t len;
    size_t offset;
    size_t split;
    uint32_t state;
    uint32_t expect;
    uint32_t got;
    unsigned char *buf;
    const size_t size = 8192;

    buf = malloc(size + 64);
    assert(buf != NULL);
    fill_random(buf, size + 64);

    /* The well known check value pins the reference itself */
    expect = crc32_bitwise(0xffffffff, (const unsigned char *) "123456789", 9);
    if ((expect ^ 0xffffffff) != 0xcbf43926) {
        fprintf(stderr, "reference crc32 is broken\n");
        exit(1);
    }

    for (k = 0; k < kernel_count; k++) {
        if (!kernels[k].compatible) {
            continue;
        }

        for (round = 0; round < 20000; round++) {
            offset = rng() % 64;
            len = round < 600 ? (size_t) round : rng() % size;
            state = round % 3 == 0 ? 0xffffffff : (uint32_t) rng();
            split = len ? rng() % (len + 1) : 0;

            expect = crc32_bitwise(state, buf + offset, len);
            got = kernels[k].fn(state, buf + offset, len);
            if (got != expect) {
                fprintf(stderr, "%s: mismatch len=%zu offset=%zu "
                        "got=%08x expected=%08x\n",
                        kernels[k].name, len, offset, got, expect);
                exit(1);
            }

            got = kernels[k].fn(state, buf + offset, split);
            got = kernels[k].fn(got, buf + offset + split, len - split);
            if (got != expect) {
                fprintf(stderr, "%s: incremental mismatch len=%zu split=%zu\n",
                        kernels[k].name, len, split);
                exit(1);
            }
        }
    }

#ifdef BENCH_X86_64
    for (k = 0; k < kernel_count; k++) {
        if (kernels[k].fn != crc32c_sse42) {
            continue;
        }

        for (round = 0; round < 2000; round++) {
            len = rng() % size;
            state = (uint32_t) rng();
            if (crc32c_sse42(state, buf, len) !=
                crc32c_bytewise(state, buf, len)) {
                fprintf(stderr, "crc32c-sse42: mismatch len=%zu\n", len);
                exit(1);
            }
        }
    }
#endif

    free(buf);
    printf("verify: all compatible kernels match the CRC-32 reference "
           "(20000 random cases each, split and unsplit)\n\n");
}

static volatile uint32_t sink;

/* Best throughput (MB/s) out of a few short timed windows */
static double measure(crc_fn fn, const unsigned char *buf, size_t len)
{
    int window;
    size_t i;
    size_t calls;
    uint32_t crc = 0xffffffff;
    double start;
    double elapsed;
    double rate;
    double best = 0;

    /* Size the batch so one window lasts roughly 40ms */
    calls = 1;
    for (;;) {
        start = seconds();
        for (i = 0; i < calls; i++) {
            crc = fn(crc, buf, len);
        }
        elapsed = seconds() - start;
        if (elapsed > 0.005 || calls > ((size_t) 1 << 30)) {
            break;
        }
        calls *= 4;
    }
    calls = (size_t) (calls * (0.04 / elapsed)) + 1;

    for (window = 0; window < 7; window++) {
        start = seconds();
        for (i = 0; i < calls; i++) {
            crc = fn(crc, buf, len);
        }
        elapsed = seconds() - start;
        rate = ((double) calls * len) / elapsed / 1e6;
        if (rate > best) {
            best = rate;
        }
    }
    sink = crc;

    return best;
}

static int run_micro(void)
{
    static const size_t sizes[] = {16, 64, 256, 1024, 4096, 65536, 2048000};
    const int size_count = sizeof(sizes) / sizeof(sizes[0]);
    int k;
    int s;
    int library = 1;
    double rates[8][8];
    unsigned char *buf;

    verify();

    buf = malloc(sizes[size_count - 1] + 1);
    assert(buf != NULL);
    fill_random(buf, sizes[size_count - 1] + 1);

    for (k = 0; k < kernel_count; k++) {
        for (s = 0; s < size_count; s++) {
            /* +1: appended records rarely start on an 8-byte boundary */
            rates[k][s] = measure(kernels[k].fn, buf + 1, sizes[s]);
        }
    }

    printf("throughput in MB/s (best of 7), buffer size in bytes\n");
    printf("%-16s", "kernel");
    for (s = 0; s < size_count; s++) {
        printf("%10zu", sizes[s]);
    }
    printf("\n");

    for (k = 0; k < kernel_count; k++) {
        printf("%-16s", kernels[k].name);
        for (s = 0; s < size_count; s++) {
            printf("%10.0f", rates[k][s]);
        }
        printf("   %s%s\n", kernels[k].compatible ? "" : "INCOMPATIBLE, ",
               kernels[k].note);
    }

    printf("\nspeedup over library\n");
    for (k = 0; k < kernel_count; k++) {
        if (k == library) {
            continue;
        }

        printf("%-16s", kernels[k].name);
        for (s = 0; s < size_count; s++) {
            printf("%9.2fx", rates[k][s] / rates[library][s]);
        }
        printf("\n");
    }

    free(buf);

    return 0;
}

static int remove_entry(const char *path, const struct stat *sb, int type,
                        struct FTW *ftw)
{
    (void) sb;
    (void) type;
    (void) ftw;

    return remove(path);
}

static int log_quiet(struct cio_ctx *ctx, int level, const char *file,
                     int line, char *str)
{
    (void) ctx;
    (void) level;
    (void) file;
    (void) line;
    (void) str;

    return 0;
}

/*
 * Write "chunks" chunks of "length" bytes in "append" sized writes, then
 * throw the context away and load everything back the way a restart with a
 * backlog does. Loading with CIO_CHECKSUM re-reads and verifies every byte.
 */
static void run_e2e_pass(int checksum, size_t chunks, size_t length,
                         size_t append, double *write_ms, double *load_ms)
{
    int err;
    size_t i;
    size_t written;
    size_t count;
    double start;
    char root[] = "/tmp/cio-crc32-bench-XXXXXX";
    char name[64];
    char *payload;
    struct cio_options opts;
    struct cio_ctx *ctx;
    struct cio_stream *st;
    struct cio_chunk *ch;

    payload = malloc(length);
    assert(payload != NULL);
    fill_random((unsigned char *) payload, length);
    assert(mkdtemp(root) != NULL);

    cio_options_init(&opts);
    opts.root_path = root;
    opts.log_cb = log_quiet;
    if (checksum) {
        opts.flags |= CIO_CHECKSUM;
    }

    ctx = cio_create(&opts);
    assert(ctx != NULL);
    cio_set_max_chunks_up(ctx, (int) chunks + 1);
    st = cio_stream_create(ctx, "bench", CIO_STORE_FS);
    assert(st != NULL);

    start = seconds();
    for (i = 0; i < chunks; i++) {
        snprintf(name, sizeof(name), "chunk-%zu", i);
        ch = cio_chunk_open(ctx, st, name, CIO_OPEN, length, &err);
        assert(ch != NULL && err == CIO_OK);
        for (written = 0; written < length; written += count) {
            count = length - written < append ? length - written : append;
            err = cio_chunk_write(ch, payload + written, count);
            assert(err == CIO_OK);
        }
        err = cio_chunk_sync(ch);
        assert(err == CIO_OK);
        cio_chunk_close(ch, CIO_FALSE);
    }
    *write_ms = (seconds() - start) * 1000;
    cio_destroy(ctx);

    ctx = cio_create(&opts);
    assert(ctx != NULL);
    cio_set_max_chunks_up(ctx, (int) chunks + 1);

    start = seconds();
    err = cio_load(ctx, NULL);
    assert(err == 0);
    *load_ms = (seconds() - start) * 1000;
    assert(ctx->total_chunks == chunks);
    assert(ctx->total_chunks_up == chunks);
    cio_destroy(ctx);

    nftw(root, remove_entry, 16, FTW_DEPTH | FTW_PHYS);
    free(payload);
}

static int run_e2e(size_t chunks, size_t length, size_t append)
{
    int pass;
    int checksum;
    double write_ms;
    double load_ms;
    double best_write[2] = {0, 0};
    double best_load[2] = {0, 0};
    double megabytes = (double) chunks * length / 1e6;

    for (pass = 0; pass < 5; pass++) {
        for (checksum = 0; checksum < 2; checksum++) {
            run_e2e_pass(checksum, chunks, length, append,
                         &write_ms, &load_ms);
            if (pass == 0 || write_ms < best_write[checksum]) {
                best_write[checksum] = write_ms;
            }
            if (pass == 0 || load_ms < best_load[checksum]) {
                best_load[checksum] = load_ms;
            }
        }
    }

    printf("e2e: %zu chunks x %zu bytes, %zu byte appends (%.0f MB), "
           "best of 5\n", chunks, length, append, megabytes);
    printf("%-22s%12s%12s%12s\n", "", "no checksum", "checksum", "crc share");
    printf("%-22s%10.1fms%10.1fms%11.0f%%\n", "write + sync + close",
           best_write[0], best_write[1],
           100 * (best_write[1] - best_write[0]) / best_write[1]);
    printf("%-22s%10.1fms%10.1fms%11.0f%%\n", "load (restart)",
           best_load[0], best_load[1],
           100 * (best_load[1] - best_load[0]) / best_load[1]);
    printf("implied crc rate: write %.0f MB/s, load %.0f MB/s\n",
           megabytes / ((best_write[1] - best_write[0]) / 1000),
           megabytes / ((best_load[1] - best_load[0]) / 1000));

    return 0;
}

int main(int argc, char **argv)
{
    size_t chunks = 100;
    size_t length = 2048000;
    size_t append = 4096;

    tables_init();
    kernels_init();

    if (argc >= 2 && strcmp(argv[1], "micro") == 0) {
        return run_micro();
    }

    if (argc >= 2 && strcmp(argv[1], "e2e") == 0) {
        if (argc > 2) {
            chunks = strtoull(argv[2], NULL, 10);
        }
        if (argc > 3) {
            length = strtoull(argv[3], NULL, 10);
        }
        if (argc > 4) {
            append = strtoull(argv[4], NULL, 10);
        }
        assert(chunks > 0 && length > 0 && append > 0);

        return run_e2e(chunks, length, append);
    }

    fprintf(stderr, "Usage: %s micro | e2e [chunks] [bytes] [append]\n",
            argv[0]);

    return 1;
}
