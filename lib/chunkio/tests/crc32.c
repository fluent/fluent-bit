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

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <chunkio/cio_crc32.h>

#include "cio_tests_internal.h"

#define BUF_SIZE  4096
#define BUF_SLACK 64

static unsigned char buf[BUF_SIZE + BUF_SLACK];
static uint32_t seed = 0x1234abcd;

static uint32_t next_random(void)
{
    seed ^= seed << 13;
    seed ^= seed >> 17;
    seed ^= seed << 5;

    return seed;
}

static void fill_buffer(void)
{
    size_t i;

    for (i = 0; i < sizeof(buf); i++) {
        buf[i] = (unsigned char) (next_random() >> 16);
    }
}

/* One bit at a time: shares no code and no tables with the library */
static crc_t crc_reference(crc_t crc, const unsigned char *data, size_t len)
{
    int bit;

    while (len--) {
        crc ^= *data++;
        for (bit = 0; bit < 8; bit++) {
            crc = (crc >> 1) ^ ((crc & 1) ? 0xedb88320 : 0);
        }
    }

    return crc;
}

static uint32_t crc_of(const char *str)
{
    crc_t crc;

    crc = cio_crc32_init();
    crc = cio_crc32_update(crc, str, strlen(str));

    return (uint32_t) cio_crc32_finalize(crc);
}

/* Values every CRC-32 (IEEE 802.3) implementation must produce */
static void test_known_values(void)
{
    size_t i;
    crc_t crc;
    unsigned char zeros[1024];
    char letters[1041];

    printf("crc32 backend: %s\n", crc_backend());

    TEST_CHECK(crc_of("") == 0x00000000);
    TEST_CHECK(crc_of("a") == 0xe8b7be43);
    TEST_CHECK(crc_of("123456789") == 0xcbf43926);
    TEST_CHECK(crc_of("The quick brown fox jumps over the lazy dog") ==
               0x414fa339);

    /* Long enough for every accelerated kernel to engage */
    memset(zeros, 0, sizeof(zeros));
    crc = cio_crc32_update(cio_crc32_init(), zeros, sizeof(zeros));
    TEST_CHECK((uint32_t) cio_crc32_finalize(crc) == 0xefb5af2e);

    for (i = 0; i < sizeof(letters) - 1; i++) {
        letters[i] = (char) ('a' + (i % 26));
    }
    letters[sizeof(letters) - 1] = '\0';
    crc = crc_reference(cio_crc32_init(), (unsigned char *) letters,
                        sizeof(letters) - 1);
    TEST_CHECK(crc_of(letters) == (uint32_t) cio_crc32_finalize(crc));
}

/*
 * The checksum stored in a chunk must not depend on the kernel that computed
 * it: sweep every length across the kernel size thresholds, at every
 * alignment, from arbitrary states.
 */
static void test_matches_reference(void)
{
    size_t len;
    size_t offset;
    int round;
    crc_t state;
    crc_t expect;

    fill_buffer();

    for (len = 0; len <= 1100; len++) {
        for (offset = 0; offset < 16; offset++) {
            state = (len + offset) % 3 == 0 ? cio_crc32_init() : next_random();
            expect = crc_reference(state, buf + offset, len);

            if (!TEST_CHECK(cio_crc32_update(state, buf + offset, len) ==
                            expect)) {
                TEST_MSG("len=%zu offset=%zu", len, offset);
                return;
            }

            if (!TEST_CHECK(crc_update_table(state, buf + offset, len) ==
                            expect)) {
                TEST_MSG("table: len=%zu offset=%zu", len, offset);
                return;
            }
        }
    }

    for (round = 0; round < 20000; round++) {
        len = next_random() % BUF_SIZE;
        offset = next_random() % BUF_SLACK;
        state = next_random();

        if (!TEST_CHECK(cio_crc32_update(state, buf + offset, len) ==
                        crc_reference(state, buf + offset, len))) {
            TEST_MSG("len=%zu offset=%zu", len, offset);
            return;
        }
    }
}

/* Chunks are checksummed one append at a time */
static void test_incremental(void)
{
    int round;
    size_t len;
    size_t pos;
    size_t step;
    crc_t whole;
    crc_t pieces;

    fill_buffer();

    for (round = 0; round < 2000; round++) {
        len = next_random() % BUF_SIZE;
        whole = cio_crc32_update(cio_crc32_init(), buf, len);

        pieces = cio_crc32_init();
        for (pos = 0; pos < len; pos += step) {
            step = next_random() % 700;
            if (step > len - pos) {
                step = len - pos;
            }
            pieces = cio_crc32_update(pieces, buf + pos, step);
        }

        if (!TEST_CHECK(pieces == whole)) {
            TEST_MSG("len=%zu", len);
            return;
        }
    }
}

/*
 * Big-endian builds used to compute something else than CRC-32. Chunks they
 * wrote are still recognized through crc_update_legacy_big_endian(), which
 * has to keep returning what those builds returned. The expected values were
 * captured from crc_update() of ChunkIO v1.5.5 on s390x, for this same data
 * at these offsets from an 8-byte aligned address.
 */
static void test_legacy_big_endian(void)
{
    static const struct {
        size_t offset;
        size_t len;
        uint32_t expect;
    } cases[] = {
        {0,    9, 0x49da06cd}, {0,  100, 0x17bb712a}, {0, 1000, 0x639ecd36},
        {3,    9, 0xcad326cd}, {3,  100, 0x9ecfe048}, {3, 1000, 0xa6eb6276},
        {5,    9, 0x5e2989dc}, {5,  100, 0x23341c19}, {5, 1000, 0xc1184f28}
    };
    static union {
        uint64_t align;
        unsigned char bytes[1024];
    } data;
    size_t i;
    uint32_t value = 0x1234abcd;
    crc_t crc;

    for (i = 0; i < sizeof(data.bytes); i++) {
        value ^= value << 13;
        value ^= value >> 17;
        value ^= value << 5;
        data.bytes[i] = (unsigned char) (value >> 16);
    }

    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        crc = crc_update_legacy_big_endian(cio_crc32_init(),
                                           data.bytes + cases[i].offset,
                                           cases[i].len);
        if (!TEST_CHECK((uint32_t) crc == cases[i].expect)) {
            TEST_MSG("offset=%zu len=%zu got=%08x", cases[i].offset,
                     cases[i].len, (uint32_t) crc);
        }
    }

    /* Shorter than one 8-byte step it is the plain CRC-32 */
    crc = crc_update_legacy_big_endian(cio_crc32_init(), "1234567", 7);
    TEST_CHECK((uint32_t) cio_crc32_finalize(crc) == 0x5003699f);
}

TEST_LIST = {
    {"known_values",      test_known_values},
    {"matches_reference", test_matches_reference},
    {"incremental",       test_incremental},
    {"legacy_big_endian", test_legacy_big_endian},
    {NULL, NULL}
};
