/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2026 The Fluent Bit Authors
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

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <limits.h>

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_mp.h>

#include <msgpack.h>
#include <mpack/mpack.h>

/*
 * Differential fuzzer for the serialized MessagePack helpers of flb_mp.
 *
 * The walker must give the answer of the two decoders bundled with Fluent
 * Bit, mpack and msgpack-c, and the log events scan must agree with the
 * walker. A disagreement is reported by aborting, the same way a memory
 * error is.
 */

/* mpack_discard() recurses: keep the nesting it can be given under control */
#define FUZZ_MPACK_MAX_SIZE     4096

/* nesting accepted by msgpack-c is 32 levels, stay below it */
#define FUZZ_MSGPACK_MAX_DEPTH  30

static void fuzz_check(int condition)
{
    if (!condition) {
        abort();
    }
}

/* the walker against mpack and msgpack-c */
static void fuzz_walker(const unsigned char *data, size_t size)
{
    int ret;
    int ret_limit;
    int ret_minimal;
    int ret_msgpack;
    size_t off = 0;
    size_t consumed = 0;
    const unsigned char *p;
    const unsigned char *end = data + size;
    mpack_reader_t reader;
    msgpack_sbuffer sbuf;
    msgpack_packer pck;
    msgpack_unpacked result;

    /* no depth limit */
    p = data;
    ret = flb_mp_raw_skip(&p, end, 0);

    if (ret == 0) {
        fuzz_check(p > data && p <= end);
        consumed = p - data;
    }
    else {
        fuzz_check(ret == -1 && p == data);
    }

    fuzz_check(flb_mp_raw_object_size((const char *) data, size, 0) == consumed);

    /* mpack: same verdict and same size */
    if (size <= FUZZ_MPACK_MAX_SIZE) {
        mpack_reader_init_data(&reader, (const char *) data, size);
        mpack_discard(&reader);

        if (mpack_reader_error(&reader) == mpack_ok) {
            fuzz_check(ret == 0);
            fuzz_check(size - mpack_reader_remaining(&reader, NULL) == consumed);
        }
        else {
            fuzz_check(ret == -1);
        }

        mpack_reader_destroy(&reader);
    }

    /* a depth limit can only turn a success into an error */
    p = data;
    ret_limit = flb_mp_raw_skip(&p, end, FLB_MP_RAW_MAX_DEPTH);

    if (ret_limit == 0) {
        fuzz_check(ret == 0 && (size_t) (p - data) == consumed);
    }
    else {
        fuzz_check(p == data);
    }

    /* minimal: a subset of what the walker accepts */
    p = data;
    ret_minimal = flb_mp_raw_skip_minimal(&p, end, 0);

    if (ret_minimal == 0) {
        fuzz_check(ret == 0 && (size_t) (p - data) == consumed);
    }
    else {
        fuzz_check(p == data);
    }

    /* msgpack-c: same size, and the same bytes for a minimal object */
    p = data;
    ret_limit = flb_mp_raw_skip(&p, end, FUZZ_MSGPACK_MAX_DEPTH);

    if (ret_limit != 0) {
        return;
    }

    msgpack_unpacked_init(&result);
    ret_msgpack = msgpack_unpack_next(&result, (const char *) data, size, &off);
    fuzz_check(ret_msgpack == MSGPACK_UNPACK_SUCCESS && off == consumed);

    if (ret_minimal == 0) {
        msgpack_sbuffer_init(&sbuf);
        msgpack_packer_init(&pck, &sbuf, msgpack_sbuffer_write);
        ret_msgpack = msgpack_pack_object(&pck, result.data);
        fuzz_check(ret_msgpack == 0 && sbuf.size == consumed &&
                   memcmp(sbuf.data, data, consumed) == 0);
        msgpack_sbuffer_destroy(&sbuf);
    }

    msgpack_unpacked_destroy(&result);
}

/* header readers: a success always leaves the cursor inside the buffer */
static void fuzz_headers(const unsigned char *data, size_t size)
{
    int ret;
    int ret_minimal;
    uint32_t count = 0;
    uint32_t length = 0;
    uint32_t length_minimal = 0;
    const unsigned char *p;
    const unsigned char *q;
    const unsigned char *end = data + size;

    p = data;
    ret = flb_mp_raw_map_header(&p, end, &count);

    if (ret == 0) {
        fuzz_check(p > data && p <= end);
    }
    else {
        fuzz_check(p == data);
    }

    p = data;
    ret = flb_mp_raw_str_header(&p, end, &length);

    if (ret == 0) {
        fuzz_check(p > data && p <= end && (size_t) (end - p) >= length);
    }
    else {
        fuzz_check(p == data);
    }

    q = data;
    ret_minimal = flb_mp_raw_str_header_minimal(&q, end, &length_minimal);

    if (ret_minimal == 0) {
        fuzz_check(ret == 0 && q == p && length_minimal == length);
    }
    else {
        fuzz_check(q == data);
    }
}

/* log events scan: an accepted buffer is a list of complete objects */
static void fuzz_scan(const unsigned char *data, size_t size)
{
    int ret;
    int ret_records;
    int records = 0;
    int records_only = 0;
    int markers = 0;
    int64_t objects = 0;
    const unsigned char *p = data;
    const unsigned char *end = data + size;

    ret = flb_mp_scan_log_events(data, size, &records, &markers);
    ret_records = flb_mp_scan_log_records(data, size, &records_only);
    fuzz_check(ret == ret_records);

    /*
     * A rejected buffer is left to the event decoder, which is not the
     * target here: msgpack-c allocates what a map or array header announces.
     */
    if (ret != 0) {
        return;
    }

    fuzz_check(records >= 0 && markers >= 0 && records == records_only);
    fuzz_check(flb_mp_count_log_records(data, size) == records);

    while (p < end) {
        fuzz_check(flb_mp_raw_skip(&p, end, 0) == 0);
        objects++;
    }

    fuzz_check(objects == (int64_t) records + (int64_t) markers);
}

int LLVMFuzzerTestOneInput(unsigned char *data, size_t size)
{
    unsigned char *copy;

    if (size == 0) {
        return 0;
    }

#ifdef FLB_HAVE_TESTS_OSSFUZZ
    /* no injected allocation failures: the checks compare results */
    flb_malloc_p = 0;
    flb_malloc_mod = INT_MAX;
#endif

    /* an exact size allocation lets the sanitizer see any read past the end */
    copy = malloc(size);

    if (copy == NULL) {
        return 0;
    }

    memcpy(copy, data, size);

    fuzz_walker(copy, size);
    fuzz_headers(copy, size);
    fuzz_scan(copy, size);

    free(copy);

    return 0;
}
