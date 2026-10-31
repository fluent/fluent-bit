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

#define _GNU_SOURCE

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <chunkio/chunkio.h>
#include <chunkio/cio_file_native.h>
#include <chunkio/cio_memfs.h>
#include <chunkio/cio_meta.h>
#include <chunkio/cio_utils.h>
#include "cio_tests_internal.h"

#define ROOT "tmp-allocation-test"

#ifdef CIO_TEST_ALLOCATION_CALLS
#include <sys/mman.h>
static size_t resize_limit;
static int resize_failure;
static int shrink_failure;
static int remap_failure;
static int map_failure;
static size_t map_limit;
static int stat_failure;
static int realloc_failure;
static size_t resize_calls;
static size_t realloc_calls;

int __real_cio_file_native_resize(struct cio_file *cf, size_t size);
int __real_cio_file_native_remap(struct cio_file *cf, size_t size);
int __real_cio_file_native_get_size(struct cio_file *cf, size_t *size);
void *__real_mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
void *__real_realloc(void *ptr, size_t size);
void *__real_mremap(void *ptr, size_t old_size, size_t new_size, int flags, ...);

void *__wrap_mremap(void *ptr, size_t old_size, size_t new_size, int flags, ...)
{
    if (map_failure) {
        errno = ENOMEM;
        return MAP_FAILED;
    }

    return __real_mremap(ptr, old_size, new_size, flags);
}

int __wrap_cio_file_native_resize(struct cio_file *cf, size_t size)
{
    resize_calls++;
    if (resize_failure || (shrink_failure && size < cf->fs_size) ||
        (resize_limit && size > resize_limit)) {
        errno = ENOSPC;
        return CIO_ERROR;
    }

    return __real_cio_file_native_resize(cf, size);
}

int __wrap_cio_file_native_remap(struct cio_file *cf, size_t size)
{
    if (remap_failure) {
        errno = ENOMEM;
        return CIO_ERROR;
    }

    return __real_cio_file_native_remap(cf, size);
}

int __wrap_cio_file_native_get_size(struct cio_file *cf, size_t *size)
{
    if (stat_failure) {
        errno = EIO;
        return CIO_ERROR;
    }

    return __real_cio_file_native_get_size(cf, size);
}

void *__wrap_mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset)
{
    if (map_failure || (map_limit && length > map_limit)) {
        errno = ENOMEM;
        return MAP_FAILED;
    }

    return __real_mmap(addr, length, prot, flags, fd, offset);
}

void *__wrap_realloc(void *ptr, size_t size)
{
    realloc_calls++;
    if (realloc_failure || (resize_limit && size > resize_limit)) {
        errno = ENOMEM;
        return NULL;
    }

    return __real_realloc(ptr, size);
}
#endif

static void reset_faults(void)
{
#ifdef CIO_TEST_ALLOCATION_CALLS
    resize_limit = 0;
    resize_failure = 0;
    shrink_failure = 0;
    remap_failure = 0;
    map_failure = 0;
    map_limit = 0;
    stat_failure = 0;
    realloc_failure = 0;
    resize_calls = 0;
    realloc_calls = 0;
#endif
}

static struct cio_ctx *context(int flags)
{
    struct cio_options opts;
    struct cio_ctx *ctx;

    cio_options_init(&opts);
    opts.root_path = ROOT;
    opts.flags = CIO_OPEN | flags;
    ctx = cio_create(&opts);
    TEST_CHECK(ctx != NULL);
    if (!ctx) {
        exit(EXIT_FAILURE);
    }

    return ctx;
}

static struct cio_chunk *open_chunk(struct cio_ctx *ctx, struct cio_stream *st,
                                    const char *name, size_t size, int flags)
{
    int err = 123;
    struct cio_chunk *ch;

    TEST_CHECK(st != NULL);
    ch = cio_chunk_open(ctx, st, name, flags, size, &err);
    TEST_CHECK(ch != NULL);
    TEST_CHECK(err == CIO_OK);
    if (!ch) {
        exit(EXIT_FAILURE);
    }

    return ch;
}

static void check_content(struct cio_chunk *ch, const void *expected, size_t length)
{
    char *data;
    size_t size;
    int ret;

    ret = cio_chunk_get_content(ch, &data, &size);
    TEST_CHECK(ret == CIO_OK);
    if (ret == CIO_OK) {
        TEST_CHECK(size == length);
        if (size == length && length > 0) {
            TEST_CHECK(memcmp(data, expected, length) == 0);
        }
    }
}

static void test_open_size(void)
{
    int i;
    int err;
    size_t size;
    size_t expected;
    size_t page;
    size_t hints[10];
    char name[32];
    struct cio_ctx *ctx;
    struct cio_stream *st;
    struct cio_chunk *ch;
    struct cio_file *cf;

    cio_utils_recursive_delete(ROOT);
    ctx = context(CIO_CHECKSUM);
    st = cio_stream_create(ctx, "fs", CIO_STORE_FS);
    page = ctx->page_size;
    hints[0] = 0;
    hints[1] = 1;
    hints[2] = 23;
    hints[3] = 24;
    hints[4] = 25;
    hints[5] = page - 1;
    hints[6] = page;
    hints[7] = page + 1;
    hints[8] = 262144;
    hints[9] = 1000003;
    for (i = 0; i < 10; i++) {
        snprintf(name, sizeof(name), "c-%i", i);
        ch = open_chunk(ctx, st, name, hints[i], CIO_OPEN);
        cf = ch->backend;
        expected = hints[i] < CIO_FILE_HEADER_MIN ? CIO_FILE_HEADER_MIN : hints[i];
        expected = ((expected + page - 1) / page) * page;
        TEST_CHECK(cf->alloc_size == expected);
        TEST_CHECK(cio_file_native_get_size(cf, &size) == CIO_OK);
        TEST_CHECK(size == expected);
        TEST_CHECK(cio_chunk_get_real_size(ch) == expected);
        check_content(ch, "", 0);
        TEST_CHECK(cio_chunk_down(ch) == CIO_OK);
        TEST_CHECK(cio_chunk_up(ch) == CIO_OK);
        TEST_CHECK(cf->alloc_size == expected);
        check_content(ch, "", 0);
        cio_chunk_close(ch, CIO_FALSE);

        /* An existing file is never resized to a new opening hint, even huge. */
        ch = open_chunk(ctx, st, name, SIZE_MAX, CIO_OPEN_RD);
        TEST_CHECK(((struct cio_file *) ch->backend)->alloc_size == expected);
        check_content(ch, "", 0);
        cio_chunk_close(ch, CIO_FALSE);
        ch = open_chunk(ctx, st, name, 1, CIO_OPEN);
        TEST_CHECK(((struct cio_file *) ch->backend)->alloc_size == expected);
        cio_chunk_close(ch, CIO_TRUE);
    }

    ch = cio_chunk_open(ctx, st, "overflow", CIO_OPEN, SIZE_MAX, &err);
    TEST_CHECK(ch == NULL);
    TEST_CHECK(err == CIO_ERROR);
    TEST_CHECK(ctx->total_chunks == 0);
    TEST_CHECK(ctx->total_chunks_up == 0);
    cio_destroy(ctx);
    cio_utils_recursive_delete(ROOT);
}

static void test_deferred_open(void)
{
    size_t projected;
    struct cio_ctx *ctx;
    struct cio_stream *st;
    struct cio_chunk *live;
    struct cio_chunk *ch;
    struct cio_file *cf;

    cio_utils_recursive_delete(ROOT);
    ctx = context(CIO_CHECKSUM);
    TEST_CHECK(cio_set_max_chunks_up(ctx, 1) == CIO_OK);
    st = cio_stream_create(ctx, "fs", CIO_STORE_FS);
    live = open_chunk(ctx, st, "live", 4096, CIO_OPEN);
    ch = open_chunk(ctx, st, "deferred", 262144, CIO_OPEN);
    cf = ch->backend;
    TEST_CHECK(cio_chunk_is_up(ch) == CIO_FALSE);
    TEST_CHECK(cio_file_native_is_open(cf) == CIO_FALSE);
    TEST_CHECK(cio_chunk_get_projected_size(ch, 1, &projected) == CIO_ERROR);
    TEST_CHECK(cio_chunk_up(ch) == CIO_ERROR);
    TEST_CHECK(cio_chunk_up_force(ch) == CIO_OK);
    TEST_CHECK(cf->alloc_size == 262144);
    TEST_CHECK(ctx->total_chunks_up == 2);
    TEST_CHECK(cio_chunk_write(ch, "data", 4) == CIO_OK);
    TEST_CHECK(cio_chunk_down(ch) == CIO_OK);
    cio_chunk_close(live, CIO_TRUE);
    TEST_CHECK(cio_chunk_up(ch) == CIO_OK);
    check_content(ch, "data", 4);
    TEST_CHECK(cf->alloc_size == 262144);
    cio_chunk_close(ch, CIO_FALSE);
    cio_destroy(ctx);

    ctx = context(CIO_CHECKSUM);
    TEST_CHECK(cio_load(ctx, NULL) == CIO_OK);
    st = cio_stream_get(ctx, "fs");
    TEST_CHECK(st != NULL);
    ch = mk_list_entry(st->chunks.next, struct cio_chunk, _head);
    TEST_CHECK(((struct cio_file *) ch->backend)->alloc_size == 262144);
    check_content(ch, "data", 4);
    cio_destroy(ctx);
    cio_utils_recursive_delete(ROOT);
}

static size_t capacity(struct cio_chunk *ch)
{
    if (ch->st->type == CIO_STORE_FS) {
        return ((struct cio_file *) ch->backend)->alloc_size;
    }

    return ((struct cio_memfs *) ch->backend)->buf_size;
}

static size_t growth_workload(int backend, int flags, size_t hint, size_t batch)
{
    size_t length = 2048000;
    size_t written = 0;
    size_t count;
    size_t previous;
    size_t projected;
    size_t growths = 0;
    size_t fixed;
    size_t required;
    size_t prefix;
    size_t cold_capacity;
    char metadata[] = {0, 1, 0, '\xff'};
    char *payload;
    struct cio_ctx *ctx;
    struct cio_stream *st;
    struct cio_chunk *ch;
    struct cio_chunk *cold;

    cio_utils_recursive_delete(ROOT);
    ctx = context(flags);
    TEST_CHECK(cio_set_realloc_size_hint(ctx, hint) == CIO_OK);
    st = cio_stream_create(ctx, "stream", backend);
    ch = open_chunk(ctx, st, "hot", 4096, CIO_OPEN);
    cold = open_chunk(ctx, st, "cold", 4096, CIO_OPEN);
    cold_capacity = capacity(cold);
    payload = malloc(length);
    TEST_CHECK(payload != NULL);
    if (!payload) {
        exit(EXIT_FAILURE);
    }

    memset(payload, 'x', length);
    TEST_CHECK(cio_meta_write(ch, metadata, sizeof(metadata)) == CIO_OK);
    prefix = backend == CIO_STORE_FS ? CIO_FILE_HEADER_MIN + sizeof(metadata) : 0;
    while (written < length) {
        count = length - written < batch ? length - written : batch;
        previous = capacity(ch);
        required = prefix + written + count;
        TEST_CHECK(cio_chunk_get_projected_size(ch, count, &projected) == CIO_OK);
        TEST_CHECK(capacity(ch) == previous);
        TEST_CHECK(cio_chunk_get_content_size(ch) == written);
        if (flags & CIO_FIXED_GROWTH) {
            fixed = previous;
            while (fixed < required) {
                fixed += hint;
            }

            if (fixed != previous && backend == CIO_STORE_FS) {
                fixed = ((fixed + ctx->page_size - 1) / ctx->page_size) * ctx->page_size;
            }

            TEST_CHECK(projected == fixed);
        }

        TEST_CHECK(cio_chunk_write(ch, payload + written, count) == CIO_OK);
        written += count;
        TEST_CHECK(capacity(ch) == projected);
        if (capacity(ch) != previous) {
            growths++;
            TEST_CHECK(capacity(ch) >= required);
            TEST_CHECK(capacity(ch) - required <
                       (hint > CIO_ADAPTIVE_GROWTH_MAX ? hint : CIO_ADAPTIVE_GROWTH_MAX) +
                       ctx->page_size);
        }

        if (backend == CIO_STORE_FS && written % (128 * 1024) == 0) {
            TEST_CHECK(cio_chunk_down(ch) == CIO_OK);
            TEST_CHECK(cio_chunk_up(ch) == CIO_OK);
            check_content(ch, payload, written);
        }
    }

    TEST_CHECK(capacity(cold) == cold_capacity);
    TEST_CHECK(cio_chunk_write(cold, "x", 1) == CIO_OK);
    TEST_CHECK(capacity(cold) == cold_capacity);
    TEST_CHECK(cio_chunk_lock(ch) == CIO_OK);
    check_content(ch, payload, length);
    TEST_CHECK(cio_meta_cmp(ch, metadata, sizeof(metadata)) == 0);
    cio_destroy(ctx);
    free(payload);
    cio_utils_recursive_delete(ROOT);
    return growths;
}

static void test_default_growth(void)
{
    int backend;
    int mode;
    size_t initial;
    size_t fixed_size;
    size_t projected;
    char *payload;
    struct cio_options options;
    struct cio_ctx *ctx;
    struct cio_stream *st;
    struct cio_chunk *ch;

    for (backend = CIO_STORE_FS; backend <= CIO_STORE_MEM; backend++) {
        for (mode = 0; mode < 4; mode++) {
            cio_utils_recursive_delete(ROOT);
            cio_options_init(&options);
            options.root_path = ROOT;

            if (mode == 1) {
                /* Fluent Bit assigns its own flags after options_init(). */
                options.flags = CIO_OPEN | CIO_CHECKSUM;
            }
            else if (mode == 2) {
                options.flags = 0;
            }
            else if (mode == 3) {
                options.flags |= CIO_FIXED_GROWTH;
            }

            ctx = cio_create(&options);
            TEST_CHECK(ctx != NULL);
            if (ctx == NULL) {
                exit(EXIT_FAILURE);
            }

            initial = ctx->page_size * 64;
            payload = calloc(1, initial + 1);
            TEST_CHECK(payload != NULL);
            if (payload == NULL) {
                exit(EXIT_FAILURE);
            }

            st = cio_stream_create(ctx, "stream", backend);
            ch = open_chunk(ctx, st, "default", initial, CIO_OPEN);
            fixed_size = initial + CIO_REALLOC_HINT_MIN;

            TEST_CHECK(cio_chunk_get_projected_size(ch, initial + 1,
                                                    &projected) == CIO_OK);
            TEST_CHECK(cio_chunk_write(ch, payload, initial + 1) == CIO_OK);
            TEST_CHECK(capacity(ch) == projected);

            if (mode == 3 || CIO_REALLOC_HINT_MIN >= CIO_ADAPTIVE_GROWTH_MAX) {
                TEST_CHECK(capacity(ch) == fixed_size);
            }
            else {
                TEST_CHECK(capacity(ch) > fixed_size);
            }

            check_content(ch, payload, initial + 1);
            free(payload);
            cio_destroy(ctx);
            cio_utils_recursive_delete(ROOT);
        }
    }

    /* Creating a context without options also uses adaptive growth. */
    ctx = cio_create(NULL);
    TEST_CHECK(ctx != NULL);
    if (ctx == NULL) {
        exit(EXIT_FAILURE);
    }

    TEST_CHECK((ctx->options.flags & CIO_FIXED_GROWTH) == 0);
    st = cio_stream_create(ctx, "default", CIO_STORE_MEM);
    ch = open_chunk(ctx, st, "default", 262144, CIO_OPEN);
    TEST_CHECK(cio_chunk_get_projected_size(ch, 262145, &projected) == CIO_OK);
    if (CIO_REALLOC_HINT_MIN < 131072) {
        TEST_CHECK(projected == 393216);
    }

    cio_destroy(ctx);
}

static void test_growth_and_projection(void)
{
    int backend;
    int flags;
    size_t fixed;
    size_t adaptive;

    for (backend = 0; backend < 2; backend++) {
        for (flags = 0; flags < 4; flags++) {
            fixed = growth_workload(backend,
                                    (flags & 1 ? CIO_CHECKSUM : 0) |
                                    (flags & 2 ? CIO_FULL_SYNC : 0) | CIO_FIXED_GROWTH,
                                    CIO_REALLOC_HINT_MIN, 1024);
            adaptive = growth_workload(backend,
                                       (flags & 1 ? CIO_CHECKSUM : 0) |
                                       (flags & 2 ? CIO_FULL_SYNC : 0),
                                       CIO_REALLOC_HINT_MIN, 1024);
            if (CIO_REALLOC_HINT_MIN < CIO_ADAPTIVE_GROWTH_MAX) {
                TEST_CHECK(adaptive < fixed);
            }
            else {
                TEST_CHECK(adaptive == fixed);
            }
        }

        growth_workload(backend, 0, CIO_REALLOC_HINT_MIN + 1, 400001);
        growth_workload(backend, CIO_FIXED_GROWTH, CIO_REALLOC_HINT_MIN + 1, 400001);
        growth_workload(backend, 0, CIO_REALLOC_HINT_MAX, 400001);
    }
}

static void test_overflow_and_zero(void)
{
    int backend;
    size_t projected;
    struct cio_ctx *ctx;
    struct cio_stream *st;
    struct cio_chunk *ch;

    cio_utils_recursive_delete(ROOT);
    ctx = context(CIO_CHECKSUM);
    for (backend = 0; backend < 2; backend++) {
        st = cio_stream_create(ctx, backend ? "mem" : "fs", backend);
        ch = open_chunk(ctx, st, "test", 0, CIO_OPEN);
        TEST_CHECK(cio_chunk_write(ch, NULL, 0) == CIO_OK);
        TEST_CHECK(cio_chunk_get_projected_size(ch, 0, &projected) == CIO_OK);
        TEST_CHECK(projected == capacity(ch));
        TEST_CHECK(cio_chunk_write(ch, "a", 1) == CIO_OK);
        projected = 42;
        TEST_CHECK(cio_chunk_get_projected_size(ch, SIZE_MAX, &projected) == CIO_ERROR);
        TEST_CHECK(projected == 42);
        TEST_CHECK(cio_chunk_write(ch, "a", SIZE_MAX) == CIO_ERROR);
        TEST_CHECK(cio_chunk_write(ch, NULL, 1) == CIO_ERROR);
        TEST_CHECK(cio_chunk_get_projected_size(ch, 1, NULL) == CIO_ERROR);
        if (backend == CIO_STORE_FS) {
            TEST_CHECK(cio_chunk_get_projected_size(ch, UINT32_MAX, &projected) == CIO_ERROR);
            if (PTRDIFF_MAX > UINT32_MAX) {
                TEST_CHECK(cio_chunk_get_projected_size(ch, UINT32_MAX - 1, &projected) == CIO_OK);
                TEST_CHECK(projected >= (size_t) UINT32_MAX + CIO_FILE_HEADER_MIN);
            }
        }
        else {
            /* Exercise overflow of optional headroom without allocating it. */
            TEST_CHECK(cio_chunk_get_projected_size(ch, PTRDIFF_MAX - 1, &projected) == CIO_OK);
            TEST_CHECK(projected == PTRDIFF_MAX);
            TEST_CHECK(cio_chunk_get_projected_size(ch, PTRDIFF_MAX, &projected) == CIO_ERROR);
        }

        check_content(ch, "a", 1);
        TEST_CHECK(cio_chunk_write_at(ch, -1, "a", 1) == CIO_ERROR);
        TEST_CHECK(cio_chunk_write_at(ch, 2, "a", 1) == CIO_ERROR);
        TEST_CHECK(cio_chunk_lock(ch) == CIO_OK);
        /* Locked backlog chunks still permit the existing repair operation. */
        TEST_CHECK(cio_chunk_write_at(ch, 0, "b", 1) == CIO_OK);
        check_content(ch, "b", 1);
    }

    TEST_CHECK(cio_chunk_get_projected_size(NULL, 1, &projected) == CIO_ERROR);
    cio_destroy(ctx);
    cio_utils_recursive_delete(ROOT);
}

static void test_rewrite_and_rollback(void)
{
    int backend;
    int checksum;
    int adaptive;
    char data[40000];
    struct cio_ctx *ctx;
    struct cio_stream *st;
    struct cio_chunk *ch;

    memset(data, 'x', sizeof(data));
    for (backend = 0; backend < 2; backend++) {
        for (checksum = 0; checksum < 2; checksum++) {
            for (adaptive = 0; adaptive < 2; adaptive++) {
                cio_utils_recursive_delete(ROOT);
                ctx = context((checksum ? CIO_CHECKSUM : 0) |
                              (adaptive ? 0 : CIO_FIXED_GROWTH));
                st = cio_stream_create(ctx, "stream", backend);
                ch = open_chunk(ctx, st, "data", 0, CIO_OPEN);
                TEST_CHECK(cio_chunk_write(ch, data, 100) == CIO_OK);
                TEST_CHECK(cio_chunk_sync(ch) == CIO_OK);
                TEST_CHECK(cio_chunk_tx_begin(ch) == CIO_OK);
                TEST_CHECK(cio_chunk_write(ch, data, sizeof(data)) == CIO_OK);
                TEST_CHECK(cio_chunk_tx_rollback(ch) == CIO_OK);
                check_content(ch, data, 100);
                TEST_CHECK(cio_chunk_down(ch) == CIO_OK);
                TEST_CHECK(cio_chunk_up(ch) == CIO_OK);
                check_content(ch, data, 100);

                /* Rollback must also dirty a transaction that was synced. */
                TEST_CHECK(cio_chunk_tx_begin(ch) == CIO_OK);
                TEST_CHECK(cio_chunk_write(ch, data, sizeof(data)) == CIO_OK);
                TEST_CHECK(cio_chunk_sync(ch) == CIO_OK);
                TEST_CHECK(cio_chunk_tx_rollback(ch) == CIO_OK);
                TEST_CHECK(cio_chunk_down(ch) == CIO_OK);
                TEST_CHECK(cio_chunk_up(ch) == CIO_OK);
                check_content(ch, data, 100);
                if (backend == CIO_STORE_FS) {
                    TEST_CHECK(cio_chunk_tx_begin(ch) == CIO_OK);
                    TEST_CHECK(cio_chunk_write(ch, data, sizeof(data)) == CIO_OK);
                    TEST_CHECK(cio_chunk_down(ch) == CIO_OK);
                    TEST_CHECK(cio_chunk_tx_rollback(ch) == CIO_ERROR);
                    TEST_CHECK(ch->tx_active == CIO_TRUE);
                    TEST_CHECK(cio_chunk_up(ch) == CIO_OK);
                    TEST_CHECK(cio_chunk_tx_rollback(ch) == CIO_OK);
                    TEST_CHECK(cio_chunk_down(ch) == CIO_OK);
                    TEST_CHECK(cio_chunk_up(ch) == CIO_OK);
                    check_content(ch, data, 100);
                }

                /* Fluent Bit drops a suffix by writing zero bytes at offset. */
                TEST_CHECK(cio_chunk_write_at(ch, 50, NULL, 0) == CIO_OK);
                TEST_CHECK(cio_chunk_down(ch) == CIO_OK);
                TEST_CHECK(cio_chunk_up(ch) == CIO_OK);
                check_content(ch, data, 50);
                TEST_CHECK(cio_chunk_write_at(ch, 0, data, sizeof(data)) == CIO_OK);
                check_content(ch, data, sizeof(data));
                TEST_CHECK(cio_chunk_down(ch) == CIO_OK);
                TEST_CHECK(cio_chunk_up(ch) == CIO_OK);
                check_content(ch, data, sizeof(data));
                cio_destroy(ctx);
                cio_utils_recursive_delete(ROOT);
            }
        }
    }
}

static void test_trim_metadata_and_reopen(void)
{
    int checksum;
    int adaptive;
    int err;
    size_t projected;
    size_t required;
    char data[40000];
    char metadata[65535];
    struct cio_ctx *ctx;
    struct cio_stream *st;
    struct cio_chunk *ch;

    memset(data, 'd', sizeof(data));
    memset(metadata, 'm', sizeof(metadata));
    for (checksum = 0; checksum < 2; checksum++) {
        for (adaptive = 0; adaptive < 2; adaptive++) {
            cio_utils_recursive_delete(ROOT);
            ctx = context(CIO_TRIM_FILES | CIO_FULL_SYNC |
                          (checksum ? CIO_CHECKSUM : 0) |
                          (adaptive ? 0 : CIO_FIXED_GROWTH));
            st = cio_stream_create(ctx, "fs", CIO_STORE_FS);
            ch = open_chunk(ctx, st, "data", 262144, CIO_OPEN);
            TEST_CHECK(cio_chunk_write(ch, data, sizeof(data)) == CIO_OK);
            TEST_CHECK(cio_meta_write(ch, metadata, sizeof(metadata)) == CIO_OK);
            TEST_CHECK(cio_meta_write(ch, metadata, sizeof(metadata) + 1) == CIO_ERROR);
            TEST_CHECK(cio_chunk_down(ch) == CIO_OK);
            TEST_CHECK(cio_chunk_up(ch) == CIO_OK);
            check_content(ch, data, sizeof(data));
            TEST_CHECK(cio_meta_cmp(ch, metadata, sizeof(metadata)) == 0);
            TEST_CHECK(cio_meta_write(ch, metadata, 3) == CIO_OK);
            TEST_CHECK(cio_chunk_write_at(ch, 1, NULL, 0) == CIO_OK);
            TEST_CHECK(cio_chunk_sync(ch) == CIO_OK);
            TEST_CHECK(capacity(ch) == ctx->page_size);
            TEST_CHECK(cio_chunk_get_projected_size(ch, sizeof(data) - 1, &projected) == CIO_OK);
            TEST_CHECK(cio_chunk_write(ch, data, sizeof(data) - 1) == CIO_OK);
            TEST_CHECK(capacity(ch) == projected);
            TEST_CHECK(cio_chunk_down(ch) == CIO_OK);
            TEST_CHECK(cio_chunk_up(ch) == CIO_OK);
            required = CIO_FILE_HEADER_MIN + 3 + sizeof(data);
            required = ((required + ctx->page_size - 1) / ctx->page_size) * ctx->page_size;
            TEST_CHECK(capacity(ch) == required);
            check_content(ch, data, sizeof(data));
            /* Force a metadata resize after trimming away the opening hint. */
            TEST_CHECK(cio_meta_write(ch, metadata, sizeof(metadata)) == CIO_OK);
            check_content(ch, data, sizeof(data));
            TEST_CHECK(cio_meta_cmp(ch, metadata, sizeof(metadata)) == 0);
            TEST_CHECK(cio_meta_write(ch, metadata, 3) == CIO_OK);
            TEST_CHECK(cio_chunk_sync(ch) == CIO_OK);
            TEST_CHECK(capacity(ch) == required);
            cio_chunk_close(ch, CIO_FALSE);
            ch = open_chunk(ctx, st, "data", SIZE_MAX, CIO_OPEN_RD);
            TEST_CHECK(capacity(ch) == required);
            TEST_CHECK(cio_chunk_write(ch, "a", 1) == CIO_ERROR);
            TEST_CHECK(cio_chunk_write_at(ch, 0, NULL, 0) == CIO_ERROR);
            check_content(ch, data, sizeof(data));
            cio_chunk_close(ch, CIO_FALSE);
            /* The hint must never turn an existing corrupt file into an empty one. */
            {
                FILE *file = fopen(ROOT "/fs/data", "r+b");
                TEST_CHECK(file != NULL);
                if (file == NULL) {
                    exit(EXIT_FAILURE);
                }

                TEST_CHECK(fwrite("BAD!", 1, 4, file) == 4);
                fclose(file);
            }

            ch = cio_chunk_open(ctx, st, "data", CIO_OPEN, 262144, &err);
            TEST_CHECK(ch == NULL);
            TEST_CHECK(err == CIO_CORRUPTED);
            {
                FILE *file = fopen(ROOT "/fs/data", "rb");
                char magic[4];
                TEST_CHECK(file != NULL);
                if (file == NULL) {
                    exit(EXIT_FAILURE);
                }

                TEST_CHECK(fread(magic, 1, 4, file) == 4);
                TEST_CHECK(memcmp(magic, "BAD!", 4) == 0);
                fclose(file);
            }

            cio_destroy(ctx);
            cio_utils_recursive_delete(ROOT);
        }
    }
}

static void test_deferred_existing_file(void)
{
    struct cio_ctx *ctx;
    struct cio_ctx *writer;
    struct cio_stream *st;
    struct cio_stream *writer_st;
    struct cio_chunk *ch;
    struct cio_chunk *written;
    size_t stored;

    cio_utils_recursive_delete(ROOT);
    ctx = context(CIO_CHECKSUM);
    TEST_CHECK(cio_set_max_chunks_up(ctx, 1) == CIO_OK);
    st = cio_stream_create(ctx, "fs", CIO_STORE_FS);
    open_chunk(ctx, st, "live", 0, CIO_OPEN);
    ch = open_chunk(ctx, st, "deferred", 262144, CIO_OPEN);
    TEST_CHECK(cio_chunk_is_up(ch) == CIO_FALSE);
    writer = context(CIO_CHECKSUM);
    writer_st = cio_stream_create(writer, "fs", CIO_STORE_FS);
    written = open_chunk(writer, writer_st, "deferred", 0, CIO_OPEN);
    TEST_CHECK(cio_chunk_write(written, "existing", 8) == CIO_OK);
    stored = capacity(written);
    cio_destroy(writer);
    TEST_CHECK(cio_chunk_up_force(ch) == CIO_OK);
    TEST_CHECK(capacity(ch) == stored);
    check_content(ch, "existing", 8);
    cio_destroy(ctx);
    cio_utils_recursive_delete(ROOT);
}

#ifdef CIO_TEST_ALLOCATION_CALLS
static void test_open_failures(void)
{
    int err;
    int failure;
    struct cio_ctx *ctx;
    struct cio_stream *st;
    struct cio_chunk *ch;
    struct cio_chunk *live;
    struct cio_file *cf;

    for (failure = 0; failure < 3; failure++) {
        reset_faults();
        cio_utils_recursive_delete(ROOT);
        ctx = context(CIO_CHECKSUM);
        st = cio_stream_create(ctx, "fs", CIO_STORE_FS);
        resize_failure = failure == 0;
        map_failure = failure == 1;
        stat_failure = failure == 2;
        ch = cio_chunk_open(ctx, st, "failed", CIO_OPEN, 262144, &err);
        TEST_CHECK(ch == NULL);
        TEST_CHECK(err == CIO_ERROR);
        TEST_CHECK(ctx->total_chunks == 0 && ctx->total_chunks_up == 0);
        reset_faults();
        ch = open_chunk(ctx, st, "failed", 262144, CIO_OPEN);
        TEST_CHECK(capacity(ch) == 262144);
        TEST_CHECK(cio_chunk_write(ch, "ok", 2) == CIO_OK);
        cio_chunk_close(ch, CIO_TRUE);

        /* The same failures during deferred creation must permit a later up. */
        TEST_CHECK(cio_set_max_chunks_up(ctx, 1) == CIO_OK);
        live = open_chunk(ctx, st, "live", 4096, CIO_OPEN);
        ch = open_chunk(ctx, st, "deferred", 262144, CIO_OPEN);
        cf = ch->backend;
        resize_failure = failure == 0;
        map_failure = failure == 1;
        stat_failure = failure == 2;
        TEST_CHECK(cio_chunk_up_force(ch) == CIO_ERROR);
        TEST_CHECK(cio_file_native_is_open(cf) == CIO_FALSE);
        TEST_CHECK(cio_chunk_is_up(ch) == CIO_FALSE);
        TEST_CHECK(ctx->total_chunks_up == 1);
        reset_faults();
        TEST_CHECK(cio_chunk_up_force(ch) == CIO_OK);
        TEST_CHECK(capacity(ch) == 262144);
        TEST_CHECK(ctx->total_chunks_up == 2);
        cio_chunk_close(live, CIO_TRUE);
        cio_destroy(ctx);
        cio_utils_recursive_delete(ROOT);
    }

    /* An advisory opening hint must not require its full disk/virtual space. */
    for (failure = 0; failure < 2; failure++) {
        reset_faults();
        ctx = context(CIO_CHECKSUM);
        st = cio_stream_create(ctx, "fs", CIO_STORE_FS);
        if (failure == 0) {
            resize_limit = ctx->page_size;
        }
        else {
            map_limit = ctx->page_size;
        }

        ch = open_chunk(ctx, st, "fallback", 262144, CIO_OPEN);
        TEST_CHECK(capacity(ch) == ctx->page_size);
        TEST_CHECK(cio_chunk_write(ch, "ok", 2) == CIO_OK);
        reset_faults();
        TEST_CHECK(cio_chunk_down(ch) == CIO_OK);
        TEST_CHECK(cio_chunk_up(ch) == CIO_OK);
        check_content(ch, "ok", 2);
        cio_destroy(ctx);
        cio_utils_recursive_delete(ROOT);
    }
}

static void test_growth_failures(void)
{
    int backend;
    int failure;
    size_t before;
    size_t projected;
    size_t required;
    char *data;
    size_t append;
    struct cio_ctx *ctx;
    struct cio_stream *st;
    struct cio_chunk *ch;

    for (backend = 0; backend < 2; backend++) {
        for (failure = 0; failure < 3; failure++) {
            reset_faults();
            cio_utils_recursive_delete(ROOT);
            ctx = context(CIO_CHECKSUM);
            append = ctx->page_size + 100;
            data = malloc(append + 100);
            TEST_CHECK(data != NULL);
            if (data == NULL) {
                exit(EXIT_FAILURE);
            }

            memset(data, 'x', append + 100);
            st = cio_stream_create(ctx, "stream", backend);
            ch = open_chunk(ctx, st, "data", 4096, CIO_OPEN);
            TEST_CHECK(cio_chunk_write(ch, data, 100) == CIO_OK);
            TEST_CHECK(cio_chunk_sync(ch) == CIO_OK);
            before = capacity(ch);
            resize_failure = failure == 0;
            realloc_failure = 1;
            remap_failure = failure == 1;
            map_failure = failure == 2;
            TEST_CHECK(cio_chunk_write(ch, data, append) == CIO_ERROR);
            TEST_CHECK(capacity(ch) == before);
            TEST_CHECK(cio_chunk_get_real_size(ch) ==
                       (backend == CIO_STORE_FS ? before : 100));
            check_content(ch, data, 100);
            TEST_CHECK(cio_chunk_write_at(ch, 50, data, append) == CIO_ERROR);
            check_content(ch, data, 100);
            reset_faults();
            TEST_CHECK(cio_chunk_get_projected_size(ch, append, &projected) == CIO_OK);
            required = backend == CIO_STORE_FS ? ctx->page_size * 2 : append + 100;
            resize_limit = required;
            TEST_CHECK(projected > required);
            TEST_CHECK(cio_chunk_write(ch, data, append) == CIO_OK);
            TEST_CHECK(capacity(ch) == required);
            check_content(ch, data, append + 100);
            reset_faults();
            TEST_CHECK(cio_chunk_down(ch) == CIO_OK);
            TEST_CHECK(cio_chunk_up(ch) == CIO_OK);
            check_content(ch, data, append + 100);
            free(data);
            cio_destroy(ctx);
            cio_utils_recursive_delete(ROOT);
        }
    }
}

static void test_resize_recovery(void)
{
    int checksum;
    char data[100];
    char *append;
    size_t before;
    size_t projected;
    struct cio_ctx *ctx;
    struct cio_stream *st;
    struct cio_chunk *ch;

    memset(data, 'x', sizeof(data));
    for (checksum = 0; checksum < 2; checksum++) {
        reset_faults();
        cio_utils_recursive_delete(ROOT);
        ctx = context(checksum ? CIO_CHECKSUM : 0);
        st = cio_stream_create(ctx, "fs", CIO_STORE_FS);
        ch = open_chunk(ctx, st, "data", 0, CIO_OPEN);
        TEST_CHECK(cio_chunk_write(ch, data, sizeof(data)) == CIO_OK);
        TEST_CHECK(cio_chunk_sync(ch) == CIO_OK);
        before = capacity(ch);
        append = malloc(ctx->page_size);
        TEST_CHECK(append != NULL);
        if (append == NULL) {
            exit(EXIT_FAILURE);
        }

        memset(append, 'y', ctx->page_size);
        remap_failure = 1;
        shrink_failure = 1;
        TEST_CHECK(cio_chunk_write(ch, append, ctx->page_size) == CIO_ERROR);
        TEST_CHECK(capacity(ch) == before);
        /* If undoing the reservation also fails, report the extra disk use. */
        TEST_CHECK(cio_chunk_get_real_size(ch) > before);
        TEST_CHECK(cio_chunk_get_projected_size(ch, 1, &projected) == CIO_OK);
        TEST_CHECK(projected >= cio_chunk_get_real_size(ch));
        TEST_CHECK(ctx->total_chunks_up == 1);
        check_content(ch, data, sizeof(data));
        reset_faults();
        TEST_CHECK(cio_chunk_down(ch) == CIO_OK);
        TEST_CHECK(cio_chunk_up(ch) == CIO_OK);
        check_content(ch, data, sizeof(data));
        ctx->options.flags |= CIO_TRIM_FILES;
        TEST_CHECK(cio_chunk_write_at(ch, 50, NULL, 0) == CIO_OK);
        remap_failure = 1;
        TEST_CHECK(cio_chunk_sync(ch) == CIO_ERROR);
        check_content(ch, data, 50);
        reset_faults();
        TEST_CHECK(cio_chunk_down(ch) == CIO_OK);
        TEST_CHECK(cio_chunk_up(ch) == CIO_OK);
        check_content(ch, data, 50);
        TEST_CHECK(capacity(ch) == ctx->page_size);
        TEST_CHECK(cio_chunk_write(ch, append, ctx->page_size) == CIO_OK);
        free(append);
        cio_destroy(ctx);
        cio_utils_recursive_delete(ROOT);
    }
}
#endif

TEST_LIST = {
    {"open_size", test_open_size},
    {"deferred_open", test_deferred_open},
    {"growth_and_projection", test_growth_and_projection},
    {"default_growth", test_default_growth},
    {"overflow_and_zero", test_overflow_and_zero},
    {"rewrite_and_rollback", test_rewrite_and_rollback},
    {"trim_metadata_and_reopen", test_trim_metadata_and_reopen},
    {"deferred_existing_file", test_deferred_existing_file},
#ifdef CIO_TEST_ALLOCATION_CALLS
    {"open_failures", test_open_failures},
    {"growth_failures", test_growth_failures},
    {"resize_recovery", test_resize_recovery},
#endif
    {0}
};
