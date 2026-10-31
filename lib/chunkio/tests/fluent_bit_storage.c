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

#include <stdlib.h>
#include <string.h>

#include <chunkio/chunkio.h>
#include <chunkio/cio_chunk.h>
#include <chunkio/cio_file.h>
#include <chunkio/cio_file_native.h>
#include <chunkio/cio_meta.h>
#include <chunkio/cio_utils.h>

#include "cio_tests_internal.h"

#define CIO_ENV_STORAGE_TEST "tmp-fluent-bit-storage"

/* Fluent Bit log metadata: tag "test", followed by two direct output IDs. */
static char route_meta[] = {
    '\xf1', '\x77', 0, 1, 't', 'e', 's', 't', 0,
    0, 6, 0, 2, 0, 1, 0, 2
};

#ifdef CIO_TEST_FILE_CALLS
static int resize_calls;
static int sync_calls;
static int last_sync_flags;
static int fail_sync;

int __real_cio_file_native_resize(struct cio_file *cf, size_t size);
int __real_cio_file_native_sync(struct cio_file *cf, int flags);

int __wrap_cio_file_native_resize(struct cio_file *cf, size_t size)
{
    resize_calls++;
    return __real_cio_file_native_resize(cf, size);
}

int __wrap_cio_file_native_sync(struct cio_file *cf, int flags)
{
    sync_calls++;
    last_sync_flags = flags;
    if (fail_sync) {
        return CIO_ERROR;
    }

    return __real_cio_file_native_sync(cf, flags);
}
#endif

static void reset_calls(void)
{
#ifdef CIO_TEST_FILE_CALLS
    resize_calls = 0;
    sync_calls = 0;
    last_sync_flags = 0;
    fail_sync = CIO_FALSE;
#endif
}

static void check_content(struct cio_chunk *chunk, const char *expected, size_t size)
{
    int ret;
    char *data;
    size_t data_size;

    ret = cio_chunk_get_content(chunk, &data, &data_size);
    TEST_CHECK(ret == CIO_OK);
    if (ret != CIO_OK) {
        return;
    }

    TEST_CHECK(data_size == size);
    if (data_size == size) {
        TEST_CHECK(memcmp(data, expected, size) == 0);
    }
}

static struct cio_ctx *create_context(int flags)
{
    struct cio_ctx *ctx;
    struct cio_options opts;

    cio_options_init(&opts);
    opts.root_path = CIO_ENV_STORAGE_TEST;
    opts.flags = CIO_OPEN | flags;
    ctx = cio_create(&opts);
    TEST_CHECK(ctx != NULL);
    if (ctx == NULL) {
        exit(EXIT_FAILURE);
    }

    return ctx;
}

static struct cio_chunk *open_chunk(struct cio_ctx *ctx, struct cio_stream *stream)
{
    int err;
    struct cio_chunk *chunk;

    TEST_CHECK(stream != NULL);
    if (stream == NULL) {
        exit(EXIT_FAILURE);
    }

    chunk = cio_chunk_open(ctx, stream, "chunk", CIO_OPEN, 262144, &err);
    TEST_CHECK(chunk != NULL);
    if (chunk == NULL) {
        exit(EXIT_FAILURE);
    }

    return chunk;
}

/* Repeated route persistence after append, at flush, and on backlog reload. */
static void route_metadata_lifecycle(int flags)
{
    int i;
    int meta_len;
    char *meta;
    char updated[sizeof(route_meta)];
    char *payload;
    size_t payload_size = 2048000;
    crc_t crc;
    struct cio_ctx *ctx;
    struct cio_stream *stream;
    struct cio_chunk *chunk;
    struct cio_file *cf;

    cio_utils_recursive_delete(CIO_ENV_STORAGE_TEST);
    ctx = create_context(flags);
    stream = cio_stream_create(ctx, "tail.0", CIO_STORE_FS);
    chunk = open_chunk(ctx, stream);
    cf = chunk->backend;
    payload = malloc(payload_size + 1);
    TEST_CHECK(payload != NULL);
    if (payload == NULL) {
        exit(EXIT_FAILURE);
    }

    memset(payload, 'x', payload_size);
    payload[payload_size] = 'y';

    TEST_CHECK(cio_meta_write(chunk, route_meta, sizeof(route_meta)) == CIO_OK);
    TEST_CHECK(cio_chunk_write(chunk, payload, payload_size) == CIO_OK);
    crc = cf->crc_cur;

    /* Repeated metadata writes must preserve content and pending writes. */
    reset_calls();
    for (i = 0; i < 8; i++) {
        TEST_CHECK(cio_meta_write(chunk, route_meta, sizeof(route_meta)) == CIO_OK);
    }

    TEST_CHECK(cf->synced == CIO_FALSE);
    TEST_CHECK(cf->crc_cur == crc);
#ifdef CIO_TEST_FILE_CALLS
    TEST_CHECK(resize_calls == 0);
    TEST_CHECK(sync_calls == 0);
#endif

    /* Fluent Bit locks before taking the pointer used by output tasks. */
    TEST_CHECK(cio_chunk_lock(chunk) == CIO_OK);
    check_content(chunk, payload, payload_size);
    TEST_CHECK(cf->synced == CIO_TRUE);
    reset_calls();
    TEST_CHECK(cio_meta_write(chunk, route_meta, sizeof(route_meta)) == CIO_OK);
    TEST_CHECK(cf->synced == CIO_FALSE);
    TEST_CHECK(cio_chunk_sync(chunk) == CIO_OK);
#ifdef CIO_TEST_FILE_CALLS
    TEST_CHECK(sync_calls == 1);
#endif
    TEST_CHECK(cio_chunk_unlock(chunk) == CIO_OK);

    /* A route ID changes after an embedded NUL, without changing metadata size. */
    memcpy(updated, route_meta, sizeof(updated));
    updated[sizeof(updated) - 1] = 3;
    TEST_CHECK(cio_meta_write(chunk, updated, sizeof(updated)) == CIO_OK);
    TEST_CHECK(cf->synced == CIO_FALSE);
    check_content(chunk, payload, payload_size);
    TEST_CHECK(cio_chunk_down(chunk) == CIO_OK);
    TEST_CHECK(cio_chunk_up_force(chunk) == CIO_OK);
    TEST_CHECK(cio_meta_cmp(chunk, updated, sizeof(updated)) == 0);
    check_content(chunk, payload, payload_size);

    /* An identical update after a later append must leave that append dirty. */
    TEST_CHECK(cio_chunk_write(chunk, "y", 1) == CIO_OK);
    reset_calls();
    TEST_CHECK(cio_meta_write(chunk, updated, sizeof(updated)) == CIO_OK);
    TEST_CHECK(cf->synced == CIO_FALSE);
    TEST_CHECK(cio_chunk_down(chunk) == CIO_OK);
    TEST_CHECK(cio_chunk_up_force(chunk) == CIO_OK);
    check_content(chunk, payload, payload_size + 1);

    /* Fluent Bit can discard a suffix using a zero-length write_at. */
    TEST_CHECK(cio_chunk_write_at(chunk, payload_size, NULL, 0) == CIO_OK);
    TEST_CHECK(cio_meta_write(chunk, updated, sizeof(updated)) == CIO_OK);
    TEST_CHECK(cf->synced == CIO_FALSE);
    TEST_CHECK(cio_chunk_down(chunk) == CIO_OK);
    cio_destroy(ctx);

    /* Restart with chunks initially down, as when loading a large backlog. */
    ctx = create_context(flags);
    TEST_CHECK(cio_set_max_chunks_up(ctx, 1) == CIO_OK);
    stream = cio_stream_create(ctx, "live", CIO_STORE_FS);
    open_chunk(ctx, stream);
    TEST_CHECK(cio_load(ctx, NULL) == CIO_OK);
    stream = cio_stream_get(ctx, "tail.0");
    TEST_CHECK(stream != NULL);
    TEST_CHECK(mk_list_size(&stream->chunks) == 1);
    chunk = mk_list_entry(stream->chunks.next, struct cio_chunk, _head);
    TEST_CHECK(cio_chunk_is_up(chunk) == CIO_FALSE);
    TEST_CHECK(cio_chunk_up_force(chunk) == CIO_OK);
    TEST_CHECK(cio_meta_read(chunk, &meta, &meta_len) == CIO_OK);
    TEST_CHECK(meta_len == sizeof(updated));
    TEST_CHECK(cio_meta_cmp(chunk, updated, sizeof(updated)) == 0);
    TEST_CHECK(cio_chunk_lock(chunk) == CIO_OK);
    check_content(chunk, payload, payload_size);
    TEST_CHECK(cio_chunk_down(chunk) == CIO_OK);
    TEST_CHECK(cio_chunk_up_force(chunk) == CIO_OK);
    check_content(chunk, payload, payload_size);
    cio_chunk_close(chunk, CIO_TRUE);
    cio_destroy(ctx);
    free(payload);
    cio_utils_recursive_delete(CIO_ENV_STORAGE_TEST);
}

static void test_route_metadata_lifecycle(void)
{
    int checksum;
    int full_sync;
    int trim;

    for (checksum = 0; checksum <= 1; checksum++) {
        for (full_sync = 0; full_sync <= 1; full_sync++) {
            for (trim = 0; trim <= 1; trim++) {
                route_metadata_lifecycle((checksum ? CIO_CHECKSUM : 0) |
                                         (full_sync ? CIO_FULL_SYNC : 0) |
                                         (trim ? CIO_TRIM_FILES : 0));
            }
        }
    }
}

static void test_opaque_metadata(void)
{
    int backend;
    int i;
    char metadata[256];
    char replacement[sizeof(metadata)];
    struct cio_ctx *ctx;
    struct cio_stream *stream;
    struct cio_chunk *chunk;

    for (i = 0; i < sizeof(metadata); i++) {
        metadata[i] = (unsigned char) i;
    }

    for (backend = 0; backend < 2; backend++) {
        cio_utils_recursive_delete(CIO_ENV_STORAGE_TEST);
        ctx = create_context(CIO_CHECKSUM | CIO_FULL_SYNC);
        stream = cio_stream_create(ctx, "opaque", backend ? CIO_STORE_FS : CIO_STORE_MEM);
        chunk = open_chunk(ctx, stream);
        TEST_CHECK(cio_chunk_write(chunk, "unrelated content", 17) == CIO_OK);
        TEST_CHECK(cio_meta_write(chunk, metadata, sizeof(metadata)) == CIO_OK);
        TEST_CHECK(cio_meta_write(chunk, metadata, sizeof(metadata)) == CIO_OK);

        /* No magic, tag, route, string terminator, or payload interpretation. */
        memcpy(replacement, metadata, sizeof(metadata));
        replacement[0] = 'a';
        replacement[127] = 0;
        replacement[255] = 'z';
        TEST_CHECK(cio_meta_write(chunk, replacement, sizeof(replacement)) == CIO_OK);
        TEST_CHECK(cio_chunk_sync(chunk) == CIO_OK);
        if (backend) {
            TEST_CHECK(cio_chunk_down(chunk) == CIO_OK);
            TEST_CHECK(cio_chunk_up(chunk) == CIO_OK);
        }

        TEST_CHECK(cio_meta_cmp(chunk, replacement, sizeof(replacement)) == 0);
        check_content(chunk, "unrelated content", 17);
        cio_destroy(ctx);
        cio_utils_recursive_delete(CIO_ENV_STORAGE_TEST);
    }
}

static void test_metadata_modified_through_read_pointer(void)
{
    int copy;
    int ret;
    int meta_len;
    char initial[] = {0, '\x80', '\xff', 0, 1};
    char updated[sizeof(initial)];
    char *meta;
    struct cio_ctx *ctx;
    struct cio_stream *stream;
    struct cio_chunk *chunk;
    struct cio_file *cf;

    for (copy = 0; copy <= 1; copy++) {
        cio_utils_recursive_delete(CIO_ENV_STORAGE_TEST);
        ctx = create_context(CIO_CHECKSUM | CIO_FULL_SYNC);
        stream = cio_stream_create(ctx, "opaque", CIO_STORE_FS);
        chunk = open_chunk(ctx, stream);
        cf = chunk->backend;
        TEST_CHECK(cio_meta_write(chunk, initial, sizeof(initial)) == CIO_OK);
        TEST_CHECK(cio_chunk_write(chunk, "content", 7) == CIO_OK);
        TEST_CHECK(cio_chunk_sync(chunk) == CIO_OK);
        TEST_CHECK(cio_meta_read(chunk, &meta, &meta_len) == CIO_OK);

        /* The API returns writable storage, not an immutable snapshot. */
        meta[sizeof(initial) - 1] = 2;
        memcpy(updated, meta, sizeof(updated));
        TEST_CHECK(cio_meta_write(chunk, copy ? updated : meta, sizeof(updated)) == CIO_OK);
        TEST_CHECK(cf->synced == CIO_FALSE);
        TEST_CHECK(cio_chunk_sync(chunk) == CIO_OK);
        TEST_CHECK(cio_chunk_down(chunk) == CIO_OK);
        ret = cio_chunk_up(chunk);
        TEST_CHECK(ret == CIO_OK);
        if (ret == CIO_OK) {
            TEST_CHECK(cio_meta_cmp(chunk, updated, sizeof(updated)) == 0);
            check_content(chunk, "content", 7);
        }

        cio_destroy(ctx);
        cio_utils_recursive_delete(CIO_ENV_STORAGE_TEST);
    }
}

static void test_metadata_empty_and_resize(void)
{
    int i;
    int backend;
    char *meta;
    int meta_len;
    char *large_meta;
    size_t sizes[] = {sizeof(route_meta), sizeof(route_meta), 65535, 4, 0, 0};
    struct cio_ctx *ctx;
    struct cio_chunk *chunk;
    struct cio_stream *stream;

    large_meta = malloc(65535);
    TEST_CHECK(large_meta != NULL);
    if (large_meta == NULL) {
        exit(EXIT_FAILURE);
    }

    memset(large_meta, 'm', 65535);
    memcpy(large_meta, route_meta, sizeof(route_meta));

    for (backend = 0; backend < 2; backend++) {
        cio_utils_recursive_delete(CIO_ENV_STORAGE_TEST);
        ctx = create_context(CIO_CHECKSUM);
        stream = cio_stream_create(ctx, "tail.0", backend ? CIO_STORE_FS : CIO_STORE_MEM);
        chunk = open_chunk(ctx, stream);
        TEST_CHECK(cio_chunk_write(chunk, "records", 7) == CIO_OK);
        for (i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++) {
            TEST_CHECK(cio_meta_write(chunk, large_meta, sizes[i]) == CIO_OK);
            TEST_CHECK(cio_meta_size(chunk) == sizes[i]);
            check_content(chunk, "records", 7);
            if (sizes[i] > 0) {
                TEST_CHECK(cio_meta_read(chunk, &meta, &meta_len) == CIO_OK);
                TEST_CHECK(cio_meta_cmp(chunk, large_meta, sizes[i]) == 0);
                /* Reusing the pointer returned by meta_read must preserve data. */
                TEST_CHECK(cio_meta_write(chunk, meta, meta_len) == CIO_OK);
            }
            else {
                TEST_CHECK(cio_meta_write(chunk, NULL, 0) == CIO_OK);
            }

            if (backend) {
                TEST_CHECK(cio_chunk_down(chunk) == CIO_OK);
                TEST_CHECK(cio_chunk_up(chunk) == CIO_OK);
                TEST_CHECK(cio_meta_size(chunk) == sizes[i]);
                check_content(chunk, "records", 7);
            }
        }

        TEST_CHECK(cio_meta_write(chunk, large_meta, 65536) == CIO_ERROR);
        TEST_CHECK(cio_meta_size(chunk) == 0);
        cio_destroy(ctx);
        cio_utils_recursive_delete(CIO_ENV_STORAGE_TEST);
    }

    free(large_meta);
}

static void trim_lifecycle(int flags)
{
    int i;
    size_t file_size;
    size_t exact_size;
    char *payload;
    struct cio_ctx *ctx;
    struct cio_stream *stream;
    struct cio_chunk *chunk;
    struct cio_file *cf;

    cio_utils_recursive_delete(CIO_ENV_STORAGE_TEST);
    ctx = create_context(flags | CIO_TRIM_FILES);
    stream = cio_stream_create(ctx, "tail.0", CIO_STORE_FS);
    chunk = open_chunk(ctx, stream);
    cf = chunk->backend;
    payload = malloc(ctx->page_size * 2);
    TEST_CHECK(payload != NULL);
    if (payload == NULL) {
        exit(EXIT_FAILURE);
    }

    memset(payload, 'x', ctx->page_size * 2);
    TEST_CHECK(cio_meta_write(chunk, route_meta, sizeof(route_meta)) == CIO_OK);

    /* Small batches forced down by max_chunks_up should not resize a page. */
    TEST_CHECK(cio_chunk_sync(chunk) == CIO_OK);
    for (i = 1; i <= 3; i++) {
        TEST_CHECK(cio_chunk_write(chunk, payload, 32) == CIO_OK);
        reset_calls();
        TEST_CHECK(cio_chunk_lock(chunk) == CIO_OK);
        TEST_CHECK(cf->synced == CIO_TRUE);
        TEST_CHECK(cio_file_native_get_size(cf, &file_size) == CIO_OK);
        TEST_CHECK(file_size == ctx->page_size);
#ifdef CIO_TEST_FILE_CALLS
        TEST_CHECK(resize_calls == 0);
        TEST_CHECK(sync_calls == 1);
        TEST_CHECK((last_sync_flags & CIO_FULL_SYNC) == (flags & CIO_FULL_SYNC));
#endif
        check_content(chunk, payload, i * 32);
        TEST_CHECK(cio_chunk_down(chunk) == CIO_OK);
        TEST_CHECK(cio_chunk_up_force(chunk) == CIO_OK);
        check_content(chunk, payload, i * 32);
        TEST_CHECK(cio_chunk_unlock(chunk) == CIO_OK);
    }

    /* A real trim must still happen after crossing an allocation boundary. */
    TEST_CHECK(cio_chunk_write(chunk, payload, ctx->page_size) == CIO_OK);
    reset_calls();
    TEST_CHECK(cio_chunk_lock(chunk) == CIO_OK);
    TEST_CHECK(cio_file_native_get_size(cf, &file_size) == CIO_OK);
    TEST_CHECK(file_size == ctx->page_size * 2);
#ifdef CIO_TEST_FILE_CALLS
    TEST_CHECK(resize_calls == 1);
    TEST_CHECK(sync_calls == 1);
#endif
    check_content(chunk, payload, ctx->page_size + 96);
    TEST_CHECK(cio_chunk_unlock(chunk) == CIO_OK);

    /* Dropping a suffix must persist its logical length and really shrink. */
    TEST_CHECK(cio_chunk_write_at(chunk, 32, NULL, 0) == CIO_OK);
    reset_calls();
    TEST_CHECK(cio_chunk_sync(chunk) == CIO_OK);
    TEST_CHECK(cio_file_native_get_size(cf, &file_size) == CIO_OK);
    TEST_CHECK(file_size == ctx->page_size);
#ifdef CIO_TEST_FILE_CALLS
    TEST_CHECK(resize_calls == 1);
    TEST_CHECK(sync_calls == 1);
#endif
    TEST_CHECK(cio_chunk_down(chunk) == CIO_OK);
    TEST_CHECK(cio_chunk_up(chunk) == CIO_OK);
    check_content(chunk, payload, 32);

    /* Preserve the existing treatment of exact, non-page-aligned files. */
    TEST_CHECK(cio_chunk_write(chunk, payload, 1) == CIO_OK);
    exact_size = CIO_FILE_HEADER_MIN + sizeof(route_meta) + 33;
    TEST_CHECK(cio_file_resize(cf, exact_size) == CIO_OK);
    reset_calls();
    TEST_CHECK(cio_chunk_sync(chunk) == CIO_OK);
    TEST_CHECK(cio_file_native_get_size(cf, &file_size) == CIO_OK);
    TEST_CHECK(file_size == exact_size);
#ifdef CIO_TEST_FILE_CALLS
    TEST_CHECK(resize_calls == 0);
    TEST_CHECK(sync_calls == 1);
#endif
    TEST_CHECK(cio_chunk_down(chunk) == CIO_OK);
    TEST_CHECK(cio_chunk_up(chunk) == CIO_OK);
    check_content(chunk, payload, 33);
    cio_destroy(ctx);
    free(payload);
    cio_utils_recursive_delete(CIO_ENV_STORAGE_TEST);
}

static void test_trim_lifecycle(void)
{
    trim_lifecycle(0);
    trim_lifecycle(CIO_CHECKSUM);
    trim_lifecycle(CIO_FULL_SYNC);
    trim_lifecycle(CIO_CHECKSUM | CIO_FULL_SYNC);
}

#ifdef CIO_TEST_FILE_CALLS
static void test_metadata_after_sync_failure(void)
{
    struct cio_ctx *ctx;
    struct cio_stream *stream;
    struct cio_chunk *chunk;
    struct cio_file *cf;

    cio_utils_recursive_delete(CIO_ENV_STORAGE_TEST);
    ctx = create_context(CIO_CHECKSUM | CIO_FULL_SYNC | CIO_TRIM_FILES);
    stream = cio_stream_create(ctx, "tail.0", CIO_STORE_FS);
    chunk = open_chunk(ctx, stream);
    cf = chunk->backend;
    TEST_CHECK(cio_meta_write(chunk, route_meta, sizeof(route_meta)) == CIO_OK);
    TEST_CHECK(cio_chunk_write(chunk, "records", 7) == CIO_OK);
    reset_calls();
    fail_sync = CIO_TRUE;
    TEST_CHECK(cio_chunk_sync(chunk) == CIO_ERROR);
    TEST_CHECK(cf->synced == CIO_FALSE);
    TEST_CHECK(cio_meta_write(chunk, route_meta, sizeof(route_meta)) == CIO_OK);
    TEST_CHECK(cf->synced == CIO_FALSE);
    TEST_CHECK(resize_calls == 1);
    fail_sync = CIO_FALSE;
    TEST_CHECK(cio_chunk_sync(chunk) == CIO_OK);
    TEST_CHECK(sync_calls == 2);
    TEST_CHECK(cf->synced == CIO_TRUE);
    TEST_CHECK(last_sync_flags & CIO_FULL_SYNC);
    TEST_CHECK(cio_chunk_down(chunk) == CIO_OK);
    TEST_CHECK(cio_chunk_up(chunk) == CIO_OK);
    check_content(chunk, "records", 7);
    cio_destroy(ctx);
    cio_utils_recursive_delete(CIO_ENV_STORAGE_TEST);
}
#endif

TEST_LIST = {
    {"route_metadata_lifecycle", test_route_metadata_lifecycle},
    {"opaque_metadata", test_opaque_metadata},
    {"metadata_modified_through_read_pointer", test_metadata_modified_through_read_pointer},
    {"metadata_empty_and_resize", test_metadata_empty_and_resize},
    {"trim_lifecycle", test_trim_lifecycle},
#ifdef CIO_TEST_FILE_CALLS
    {"metadata_after_sync_failure", test_metadata_after_sync_failure},
#endif
    {0}
};
