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

#include <errno.h>
#include <chunkio/chunkio.h>
#include <chunkio/cio_file_native.h>
#include <chunkio/cio_utils.h>
#include "cio_tests_internal.h"
#include "cio_test_caller.h"

#define ROOT "tmp-caller-allocation"
#define REQUIRE(condition) do { \
    if (!TEST_CHECK(condition)) { \
        exit(EXIT_FAILURE); \
    } \
} while (0)

#ifdef CIO_TEST_CALLER_CALLS
static int fail_reservation_once;
static int fail_mapping_once;
static int fail_remap;
static size_t resize_limit;
static size_t remaps;

int __real_cio_file_native_resize(struct cio_file *file, size_t size);
int __real_cio_file_native_map(struct cio_file *file, size_t size);
int __real_cio_file_native_remap(struct cio_file *file, size_t size);

int __wrap_cio_file_native_resize(struct cio_file *file, size_t size)
{
    if ((fail_reservation_once && size > file->page_size) ||
        (resize_limit && size > resize_limit)) {
        fail_reservation_once = 0;
        errno = ENOSPC;

        return CIO_ERROR;
    }

    return __real_cio_file_native_resize(file, size);
}

int __wrap_cio_file_native_map(struct cio_file *file, size_t size)
{
    if (fail_mapping_once && size > file->page_size) {
        fail_mapping_once = 0;
        errno = ENOMEM;

        return CIO_ERROR;
    }

    return __real_cio_file_native_map(file, size);
}

int __wrap_cio_file_native_remap(struct cio_file *file, size_t size)
{
    remaps++;
    if (fail_remap) {
        errno = ENOMEM;

        return CIO_ERROR;
    }

    return __real_cio_file_native_remap(file, size);
}
#endif

static void setup(struct caller *caller, int checksum, int policy)
{
    struct cio_options options;
    struct cio_ctx *ctx;
    struct cio_stream *stream;

    cio_utils_recursive_delete(ROOT);
    cio_options_init(&options);
    options.root_path = ROOT;
    options.flags = CIO_OPEN | (checksum ? CIO_CHECKSUM : 0);
    ctx = cio_create(&options);
    REQUIRE(ctx != NULL);
    stream = cio_stream_create(ctx, "input", CIO_STORE_FS);
    REQUIRE(stream != NULL);
    REQUIRE(caller_init(caller, ctx, stream, 4, 32,
                        2048000, policy) == CIO_OK);
}

static void cleanup(struct caller *caller)
{
    caller_destroy(caller);
    cio_destroy(caller->ctx);
    cio_utils_recursive_delete(ROOT);
}

static void verify(struct caller_chunk *entry, const void *expected)
{
    char *content;
    size_t length;

    REQUIRE(cio_chunk_get_content(entry->chunk, &content, &length) == CIO_OK);
    TEST_CHECK(length == entry->length);
    if (length == entry->length && length > 0) {
        TEST_CHECK(memcmp(content, expected, length) == 0);
    }

    TEST_CHECK(cio_meta_cmp(entry->chunk, entry->metadata,
                           sizeof(entry->metadata)) == 0);
}

static void test_immediate_requirement(void)
{
    int checksum;
    size_t i;
    size_t page;
    size_t hint;
    size_t sizes[6];
    char *data;
    struct caller caller;
    struct caller_chunk *entry;
    struct cio_file *file;

    data = malloc(1024 * 1024);
    REQUIRE(data != NULL);
    memset(data, 'a', 1024 * 1024);
    for (checksum = 0; checksum < 2; checksum++) {
        setup(&caller, checksum, CALLER_APPEND_HINT);
        page = caller.ctx->page_size;
        sizes[0] = 1;
        sizes[1] = page - CIO_FILE_HEADER_MIN - CALLER_METADATA_SIZE - 1;
        sizes[2] = sizes[1] + 1;
        sizes[3] = sizes[2] + 1;
        sizes[4] = 256 * 1024;
        sizes[5] = 1024 * 1024;
        for (i = 0; i < 6; i++) {
            caller.active[0] = NULL;
#ifdef CIO_TEST_CALLER_CALLS
            remaps = 0;
#endif
            REQUIRE(caller_append(&caller, 0, data, sizes[i]) == CIO_OK);
            entry = caller.active[0];
            hint = CIO_FILE_HEADER_MIN + CALLER_METADATA_SIZE + sizes[i];
            TEST_CHECK(entry->hint == hint);
            TEST_CHECK(entry->initial_capacity == ((hint + page - 1) / page) * page);
            file = entry->chunk->backend;
            TEST_CHECK(file->alloc_size == entry->initial_capacity);
#ifdef CIO_TEST_CALLER_CALLS
            TEST_CHECK(remaps == 0);
#endif
            verify(entry, data);
        }

        hint = 123;
        TEST_CHECK(caller_hint(SIZE_MAX, 64, CALLER_APPEND_HINT, &hint) == CIO_ERROR);
        TEST_CHECK(hint == 123);
        TEST_CHECK(caller_hint(1, 65536, CALLER_APPEND_HINT, &hint) == CIO_ERROR);
        TEST_CHECK(caller_hint(1, 65535, CALLER_APPEND_HINT, &hint) == CIO_OK);
        TEST_CHECK(hint == CIO_FILE_HEADER_MIN + 65535 + 1);
        cleanup(&caller);
    }

    free(data);
}

static void test_logical_reuse_and_rollover(void)
{
    int checksum;
    int policy;
    size_t page;
    char *data;
    struct caller caller;
    struct caller_chunk *first;
    struct caller_chunk *second;

    for (checksum = 0; checksum < 2; checksum++) {
        for (policy = CALLER_FIXED_HINT; policy <= CALLER_APPEND_HINT; policy++) {
            setup(&caller, checksum, policy);
            page = caller.ctx->page_size;
            caller.content_threshold = page * 3;
            data = malloc(page * 4);
            REQUIRE(data != NULL);
            memset(data, 'r', page * 4);
            REQUIRE(caller_append(&caller, 0, data, page) == CIO_OK);
            first = caller.active[0];
            REQUIRE(caller_append(&caller, 0, data, page * 2) == CIO_OK);
            TEST_CHECK(caller.active[0] == first);
            TEST_CHECK(caller.chunk_count == 1);
            TEST_CHECK(first->length == caller.content_threshold);
            TEST_CHECK(!cio_chunk_is_locked(first->chunk));
            if (policy == CALLER_APPEND_HINT) {
                TEST_CHECK(((struct cio_file *) first->chunk->backend)->alloc_size >
                           first->initial_capacity);
            }
            verify(first, data);

            /* Fluent Bit locks only AFTER exceeding the soft content threshold. */
            REQUIRE(caller_append(&caller, 0, data, 1) == CIO_OK);
            TEST_CHECK(caller.active[0] == first);
            TEST_CHECK(cio_chunk_is_locked(first->chunk));
            verify(first, data);
            REQUIRE(caller_append(&caller, 0, data, 1) == CIO_OK);
            second = caller.active[0];
            TEST_CHECK(second != first);
            TEST_CHECK(second->offset == page * 3 + 1);
            TEST_CHECK(caller.chunk_count == 2);

            /* Same tag/different event type and different tag are separate keys. */
            REQUIRE(caller_append(&caller, 1, data, 1) == CIO_OK);
            REQUIRE(caller_append(&caller, 2, data, 1) == CIO_OK);
            TEST_CHECK(caller.active[1] != second);
            TEST_CHECK(caller.active[2] != caller.active[1]);
            TEST_CHECK(caller.chunk_count == 4);

            /* A whole batch can cross the threshold on an existing chunk. */
            first = caller.active[1];
            REQUIRE(caller_append(&caller, 1, data, page * 3) == CIO_OK);
            TEST_CHECK(caller.active[1] == first);
            TEST_CHECK(caller.chunk_count == 4);
            TEST_CHECK(cio_chunk_is_locked(first->chunk));
            verify(first, data);

            second->busy = 1;
            REQUIRE(caller_append(&caller, 0, data, 1) == CIO_OK);
            TEST_CHECK(caller.active[0] != second);
            second = caller.active[0];
            REQUIRE(cio_chunk_lock(second->chunk) == CIO_OK);
            REQUIRE(caller_append(&caller, 0, data, 1) == CIO_OK);
            TEST_CHECK(caller.active[0] != second);

            /* An oversized append is stored whole, then cannot accept another. */
            REQUIRE(caller_append(&caller, 3, data, page * 4) == CIO_OK);
            first = caller.active[3];
            TEST_CHECK(first->length == page * 4);
            REQUIRE(caller_append(&caller, 3, data, 1) == CIO_OK);
            TEST_CHECK(caller.active[3] != first);
            verify(first, data);
            free(data);
            cleanup(&caller);
        }
    }
}

static void test_reopen_and_continue(void)
{
    int checksum;
    int err;
    size_t before;
    size_t i;
    size_t hints[] = {1, 8 * 1024 * 1024};
    char data[32768];
    struct caller caller;
    struct caller_chunk *entry;

    memset(data, 'z', sizeof(data));
    for (checksum = 0; checksum < 2; checksum++) {
        setup(&caller, checksum, CALLER_APPEND_HINT);
        REQUIRE(caller_append(&caller, 0, data, 1024) == CIO_OK);
        entry = caller.active[0];
        before = ((struct cio_file *) entry->chunk->backend)->alloc_size;
        REQUIRE(cio_chunk_down(entry->chunk) == CIO_OK);
        REQUIRE(cio_chunk_up(entry->chunk) == CIO_OK);
        TEST_CHECK(((struct cio_file *) entry->chunk->backend)->alloc_size == before);
        verify(entry, data);
        REQUIRE(caller_append(&caller, 0, data, 4096) == CIO_OK);
        TEST_CHECK(caller.active[0] == entry);

        for (i = 0; i < 2; i++) {
            REQUIRE(cio_chunk_sync(entry->chunk) == CIO_OK);
            before = ((struct cio_file *) entry->chunk->backend)->alloc_size;
            cio_chunk_close(entry->chunk, CIO_FALSE);
            entry->chunk = cio_chunk_open(caller.ctx, caller.stream, entry->name,
                                          CIO_OPEN, hints[i], &err);
            REQUIRE(entry->chunk != NULL);
            TEST_CHECK(((struct cio_file *) entry->chunk->backend)->alloc_size == before);
            verify(entry, data);
            REQUIRE(caller_append(&caller, 0, data, 4096) == CIO_OK);
            TEST_CHECK(caller.active[0] == entry);
            verify(entry, data);
        }

        TEST_CHECK(caller.chunk_count == 1);
        cleanup(&caller);
    }
}

static void test_deferred_and_down_reuse(void)
{
    int checksum;
    char data[32768];
    struct caller caller;
    struct caller_chunk *entry;

    memset(data, 'd', sizeof(data));
    for (checksum = 0; checksum < 2; checksum++) {
        setup(&caller, checksum, CALLER_APPEND_HINT);
        REQUIRE(cio_set_max_chunks_up(caller.ctx, 1) == CIO_OK);
        TEST_CHECK(caller_append(&caller, 0, data, 0) == CIO_ERROR);
        TEST_CHECK(caller.chunk_count == 0);
        REQUIRE(caller_append(&caller, 0, data, 1024) == CIO_OK);
        REQUIRE(caller_append(&caller, 1, data, 16384) == CIO_OK);
        entry = caller.active[1];
        TEST_CHECK(!cio_chunk_is_up(entry->chunk));
        TEST_CHECK(caller.ctx->total_chunks_up == 1);

        /* Like input_chunk_get(), force a down chunk up and restore it after write. */
        REQUIRE(caller_append(&caller, 1, data, 8192) == CIO_OK);
        TEST_CHECK(caller.active[1] == entry);
        TEST_CHECK(caller.chunk_count == 2);
        TEST_CHECK(!cio_chunk_is_up(entry->chunk));
        REQUIRE(cio_chunk_up_force(entry->chunk) == CIO_OK);
        verify(entry, data);
        verify(caller.active[0], data);
        cleanup(&caller);
    }
}

#ifdef CIO_TEST_CALLER_CALLS
static void test_append_hint_fallback(void)
{
    int checksum;
    int failure;
    size_t before;
    char *data;
    struct caller caller;
    struct caller_chunk *entry;

    data = malloc(2 * 1024 * 1024);
    REQUIRE(data != NULL);
    memset(data, 'f', 2 * 1024 * 1024);
    for (checksum = 0; checksum < 2; checksum++) {
        for (failure = 0; failure < 3; failure++) {
            setup(&caller, checksum, CALLER_APPEND_HINT);
            fail_reservation_once = failure == 0;
            fail_mapping_once = failure == 1;
            resize_limit = failure == 2 ? caller.ctx->page_size : 0;
            if (failure == 2) {
                TEST_CHECK(caller_append(&caller, 0, data, 1024 * 1024) == CIO_ERROR);
                REQUIRE(caller.chunk_count == 1);
                entry = caller.active[0];
                TEST_CHECK(entry->length == 0);
                TEST_CHECK(caller.written[0] == 0);
                verify(entry, data);
                REQUIRE(cio_chunk_down(entry->chunk) == CIO_OK);
                REQUIRE(cio_chunk_up(entry->chunk) == CIO_OK);
                verify(entry, data);
                resize_limit = 0;
            }

            REQUIRE(caller_append(&caller, 0, data, 1024 * 1024) == CIO_OK);
            entry = caller.active[0];
            TEST_CHECK(entry->initial_capacity == caller.ctx->page_size);
            TEST_CHECK(caller.chunk_count == 1);
            verify(entry, data);
            REQUIRE(cio_chunk_down(entry->chunk) == CIO_OK);
            REQUIRE(cio_chunk_up(entry->chunk) == CIO_OK);
            verify(entry, data);

            /* A later failed growth must preserve the successful first append. */
            before = ((struct cio_file *) entry->chunk->backend)->alloc_size;
            fail_remap = 1;
            TEST_CHECK(caller_append(&caller, 0, data, 512 * 1024) == CIO_ERROR);
            TEST_CHECK(entry->length == 1024 * 1024);
            TEST_CHECK(((struct cio_file *) entry->chunk->backend)->alloc_size == before);
            verify(entry, data);
            fail_remap = 0;
            REQUIRE(caller_append(&caller, 0, data, 512 * 1024) == CIO_OK);
            verify(entry, data);
            REQUIRE(cio_chunk_down(entry->chunk) == CIO_OK);
            REQUIRE(cio_chunk_up(entry->chunk) == CIO_OK);
            verify(entry, data);
            cleanup(&caller);
        }
    }

    free(data);
}
#endif

TEST_LIST = {
    {"immediate_requirement", test_immediate_requirement},
    {"logical_reuse_and_rollover", test_logical_reuse_and_rollover},
    {"reopen_and_continue", test_reopen_and_continue},
    {"deferred_and_down_reuse", test_deferred_and_down_reuse},
#ifdef CIO_TEST_CALLER_CALLS
    {"append_hint_fallback", test_append_hint_fallback},
#endif
    {0}
};
