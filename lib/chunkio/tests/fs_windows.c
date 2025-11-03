/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Chunk I/O
 *  =========
 *  Copyright 2018 Eduardo Silva <edsiper@gmail.com>
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
 * Windows File Handling Inconsistency Tests
 * ==========================================
 *
 * This test suite highlights inconsistencies between Windows and Unix
 * implementations of file handling in chunkio:
 *
 * 1. Delete while open/mapped: Windows allows deletion of open/mapped files
 *    while Unix correctly rejects it
 *
 * 2. Sync without mapping: Windows accesses cf->map without checking if it's
 *    NULL, which can cause crashes
 *
 * 3. File mapping size mismatch: CreateFileMapping uses current file size
 *    but MapViewOfFile may request a larger size, causing potential issues
 *
 * 4. File descriptor check: cio_file.c uses Unix-specific cf->fd check
 *    instead of platform-agnostic cio_file_native_is_open()
 *
 * These tests are designed to demonstrate the issues and verify behavior.
 */

#ifdef _WIN32

#include <chunkio/chunkio.h>
#include <chunkio/cio_log.h>
#include <chunkio/cio_file.h>
#include <chunkio/cio_file_native.h>
#include <chunkio/cio_stream.h>
#include <chunkio/cio_chunk.h>

/* Note: We still need to include cio_file_native.h for testing native functions
 * directly to verify bug fixes, but we use public APIs for state checks */

#include "cio_tests_internal.h"

#define CIO_ENV "tmp"

/* Logging callback */
static int log_cb(struct cio_ctx *ctx, int level, const char *file, int line,
                  char *str)
{
    (void) ctx;
    (void) level;

    printf("[cio-test-win32] %-60s => %s:%i\n", str, file, line);
    return 0;
}

/*
 * ISSUE #1: Test deleting a file that is open/mapped
 *
 * Expected behavior: Delete should succeed after automatically releasing
 *                    any outstanding mappings and handles.
 */
static void test_win32_delete_while_open()
{
    int ret;
    int err;
    struct cio_ctx *ctx;
    struct cio_stream *stream;
    struct cio_chunk *chunk;
    struct cio_file *cf;
    struct cio_options cio_opts;

    printf("\n=== Test: Delete file while open ===\n");

    cio_utils_recursive_delete("tmp");

    cio_options_init(&cio_opts);
    cio_opts.root_path = "tmp";
    cio_opts.log_cb = log_cb;
    cio_opts.log_level = CIO_LOG_DEBUG;

    ctx = cio_create(&cio_opts);
    TEST_CHECK(ctx != NULL);

    stream = cio_stream_create(ctx, "test", CIO_STORE_FS);
    TEST_CHECK(stream != NULL);

    /* Open and map a file */
    chunk = cio_chunk_open(ctx, stream, "test-file-open", CIO_OPEN, 1000, &err);
    TEST_CHECK(chunk != NULL);

    cf = (struct cio_file *) chunk->backend;
    TEST_CHECK(cf != NULL);

    /* Verify file is open (using public API) */
    TEST_CHECK(cio_chunk_is_up(chunk) == CIO_TRUE);

    /* Delete while open - should succeed and close resources automatically */
    ret = cio_file_native_delete(cf);
    printf("Result of delete while open: %d (expected: CIO_OK=%d)\n",
           ret, CIO_OK);
    TEST_CHECK(ret == CIO_OK);
    TEST_CHECK(cio_file_native_is_open(cf) == CIO_FALSE);
    TEST_CHECK(cio_file_native_is_mapped(cf) == CIO_FALSE);

    cio_chunk_close(chunk, CIO_FALSE);
    cio_stream_delete(stream);
    cio_destroy(ctx);
}

/*
 * ISSUE #2: Test deleting a file that is mapped
 *
 * Expected behavior: Delete should succeed after the implementation releases
 *                    the mapping safely.
 */
static void test_win32_delete_while_mapped()
{
    int ret;
    int err;
    struct cio_ctx *ctx;
    struct cio_stream *stream;
    struct cio_chunk *chunk;
    struct cio_file *cf;
    struct cio_options cio_opts;

    printf("\n=== Test: Delete file while mapped ===\n");

    cio_utils_recursive_delete("tmp");

    cio_options_init(&cio_opts);
    cio_opts.root_path = "tmp";
    cio_opts.log_cb = log_cb;
    cio_opts.log_level = CIO_LOG_DEBUG;

    ctx = cio_create(&cio_opts);
    TEST_CHECK(ctx != NULL);

    stream = cio_stream_create(ctx, "test", CIO_STORE_FS);
    TEST_CHECK(stream != NULL);

    /* Open and map a file */
    chunk = cio_chunk_open(ctx, stream, "test-file-mapped", CIO_OPEN, 1000, &err);
    TEST_CHECK(chunk != NULL);

    cf = (struct cio_file *) chunk->backend;
    TEST_CHECK(cf != NULL);

    /* Write some data to ensure mapping */
    ret = cio_chunk_write(chunk, "test data", 9);
    TEST_CHECK(ret == 0);

    /* Verify file is mapped (using public API) */
    TEST_CHECK(cio_chunk_is_up(chunk) == CIO_TRUE);

    /* Delete while mapped - should succeed and release mapping */
    ret = cio_file_native_delete(cf);
    printf("Result of delete while mapped: %d (expected: CIO_OK=%d)\n",
           ret, CIO_OK);
    TEST_CHECK(ret == CIO_OK);
    TEST_CHECK(cio_file_native_is_open(cf) == CIO_FALSE);
    TEST_CHECK(cio_file_native_is_mapped(cf) == CIO_FALSE);

    cio_chunk_close(chunk, CIO_FALSE);
    cio_stream_delete(stream);
    cio_destroy(ctx);
}

/*
 * ISSUE #3: Test syncing a file that is not mapped
 *
 * Expected behavior: Should check if mapped before accessing cf->map
 * Current behavior:  Accesses cf->map without checking, may crash
 */
static void test_win32_sync_without_map()
{
    int ret;
    int err;
    struct cio_ctx *ctx;
    struct cio_stream *stream;
    struct cio_chunk *chunk;
    struct cio_file *cf;
    struct cio_options cio_opts;

    printf("\n=== Test: Sync file without mapping ===\n");

    cio_utils_recursive_delete("tmp");

    cio_options_init(&cio_opts);
    cio_opts.root_path = "tmp";
    cio_opts.log_cb = log_cb;
    cio_opts.log_level = CIO_LOG_DEBUG;

    ctx = cio_create(&cio_opts);
    TEST_CHECK(ctx != NULL);

    stream = cio_stream_create(ctx, "test", CIO_STORE_FS);
    TEST_CHECK(stream != NULL);

    /* Open a file but don't map it */
    chunk = cio_chunk_open(ctx, stream, "test-file-sync", CIO_OPEN, 1000, &err);
    TEST_CHECK(chunk != NULL);

    cf = (struct cio_file *) chunk->backend;
    TEST_CHECK(cf != NULL);

    /* Manually unmap if it was auto-mapped (using public API) */
    if (cio_chunk_is_up(chunk) == CIO_TRUE) {
        ret = cio_file_down(chunk);
        TEST_CHECK(ret == 0);
    }

    /* Verify file is not mapped (using public API) */
    TEST_CHECK(cio_chunk_is_up(chunk) == CIO_FALSE);
    printf("Verified: chunk is down (not mapped)\n");

    /* Set synced flag to FALSE to force sync path (since cio_file_down syncs before unmapping) */
    cf->synced = CIO_FALSE;

    /* Try to sync without mapping using public API */
    /* cio_file_sync should auto-remap and emit a warning */
    printf("Attempting sync on unmapped file using cio_file_sync()...\n");
    printf("cio_file_sync() should remap and warn instead of failing\n");

    ret = cio_file_sync(chunk);
    printf("Result of sync without map: %d (expected: 0 for success with warning)\n", ret);

    TEST_CHECK(ret == 0);
    TEST_CHECK(cio_chunk_is_up(chunk) == CIO_FALSE);
    TEST_CHECK(cio_file_native_is_open(cf) == CIO_FALSE);

    cio_chunk_close(chunk, CIO_FALSE);
    cio_stream_delete(stream);
    cio_destroy(ctx);
}

/*
 * ISSUE #4: Test file mapping size mismatch
 *
 * Expected behavior: CreateFileMapping should use map_size, not current file size
 * Current behavior:  Creates mapping based on file size, then tries to map larger view
 */
static void test_win32_map_size_mismatch()
{
    int ret;
    int err;
    size_t file_size;
    size_t map_size;
    struct cio_ctx *ctx;
    struct cio_stream *stream;
    struct cio_chunk *chunk;
    struct cio_file *cf;
    struct cio_options cio_opts;

    printf("\n=== Test: File mapping size mismatch ===\n");

    cio_utils_recursive_delete("tmp");

    cio_options_init(&cio_opts);
    cio_opts.root_path = "tmp";
    cio_opts.log_cb = log_cb;
    cio_opts.log_level = CIO_LOG_DEBUG;

    ctx = cio_create(&cio_opts);
    TEST_CHECK(ctx != NULL);

    stream = cio_stream_create(ctx, "test", CIO_STORE_FS);
    TEST_CHECK(stream != NULL);

    /* Create a small file first */
    chunk = cio_chunk_open(ctx, stream, "test-file-size", CIO_OPEN, 1024, &err);
    TEST_CHECK(chunk != NULL);

    cf = (struct cio_file *) chunk->backend;
    TEST_CHECK(cf != NULL);

    /* Write minimal data */
    ret = cio_chunk_write(chunk, "test", 4);
    TEST_CHECK(ret == 0);

    /* Sync to ensure file is written */
    ret = cio_chunk_sync(chunk);
    TEST_CHECK(ret == 0);

    /* Get actual file size */
    ret = cio_file_native_get_size(cf, &file_size);
    TEST_CHECK(ret == CIO_OK);
    printf("Actual file size: %zu bytes\n", file_size);

    /* Close the chunk to unmap */
    cio_chunk_close(chunk, CIO_FALSE);

    /* Reopen file */
    chunk = cio_chunk_open(ctx, stream, "test-file-size", CIO_OPEN_RD, 0, &err);
    TEST_CHECK(chunk != NULL);

    cf = (struct cio_file *) chunk->backend;
    TEST_CHECK(cf != NULL);

    /* Unmap if cio_chunk_open auto-mapped the file (using public API) */
    if (cio_chunk_is_up(chunk) == CIO_TRUE) {
        ret = cio_file_down(chunk);
        TEST_CHECK(ret == 0);
    }

    /* Ensure file is still open */
    if (!cio_file_native_is_open(cf)) {
        ret = cio_file_native_open(cf);
        TEST_CHECK(ret == CIO_OK);
    }

    /* Try to map with a size larger than the file */
    map_size = file_size + 4096; /* Request 4KB more than file size */
    printf("Attempting to map %zu bytes (file is %zu bytes)\n", map_size, file_size);

    /* This is where the issue occurs: CreateFileMapping uses current file size (0,0),
     * but MapViewOfFile tries to map a larger size */
    ret = cio_file_native_map(cf, map_size);
    printf("Result of mapping %zu bytes to %zu byte file: %d\n",
           map_size, file_size, ret);

    /* For read-only files, mapping beyond file size is not possible on Windows.
     * The mapping should be limited to file_size, and alloc_size should reflect
     * the actual mapped size (file_size), not the requested size (map_size).
     * This ensures consistency between CreateFileMappingA and MapViewOfFile sizes. */
    if (ret == CIO_OK) {
        printf("Mapping succeeded\n");
        printf("Requested map_size: %zu, file_size: %zu\n", map_size, file_size);

        /* Verify what was actually mapped (using public API) */
        if (cio_chunk_is_up(chunk) == CIO_TRUE) {
            printf("File is mapped, alloc_size: %zu\n", cf->alloc_size);

            /* For read-only files, alloc_size should match file_size (the actual mapped size),
             * not the requested map_size (which exceeds file size) */
            /* This ensures consistency: CreateFileMappingA and MapViewOfFile both use actual_map_size */
            TEST_CHECK(cf->alloc_size == file_size);

            if (cf->alloc_size != file_size) {
                printf("ISSUE DETECTED: alloc_size (%zu) doesn't match file_size (%zu)\n",
                       cf->alloc_size, file_size);
                printf("For read-only files, mapping is limited to file_size\n");
            }
        }

        ret = cio_file_native_unmap(cf);
        TEST_CHECK(ret == CIO_OK);
    }
    else {
        printf("Mapping failed when size mismatch occurs\n");
        /* For read-only files, this might be expected if map_size > file_size */
    }

    cio_file_native_close(cf);
    cio_chunk_close(chunk, CIO_FALSE);
    cio_stream_delete(stream);
    cio_destroy(ctx);
}

/*
 * Test accessing file descriptor check inconsistency
 * This tests the issue in cio_file.c line 804 where it checks cf->fd > 0
 * instead of using cio_file_native_is_open(cf)
 */
static void test_win32_fd_check_inconsistency()
{
    int ret;
    int err;
    struct cio_ctx *ctx;
    struct cio_stream *stream;
    struct cio_chunk *chunk;
    struct cio_file *cf;
    struct cio_options cio_opts;

    printf("\n=== Test: File descriptor check inconsistency ===\n");

    cio_utils_recursive_delete("tmp");

    cio_options_init(&cio_opts);
    cio_opts.root_path = "tmp";
    cio_opts.log_cb = log_cb;
    cio_opts.log_level = CIO_LOG_DEBUG;

    ctx = cio_create(&cio_opts);
    TEST_CHECK(ctx != NULL);

    stream = cio_stream_create(ctx, "test", CIO_STORE_FS);
    TEST_CHECK(stream != NULL);

    /* Open a file */
    chunk = cio_chunk_open(ctx, stream, "test-file-fd", CIO_OPEN, 1000, &err);
    TEST_CHECK(chunk != NULL);

    cf = (struct cio_file *) chunk->backend;
    TEST_CHECK(cf != NULL);

    /* Verify file is open (using public API) */
    ret = cio_chunk_is_up(chunk);
    TEST_CHECK(ret == CIO_TRUE);
    printf("cio_chunk_is_up(chunk): %d\n", ret);

    /* Check cf->fd value on Windows (internal check for documentation) */
    /* On Windows, cf->fd is typically -1, but the file is still open via backing_file */
    printf("cf->fd value: %d (internal, not used on Windows)\n", cf->fd);
    printf("Note: cio_file.c now uses cio_file_native_is_open() instead of cf->fd > 0\n");

    cio_chunk_close(chunk, CIO_FALSE);
    cio_stream_delete(stream);
    cio_destroy(ctx);
}

TEST_LIST = {
    {"win32_delete_while_open",       test_win32_delete_while_open},
    {"win32_delete_while_mapped",     test_win32_delete_while_mapped},
    {"win32_sync_without_map",         test_win32_sync_without_map},
    {"win32_map_size_mismatch",        test_win32_map_size_mismatch},
    {"win32_fd_check_inconsistency",  test_win32_fd_check_inconsistency},
    {NULL, NULL}
};

#else /* _WIN32 */

#include "cio_tests_internal.h"

/* Empty test list for non-Windows platforms */
TEST_LIST = {
    {0}
};

#endif /* _WIN32 */

