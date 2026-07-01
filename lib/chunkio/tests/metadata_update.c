/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Chunk I/O
 *  =========
 *  Copyright 2018-2019 Eduardo Silva <eduardo@monkey.io>
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

#include <chunkio/chunkio.h>
#include <chunkio/cio_log.h>
#include <chunkio/cio_meta.h>
#include <chunkio/cio_chunk.h>
#include <chunkio/cio_stream.h>
#include <chunkio/cio_utils.h>
#include <string.h>
#include <stdlib.h>

#include "cio_tests_internal.h"

#define CIO_ENV_META_TEST   "/tmp/cio-metadata-update-test/"

/* Logging callback */
static int log_cb(struct cio_ctx *ctx, int level, const char *file, int line,
                  char *str)
{
    (void) ctx;
    (void) level;
    (void) file;
    (void) line;

    printf("[cio-test-metadata] %s\n", str);
    return 0;
}

/*
 * Test case: Validate that updating metadata after writing content data
 * correctly moves the content data and preserves both metadata and content
 * integrity.
 *
 * This test specifically validates the fix for the bug where memmove()
 * was using metadata size instead of content data size when moving content
 * after metadata update.
 */
static void test_metadata_update_with_content()
{
    int ret;
    int err;
    char *meta_buf;
    int meta_len;
    void *content_buf;
    size_t content_size;
    size_t expected_content_size;
    struct cio_ctx *ctx;
    struct cio_chunk *chunk;
    struct cio_stream *stream;
    struct cio_options cio_opts;

    /* Test data */
    const char *initial_meta = "initial-metadata";
    const char *updated_meta = "this-is-a-much-longer-metadata-string-that-will-require-content-to-be-moved";
    const char *content_data = "This is test content data that must be preserved when metadata is updated.";
    const char *more_content = " Additional content appended after metadata update.";

    /* Expected final content */
    char *expected_content;
    size_t expected_content_len;

    /* Cleanup any existing test directory */
    cio_utils_recursive_delete(CIO_ENV_META_TEST);

    /* Initialize options */
    cio_options_init(&cio_opts);
    cio_opts.root_path = CIO_ENV_META_TEST;
    cio_opts.log_cb = log_cb;
    cio_opts.log_level = CIO_LOG_INFO;
    cio_opts.flags = CIO_CHECKSUM;

    /* Create context */
    ctx = cio_create(&cio_opts);
    TEST_CHECK(ctx != NULL);
    if (!ctx) {
        printf("cannot create context\n");
        exit(1);
    }

    /* Create stream */
    stream = cio_stream_create(ctx, "test_stream", CIO_STORE_FS);
    TEST_CHECK(stream != NULL);
    if (!stream) {
        printf("cannot create stream\n");
        cio_destroy(ctx);
        exit(1);
    }

    /* Create chunk */
    chunk = cio_chunk_open(ctx, stream, "test_chunk", CIO_OPEN, 1000, &err);
    TEST_CHECK(chunk != NULL);
    if (!chunk) {
        printf("cannot open chunk\n");
        cio_destroy(ctx);
        exit(1);
    }

    /* Step 1: Write initial metadata */
    ret = cio_meta_write(chunk, (char *) initial_meta, strlen(initial_meta));
    TEST_CHECK(ret == CIO_OK);

    /* Step 2: Write some content data */
    ret = cio_chunk_write(chunk, content_data, strlen(content_data));
    TEST_CHECK(ret == CIO_OK);

    expected_content_size = strlen(content_data);

    /* Step 3: Update metadata to a larger size (this triggers content move) */
    /* This is the critical test case - when metadata grows, content data
     * must be moved correctly using cf->data_size, not the metadata size */
    ret = cio_meta_write(chunk, (char *) updated_meta, strlen(updated_meta));
    TEST_CHECK(ret == CIO_OK);

    /* Step 4: Write more content after metadata update */
    ret = cio_chunk_write(chunk, more_content, strlen(more_content));
    TEST_CHECK(ret == CIO_OK);

    expected_content_size += strlen(more_content);

    /* Build expected content */
    expected_content_len = strlen(content_data) + strlen(more_content);
    expected_content = malloc(expected_content_len + 1);
    TEST_CHECK(expected_content != NULL);
    if (!expected_content) {
        cio_destroy(ctx);
        exit(1);
    }
    memcpy(expected_content, content_data, strlen(content_data));
    memcpy(expected_content + strlen(content_data), more_content, strlen(more_content));
    expected_content[expected_content_len] = '\0';

    /* Step 5: Sync to disk */
    ret = cio_chunk_sync(chunk);
    TEST_CHECK(ret == CIO_OK);

    /* Step 6: Put chunk down */
    ret = cio_chunk_down(chunk);
    TEST_CHECK(ret == CIO_OK);

    /* Verify chunk is down */
    ret = cio_chunk_is_up(chunk);
    TEST_CHECK(ret == CIO_FALSE);

    /* Step 7: Put chunk up again */
    ret = cio_chunk_up(chunk);
    TEST_CHECK(ret == CIO_OK);

    /* Verify chunk is up */
    ret = cio_chunk_is_up(chunk);
    TEST_CHECK(ret == CIO_TRUE);

    /* Step 8: Validate metadata */
    ret = cio_meta_read(chunk, &meta_buf, &meta_len);
    TEST_CHECK(ret == CIO_OK);
    TEST_CHECK(meta_len == (int) strlen(updated_meta));
    TEST_CHECK(memcmp(meta_buf, updated_meta, strlen(updated_meta)) == 0);

    /* Step 9: Validate content data */
    ret = cio_chunk_get_content_copy(chunk, &content_buf, &content_size);
    TEST_CHECK(ret == CIO_OK);
    TEST_CHECK(content_size == expected_content_size);
    TEST_CHECK(memcmp(content_buf, expected_content, expected_content_len) == 0);

    /* Cleanup */
    free(expected_content);
    free(content_buf);
    cio_destroy(ctx);
}

/*
 * Test case: Update metadata multiple times with varying sizes to ensure
 * content data integrity is maintained throughout.
 */
static void test_metadata_multiple_updates()
{
    int ret;
    int err;
    char *meta_buf;
    int meta_len;
    void *content_buf;
    size_t content_size;
    struct cio_ctx *ctx;
    struct cio_chunk *chunk;
    struct cio_stream *stream;
    struct cio_options cio_opts;
    const char *test_strings[] = {
        "small",
        "medium-sized-metadata",
        "very-long-metadata-string-that-exceeds-previous-sizes",
        "tiny",
        "another-medium-metadata-string"
    };
    const char *content = "Test content that must remain intact";
    int i;

    /* Cleanup any existing test directory */
    cio_utils_recursive_delete(CIO_ENV_META_TEST);

    /* Initialize options */
    cio_options_init(&cio_opts);
    cio_opts.root_path = CIO_ENV_META_TEST;
    cio_opts.log_cb = log_cb;
    cio_opts.log_level = CIO_LOG_INFO;
    cio_opts.flags = CIO_CHECKSUM;

    /* Create context */
    ctx = cio_create(&cio_opts);
    TEST_CHECK(ctx != NULL);

    /* Create stream */
    stream = cio_stream_create(ctx, "test_stream", CIO_STORE_FS);
    TEST_CHECK(stream != NULL);

    /* Create chunk */
    chunk = cio_chunk_open(ctx, stream, "test_chunk2", CIO_OPEN, 1000, &err);
    TEST_CHECK(chunk != NULL);

    /* Write initial content */
    ret = cio_chunk_write(chunk, content, strlen(content));
    TEST_CHECK(ret == CIO_OK);

    /* Update metadata multiple times with different sizes */
    for (i = 0; i < 5; i++) {
        ret = cio_meta_write(chunk, (char *) test_strings[i], strlen(test_strings[i]));
        TEST_CHECK(ret == CIO_OK);

        /* Verify metadata after each update */
        ret = cio_meta_read(chunk, &meta_buf, &meta_len);
        TEST_CHECK(ret == CIO_OK);
        TEST_CHECK(meta_len == (int) strlen(test_strings[i]));
        TEST_CHECK(memcmp(meta_buf, test_strings[i], strlen(test_strings[i])) == 0);

        /* Verify content remains intact */
        ret = cio_chunk_get_content_copy(chunk, &content_buf, &content_size);
        TEST_CHECK(ret == CIO_OK);
        TEST_CHECK(content_size == strlen(content));
        TEST_CHECK(memcmp(content_buf, content, strlen(content)) == 0);
        free(content_buf);
    }

    /* Sync and test persistence */
    ret = cio_chunk_sync(chunk);
    TEST_CHECK(ret == CIO_OK);

    ret = cio_chunk_down(chunk);
    TEST_CHECK(ret == CIO_OK);

    ret = cio_chunk_up(chunk);
    TEST_CHECK(ret == CIO_OK);

    /* Final validation after up/down cycle */
    ret = cio_meta_read(chunk, &meta_buf, &meta_len);
    TEST_CHECK(ret == CIO_OK);
    TEST_CHECK(meta_len == (int) strlen(test_strings[4]));
    TEST_CHECK(memcmp(meta_buf, test_strings[4], strlen(test_strings[4])) == 0);

    ret = cio_chunk_get_content_copy(chunk, &content_buf, &content_size);
    TEST_CHECK(ret == CIO_OK);
    TEST_CHECK(content_size == strlen(content));
    TEST_CHECK(memcmp(content_buf, content, strlen(content)) == 0);

    /* Cleanup */
    free(content_buf);
    cio_destroy(ctx);
}

TEST_LIST = {
    {"metadata_update_with_content", test_metadata_update_with_content},
    {"metadata_multiple_updates",     test_metadata_multiple_updates},
    { 0 }
};
