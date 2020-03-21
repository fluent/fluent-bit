/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Chunk I/O
 *  =========
 *  Copyright 2018 Eduardo Silva <eduardo@monkey.io>
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

#include <sys/mman.h>
#include <arpa/inet.h>

#include <chunkio/chunkio.h>
#include <chunkio/cio_log.h>
#include <chunkio/cio_scan.h>
#include <chunkio/cio_file.h>
#include <chunkio/cio_meta.h>
#include <chunkio/cio_stream.h>
#include <chunkio/cio_utils.h>

#include "cio_tests_internal.h"

#define CIO_ENV           "/tmp/cio-fs-test/"
#define CIO_FILE_400KB    CIO_TESTS_DATA_PATH "/data/400kb.txt"

/* Logging callback, once called it just turn on the log_check flag */
static int log_cb(struct cio_ctx *ctx, int level, const char *file, int line,
                  char *str)
{
    (void) ctx;

    printf("[cio-test-fs] %-60s => %s:%i\n",  str, file, line);
    return 0;
}

/* Test API generating files to the file system and then scanning them back */
static void test_fs_write()
{
    int i;
    int ret;
    int len;
    int err;
    int n_files = 100;
    int flags;
    char *in_data;
    size_t in_size;
    char tmp[255];
    struct cio_ctx *ctx;
    struct cio_stream *stream;
    struct cio_chunk *chunk;
    struct cio_chunk **carr;

    /* Dummy break line for clarity on acutest output */
    printf("\n");

    flags = CIO_CHECKSUM;

    /* cleanup environment */
    cio_utils_recursive_delete(CIO_ENV);

    /* Create main context */
    ctx = cio_create(CIO_ENV, log_cb, CIO_LOG_INFO, flags);
    TEST_CHECK(ctx != NULL);

    /* Try to create a file with an invalid stream */
    chunk = cio_chunk_open(ctx, NULL, "invalid", 0, 0, &err);
    TEST_CHECK(chunk == NULL);

    /* Check invalid stream */
    stream = cio_stream_create(ctx, "", CIO_STORE_FS);
    TEST_CHECK(stream == NULL);

    /* Another invalid name */
    stream = cio_stream_create(ctx, "/", CIO_STORE_FS);
    TEST_CHECK(stream == NULL);

    /* Create valid stream */
    stream = cio_stream_create(ctx, "test-write", CIO_STORE_FS);
    TEST_CHECK(stream != NULL);

    /*
     * Load sample data file and with the same content through multiple write
     * operations generating other files.
     */
    ret = cio_utils_read_file(CIO_FILE_400KB, &in_data, &in_size);
    TEST_CHECK(ret == 0);
    if (ret == -1) {
        cio_destroy(ctx);
        exit(EXIT_FAILURE);
    }

    /* Number of test files to create */
    n_files = 100;

    /* Allocate files array */
    carr = calloc(1, sizeof(struct cio_file) * n_files);
    if (!carr) {
        perror("calloc");
        exit(EXIT_FAILURE);
    }


    for (i = 0; i < n_files; i++) {
        len = snprintf(tmp, sizeof(tmp), "api-test-%04i.txt", i);
        carr[i] = cio_chunk_open(ctx, stream, tmp, CIO_OPEN, 1000000, &err);

        if (carr[i] == NULL) {
            continue;
        }

        /* Check that next buffers are 'down' */
        if (i >= CIO_MAX_CHUNKS_UP) {
            ret = cio_chunk_is_up(carr[i]);
            TEST_CHECK(ret == CIO_FALSE);
            cio_chunk_up_force(carr[i]);
        }

        cio_chunk_write(carr[i], in_data, in_size);
        cio_chunk_write(carr[i], in_data, in_size);

        /* update metadata */
        cio_meta_write(carr[i], tmp, len);

        /* continue appending data to content area */
        cio_chunk_write(carr[i], in_data, in_size);
        cio_chunk_write(carr[i], in_data, in_size);
        cio_chunk_write(carr[i], in_data, in_size);

        /* sync to disk */
        cio_chunk_sync(carr[i]);
    }

    /* Release file data and destroy context */
    free(carr);
    free(in_data);
    cio_destroy(ctx);

    /* Create new context using the data generated above */
    ctx = cio_create(CIO_ENV, log_cb, CIO_LOG_INFO, flags);
    TEST_CHECK(ctx != NULL);
    cio_scan_dump(ctx);
    cio_destroy(ctx);
}

/*
 * Create one file chunk and check it updated sha1 after a couple of writes
 * and sync.
 */
static void test_fs_checksum()
{
    int ret;
    int err;
    int flags;
    char *in_data;
    char *f_hash;
    size_t in_size;
    uint32_t val;
    struct cio_ctx *ctx;
    struct cio_stream *stream;
    struct cio_chunk *chunk;

    /*
     * crc32 checksums
     * ===============
     */

    /* Empty file */
    char crc32_test1[] =  {
        0xff, 0x12, 0xd9, 0x41, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00
    };

    /* CRC32 of 2 zero bytes + content of data/400kb.txt file */
    char crc32_test2[] = {
        0x67, 0xfa, 0x3c, 0x10, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00
    };

    flags = CIO_CHECKSUM;

    /* Dummy break line for clarity on acutest output */
    printf("\n");

    /* cleanup environment */
    cio_utils_recursive_delete(CIO_ENV);

    ctx = cio_create(CIO_ENV, log_cb, CIO_LOG_INFO, flags);
    TEST_CHECK(ctx != NULL);

    stream = cio_stream_create(ctx, "test-crc32", CIO_STORE_FS);
    TEST_CHECK(stream != NULL);

    /* Load sample data file in memory */
    ret = cio_utils_read_file(CIO_FILE_400KB, &in_data, &in_size);
    TEST_CHECK(ret == 0);
    if (ret == -1) {
        cio_destroy(ctx);
        exit(EXIT_FAILURE);
    }

    /*
     * Test 1:
     *  - create one empty file
     *  - sync
     *  - validate crc32_test1
     */
    chunk = cio_chunk_open(ctx, stream, "test1.out", CIO_OPEN, 10, &err);
    TEST_CHECK(chunk != NULL);

    /* Check default crc32() for an empty file after sync */
    f_hash = cio_chunk_hash(chunk);
    TEST_CHECK(f_hash != NULL);
    cio_chunk_sync(chunk);

    memcpy(&val, f_hash, sizeof(val));
    val = ntohl(val);

    ret = memcmp(&val, crc32_test1, 4);
    TEST_CHECK(ret == 0);

    /*
     * Test 2:
     *  - append content of 400kb.txt file to file context
     *  - validate file crc32 in mem is the same as crc_test1
     *  - sync
     *  - validate file crc32 in mem is equal to sha_test2
     *
     * note that the second sha1 calculation is done using the initial
     * sha1 context so it skip old data to perform the verification.
     */
    cio_chunk_write(chunk, in_data, in_size);
    cio_chunk_sync(chunk);

    f_hash = cio_chunk_hash(chunk);
    memcpy(&val, f_hash, sizeof(val));
    val = ntohl(val);

    ret = memcmp(&val, crc32_test2, 4);
    TEST_CHECK(ret == 0);

    /* Release */
    cio_destroy(ctx);
    free(in_data);
}

/*
 * Create one file chunk, do writes and invoke up()/down() calls, then validate
 * it checksum.
 */
static void test_fs_up_down()
{
    int ret;
    int err;
    int flags;
    char *in_data;
    char *f_hash;
    size_t in_size;
    uint32_t val;
    struct cio_ctx *ctx;
    struct cio_stream *stream;
    struct cio_chunk *chunk;

    /*
     * crc32 checksums
     * ===============
     */

    /* Empty file */
    char crc32_test1[] =  {
        0xff, 0x12, 0xd9, 0x41, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00
    };

    /* CRC32 of 2 zero bytes + content of data/400kb.txt file */
    char crc32_test2[] = {
        0x67, 0xfa, 0x3c, 0x10, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00
    };

    flags = CIO_CHECKSUM;

    /* Dummy break line for clarity on acutest output */
    printf("\n");

    /* cleanup environment */
    cio_utils_recursive_delete(CIO_ENV);

    ctx = cio_create(CIO_ENV, log_cb, CIO_LOG_INFO, flags);
    TEST_CHECK(ctx != NULL);

    stream = cio_stream_create(ctx, "test-crc32", CIO_STORE_FS);
    TEST_CHECK(stream != NULL);

    /* Load sample data file in memory */
    ret = cio_utils_read_file(CIO_FILE_400KB, &in_data, &in_size);
    TEST_CHECK(ret == 0);
    if (ret == -1) {
        cio_destroy(ctx);
        exit(EXIT_FAILURE);
    }

    /*
     * Test 1:
     *  - create one empty file
     *  - sync
     *  - validate crc32_test1
     */
    chunk = cio_chunk_open(ctx, stream, "test1.out", CIO_OPEN, 10, &err);
    TEST_CHECK(chunk != NULL);

    /* file down/up */
    TEST_CHECK(cio_chunk_is_up(chunk) == CIO_TRUE);
    ret = cio_chunk_down(chunk);
    TEST_CHECK(ret == 0);
    TEST_CHECK(cio_chunk_is_up(chunk) == CIO_FALSE);
    ret = cio_chunk_up(chunk);
    TEST_CHECK(ret == 0);
    TEST_CHECK(cio_chunk_is_up(chunk) == CIO_TRUE);

    /* Check default crc32() for an empty file after sync */
    f_hash = cio_chunk_hash(chunk);
    TEST_CHECK(f_hash != NULL);
    cio_chunk_sync(chunk);

    memcpy(&val, f_hash, sizeof(val));
    val = ntohl(val);

    ret = memcmp(&val, crc32_test1, 4);
    TEST_CHECK(ret == 0);

    /*
     * Test 2:
     *  - append content of 400kb.txt file to file context
     *  - validate file crc32 in mem is the same as crc_test1
     *  - sync
     *  - validate file crc32 in mem is equal to sha_test2
     *
     * note that the second sha1 calculation is done using the initial
     * sha1 context so it skip old data to perform the verification.
     */
    cio_chunk_write(chunk, in_data, in_size);
    cio_chunk_sync(chunk);

    /* file down/up */
    TEST_CHECK(cio_chunk_is_up(chunk) == CIO_TRUE);
    ret = cio_chunk_down(chunk);
    TEST_CHECK(ret == 0);
    TEST_CHECK(cio_chunk_is_up(chunk) == CIO_FALSE);
    ret = cio_chunk_up(chunk);
    TEST_CHECK(ret == 0);
    TEST_CHECK(cio_chunk_is_up(chunk) == CIO_TRUE);

    f_hash = cio_chunk_hash(chunk);
    memcpy(&val, f_hash, sizeof(val));
    val = ntohl(val);

    ret = memcmp(&val, crc32_test2, 4);
    TEST_CHECK(ret == 0);

    /* Release */
    cio_destroy(ctx);
    free(in_data);
}

/* ref: https://github.com/edsiper/chunkio/pull/51 */
static void test_issue_51()
{
    int fd;
    int err;
    struct cio_ctx *ctx;
    struct cio_stream *stream;

    /* Create a temporal storage */
    ctx = cio_create("tmp", log_cb, CIO_LOG_DEBUG, 0);
    stream = cio_stream_create(ctx, "test", CIO_STORE_FS);
    cio_chunk_open(ctx, stream, "c", CIO_OPEN, 1000, &err);
    cio_destroy(ctx);

    /* Corrupt the file */
    fd = open("tmp/test/c", O_WRONLY);
    TEST_CHECK(fd != -1);
    if (fd == -1) {
        perror("open");
        exit(1);
    }
    ftruncate(fd, 1);
    close(fd);

    /* Re-read the content */
    ctx = cio_create("tmp", log_cb, CIO_LOG_DEBUG, 0);

    /* Upon scanning an existing stream, if not fixed, the program crashes */
    stream = cio_stream_create(ctx, "test", CIO_STORE_FS);
    cio_chunk_open(ctx, stream, "c", CIO_OPEN, 1000, &err);
    cio_destroy(ctx);
}

/* ref: https://github.com/fluent/fluent-bit/2025 */
static void test_issue_flb_2025()
{
    int i;
    int ret;
    int err;
    int len;
    char line[] = "this is a test line\n";
    struct cio_ctx *ctx;
    struct cio_chunk *chunk;
    struct cio_stream *stream;

    cio_utils_recursive_delete("tmp");

    /* Create a temporal storage */
    ctx = cio_create("tmp", log_cb, CIO_LOG_DEBUG, CIO_CHECKSUM);
    stream = cio_stream_create(ctx, "test", CIO_STORE_FS);
    chunk = cio_chunk_open(ctx, stream, "c", CIO_OPEN, 1000, &err);
    TEST_CHECK(chunk != NULL);
    if (!chunk) {
        printf("cannot open chunk\n");
        exit(1);
    }

    len = strlen(line);
    for (i = 0; i < 1000; i++) {
        ret = cio_chunk_write(chunk, line, len);
        TEST_CHECK(ret == CIO_OK);

        ret = cio_chunk_down(chunk);
        TEST_CHECK(ret == CIO_OK);

        ret = cio_chunk_up(chunk);
        TEST_CHECK(ret == CIO_OK);
    }

    cio_destroy(ctx);
}

TEST_LIST = {
    {"fs_write",   test_fs_write},
    {"fs_checksum",  test_fs_checksum},
    {"fs_up_down", test_fs_up_down},
    {"issue_51",   test_issue_51},
    {"issue_flb_2025", test_issue_flb_2025},
    { 0 }
};
