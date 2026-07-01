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

#ifndef _WIN32
#include <sys/mman.h>
#include <arpa/inet.h>
#endif
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <chunkio/chunkio.h>
#include <chunkio/cio_log.h>
#include <chunkio/cio_scan.h>
#include <chunkio/cio_file.h>
#include <chunkio/cio_meta.h>
#include <chunkio/cio_stream.h>
#include <chunkio/cio_utils.h>
#include <chunkio/cio_error.h>
#include <chunkio/cio_file_native.h>

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
    struct cio_options cio_opts;

    /* Dummy break line for clarity on acutest output */
    printf("\n");

    flags = CIO_CHECKSUM;

    cio_options_init(&cio_opts);

    cio_opts.root_path = CIO_ENV;
    cio_opts.log_cb = log_cb;
    cio_opts.flags = flags;

    /* cleanup environment */
    cio_utils_recursive_delete(CIO_ENV);

    /* Create main context */
    ctx = cio_create(&cio_opts);
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

    cio_options_init(&cio_opts);

    cio_opts.root_path = CIO_ENV;
    cio_opts.log_cb = log_cb;
    cio_opts.log_level = CIO_LOG_INFO;
    cio_opts.flags = flags;

    /* Create new context using the data generated above */
    ctx = cio_create(&cio_opts);
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
    struct cio_options cio_opts;

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

    cio_options_init(&cio_opts);

    cio_opts.root_path = CIO_ENV;
    cio_opts.log_cb = log_cb;
    cio_opts.flags = flags;

    ctx = cio_create(&cio_opts);
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
    char path[1024];
    struct stat st;
    struct cio_ctx *ctx;
    struct cio_stream *stream;
    struct cio_chunk *chunk;
    struct cio_options cio_opts;

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

    cio_options_init(&cio_opts);

    cio_opts.root_path = CIO_ENV;
    cio_opts.log_cb = log_cb;
    cio_opts.log_level = CIO_LOG_INFO;
    cio_opts.flags = flags;

    ctx = cio_create(&cio_opts);
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

    /*
     * Bug https://github.com/fluent/fluent-bit/pull/3054#issuecomment-778831815
     *
     * the fs_size cache value is not being updated after a sync, let's validate.
     */
    snprintf(path, sizeof(path) - 1, "%s%s", CIO_ENV, "test-crc32/test1.out");
    ret = stat(path, &st);
    TEST_CHECK(ret == 0);
    TEST_CHECK(st.st_size == cio_chunk_get_real_size(chunk));

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
    struct cio_options cio_opts;

    /* Create a temporal storage */
    cio_options_init(&cio_opts);

    cio_opts.root_path = "tmp";
    cio_opts.log_cb = log_cb;
    cio_opts.log_level = CIO_LOG_DEBUG;
    cio_opts.flags = 0;

    ctx = cio_create(&cio_opts);
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

#ifdef _WIN32
    _chsize(fd, 1);
#else
    ftruncate(fd, 1);
#endif

    close(fd);

    /* Re-read the content */
    ctx = cio_create(&cio_opts);

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
    struct cio_options cio_opts;

    cio_utils_recursive_delete("tmp");

    /* Create a temporal storage */
    cio_options_init(&cio_opts);

    cio_opts.root_path = "tmp";
    cio_opts.log_cb = log_cb;
    cio_opts.log_level = CIO_LOG_DEBUG;
    cio_opts.flags = CIO_CHECKSUM;

    ctx = cio_create(&cio_opts);
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

void test_fs_size_chunks_up()
{
    int i;
    int ret;
    int len;
    int err;
    int flags;
    char line[] = "this is a test line\n";
    char name[32];
    size_t expected;
    struct cio_ctx *ctx;
    struct cio_chunk *chunk;
    struct cio_chunk *chunk_tmp;
    struct cio_stream *stream;
    struct cio_options cio_opts;

    /* cleanup environment */
    cio_utils_recursive_delete(CIO_ENV);

    flags = CIO_CHECKSUM;

    cio_options_init(&cio_opts);

    cio_opts.root_path = CIO_ENV;
    cio_opts.log_cb = log_cb;
    cio_opts.log_level = CIO_LOG_INFO;
    cio_opts.flags = flags;

    ctx = cio_create(&cio_opts);
    TEST_CHECK(ctx != NULL);

    /* Set default number of chunks up */
    cio_set_max_chunks_up(ctx, 50);

    stream = cio_stream_create(ctx, "test_size_chunks_up", CIO_STORE_FS);
    TEST_CHECK(stream != NULL);

    len = strlen(line);
    for (i = 0; i < 100; i++) {
        /* Create the chunk */
        snprintf(name, sizeof(name) - 1, "test-%i", i);

        chunk = cio_chunk_open(ctx, stream, name, CIO_OPEN, 1000, &err);
        TEST_CHECK(chunk != NULL);
        if (!chunk) {
            exit(1);
        }

        if (i < 50) {
            /* First 50 chunks (0-49) will be in an 'up' state */
            ret = cio_chunk_is_up(chunk);
            TEST_CHECK(ret == CIO_TRUE);
            if (ret == CIO_FALSE) {
                exit(1);
            }
            ret = cio_chunk_write(chunk, line, len);
            TEST_CHECK(ret == CIO_OK);

            /* Check this chunk is in the 'chunks_up' list */
            chunk_tmp = mk_list_entry_last(&stream->chunks_up,
                                           struct cio_chunk,
                                           _state_head);
            TEST_CHECK(chunk_tmp == chunk);

            /* Put the chunk down and now recheck 'chunks_down' list */
            ret = cio_chunk_down(chunk);
            TEST_CHECK(ret == CIO_OK);

            /* Down list */
            chunk_tmp = mk_list_entry_last(&stream->chunks_down,
                                           struct cio_chunk,
                                           _state_head);
            TEST_CHECK(chunk_tmp == chunk);

            /* Put the chunk UP again */
            ret = cio_chunk_up(chunk);
            TEST_CHECK(ret == CIO_OK);

            /* Check this chunk is in the 'chunks_up' list */
            chunk_tmp = mk_list_entry_last(&stream->chunks_up,
                                           struct cio_chunk,
                                           _state_head);
            TEST_CHECK(chunk_tmp == chunk);
        }
        else {
            /*
             * Remaining created chunks are in a down state, after creation
             * this chunks must be linked in the struct cio_stream->chunks_down
             * list.
             */
            chunk_tmp = mk_list_entry_last(&stream->chunks_down,
                                           struct cio_chunk,
                                           _state_head);
            TEST_CHECK(chunk_tmp == chunk);
        }
    }

    /* 50 chunks are up, each chunk contains 'len' bytes */
    expected = 50 * len;
    TEST_CHECK(cio_stream_size_chunks_up(stream) == expected);

    /* Cleanup */
    cio_destroy(ctx);
}

void test_issue_write_at()
{
    int ret;
    int len;
    int err;
    char line[] = "this is a test line\n";
    struct cio_ctx *ctx;
    struct cio_chunk *chunk;
    struct cio_stream *stream;
    struct cio_options cio_opts;

    /* cleanup environment */
    cio_utils_recursive_delete(CIO_ENV);

    /* create Chunk I/O context */
    cio_options_init(&cio_opts);

    cio_opts.root_path = CIO_ENV;
    cio_opts.log_cb = log_cb;
    cio_opts.log_level = CIO_LOG_INFO;
    cio_opts.flags = CIO_CHECKSUM;

    ctx = cio_create(&cio_opts);
    TEST_CHECK(ctx != NULL);

    /* Set default number of chunks up */
    cio_set_max_chunks_up(ctx, 50);

    /* create stream */
    stream = cio_stream_create(ctx, "test_write_at", CIO_STORE_FS);
    TEST_CHECK(stream != NULL);

    /* create chunk */
    chunk = cio_chunk_open(ctx, stream, "test", CIO_OPEN, 1000, &err);
    TEST_CHECK(chunk != NULL);
    if (!chunk) {
        exit(1);
    }

    len = strlen(line);

    /* Write 3 lines */
    ret = cio_chunk_write(chunk, line, len);
    TEST_CHECK(ret == CIO_OK);

    ret = cio_chunk_write(chunk, line, len);
    TEST_CHECK(ret == CIO_OK);

    ret = cio_chunk_write(chunk, line, len);
    TEST_CHECK(ret == CIO_OK);

    /*
     * Write some content after the second line: this is the issue, when writing
     * to a position lowest than the last offset the checksum is not updated, for
     * hence after putting it down and up again, the checksym validation fails
     * and we get in the wrong state.
     */
    ret = cio_chunk_write_at(chunk, len * 2, "test\n", 5);
    TEST_CHECK(ret == CIO_OK);

    /* Put the chunk down and up */
    ret = cio_chunk_down(chunk);
    TEST_CHECK(ret == CIO_OK);

    /* Trigger the 'format check failed' error */
    ret = cio_chunk_up(chunk);
    TEST_CHECK(ret == CIO_OK);

    /*
     * Corrupt the CRC manually, alter the current CRC and write a byte
     * to the chunk to get the checksum corruption. Here we expect two
     * things:
     *
     * - when trying to put the chunk get CIO_CORRUPTED
     * - check the error number, it must be CIO_ERR_BAD_CHECKSUM
     * - memory map must be null and file descriptor must be in a closed state
     */
    struct cio_file *cf = (struct cio_file *) chunk->backend;
    cf->crc_cur = 10;
    cio_chunk_write(chunk, "\0", 1);

    ret = cio_chunk_down(chunk);
    TEST_CHECK(ret == CIO_OK);

    ret = cio_chunk_up(chunk);
    TEST_CHECK(ret == CIO_CORRUPTED);
    TEST_CHECK(cio_error_get(chunk) == CIO_ERR_BAD_CHECKSUM);

    cf = (struct cio_file *) chunk->backend;
    TEST_CHECK(cf->map == NULL);
    TEST_CHECK(cf->fd <= 0);
}


void test_fs_up_down_up_append()
{
    int ret;
    int err;
    struct cio_ctx *ctx;
    struct cio_chunk *chunk;
    struct cio_stream *stream;
    struct cio_options cio_opts;

    void *out_buf;
    size_t out_size;

    cio_utils_recursive_delete(CIO_ENV);

    /* create Chunk I/O context */
    cio_options_init(&cio_opts);

    cio_opts.root_path = CIO_ENV;
    cio_opts.log_cb = log_cb;
    cio_opts.log_level = CIO_LOG_DEBUG;
    cio_opts.flags = CIO_CHECKSUM;

    /* Create a temporal storage */
    ctx = cio_create(&cio_opts);
    stream = cio_stream_create(ctx, "cio", CIO_STORE_FS);
    chunk = cio_chunk_open(ctx, stream, "c", CIO_OPEN, 1000, &err);
    TEST_CHECK(chunk != NULL);
    if (!chunk) {
        printf("cannot open chunk\n");
        exit(1);
    }

    ret = cio_chunk_get_content_copy(chunk, &out_buf, &out_size);
    TEST_CHECK(ret == CIO_OK);
    TEST_CHECK(memcmp(out_buf, "", 1) == 0);
    TEST_CHECK(out_size == 0);
    free(out_buf);

    ret = cio_chunk_write(chunk, "line 1\n", 7);
    TEST_CHECK(ret == CIO_OK);

    ret = cio_chunk_get_content_copy(chunk, &out_buf, &out_size);
    TEST_CHECK(ret == CIO_OK);
    TEST_CHECK(memcmp(out_buf, "line 1\n", 7+1) == 0);
    TEST_CHECK(out_size == 7);
    free(out_buf);

    ret = cio_chunk_down(chunk);
    TEST_CHECK(ret == CIO_OK);

    ret = cio_chunk_up(chunk);
    TEST_CHECK(ret == CIO_OK);

    ret = cio_chunk_get_content_copy(chunk, &out_buf, &out_size);
    TEST_CHECK(ret == CIO_OK);
    TEST_CHECK(memcmp(out_buf, "line 1\n", 7+1) == 0);
    TEST_CHECK(out_size == 7);
    free(out_buf);

    /* append */
    ret = cio_chunk_write(chunk, "line 2\n", 7);
    TEST_CHECK(ret == CIO_OK);

    ret = cio_chunk_down(chunk);
    TEST_CHECK(ret == CIO_OK);

    ret = cio_chunk_up(chunk);
    TEST_CHECK(ret == CIO_OK);

    ret = cio_chunk_get_content_copy(chunk, &out_buf, &out_size);
    TEST_CHECK(ret == CIO_OK);
    TEST_CHECK(memcmp(out_buf, "line 1\nline 2\n", 7*2+1) == 0);
    TEST_CHECK(out_size == 7*2);
    free(out_buf);

    cio_destroy(ctx);
}

static void test_deep_hierarchy()
{
    int i;
    int ret;
    int err;
    int len;
    char line[] = "this is a test line\n";
    struct cio_ctx *ctx;
    struct cio_chunk *chunk;
    struct cio_stream *stream;
    struct cio_options cio_opts;

    cio_utils_recursive_delete("tmp");

    /* Create a temporal storage */
    cio_options_init(&cio_opts);

    cio_opts.root_path = "tmp/deep/log/dir";
    cio_opts.log_cb = log_cb;
    cio_opts.log_level = CIO_LOG_DEBUG;
    cio_opts.flags = 0;

    ctx = cio_create(&cio_opts);
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

static void truncate_file(struct cio_file *chunk_file,
                          size_t new_file_size,
                          int remove_content_length)
{
    int result;

    result = cio_file_native_open(chunk_file);
    TEST_CHECK(result == CIO_OK);

    result = cio_file_native_map(chunk_file,
                                 chunk_file->page_size);
    TEST_CHECK(result == CIO_OK);

    if (remove_content_length) {
        chunk_file->map[CIO_FILE_CONTENT_LENGTH_OFFSET + 0] = 0;
        chunk_file->map[CIO_FILE_CONTENT_LENGTH_OFFSET + 1] = 0;
        chunk_file->map[CIO_FILE_CONTENT_LENGTH_OFFSET + 2] = 0;
        chunk_file->map[CIO_FILE_CONTENT_LENGTH_OFFSET + 3] = 0;
    }

    result = cio_file_native_unmap(chunk_file);
    TEST_CHECK(result == CIO_OK);

    result = cio_file_native_resize(chunk_file, new_file_size);
    TEST_CHECK(result == 0);

    result = cio_file_native_close(chunk_file);
    TEST_CHECK(result == CIO_OK);
}

static void test_legacy_core(int trigger_checksum_error)
{
    struct cio_options cio_opts;
    char              *in_data;
    size_t             in_size;
    struct cio_stream *stream;
    struct cio_chunk  *chunk;
    size_t             delta;
    struct cio_ctx    *ctx;
    int                ret;

    /* delete any previous temporary content directory */
    cio_utils_recursive_delete(CIO_ENV);
     /*
     * Load sample data file and with the same content through multiple write
     * operations generating other files.
     */
    ret = cio_utils_read_file(CIO_FILE_400KB, &in_data, &in_size);
    TEST_CHECK(ret == 0);
    if (ret == -1) {
        exit(EXIT_FAILURE);
    }

    /* create Chunk I/O context */
    cio_options_init(&cio_opts);

    cio_opts.root_path = CIO_ENV;
    cio_opts.log_cb = log_cb;
    cio_opts.log_level = CIO_LOG_DEBUG;
    cio_opts.flags = CIO_CHECKSUM;

    /* Create a temporal storage */
    ctx = cio_create(&cio_opts);

    stream = cio_stream_create(ctx, "test-legacy", CIO_STORE_FS);

    /* do not force a maximum of chunks up, we want to test writing overhead */
    cio_set_max_chunks_up(ctx, 1);

    chunk = cio_chunk_open(ctx,
                           stream,
                           "test_chunk",
                           CIO_OPEN,
                           1000,
                           &ret);

    ret = cio_chunk_write(chunk, in_data, 128);
    TEST_CHECK(ret == 0);

    ret = cio_chunk_down(chunk);
    TEST_CHECK(ret == CIO_OK);

    delta = CIO_FILE_HEADER_MIN;

    if (trigger_checksum_error) {
        delta++;
    }

    truncate_file((struct cio_file *) chunk->backend,
                  128 + delta,
                  CIO_TRUE);

    ret = cio_chunk_up(chunk);

    if (trigger_checksum_error) {
        TEST_CHECK(ret != CIO_OK);
    }
    else {
        TEST_CHECK(ret == CIO_OK);
    }

    cio_destroy(ctx);

    free(in_data);
}

void test_legacy_success()
{
    test_legacy_core(CIO_FALSE);
}

void test_legacy_failure()
{
    test_legacy_core(CIO_TRUE);
}

/*
 * Test case: Prevent unsigned underflow when writing large metadata to a
 * chunk with small initial allocation.
 *
 * This test specifically validates the fix for the bug where calculating
 * content_av = alloc_size - CIO_FILE_HEADER_MIN - size could underflow
 * when size is large, causing the resize check to be skipped and leading
 * to out-of-bounds writes.
 *
 * Scenario:
 * - Create chunk with minimal initial size (e.g., ~100 bytes page-aligned)
 * - Write small metadata (10 bytes) and small content (20 bytes)
 * - Write large metadata (80 bytes) that would cause underflow:
 *   old code: content_av = 100 - 24 - 80 = -4 (wraps to huge unsigned)
 * - Verify resize happens correctly and no buffer overrun occurs
 */
static void test_metadata_unsigned_underflow()
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

    /* Test data */
    const char *small_meta = "small";
    const char *large_meta = "this-is-a-very-large-metadata-string-that-would-cause-unsigned-underflow-in-old-code";
    const char *content_data = "test-content";

    /* Cleanup any existing test directory */
    cio_utils_recursive_delete(CIO_ENV);

    /* Initialize options */
    cio_options_init(&cio_opts);
    cio_opts.root_path = CIO_ENV;
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
    stream = cio_stream_create(ctx, "test_stream_underflow", CIO_STORE_FS);
    TEST_CHECK(stream != NULL);
    if (!stream) {
        printf("cannot create stream\n");
        cio_destroy(ctx);
        exit(1);
    }

    /* Create chunk with minimal initial size (forces small alloc_size) */
    chunk = cio_chunk_open(ctx, stream, "test_chunk_underflow", CIO_OPEN, 100, &err);
    TEST_CHECK(chunk != NULL);
    if (!chunk) {
        printf("cannot open chunk\n");
        cio_destroy(ctx);
        exit(1);
    }

    /* Step 1: Write small initial metadata */
    ret = cio_meta_write(chunk, (char *) small_meta, strlen(small_meta));
    TEST_CHECK(ret == CIO_OK);

    /* Step 2: Write some content data */
    ret = cio_chunk_write(chunk, content_data, strlen(content_data));
    TEST_CHECK(ret == CIO_OK);

    /* Verify initial state */
    ret = cio_meta_read(chunk, &meta_buf, &meta_len);
    TEST_CHECK(ret == CIO_OK);
    TEST_CHECK(meta_len == (int) strlen(small_meta));
    TEST_CHECK(memcmp(meta_buf, small_meta, strlen(small_meta)) == 0);

    ret = cio_chunk_get_content_copy(chunk, &content_buf, &content_size);
    TEST_CHECK(ret == CIO_OK);
    TEST_CHECK(content_size == strlen(content_data));
    TEST_CHECK(memcmp(content_buf, content_data, strlen(content_data)) == 0);
    free(content_buf);

    /* Step 3: Write large metadata that would cause underflow in old code
     * This is the critical test - the new metadata (80 bytes) is larger than
     * what would fit without resize, and with a small initial alloc_size,
     * the old calculation would have underflowed.
     */
    ret = cio_meta_write(chunk, (char *) large_meta, strlen(large_meta));
    TEST_CHECK(ret == CIO_OK);

    /* Step 4: Verify metadata was written correctly */
    ret = cio_meta_read(chunk, &meta_buf, &meta_len);
    TEST_CHECK(ret == CIO_OK);
    TEST_CHECK(meta_len == (int) strlen(large_meta));
    TEST_CHECK(memcmp(meta_buf, large_meta, strlen(large_meta)) == 0);

    /* Step 5: Verify content data integrity - must be preserved */
    ret = cio_chunk_get_content_copy(chunk, &content_buf, &content_size);
    TEST_CHECK(ret == CIO_OK);
    TEST_CHECK(content_size == strlen(content_data));
    TEST_CHECK(memcmp(content_buf, content_data, strlen(content_data)) == 0);

    /* Step 6: Sync to disk to ensure persistence */
    ret = cio_chunk_sync(chunk);
    TEST_CHECK(ret == CIO_OK);

    /* Step 7: Put chunk down and up again to test persistence */
    ret = cio_chunk_down(chunk);
    TEST_CHECK(ret == CIO_OK);

    ret = cio_chunk_up(chunk);
    TEST_CHECK(ret == CIO_OK);

    /* Step 8: Final validation after persistence cycle */
    ret = cio_meta_read(chunk, &meta_buf, &meta_len);
    TEST_CHECK(ret == CIO_OK);
    TEST_CHECK(meta_len == (int) strlen(large_meta));
    TEST_CHECK(memcmp(meta_buf, large_meta, strlen(large_meta)) == 0);

    ret = cio_chunk_get_content_copy(chunk, &content_buf, &content_size);
    TEST_CHECK(ret == CIO_OK);
    TEST_CHECK(content_size == strlen(content_data));
    TEST_CHECK(memcmp(content_buf, content_data, strlen(content_data)) == 0);

    /* Cleanup */
    free(content_buf);
    cio_destroy(ctx);
}

TEST_LIST = {
    {"fs_write",   test_fs_write},
    {"fs_checksum",  test_fs_checksum},
    {"fs_up_down", test_fs_up_down},
    {"fs_size_chunks_up", test_fs_size_chunks_up},
    {"issue_51",   test_issue_51},
    {"issue_flb_2025", test_issue_flb_2025},
    {"issue_write_at", test_issue_write_at},
    {"fs_up_down_up_append", test_fs_up_down_up_append},
    {"fs_deep_hierachy", test_deep_hierarchy},
    {"legacy_success", test_legacy_success},
    {"legacy_failure", test_legacy_failure},
    {"metadata_unsigned_underflow", test_metadata_unsigned_underflow},
    { 0 }
};
