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
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <limits.h>
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
#include <chunkio/cio_crc32.h>

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

static void set_test_header_u32(char *map, int offset, uint32_t value)
{
    uint8_t *buffer;

    buffer = (uint8_t *) &map[offset];

    buffer[0] = (uint8_t) ((value & 0xFF000000) >> 24);
    buffer[1] = (uint8_t) ((value & 0x00FF0000) >> 16);
    buffer[2] = (uint8_t) ((value & 0x0000FF00) >>  8);
    buffer[3] = (uint8_t) ((value & 0x000000FF) >>  0);
}

static uint32_t get_test_header_u32(char *map, int offset)
{
    uint8_t *buffer;

    buffer = (uint8_t *) &map[offset];

    return (((uint32_t) buffer[0]) << 24) |
           (((uint32_t) buffer[1]) << 16) |
           (((uint32_t) buffer[2]) <<  8) |
           (((uint32_t) buffer[3]) <<  0);
}

static struct cio_chunk *find_stream_chunk(struct cio_stream *stream,
                                           const char *name)
{
    struct mk_list *head;
    struct cio_chunk *chunk;

    if (stream == NULL || name == NULL) {
        return NULL;
    }

    mk_list_foreach(head, &stream->chunks) {
        chunk = mk_list_entry(head, struct cio_chunk, _head);

        if (strcmp(chunk->name, name) == 0) {
            return chunk;
        }
    }

    return NULL;
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

    cio_destroy(ctx);
}

static void test_fs_recover_unfinalized_checksum()
{
    int ret;
    int err;
    char *hash;
    char *out_buf;
    size_t out_size;
    crc_t crc_unfinalized;
    struct cio_ctx *ctx;
    struct cio_file *cf;
    struct cio_chunk *chunk;
    struct cio_stream *stream;
    struct cio_options cio_opts;
    char line[] = "recoverable checksum payload\n";

    cio_utils_recursive_delete(CIO_ENV);

    cio_options_init(&cio_opts);

    cio_opts.root_path = CIO_ENV;
    cio_opts.log_cb = log_cb;
    cio_opts.log_level = CIO_LOG_INFO;
    cio_opts.flags = CIO_CHECKSUM;

    ctx = cio_create(&cio_opts);
    TEST_CHECK(ctx != NULL);

    stream = cio_stream_create(ctx, "test_recover_crc", CIO_STORE_FS);
    TEST_CHECK(stream != NULL);

    chunk = cio_chunk_open(ctx, stream, "test", CIO_OPEN, 1000, &err);
    TEST_CHECK(chunk != NULL);
    if (!chunk) {
        exit(1);
    }

    ret = cio_chunk_write(chunk, line, strlen(line));
    TEST_CHECK(ret == CIO_OK);

    ret = cio_chunk_sync(chunk);
    TEST_CHECK(ret == CIO_OK);

    cf = (struct cio_file *) chunk->backend;
    crc_unfinalized = cf->crc_cur;
    hash = cio_file_hash(cf);
    /*
     * Reproduce the legacy on-disk layout exactly: the old writer stored the
     * non finalized crc with memcpy(map + 2, &crc, sizeof(crc)). Using the full
     * native width here means this test exercises the correct bytes on both
     * little- and big-endian targets (on big-endian 64-bit the significant
     * bytes land at offset 6..9, not 2..5).
     */
    memcpy(hash, &crc_unfinalized, sizeof(crc_unfinalized));

    ret = cio_file_native_sync(cf, CIO_FULL_SYNC);
    TEST_CHECK(ret == CIO_OK);

    ret = cio_chunk_down(chunk);
    TEST_CHECK(ret == CIO_OK);

    ret = cio_chunk_up(chunk);
    TEST_CHECK(ret == CIO_OK);

    ret = cio_chunk_get_content_copy(chunk, (void **) &out_buf, &out_size);
    TEST_CHECK(ret == CIO_OK);
    TEST_CHECK(out_size == strlen(line));
    TEST_CHECK(memcmp(out_buf, line, out_size) == 0);
    free(out_buf);

    ret = cio_chunk_down(chunk);
    TEST_CHECK(ret == CIO_OK);

    ret = cio_chunk_up(chunk);
    TEST_CHECK(ret == CIO_OK);

    cio_destroy(ctx);
}

static void test_fs_shadow_checksum_recovers_primary_header()
{
    int ret;
    int err;
    char *hash;
    char *out_buf;
    size_t out_size;
    struct cio_ctx *ctx;
    struct cio_file *cf;
    struct cio_chunk *chunk;
    struct cio_stream *stream;
    struct cio_options cio_opts;
    char line[] = "shadow checksum payload\n";

    cio_utils_recursive_delete(CIO_ENV);

    cio_options_init(&cio_opts);

    cio_opts.root_path = CIO_ENV;
    cio_opts.log_cb = log_cb;
    cio_opts.log_level = CIO_LOG_INFO;
    cio_opts.flags = CIO_CHECKSUM;

    ctx = cio_create(&cio_opts);
    TEST_CHECK(ctx != NULL);

    stream = cio_stream_create(ctx, "test_shadow_crc", CIO_STORE_FS);
    TEST_CHECK(stream != NULL);

    chunk = cio_chunk_open(ctx, stream, "test", CIO_OPEN, 1000, &err);
    TEST_CHECK(chunk != NULL);
    if (!chunk) {
        exit(1);
    }

    ret = cio_chunk_write(chunk, line, strlen(line));
    TEST_CHECK(ret == CIO_OK);

    ret = cio_chunk_sync(chunk);
    TEST_CHECK(ret == CIO_OK);

    cf = (struct cio_file *) chunk->backend;
    hash = cio_file_hash(cf);
    hash[0] ^= 0xff;

    ret = cio_file_native_sync(cf, CIO_FULL_SYNC);
    TEST_CHECK(ret == CIO_OK);

    ret = cio_chunk_down(chunk);
    TEST_CHECK(ret == CIO_OK);

    ret = cio_chunk_up(chunk);
    TEST_CHECK(ret == CIO_OK);

    ret = cio_chunk_get_content_copy(chunk, (void **) &out_buf, &out_size);
    TEST_CHECK(ret == CIO_OK);
    TEST_CHECK(out_size == strlen(line));
    TEST_CHECK(memcmp(out_buf, line, out_size) == 0);
    free(out_buf);

    ret = cio_chunk_down(chunk);
    TEST_CHECK(ret == CIO_OK);

    ret = cio_chunk_up(chunk);
    TEST_CHECK(ret == CIO_OK);

    cio_destroy(ctx);
}

static void test_fs_shadow_checksum_recovers_read_only()
{
    int ret;
    int err;
    FILE *fp;
    char *hash;
    char *out_buf;
    size_t out_size;
    struct cio_ctx *ctx;
    struct cio_file *cf;
    struct cio_chunk *chunk;
    struct cio_stream *stream;
    struct cio_options cio_opts;
    unsigned char corrupted_hash[4];
    unsigned char stored_hash[4];
    char path[1024];
    char line[] = "read-only shadow checksum payload\n";

    cio_utils_recursive_delete(CIO_ENV);

    cio_options_init(&cio_opts);

    cio_opts.root_path = CIO_ENV;
    cio_opts.log_cb = log_cb;
    cio_opts.log_level = CIO_LOG_INFO;
    cio_opts.flags = CIO_CHECKSUM;

    ctx = cio_create(&cio_opts);
    TEST_CHECK(ctx != NULL);

    stream = cio_stream_create(ctx, "test_shadow_read_only", CIO_STORE_FS);
    TEST_CHECK(stream != NULL);

    chunk = cio_chunk_open(ctx, stream, "test", CIO_OPEN, 1000, &err);
    TEST_CHECK(chunk != NULL);
    if (!chunk) {
        exit(1);
    }

    ret = cio_chunk_write(chunk, line, strlen(line));
    TEST_CHECK(ret == CIO_OK);

    ret = cio_chunk_sync(chunk);
    TEST_CHECK(ret == CIO_OK);

    cf = (struct cio_file *) chunk->backend;
    hash = cio_file_hash(cf);
    hash[0] ^= 0xff;
    memcpy(corrupted_hash, hash, sizeof(corrupted_hash));

    ret = cio_file_native_sync(cf, CIO_FULL_SYNC);
    TEST_CHECK(ret == CIO_OK);

    snprintf(path, sizeof(path), "%s/%s/%s", CIO_ENV,
             "test_shadow_read_only", "test");

    cio_destroy(ctx);

    cio_options_init(&cio_opts);

    cio_opts.root_path = CIO_ENV;
    cio_opts.log_cb = log_cb;
    cio_opts.log_level = CIO_LOG_INFO;
    cio_opts.flags = CIO_OPEN_RD | CIO_CHECKSUM;

    ctx = cio_create(&cio_opts);
    TEST_CHECK(ctx != NULL);

    stream = cio_stream_create(ctx, "test_shadow_read_only", CIO_STORE_FS);
    TEST_CHECK(stream != NULL);

    chunk = cio_chunk_open(ctx, stream, "test", CIO_OPEN_RD, 0, &err);
    TEST_CHECK(chunk != NULL);
    if (!chunk) {
        exit(1);
    }

    ret = cio_chunk_get_content_copy(chunk, (void **) &out_buf, &out_size);
    TEST_CHECK(ret == CIO_OK);
    TEST_CHECK(out_size == strlen(line));
    TEST_CHECK(memcmp(out_buf, line, out_size) == 0);
    free(out_buf);

    cio_destroy(ctx);

    fp = fopen(path, "rb+");
    TEST_CHECK(fp != NULL);
    if (!fp) {
        exit(1);
    }

    ret = fseek(fp, 2, SEEK_SET);
    TEST_CHECK(ret == 0);

    ret = fread(stored_hash, 1, sizeof(stored_hash), fp);
    TEST_CHECK(ret == sizeof(stored_hash));

    ret = fclose(fp);
    TEST_CHECK(ret == 0);

    TEST_CHECK(memcmp(stored_hash, corrupted_hash, sizeof(stored_hash)) == 0);
}

static void test_fs_shadow_checksum_recovers_primary_length()
{
    int ret;
    int err;
    char *out_buf;
    size_t out_size;
    struct cio_ctx *ctx;
    struct cio_file *cf;
    struct cio_chunk *chunk;
    struct cio_stream *stream;
    struct cio_options cio_opts;
    char line[] = "shadow checksum payload\n";
    char tail[] = "after recovery\n";

    cio_utils_recursive_delete(CIO_ENV);

    cio_options_init(&cio_opts);

    cio_opts.root_path = CIO_ENV;
    cio_opts.log_cb = log_cb;
    cio_opts.log_level = CIO_LOG_INFO;
    cio_opts.flags = CIO_CHECKSUM;

    ctx = cio_create(&cio_opts);
    TEST_CHECK(ctx != NULL);

    stream = cio_stream_create(ctx, "test_shadow_len", CIO_STORE_FS);
    TEST_CHECK(stream != NULL);

    chunk = cio_chunk_open(ctx, stream, "test", CIO_OPEN, 1000, &err);
    TEST_CHECK(chunk != NULL);
    if (!chunk) {
        exit(1);
    }

    ret = cio_chunk_write(chunk, line, strlen(line));
    TEST_CHECK(ret == CIO_OK);

    ret = cio_chunk_sync(chunk);
    TEST_CHECK(ret == CIO_OK);

    cf = (struct cio_file *) chunk->backend;
    cio_file_st_set_content_len(cf->map, 5);

    ret = cio_file_native_sync(cf, CIO_FULL_SYNC);
    TEST_CHECK(ret == CIO_OK);

    ret = cio_chunk_down(chunk);
    TEST_CHECK(ret == CIO_OK);

    ret = cio_chunk_up(chunk);
    TEST_CHECK(ret == CIO_OK);

    ret = cio_chunk_get_content_copy(chunk, (void **) &out_buf, &out_size);
    TEST_CHECK(ret == CIO_OK);
    TEST_CHECK(out_size == strlen(line));
    TEST_CHECK(memcmp(out_buf, line, out_size) == 0);
    free(out_buf);

    ret = cio_chunk_write(chunk, tail, strlen(tail));
    TEST_CHECK(ret == CIO_OK);

    ret = cio_chunk_sync(chunk);
    TEST_CHECK(ret == CIO_OK);

    ret = cio_chunk_down(chunk);
    TEST_CHECK(ret == CIO_OK);

    ret = cio_chunk_up(chunk);
    TEST_CHECK(ret == CIO_OK);

    ret = cio_chunk_get_content_copy(chunk, (void **) &out_buf, &out_size);
    TEST_CHECK(ret == CIO_OK);
    TEST_CHECK(out_size == strlen(line) + strlen(tail));
    TEST_CHECK(memcmp(out_buf, line, strlen(line)) == 0);
    TEST_CHECK(memcmp(out_buf + strlen(line), tail, strlen(tail)) == 0);
    free(out_buf);

    cio_destroy(ctx);
}

static void test_fs_valid_primary_precedes_newer_shadow()
{
    int ret;
    int err;
    char *out_buf;
    size_t out_size;
    crc_t crc;
    struct cio_ctx *ctx;
    struct cio_file *cf;
    struct cio_chunk *chunk;
    struct cio_stream *stream;
    struct cio_options cio_opts;
    char line[] = "shadow checksum payload\n";
    char tail[] = "after recovery\n";

    cio_utils_recursive_delete(CIO_ENV);

    cio_options_init(&cio_opts);

    cio_opts.root_path = CIO_ENV;
    cio_opts.log_cb = log_cb;
    cio_opts.log_level = CIO_LOG_INFO;
    cio_opts.flags = CIO_CHECKSUM;

    ctx = cio_create(&cio_opts);
    TEST_CHECK(ctx != NULL);

    stream = cio_stream_create(ctx, "test_shadow_stale", CIO_STORE_FS);
    TEST_CHECK(stream != NULL);

    chunk = cio_chunk_open(ctx, stream, "test", CIO_OPEN, 1000, &err);
    TEST_CHECK(chunk != NULL);
    if (!chunk) {
        exit(1);
    }

    ret = cio_chunk_write(chunk, line, strlen(line));
    TEST_CHECK(ret == CIO_OK);

    ret = cio_chunk_sync(chunk);
    TEST_CHECK(ret == CIO_OK);

    ret = cio_chunk_write(chunk, tail, strlen(tail));
    TEST_CHECK(ret == CIO_OK);

    /* Both tuples validate: without a generation marker the primary wins. */
    cf = (struct cio_file *) chunk->backend;
    cf->crc_cur = cio_crc32_init();
    cio_file_calculate_checksum(cf, &crc);
    cf->crc_cur = crc;

    set_test_header_u32(cf->map,
                        CIO_FILE_SHADOW_CONTENT_LENGTH_OFFSET,
                        (uint32_t) cf->data_size);
    set_test_header_u32(cf->map,
                        CIO_FILE_SHADOW_HASH_OFFSET,
                        (uint32_t) cio_crc32_finalize(crc));

    ret = cio_file_native_sync(cf, CIO_FULL_SYNC);
    TEST_CHECK(ret == CIO_OK);

    cf->synced = CIO_TRUE;

    ret = cio_chunk_down(chunk);
    TEST_CHECK(ret == CIO_OK);

    ret = cio_chunk_up(chunk);
    TEST_CHECK(ret == CIO_OK);

    ret = cio_chunk_get_content_copy(chunk, (void **) &out_buf, &out_size);
    TEST_CHECK(ret == CIO_OK);
    TEST_CHECK(out_size == strlen(line));
    TEST_CHECK(memcmp(out_buf, line, strlen(line)) == 0);
    free(out_buf);

    cio_destroy(ctx);
}

/* Older writers update the primary tuple but leave shadow padding untouched. */
static void check_stale_shadow_after_legacy_write(int truncate, int read_only)
{
    int ret;
    int err;
    char *out_buf;
    size_t out_size;
    size_t expected_size;
    unsigned char shadow[8];
    unsigned char header[CIO_FILE_HEADER_MIN];
    struct cio_options opts;
    struct cio_ctx *ctx;
    struct cio_stream *stream;
    struct cio_chunk *chunk;
    struct cio_file *cf;
    char head[] = "original records\n";
    char tail[] = "appended records\n";

    cio_utils_recursive_delete(CIO_ENV);
    cio_options_init(&opts);
    opts.root_path = CIO_ENV;
    opts.flags = CIO_CHECKSUM;
    ctx = cio_create(&opts);
    if (!TEST_CHECK(ctx != NULL)) {
        exit(1);
    }
    stream = cio_stream_create(ctx, "legacy_writer", CIO_STORE_FS);
    if (!TEST_CHECK(stream != NULL)) {
        exit(1);
    }
    chunk = cio_chunk_open(ctx, stream, "test", CIO_OPEN, 1000, &err);
    if (!TEST_CHECK(chunk != NULL)) {
        exit(1);
    }
    ret = cio_chunk_write(chunk, head, strlen(head));
    if (!TEST_CHECK(ret == CIO_OK)) {
        exit(1);
    }
    if (truncate) {
        ret = cio_chunk_write(chunk, tail, strlen(tail));
        if (!TEST_CHECK(ret == CIO_OK)) {
            exit(1);
        }
    }
    ret = cio_chunk_sync(chunk);
    if (!TEST_CHECK(ret == CIO_OK)) {
        exit(1);
    }
    cf = chunk->backend;
    memcpy(shadow, cf->map + CIO_FILE_SHADOW_CONTENT_LENGTH_OFFSET, sizeof(shadow));

    if (truncate) {
        ret = cio_chunk_write_at(chunk, strlen(head), NULL, 0);
        expected_size = strlen(head);
    }
    else {
        ret = cio_chunk_write(chunk, tail, strlen(tail));
        expected_size = strlen(head) + strlen(tail);
    }
    if (!TEST_CHECK(ret == CIO_OK)) {
        exit(1);
    }
    ret = cio_chunk_sync(chunk);
    if (!TEST_CHECK(ret == CIO_OK)) {
        exit(1);
    }

    /* Reproduce an old writer's valid primary with the previous shadow tuple. */
    memcpy(cf->map + CIO_FILE_SHADOW_CONTENT_LENGTH_OFFSET, shadow, sizeof(shadow));
    memcpy(header, cf->map, sizeof(header));
    ret = cio_file_native_sync(cf, CIO_FULL_SYNC);
    if (!TEST_CHECK(ret == CIO_OK)) {
        exit(1);
    }
    cio_destroy(ctx);

    cio_options_init(&opts);
    opts.root_path = CIO_ENV;
    opts.flags = CIO_CHECKSUM | (read_only ? CIO_OPEN_RD : 0);
    ctx = cio_create(&opts);
    if (!TEST_CHECK(ctx != NULL)) {
        exit(1);
    }
    stream = cio_stream_create(ctx, "legacy_writer", CIO_STORE_FS);
    if (!TEST_CHECK(stream != NULL)) {
        exit(1);
    }
    chunk = cio_chunk_open(ctx, stream, "test",
                           read_only ? CIO_OPEN_RD : CIO_OPEN, 0, &err);
    if (!TEST_CHECK(chunk != NULL)) {
        exit(1);
    }
    cf = chunk->backend;
    TEST_CHECK(memcmp(cf->map, header, sizeof(header)) == 0);
    ret = cio_chunk_get_content_copy(chunk, (void **) &out_buf, &out_size);
    if (!TEST_CHECK(ret == CIO_OK)) {
        exit(1);
    }
    TEST_CHECK(out_size == expected_size);
    if (out_size == expected_size) {
        TEST_CHECK(memcmp(out_buf, head, strlen(head)) == 0);
        if (!truncate) {
            TEST_CHECK(memcmp(out_buf + strlen(head), tail, strlen(tail)) == 0);
        }
    }
    free(out_buf);
    cio_destroy(ctx);
}

static void test_fs_valid_primary_with_stale_shadow_append()
{
    check_stale_shadow_after_legacy_write(CIO_FALSE, CIO_FALSE);
}

static void test_fs_valid_primary_with_stale_shadow_truncate()
{
    check_stale_shadow_after_legacy_write(CIO_TRUE, CIO_FALSE);
}

static void test_fs_valid_primary_with_stale_shadow_read_only_append()
{
    check_stale_shadow_after_legacy_write(CIO_FALSE, CIO_TRUE);
}

static void test_fs_valid_primary_with_stale_shadow_read_only_truncate()
{
    check_stale_shadow_after_legacy_write(CIO_TRUE, CIO_TRUE);
}

static void test_fs_write_at_zero_truncates_synced_checksum()
{
    int ret;
    int err;
    char *out_buf;
    size_t out_size;
    struct cio_ctx *ctx;
    struct cio_file *cf;
    struct cio_chunk *chunk;
    struct cio_stream *stream;
    struct cio_options cio_opts;
    char head[] = "valid records\n";
    char stale[] = "stale records\n";
    char next[] = "next records\n";

    cio_utils_recursive_delete(CIO_ENV);

    cio_options_init(&cio_opts);

    cio_opts.root_path = CIO_ENV;
    cio_opts.log_cb = log_cb;
    cio_opts.log_level = CIO_LOG_INFO;
    cio_opts.flags = CIO_CHECKSUM;

    ctx = cio_create(&cio_opts);
    TEST_CHECK(ctx != NULL);

    stream = cio_stream_create(ctx, "test_write_at_zero_crc", CIO_STORE_FS);
    TEST_CHECK(stream != NULL);

    chunk = cio_chunk_open(ctx, stream, "test", CIO_OPEN, 1000, &err);
    TEST_CHECK(chunk != NULL);
    if (!chunk) {
        exit(1);
    }

    ret = cio_chunk_write(chunk, head, strlen(head));
    TEST_CHECK(ret == CIO_OK);

    ret = cio_chunk_write(chunk, stale, strlen(stale));
    TEST_CHECK(ret == CIO_OK);

    ret = cio_chunk_sync(chunk);
    TEST_CHECK(ret == CIO_OK);

    ret = cio_chunk_write_at(chunk, strlen(head), NULL, 0);
    TEST_CHECK(ret == CIO_OK);

    ret = cio_chunk_down(chunk);
    TEST_CHECK(ret == CIO_OK);

    ret = cio_chunk_up(chunk);
    TEST_CHECK(ret == CIO_OK);

    ret = cio_chunk_get_content_copy(chunk, (void **) &out_buf, &out_size);
    TEST_CHECK(ret == CIO_OK);
    TEST_CHECK(out_size == strlen(head));
    TEST_CHECK(memcmp(out_buf, head, out_size) == 0);
    free(out_buf);

    ret = cio_chunk_write(chunk, next, strlen(next));
    TEST_CHECK(ret == CIO_OK);

    ret = cio_chunk_sync(chunk);
    TEST_CHECK(ret == CIO_OK);

    ret = cio_chunk_down(chunk);
    TEST_CHECK(ret == CIO_OK);

    ret = cio_chunk_up(chunk);
    TEST_CHECK(ret == CIO_OK);

    ret = cio_chunk_get_content_copy(chunk, (void **) &out_buf, &out_size);
    TEST_CHECK(ret == CIO_OK);
    TEST_CHECK(out_size == strlen(head) + strlen(next));
    TEST_CHECK(memcmp(out_buf, head, strlen(head)) == 0);
    TEST_CHECK(memcmp(out_buf + strlen(head), next, strlen(next)) == 0);
    free(out_buf);

    cf = (struct cio_file *) chunk->backend;
    TEST_CHECK(cf->map[CIO_FILE_LEGACY_CRC_PADDING_OFFSET + 0] == 0);
    TEST_CHECK(cf->map[CIO_FILE_LEGACY_CRC_PADDING_OFFSET + 1] == 0);
    TEST_CHECK(cf->map[CIO_FILE_LEGACY_CRC_PADDING_OFFSET + 2] == 0);
    TEST_CHECK(cf->map[CIO_FILE_LEGACY_CRC_PADDING_OFFSET + 3] == 0);

    cio_destroy(ctx);
}

static void test_fs_legacy_checksum_without_shadow_header()
{
    int ret;
    int err;
    char *out_buf;
    size_t out_size;
    struct cio_ctx *ctx;
    struct cio_file *cf;
    struct cio_chunk *chunk;
    struct cio_stream *stream;
    struct cio_options cio_opts;
    char line[] = "legacy checksum payload\n";

    cio_utils_recursive_delete(CIO_ENV);

    cio_options_init(&cio_opts);

    cio_opts.root_path = CIO_ENV;
    cio_opts.log_cb = log_cb;
    cio_opts.log_level = CIO_LOG_INFO;
    cio_opts.flags = CIO_CHECKSUM;

    ctx = cio_create(&cio_opts);
    TEST_CHECK(ctx != NULL);

    stream = cio_stream_create(ctx, "test_legacy_crc", CIO_STORE_FS);
    TEST_CHECK(stream != NULL);

    chunk = cio_chunk_open(ctx, stream, "test", CIO_OPEN, 1000, &err);
    TEST_CHECK(chunk != NULL);
    if (!chunk) {
        exit(1);
    }

    ret = cio_chunk_write(chunk, line, strlen(line));
    TEST_CHECK(ret == CIO_OK);

    ret = cio_chunk_sync(chunk);
    TEST_CHECK(ret == CIO_OK);

    cf = (struct cio_file *) chunk->backend;
    TEST_CHECK(cf->map[CIO_FILE_LEGACY_CRC_PADDING_OFFSET + 0] == 0);
    TEST_CHECK(cf->map[CIO_FILE_LEGACY_CRC_PADDING_OFFSET + 1] == 0);
    TEST_CHECK(cf->map[CIO_FILE_LEGACY_CRC_PADDING_OFFSET + 2] == 0);
    TEST_CHECK(cf->map[CIO_FILE_LEGACY_CRC_PADDING_OFFSET + 3] == 0);

    memset(cf->map + CIO_FILE_SHADOW_CONTENT_LENGTH_OFFSET, 0, 4);
    memset(cf->map + CIO_FILE_SHADOW_HASH_OFFSET, 0, 4);

    ret = cio_file_native_sync(cf, CIO_FULL_SYNC);
    TEST_CHECK(ret == CIO_OK);

    ret = cio_chunk_down(chunk);
    TEST_CHECK(ret == CIO_OK);

    ret = cio_chunk_up(chunk);
    TEST_CHECK(ret == CIO_OK);

    ret = cio_chunk_get_content_copy(chunk, (void **) &out_buf, &out_size);
    TEST_CHECK(ret == CIO_OK);
    TEST_CHECK(out_size == strlen(line));
    TEST_CHECK(memcmp(out_buf, line, out_size) == 0);
    free(out_buf);

    cio_destroy(ctx);
}

/*
 * Forward compatibility: a chunk written in the legacy on-disk format (no shadow
 * tuple, primary CRC + content length only) must be loaded correctly by the
 * current code after a full restart (fresh context + cio_load), and the legacy
 * chunk must NOT be rewritten/decorated with a shadow tuple just by reading it.
 */
static void test_fs_old_format_loads_via_restart()
{
    int ret;
    int err;
    char *buf;
    size_t buf_size;
    struct cio_ctx *ctx;
    struct cio_file *cf;
    struct cio_chunk *chunk;
    struct cio_stream *stream;
    struct cio_options cio_opts;
    char line[] = "legacy on-disk chunk payload\n";

    cio_utils_recursive_delete(CIO_ENV);

    cio_options_init(&cio_opts);

    cio_opts.root_path = CIO_ENV;
    cio_opts.log_cb = log_cb;
    cio_opts.log_level = CIO_LOG_INFO;
    cio_opts.flags = CIO_OPEN | CIO_CHECKSUM;

    ctx = cio_create(&cio_opts);
    TEST_CHECK(ctx != NULL);
    if (!ctx) {
        exit(1);
    }

    stream = cio_stream_create(ctx, "test_old_format", CIO_STORE_FS);
    TEST_CHECK(stream != NULL);

    chunk = cio_chunk_open(ctx, stream, "chunk.0", CIO_OPEN, 1000, &err);
    TEST_CHECK(chunk != NULL);
    if (!chunk) {
        exit(1);
    }

    ret = cio_chunk_write(chunk, line, strlen(line));
    TEST_CHECK(ret == CIO_OK);

    ret = cio_chunk_sync(chunk);
    TEST_CHECK(ret == CIO_OK);

    /*
     * Downgrade the header to the legacy layout: the primary CRC (bytes 2..5)
     * and the content length (bytes 10..13) are already byte-identical to what
     * old writers produced; the only legacy difference is the absence of the
     * shadow tuple, so we zero bytes 14..21.
     */
    cf = (struct cio_file *) chunk->backend;
    memset(cf->map + CIO_FILE_SHADOW_CONTENT_LENGTH_OFFSET, 0, 4);
    memset(cf->map + CIO_FILE_SHADOW_HASH_OFFSET, 0, 4);

    ret = cio_file_native_sync(cf, CIO_FULL_SYNC);
    TEST_CHECK(ret == CIO_OK);

    ret = cio_chunk_down(chunk);
    TEST_CHECK(ret == CIO_OK);

    cio_destroy(ctx);

    /* Restart: a fresh context discovers the legacy chunk on disk */
    cio_options_init(&cio_opts);

    cio_opts.root_path = CIO_ENV;
    cio_opts.log_cb = log_cb;
    cio_opts.log_level = CIO_LOG_INFO;
    cio_opts.flags = CIO_OPEN | CIO_CHECKSUM;

    ctx = cio_create(&cio_opts);
    TEST_CHECK(ctx != NULL);
    if (!ctx) {
        exit(1);
    }

    ret = cio_load(ctx, NULL);
    TEST_CHECK(ret == CIO_OK);

    stream = cio_stream_get(ctx, "test_old_format");
    TEST_CHECK(stream != NULL);
    chunk = find_stream_chunk(stream, "chunk.0");
    TEST_CHECK(chunk != NULL);
    if (!chunk) {
        exit(1);
    }

    if (cio_chunk_is_up(chunk) == CIO_FALSE) {
        ret = cio_chunk_up_force(chunk);
        TEST_CHECK(ret == CIO_OK);
    }

    ret = cio_chunk_get_content(chunk, &buf, &buf_size);
    TEST_CHECK(ret == CIO_OK);
    TEST_CHECK(buf_size == strlen(line));
    TEST_CHECK(memcmp(buf, line, strlen(line)) == 0);

    /*
     * Reading a valid legacy chunk must not have synthesized a shadow tuple:
     * bytes 14..21 stay zero until the chunk is actually re-synced.
     */
    cf = (struct cio_file *) chunk->backend;
    TEST_CHECK(get_test_header_u32(cf->map,
                                   CIO_FILE_SHADOW_CONTENT_LENGTH_OFFSET) == 0);
    TEST_CHECK(get_test_header_u32(cf->map, CIO_FILE_SHADOW_HASH_OFFSET) == 0);

    cio_destroy(ctx);
}

/*
 * Shadow recovery must reject a tuple whose content length does not fit in the
 * file: a corrupted primary CRC combined with an oversized shadow length must
 * surface as CIO_CORRUPTED, never a silent accept of out-of-bounds content.
 */
static void check_shadow_rejects_oversized_length(int maximum_length)
{
    int ret;
    int err;
    char *hash;
    struct cio_ctx *ctx;
    struct cio_file *cf;
    struct cio_chunk *chunk;
    struct cio_stream *stream;
    struct cio_options cio_opts;
    char line[] = "shadow oversized payload\n";

    cio_utils_recursive_delete(CIO_ENV);

    cio_options_init(&cio_opts);

    cio_opts.root_path = CIO_ENV;
    cio_opts.log_cb = log_cb;
    cio_opts.log_level = CIO_LOG_INFO;
    cio_opts.flags = CIO_CHECKSUM;

    ctx = cio_create(&cio_opts);
    TEST_CHECK(ctx != NULL);

    stream = cio_stream_create(ctx, "test_shadow_oversized", CIO_STORE_FS);
    TEST_CHECK(stream != NULL);

    chunk = cio_chunk_open(ctx, stream, "test", CIO_OPEN, 1000, &err);
    TEST_CHECK(chunk != NULL);
    if (!chunk) {
        exit(1);
    }

    ret = cio_chunk_write(chunk, line, strlen(line));
    TEST_CHECK(ret == CIO_OK);

    ret = cio_chunk_sync(chunk);
    TEST_CHECK(ret == CIO_OK);

    /* Corrupt the primary CRC so recovery must fall through to the shadow */
    cf = (struct cio_file *) chunk->backend;
    hash = cio_file_hash(cf);
    hash[0] ^= 0xff;

    /* Make the shadow content length larger than the file */
    set_test_header_u32(cf->map, CIO_FILE_SHADOW_CONTENT_LENGTH_OFFSET,
                        maximum_length ? UINT32_MAX : (uint32_t) (cf->fs_size + 4096));
    if (maximum_length) {
        /* On 32-bit size_t, UINT32_MAX + the two metadata bytes wraps to 1. */
        set_test_header_u32(cf->map, CIO_FILE_SHADOW_HASH_OFFSET,
                            (uint32_t) cio_crc32_finalize(cio_crc32_update(
                                cio_crc32_init(),
                                cf->map + CIO_FILE_CONTENT_OFFSET, 1)));
    }

    ret = cio_file_native_sync(cf, CIO_FULL_SYNC);
    TEST_CHECK(ret == CIO_OK);

    ret = cio_chunk_down(chunk);
    TEST_CHECK(ret == CIO_OK);

    ret = cio_chunk_up(chunk);
    TEST_CHECK(ret == CIO_CORRUPTED);
    TEST_CHECK(cio_error_get(chunk) == CIO_ERR_BAD_CHECKSUM);

    cf = (struct cio_file *) chunk->backend;
    TEST_CHECK(cf->map == NULL);

    cio_destroy(ctx);
}

static void test_fs_shadow_rejects_oversized_length()
{
    check_shadow_rejects_oversized_length(CIO_FALSE);
}

static void test_fs_shadow_rejects_maximum_length()
{
    check_shadow_rejects_oversized_length(CIO_TRUE);
}

/*
 * Shadow recovery must not mask real content corruption: if a content byte is
 * altered, neither the primary nor the shadow CRC validate against it and the
 * chunk must be reported as corrupted.
 */
static void test_fs_shadow_rejects_corrupt_content()
{
    int ret;
    int err;
    struct cio_ctx *ctx;
    struct cio_file *cf;
    struct cio_chunk *chunk;
    struct cio_stream *stream;
    struct cio_options cio_opts;
    char line[] = "shadow corrupt content payload\n";

    cio_utils_recursive_delete(CIO_ENV);

    cio_options_init(&cio_opts);

    cio_opts.root_path = CIO_ENV;
    cio_opts.log_cb = log_cb;
    cio_opts.log_level = CIO_LOG_INFO;
    cio_opts.flags = CIO_CHECKSUM;

    ctx = cio_create(&cio_opts);
    TEST_CHECK(ctx != NULL);

    stream = cio_stream_create(ctx, "test_shadow_corrupt", CIO_STORE_FS);
    TEST_CHECK(stream != NULL);

    chunk = cio_chunk_open(ctx, stream, "test", CIO_OPEN, 1000, &err);
    TEST_CHECK(chunk != NULL);
    if (!chunk) {
        exit(1);
    }

    ret = cio_chunk_write(chunk, line, strlen(line));
    TEST_CHECK(ret == CIO_OK);

    ret = cio_chunk_sync(chunk);
    TEST_CHECK(ret == CIO_OK);

    /*
     * Flip the first content byte. Both the primary and the (still valid)
     * shadow CRC were computed over the original content, so neither matches
     * the altered data.
     */
    cf = (struct cio_file *) chunk->backend;
    cf->map[CIO_FILE_HEADER_MIN] ^= 0xff;

    ret = cio_file_native_sync(cf, CIO_FULL_SYNC);
    TEST_CHECK(ret == CIO_OK);

    ret = cio_chunk_down(chunk);
    TEST_CHECK(ret == CIO_OK);

    ret = cio_chunk_up(chunk);
    TEST_CHECK(ret == CIO_CORRUPTED);
    TEST_CHECK(cio_error_get(chunk) == CIO_ERR_BAD_CHECKSUM);

    cf = (struct cio_file *) chunk->backend;
    TEST_CHECK(cf->map == NULL);

    cio_destroy(ctx);
}

/*
 * When both the primary and the shadow CRC fields are damaged (even with intact
 * content), recovery must fail closed rather than fabricate an accept.
 */
static void test_fs_shadow_rejects_both_tuples_corrupt()
{
    int ret;
    int err;
    char *hash;
    struct cio_ctx *ctx;
    struct cio_file *cf;
    struct cio_chunk *chunk;
    struct cio_stream *stream;
    struct cio_options cio_opts;
    char line[] = "shadow both corrupt payload\n";

    cio_utils_recursive_delete(CIO_ENV);

    cio_options_init(&cio_opts);

    cio_opts.root_path = CIO_ENV;
    cio_opts.log_cb = log_cb;
    cio_opts.log_level = CIO_LOG_INFO;
    cio_opts.flags = CIO_CHECKSUM;

    ctx = cio_create(&cio_opts);
    TEST_CHECK(ctx != NULL);

    stream = cio_stream_create(ctx, "test_shadow_both", CIO_STORE_FS);
    TEST_CHECK(stream != NULL);

    chunk = cio_chunk_open(ctx, stream, "test", CIO_OPEN, 1000, &err);
    TEST_CHECK(chunk != NULL);
    if (!chunk) {
        exit(1);
    }

    ret = cio_chunk_write(chunk, line, strlen(line));
    TEST_CHECK(ret == CIO_OK);

    ret = cio_chunk_sync(chunk);
    TEST_CHECK(ret == CIO_OK);

    /* Corrupt the primary CRC and the shadow CRC, leaving content intact */
    cf = (struct cio_file *) chunk->backend;
    hash = cio_file_hash(cf);
    hash[0] ^= 0xff;
    cf->map[CIO_FILE_SHADOW_HASH_OFFSET] ^= 0xff;

    ret = cio_file_native_sync(cf, CIO_FULL_SYNC);
    TEST_CHECK(ret == CIO_OK);

    ret = cio_chunk_down(chunk);
    TEST_CHECK(ret == CIO_OK);

    ret = cio_chunk_up(chunk);
    TEST_CHECK(ret == CIO_CORRUPTED);
    TEST_CHECK(cio_error_get(chunk) == CIO_ERR_BAD_CHECKSUM);

    cf = (struct cio_file *) chunk->backend;
    TEST_CHECK(cf->map == NULL);

    cio_destroy(ctx);
}

/*
 * Wire-format contract + rollback safety.
 *
 * Pins the exact on-disk header bytes a freshly synced checksum chunk produces,
 * computed independently from the documented format (CRC32 of the content
 * section, finalized, stored big-endian at offset 2):
 *
 *   - bytes 2..5  : finalized CRC32, big-endian
 *   - bytes 6..9  : kept zero
 *   - bytes 10..13: content length, big-endian
 *
 * Rollback safety scope: an OLDER chunkio binary that reads these chunks after
 * a downgrade compares sizeof(crc_t) bytes starting at offset 2.
 *   - little-endian 64-bit (x86_64, aarch64) and big-endian 32-bit readers:
 *     compatible. They expect the significant CRC bytes at offset 2 and zeros
 *     filling the rest, which is exactly what we write, so the chunk is
 *     accepted. This covers every architecture Fluent Bit ships on.
 *   - big-endian 64-bit readers (s390x, ppc64be): NOT rollback compatible. With
 *     an 8-byte crc_t those builds expected the significant bytes at offset 6..9
 *     and zeros at 2..5 -- the mirror of the canonical layout. The canonical
 *     format was deliberately chosen to be portable across architectures
 *     (forward compatible: see fs_legacy_big_endian_wide_checksum_migrates,
 *     which lets the current code READ such legacy chunks), at the cost of
 *     downgrade compatibility on big-endian 64-bit specifically.
 *
 * If any of the asserted bytes drift, old little-endian binaries would reject
 * chunks written by new ones.
 */
static void test_fs_format_contract_new_chunk_layout()
{
    int ret;
    int err;
    crc_t crc;
    uint32_t expected_crc;
    uint8_t region[2 + 64];
    uint8_t legacy_field[8];
    size_t region_len;
    struct cio_ctx *ctx;
    struct cio_file *cf;
    struct cio_chunk *chunk;
    struct cio_stream *stream;
    struct cio_options cio_opts;
    char line[] = "wire format contract payload\n";

    cio_utils_recursive_delete(CIO_ENV);

    cio_options_init(&cio_opts);

    cio_opts.root_path = CIO_ENV;
    cio_opts.log_cb = log_cb;
    cio_opts.log_level = CIO_LOG_INFO;
    cio_opts.flags = CIO_CHECKSUM;

    ctx = cio_create(&cio_opts);
    TEST_CHECK(ctx != NULL);

    stream = cio_stream_create(ctx, "test_contract", CIO_STORE_FS);
    TEST_CHECK(stream != NULL);

    chunk = cio_chunk_open(ctx, stream, "test", CIO_OPEN, 1000, &err);
    TEST_CHECK(chunk != NULL);
    if (!chunk) {
        exit(1);
    }

    ret = cio_chunk_write(chunk, line, strlen(line));
    TEST_CHECK(ret == CIO_OK);

    ret = cio_chunk_sync(chunk);
    TEST_CHECK(ret == CIO_OK);

    /*
     * Independently compute the CRC the way the format documents it: over the
     * content section which begins with the 2-byte metadata-length field
     * (zero here, no metadata) followed by the user content.
     */
    region[0] = 0x00;
    region[1] = 0x00;
    memcpy(region + 2, line, strlen(line));
    region_len = 2 + strlen(line);

    crc = cio_crc32_init();
    crc = cio_crc32_update(crc, region, region_len);
    expected_crc = (uint32_t) cio_crc32_finalize(crc);

    cf = (struct cio_file *) chunk->backend;

    /*
     * Assert the raw bytes are stored most-significant-byte first, independent
     * of host endianness. These per-byte checks fail on a little-endian host if
     * the implementation were ever changed to a native memcpy (which would put
     * the least-significant byte at offset 2), so they guard portability even
     * when CI only runs on little-endian.
     */
    TEST_CHECK((uint8_t) cf->map[2] == (uint8_t) ((expected_crc >> 24) & 0xFF));
    TEST_CHECK((uint8_t) cf->map[3] == (uint8_t) ((expected_crc >> 16) & 0xFF));
    TEST_CHECK((uint8_t) cf->map[4] == (uint8_t) ((expected_crc >>  8) & 0xFF));
    TEST_CHECK((uint8_t) cf->map[5] == (uint8_t) ((expected_crc >>  0) & 0xFF));

    /* Primary CRC at bytes 2..5, big-endian */
    TEST_CHECK(get_test_header_u32(cf->map, 2) == expected_crc);

    /* Legacy CRC padding bytes 6..9 must stay zero (little-endian rollback) */
    TEST_CHECK(get_test_header_u32(cf->map,
                                   CIO_FILE_LEGACY_CRC_PADDING_OFFSET) == 0);

    /* Content length at bytes 10..13, big-endian (most-significant byte first) */
    TEST_CHECK((uint8_t) cf->map[CIO_FILE_CONTENT_LENGTH_OFFSET + 0] ==
               (uint8_t) (((uint32_t) strlen(line) >> 24) & 0xFF));
    TEST_CHECK((uint8_t) cf->map[CIO_FILE_CONTENT_LENGTH_OFFSET + 1] ==
               (uint8_t) (((uint32_t) strlen(line) >> 16) & 0xFF));
    TEST_CHECK((uint8_t) cf->map[CIO_FILE_CONTENT_LENGTH_OFFSET + 2] ==
               (uint8_t) (((uint32_t) strlen(line) >>  8) & 0xFF));
    TEST_CHECK((uint8_t) cf->map[CIO_FILE_CONTENT_LENGTH_OFFSET + 3] ==
               (uint8_t) (((uint32_t) strlen(line) >>  0) & 0xFF));
    TEST_CHECK(get_test_header_u32(cf->map, CIO_FILE_CONTENT_LENGTH_OFFSET) ==
               (uint32_t) strlen(line));

    /*
     * Emulate the exact comparison an old 64-bit reader performed:
     * memcmp(map + 2, &crc_check, sizeof(crc_t)) where crc_check held the
     * big-endian CRC in its low 4 bytes and zero in the upper 4. The new chunk
     * must satisfy that 8-byte comparison.
     */
    legacy_field[0] = (uint8_t) ((expected_crc & 0xFF000000) >> 24);
    legacy_field[1] = (uint8_t) ((expected_crc & 0x00FF0000) >> 16);
    legacy_field[2] = (uint8_t) ((expected_crc & 0x0000FF00) >>  8);
    legacy_field[3] = (uint8_t) ((expected_crc & 0x000000FF) >>  0);
    legacy_field[4] = 0;
    legacy_field[5] = 0;
    legacy_field[6] = 0;
    legacy_field[7] = 0;
    TEST_CHECK(memcmp(cf->map + 2, legacy_field, sizeof(legacy_field)) == 0);

    cio_destroy(ctx);
}

/*
 * Golden legacy fixture: a chunk whose header is constructed by hand in the
 * pre-shadow on-disk format (no shadow tuple), independent of the current
 * writer, must be discovered and read correctly after a restart. This guards
 * the millions of chunks already on disk from prior chunkio releases.
 */
static void test_fs_golden_legacy_chunk_loads()
{
    int ret;
    int err;
    FILE *fp;
    char *buf;
    size_t buf_size;
    crc_t crc;
    uint32_t crc_final;
    uint8_t header[CIO_FILE_HEADER_MIN];
    uint8_t region[2 + 64];
    size_t region_len;
    char path[PATH_MAX];
    struct cio_ctx *ctx;
    struct cio_chunk *chunk;
    struct cio_stream *stream;
    struct cio_options cio_opts;
    char line[] = "golden legacy chunk payload\n";

    cio_utils_recursive_delete(CIO_ENV);

    cio_options_init(&cio_opts);

    cio_opts.root_path = CIO_ENV;
    cio_opts.log_cb = log_cb;
    cio_opts.log_level = CIO_LOG_INFO;
    cio_opts.flags = CIO_OPEN | CIO_CHECKSUM;

    ctx = cio_create(&cio_opts);
    TEST_CHECK(ctx != NULL);
    if (!ctx) {
        exit(1);
    }

    /* Create a real chunk so the stream directory and naming exist */
    stream = cio_stream_create(ctx, "test_golden", CIO_STORE_FS);
    TEST_CHECK(stream != NULL);

    chunk = cio_chunk_open(ctx, stream, "chunk.0", CIO_OPEN, 1000, &err);
    TEST_CHECK(chunk != NULL);
    if (!chunk) {
        exit(1);
    }

    ret = cio_chunk_write(chunk, "placeholder", 11);
    TEST_CHECK(ret == CIO_OK);
    ret = cio_chunk_sync(chunk);
    TEST_CHECK(ret == CIO_OK);

    snprintf(path, sizeof(path), "%s/%s/%s", CIO_ENV, "test_golden", "chunk.0");

    ret = cio_chunk_down(chunk);
    TEST_CHECK(ret == CIO_OK);

    cio_destroy(ctx);

    /*
     * Overwrite the chunk file with a hand-built legacy image:
     *   [0..1]   0xC1 0x00            magic
     *   [2..5]   finalized CRC32 BE   over (2-byte meta len + content)
     *   [6..9]   0                    legacy CRC padding
     *   [10..13] content length BE
     *   [14..21] 0                    no shadow tuple (legacy)
     *   [22..23] 0                    metadata length
     *   [24..]   content
     */
    region[0] = 0x00;
    region[1] = 0x00;
    memcpy(region + 2, line, strlen(line));
    region_len = 2 + strlen(line);

    crc = cio_crc32_init();
    crc = cio_crc32_update(crc, region, region_len);
    crc_final = (uint32_t) cio_crc32_finalize(crc);

    memset(header, 0, sizeof(header));
    header[0] = 0xc1;
    header[1] = 0x00;
    header[2] = (uint8_t) ((crc_final & 0xFF000000) >> 24);
    header[3] = (uint8_t) ((crc_final & 0x00FF0000) >> 16);
    header[4] = (uint8_t) ((crc_final & 0x0000FF00) >>  8);
    header[5] = (uint8_t) ((crc_final & 0x000000FF) >>  0);
    /* content length at offset 10, big-endian */
    header[10] = (uint8_t) (((uint32_t) strlen(line) & 0xFF000000) >> 24);
    header[11] = (uint8_t) (((uint32_t) strlen(line) & 0x00FF0000) >> 16);
    header[12] = (uint8_t) (((uint32_t) strlen(line) & 0x0000FF00) >>  8);
    header[13] = (uint8_t) (((uint32_t) strlen(line) & 0x000000FF) >>  0);

    fp = fopen(path, "wb");
    TEST_CHECK(fp != NULL);
    if (!fp) {
        exit(1);
    }
    TEST_CHECK(fwrite(header, 1, sizeof(header), fp) == sizeof(header));
    TEST_CHECK(fwrite(line, 1, strlen(line), fp) == strlen(line));
    fclose(fp);

    /* Restart and discover the hand-built legacy chunk */
    cio_options_init(&cio_opts);

    cio_opts.root_path = CIO_ENV;
    cio_opts.log_cb = log_cb;
    cio_opts.log_level = CIO_LOG_INFO;
    cio_opts.flags = CIO_OPEN | CIO_CHECKSUM;

    ctx = cio_create(&cio_opts);
    TEST_CHECK(ctx != NULL);
    if (!ctx) {
        exit(1);
    }

    ret = cio_load(ctx, NULL);
    TEST_CHECK(ret == CIO_OK);

    stream = cio_stream_get(ctx, "test_golden");
    TEST_CHECK(stream != NULL);
    chunk = find_stream_chunk(stream, "chunk.0");
    TEST_CHECK(chunk != NULL);
    if (!chunk) {
        exit(1);
    }

    if (cio_chunk_is_up(chunk) == CIO_FALSE) {
        ret = cio_chunk_up_force(chunk);
        TEST_CHECK(ret == CIO_OK);
    }

    ret = cio_chunk_get_content(chunk, &buf, &buf_size);
    TEST_CHECK(ret == CIO_OK);
    TEST_CHECK(buf_size == strlen(line));
    TEST_CHECK(memcmp(buf, line, strlen(line)) == 0);

    cio_destroy(ctx);
}

/*
 * Cross-endianness upgrade: an older 64-bit BIG-ENDIAN build stored the
 * finalized crc as a full 8-byte crc_t, landing the significant bytes at
 * offset 6..9 with the canonical slot (offset 2..5) left zero. This test
 * reproduces that exact on-disk layout (in an endianness-independent way, so it
 * runs on any host), then verifies the current code recovers the content and
 * migrates the chunk into the canonical portable layout.
 */
static void test_fs_legacy_big_endian_wide_checksum_migrates()
{
    int ret;
    int err;
    char *out_buf;
    size_t out_size;
    uint32_t real_crc;
    struct cio_ctx *ctx;
    struct cio_file *cf;
    struct cio_chunk *chunk;
    struct cio_stream *stream;
    struct cio_options cio_opts;
    char line[] = "legacy big-endian wide crc payload\n";

    cio_utils_recursive_delete(CIO_ENV);

    cio_options_init(&cio_opts);

    cio_opts.root_path = CIO_ENV;
    cio_opts.log_cb = log_cb;
    cio_opts.log_level = CIO_LOG_INFO;
    cio_opts.flags = CIO_CHECKSUM;

    ctx = cio_create(&cio_opts);
    TEST_CHECK(ctx != NULL);

    stream = cio_stream_create(ctx, "test_legacy_be64", CIO_STORE_FS);
    TEST_CHECK(stream != NULL);

    chunk = cio_chunk_open(ctx, stream, "test", CIO_OPEN, 1000, &err);
    TEST_CHECK(chunk != NULL);
    if (!chunk) {
        exit(1);
    }

    ret = cio_chunk_write(chunk, line, strlen(line));
    TEST_CHECK(ret == CIO_OK);

    ret = cio_chunk_sync(chunk);
    TEST_CHECK(ret == CIO_OK);

    cf = (struct cio_file *) chunk->backend;

    /*
     * Rewrite the header into the legacy 64-bit big-endian layout:
     *   - move the finalized crc from the canonical slot (2..5) to 6..9
     *   - zero the canonical slot
     *   - drop the shadow tuple (it did not exist in that era)
     */
    real_crc = get_test_header_u32(cf->map, 2);
    set_test_header_u32(cf->map, CIO_FILE_LEGACY_CRC_PADDING_OFFSET, real_crc);
    set_test_header_u32(cf->map, 2, 0);
    memset(cf->map + CIO_FILE_SHADOW_CONTENT_LENGTH_OFFSET, 0, 4);
    memset(cf->map + CIO_FILE_SHADOW_HASH_OFFSET, 0, 4);

    ret = cio_file_native_sync(cf, CIO_FULL_SYNC);
    TEST_CHECK(ret == CIO_OK);

    ret = cio_chunk_down(chunk);
    TEST_CHECK(ret == CIO_OK);

    /* Bring it up read/write: recovery + migration to canonical layout */
    ret = cio_chunk_up(chunk);
    TEST_CHECK(ret == CIO_OK);

    ret = cio_chunk_get_content_copy(chunk, (void **) &out_buf, &out_size);
    TEST_CHECK(ret == CIO_OK);
    TEST_CHECK(out_size == strlen(line));
    TEST_CHECK(memcmp(out_buf, line, out_size) == 0);
    free(out_buf);

    /* After migration the crc must live in the canonical slot, padding zeroed */
    cf = (struct cio_file *) chunk->backend;
    TEST_CHECK(get_test_header_u32(cf->map, 2) == real_crc);
    TEST_CHECK(get_test_header_u32(cf->map,
                                   CIO_FILE_LEGACY_CRC_PADDING_OFFSET) == 0);

    /* And it must keep validating through a normal restart cycle */
    ret = cio_chunk_down(chunk);
    TEST_CHECK(ret == CIO_OK);

    ret = cio_chunk_up(chunk);
    TEST_CHECK(ret == CIO_OK);

    ret = cio_chunk_get_content_copy(chunk, (void **) &out_buf, &out_size);
    TEST_CHECK(ret == CIO_OK);
    TEST_CHECK(out_size == strlen(line));
    TEST_CHECK(memcmp(out_buf, line, out_size) == 0);
    free(out_buf);

    cio_destroy(ctx);
}

/*
 * Read-only counterpart of the legacy big-endian recovery: opening such a
 * chunk read-only must recover the content in memory but must NOT rewrite the
 * header (no migration to the canonical layout). The on-disk bytes 2..9 must be
 * byte-for-byte identical before and after the read-only open.
 */
static void test_fs_legacy_big_endian_wide_checksum_read_only()
{
    int ret;
    int err;
    FILE *fp;
    char *out_buf;
    size_t out_size;
    uint32_t real_crc;
    unsigned char before[8];
    unsigned char after[8];
    char path[1024];
    struct cio_ctx *ctx;
    struct cio_file *cf;
    struct cio_chunk *chunk;
    struct cio_stream *stream;
    struct cio_options cio_opts;
    char line[] = "legacy big-endian read-only payload\n";

    cio_utils_recursive_delete(CIO_ENV);

    cio_options_init(&cio_opts);

    cio_opts.root_path = CIO_ENV;
    cio_opts.log_cb = log_cb;
    cio_opts.log_level = CIO_LOG_INFO;
    cio_opts.flags = CIO_CHECKSUM;

    ctx = cio_create(&cio_opts);
    TEST_CHECK(ctx != NULL);

    stream = cio_stream_create(ctx, "test_legacy_be64_ro", CIO_STORE_FS);
    TEST_CHECK(stream != NULL);

    chunk = cio_chunk_open(ctx, stream, "test", CIO_OPEN, 1000, &err);
    TEST_CHECK(chunk != NULL);
    if (!chunk) {
        exit(1);
    }

    ret = cio_chunk_write(chunk, line, strlen(line));
    TEST_CHECK(ret == CIO_OK);

    ret = cio_chunk_sync(chunk);
    TEST_CHECK(ret == CIO_OK);

    /* Reproduce the legacy 64-bit big-endian layout (crc at 6..9, no shadow) */
    cf = (struct cio_file *) chunk->backend;
    real_crc = get_test_header_u32(cf->map, 2);
    set_test_header_u32(cf->map, CIO_FILE_LEGACY_CRC_PADDING_OFFSET, real_crc);
    set_test_header_u32(cf->map, 2, 0);
    memset(cf->map + CIO_FILE_SHADOW_CONTENT_LENGTH_OFFSET, 0, 4);
    memset(cf->map + CIO_FILE_SHADOW_HASH_OFFSET, 0, 4);

    ret = cio_file_native_sync(cf, CIO_FULL_SYNC);
    TEST_CHECK(ret == CIO_OK);

    snprintf(path, sizeof(path), "%s/%s/%s", CIO_ENV,
             "test_legacy_be64_ro", "test");

    cio_destroy(ctx);

    /* Snapshot on-disk bytes 2..9 before the read-only open */
    fp = fopen(path, "rb");
    TEST_CHECK(fp != NULL);
    if (!fp) {
        exit(1);
    }
    TEST_CHECK(fseek(fp, 2, SEEK_SET) == 0);
    TEST_CHECK(fread(before, 1, sizeof(before), fp) == sizeof(before));
    fclose(fp);

    /* Open read-only: content recovered in memory, nothing persisted */
    cio_options_init(&cio_opts);

    cio_opts.root_path = CIO_ENV;
    cio_opts.log_cb = log_cb;
    cio_opts.log_level = CIO_LOG_INFO;
    cio_opts.flags = CIO_OPEN_RD | CIO_CHECKSUM;

    ctx = cio_create(&cio_opts);
    TEST_CHECK(ctx != NULL);

    stream = cio_stream_create(ctx, "test_legacy_be64_ro", CIO_STORE_FS);
    TEST_CHECK(stream != NULL);

    chunk = cio_chunk_open(ctx, stream, "test", CIO_OPEN_RD, 0, &err);
    TEST_CHECK(chunk != NULL);
    if (!chunk) {
        exit(1);
    }

    ret = cio_chunk_get_content_copy(chunk, (void **) &out_buf, &out_size);
    TEST_CHECK(ret == CIO_OK);
    TEST_CHECK(out_size == strlen(line));
    TEST_CHECK(memcmp(out_buf, line, out_size) == 0);
    free(out_buf);

    cio_destroy(ctx);

    /* On-disk header must be untouched: still legacy layout, not migrated */
    fp = fopen(path, "rb");
    TEST_CHECK(fp != NULL);
    if (!fp) {
        exit(1);
    }
    TEST_CHECK(fseek(fp, 2, SEEK_SET) == 0);
    TEST_CHECK(fread(after, 1, sizeof(after), fp) == sizeof(after));
    fclose(fp);

    TEST_CHECK(memcmp(before, after, sizeof(before)) == 0);
    /*
     * after[] starts at file offset 2, so after[0..3] is the canonical slot
     * (offsets 2..5) and after[4..7] is the legacy slot (offsets 6..9). The
     * canonical slot must still be empty and the crc must still live in the
     * legacy slot -- i.e. no migration happened on a read-only open.
     */
    TEST_CHECK(get_test_header_u32((char *) after, 0) == 0);
    TEST_CHECK(get_test_header_u32((char *) after, 4) == real_crc);
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

        chunk_file->map[CIO_FILE_SHADOW_CONTENT_LENGTH_OFFSET + 0] = 0;
        chunk_file->map[CIO_FILE_SHADOW_CONTENT_LENGTH_OFFSET + 1] = 0;
        chunk_file->map[CIO_FILE_SHADOW_CONTENT_LENGTH_OFFSET + 2] = 0;
        chunk_file->map[CIO_FILE_SHADOW_CONTENT_LENGTH_OFFSET + 3] = 0;
        chunk_file->map[CIO_FILE_SHADOW_HASH_OFFSET + 0] = 0;
        chunk_file->map[CIO_FILE_SHADOW_HASH_OFFSET + 1] = 0;
        chunk_file->map[CIO_FILE_SHADOW_HASH_OFFSET + 2] = 0;
        chunk_file->map[CIO_FILE_SHADOW_HASH_OFFSET + 3] = 0;
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
 * Exercise the filesystem/checksum call pattern used by Fluent Bit storage:
 * create a chunk with metadata, reload it with cio_load(), bring it up for
 * backlog processing, lock/down it, truncate the valid content prefix through
 * cio_chunk_write_at(..., NULL, 0), reload again, append, and copy to a DLQ
 * style stream.
 */
static void test_fs_fluent_bit_storage_lifecycle()
{
    int ret;
    int err;
    int meta_len;
    char *buf;
    char *meta_buf;
    void *copy_buf;
    size_t buf_size;
    size_t copy_size;
    size_t valid_size;
    ssize_t content_size;
    ssize_t real_size;
    struct stat st;
    struct cio_ctx *ctx;
    struct cio_chunk *chunk;
    struct cio_chunk *dlq_chunk;
    struct cio_file *cf;
    struct cio_stream *stream;
    struct cio_stream *dlq_stream;
    struct cio_options cio_opts;
    char path[1024];
    char meta[] = "event_type=logs;tag=fb.test";
    char valid[] = "record one\nrecord two\n";
    char stale[] = "partial trailing record";
    char next[] = "record three\n";

    valid_size = strlen(valid);
    copy_buf = NULL;

    cio_utils_recursive_delete(CIO_ENV);

    cio_options_init(&cio_opts);
    cio_opts.root_path = CIO_ENV;
    cio_opts.log_cb = log_cb;
    cio_opts.log_level = CIO_LOG_INFO;
    cio_opts.flags = CIO_OPEN | CIO_CHECKSUM | CIO_FULL_SYNC | CIO_TRIM_FILES;

    ctx = cio_create(&cio_opts);
    TEST_CHECK(ctx != NULL);
    if (!ctx) {
        exit(1);
    }

    cio_set_max_chunks_up(ctx, 1);

    stream = cio_stream_create(ctx, "fluent-bit", CIO_STORE_FS);
    TEST_CHECK(stream != NULL);

    chunk = cio_chunk_open(ctx, stream, "chunk.0", CIO_OPEN, 64, &err);
    TEST_CHECK(chunk != NULL);
    if (!chunk) {
        exit(1);
    }

    ret = cio_meta_write(chunk, meta, strlen(meta));
    TEST_CHECK(ret == CIO_OK);

    ret = cio_chunk_write(chunk, valid, strlen(valid));
    TEST_CHECK(ret == CIO_OK);

    ret = cio_chunk_write(chunk, stale, strlen(stale));
    TEST_CHECK(ret == CIO_OK);

    ret = cio_chunk_sync(chunk);
    TEST_CHECK(ret == CIO_OK);

    snprintf(path, sizeof(path), "%s/%s/%s", CIO_ENV, "fluent-bit", "chunk.0");
    ret = stat(path, &st);
    TEST_CHECK(ret == 0);
    real_size = cio_chunk_get_real_size(chunk);
    TEST_CHECK(real_size == st.st_size);

    content_size = cio_chunk_get_content_size(chunk);
    TEST_CHECK(content_size == (ssize_t) (strlen(valid) + strlen(stale)));

    ret = cio_chunk_down(chunk);
    TEST_CHECK(ret == CIO_OK);

    cio_destroy(ctx);

    cio_options_init(&cio_opts);
    cio_opts.root_path = CIO_ENV;
    cio_opts.log_cb = log_cb;
    cio_opts.log_level = CIO_LOG_INFO;
    cio_opts.flags = CIO_OPEN | CIO_CHECKSUM | CIO_FULL_SYNC | CIO_TRIM_FILES;

    ctx = cio_create(&cio_opts);
    TEST_CHECK(ctx != NULL);
    if (!ctx) {
        exit(1);
    }

    cio_set_max_chunks_up(ctx, 1);

    ret = cio_load(ctx, NULL);
    TEST_CHECK(ret == CIO_OK);

    stream = cio_stream_get(ctx, "fluent-bit");
    TEST_CHECK(stream != NULL);
    chunk = find_stream_chunk(stream, "chunk.0");
    TEST_CHECK(chunk != NULL);
    if (!chunk) {
        exit(1);
    }

    if (cio_chunk_is_up(chunk) == CIO_TRUE) {
        ret = cio_chunk_down(chunk);
        TEST_CHECK(ret == CIO_OK);
    }

    if (cio_chunk_is_up(chunk) == CIO_FALSE) {
        ret = cio_chunk_up_force(chunk);
        TEST_CHECK(ret == CIO_OK);
    }

    ret = cio_meta_read(chunk, &meta_buf, &meta_len);
    TEST_CHECK(ret == CIO_OK);
    TEST_CHECK(meta_len == (int) strlen(meta));
    TEST_CHECK(memcmp(meta_buf, meta, strlen(meta)) == 0);

    ret = cio_chunk_get_content(chunk, &buf, &buf_size);
    TEST_CHECK(ret == CIO_OK);
    TEST_CHECK(buf_size == strlen(valid) + strlen(stale));
    TEST_CHECK(memcmp(buf, valid, strlen(valid)) == 0);
    TEST_CHECK(memcmp(buf + strlen(valid), stale, strlen(stale)) == 0);

    ret = cio_chunk_lock(chunk);
    TEST_CHECK(ret == CIO_OK);
    TEST_CHECK(cio_chunk_is_locked(chunk) == CIO_TRUE);

    ret = cio_chunk_down(chunk);
    TEST_CHECK(ret == CIO_OK);

    if (cio_chunk_is_up(chunk) == CIO_FALSE) {
        ret = cio_chunk_up_force(chunk);
        TEST_CHECK(ret == CIO_OK);
    }

    ret = cio_chunk_write_at(chunk, (off_t) valid_size, NULL, 0);
    TEST_CHECK(ret == CIO_OK);

    content_size = cio_chunk_get_content_size(chunk);
    TEST_CHECK(content_size == (ssize_t) valid_size);

    ret = cio_chunk_down(chunk);
    TEST_CHECK(ret == CIO_OK);

    cio_destroy(ctx);

    cio_options_init(&cio_opts);
    cio_opts.root_path = CIO_ENV;
    cio_opts.log_cb = log_cb;
    cio_opts.log_level = CIO_LOG_INFO;
    cio_opts.flags = CIO_OPEN | CIO_CHECKSUM | CIO_FULL_SYNC | CIO_TRIM_FILES;

    ctx = cio_create(&cio_opts);
    TEST_CHECK(ctx != NULL);
    if (!ctx) {
        exit(1);
    }

    ret = cio_load(ctx, NULL);
    TEST_CHECK(ret == CIO_OK);

    stream = cio_stream_get(ctx, "fluent-bit");
    TEST_CHECK(stream != NULL);
    chunk = find_stream_chunk(stream, "chunk.0");
    TEST_CHECK(chunk != NULL);
    if (!chunk) {
        exit(1);
    }

    if (cio_chunk_is_up(chunk) == CIO_FALSE) {
        ret = cio_chunk_up_force(chunk);
        TEST_CHECK(ret == CIO_OK);
    }

    ret = cio_chunk_get_content_copy(chunk, &copy_buf, &copy_size);
    TEST_CHECK(ret == CIO_OK);
    TEST_CHECK(copy_size == strlen(valid));
    TEST_CHECK(memcmp(copy_buf, valid, strlen(valid)) == 0);
    free(copy_buf);
    copy_buf = NULL;

    ret = cio_chunk_write(chunk, next, strlen(next));
    TEST_CHECK(ret == CIO_OK);

    ret = cio_chunk_sync(chunk);
    TEST_CHECK(ret == CIO_OK);

    ret = cio_chunk_down(chunk);
    TEST_CHECK(ret == CIO_OK);

    ret = cio_chunk_up_force(chunk);
    TEST_CHECK(ret == CIO_OK);

    ret = cio_chunk_get_content_copy(chunk, &copy_buf, &copy_size);
    TEST_CHECK(ret == CIO_OK);
    TEST_CHECK(copy_size == strlen(valid) + strlen(next));
    TEST_CHECK(memcmp(copy_buf, valid, strlen(valid)) == 0);
    TEST_CHECK(memcmp((char *) copy_buf + strlen(valid), next, strlen(next)) == 0);

    dlq_stream = cio_stream_create(ctx, "rejected", CIO_STORE_FS);
    TEST_CHECK(dlq_stream != NULL);

    dlq_chunk = cio_chunk_open(ctx, dlq_stream, "fb.test_500_out.flb",
                               CIO_OPEN, copy_size, &err);
    TEST_CHECK(dlq_chunk != NULL);
    if (!dlq_chunk) {
        free(copy_buf);
        exit(1);
    }

    ret = cio_chunk_write(dlq_chunk, copy_buf, copy_size);
    TEST_CHECK(ret == CIO_OK);

    ret = cio_chunk_sync(dlq_chunk);
    TEST_CHECK(ret == CIO_OK);

    cio_chunk_close(dlq_chunk, CIO_FALSE);
    free(copy_buf);

    cf = (struct cio_file *) chunk->backend;
    TEST_CHECK(cf->map[CIO_FILE_LEGACY_CRC_PADDING_OFFSET + 0] == 0);
    TEST_CHECK(cf->map[CIO_FILE_LEGACY_CRC_PADDING_OFFSET + 1] == 0);
    TEST_CHECK(cf->map[CIO_FILE_LEGACY_CRC_PADDING_OFFSET + 2] == 0);
    TEST_CHECK(cf->map[CIO_FILE_LEGACY_CRC_PADDING_OFFSET + 3] == 0);

    if (cio_chunk_is_locked(chunk) == CIO_TRUE) {
        ret = cio_chunk_unlock(chunk);
        TEST_CHECK(ret == CIO_OK);
    }

    cio_destroy(ctx);
}

static void test_fs_fluent_bit_delete_irrecoverable_on_load()
{
    int ret;
    int err;
    struct stat st;
    struct cio_ctx *ctx;
    struct cio_chunk *chunk;
    struct cio_stream *stream;
    struct cio_options cio_opts;
    char path[1024];
    char payload[] = "irrecoverable payload";

    cio_utils_recursive_delete(CIO_ENV);

    cio_options_init(&cio_opts);
    cio_opts.root_path = CIO_ENV;
    cio_opts.log_cb = log_cb;
    cio_opts.log_level = CIO_LOG_INFO;
    cio_opts.flags = CIO_OPEN | CIO_CHECKSUM;

    ctx = cio_create(&cio_opts);
    TEST_CHECK(ctx != NULL);
    if (!ctx) {
        exit(1);
    }

    stream = cio_stream_create(ctx, "fluent-bit-bad", CIO_STORE_FS);
    TEST_CHECK(stream != NULL);

    chunk = cio_chunk_open(ctx, stream, "bad.0", CIO_OPEN, 64, &err);
    TEST_CHECK(chunk != NULL);
    if (!chunk) {
        exit(1);
    }

    ret = cio_chunk_write(chunk, payload, strlen(payload));
    TEST_CHECK(ret == CIO_OK);

    ret = cio_chunk_sync(chunk);
    TEST_CHECK(ret == CIO_OK);

    snprintf(path, sizeof(path), "%s/%s/%s", CIO_ENV, "fluent-bit-bad", "bad.0");

    ret = cio_chunk_down(chunk);
    TEST_CHECK(ret == CIO_OK);

    truncate_file((struct cio_file *) chunk->backend, 1, CIO_FALSE);

    cio_destroy(ctx);

    cio_options_init(&cio_opts);
    cio_opts.root_path = CIO_ENV;
    cio_opts.log_cb = log_cb;
    cio_opts.log_level = CIO_LOG_INFO;
    cio_opts.flags = CIO_OPEN | CIO_CHECKSUM | CIO_DELETE_IRRECOVERABLE;

    ctx = cio_create(&cio_opts);
    TEST_CHECK(ctx != NULL);
    if (!ctx) {
        exit(1);
    }

    ret = cio_load(ctx, NULL);
    TEST_CHECK(ret == CIO_OK);

    ret = stat(path, &st);
    TEST_CHECK(ret == -1);

    stream = cio_stream_get(ctx, "fluent-bit-bad");
    TEST_CHECK(stream != NULL);
    TEST_CHECK(find_stream_chunk(stream, "bad.0") == NULL);

    cio_destroy(ctx);
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
    free(content_buf);

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
    {"fs_recover_unfinalized_checksum", test_fs_recover_unfinalized_checksum},
    {"fs_shadow_checksum_recovers_primary_header", test_fs_shadow_checksum_recovers_primary_header},
    {"fs_shadow_checksum_recovers_read_only", test_fs_shadow_checksum_recovers_read_only},
    {"fs_shadow_checksum_recovers_primary_length", test_fs_shadow_checksum_recovers_primary_length},
    {"fs_valid_primary_precedes_newer_shadow", test_fs_valid_primary_precedes_newer_shadow},
    {"fs_valid_primary_with_stale_shadow_read_only_truncate", test_fs_valid_primary_with_stale_shadow_read_only_truncate},
    {"fs_valid_primary_with_stale_shadow_read_only_append", test_fs_valid_primary_with_stale_shadow_read_only_append},
    {"fs_valid_primary_with_stale_shadow_truncate", test_fs_valid_primary_with_stale_shadow_truncate},
    {"fs_valid_primary_with_stale_shadow_append", test_fs_valid_primary_with_stale_shadow_append},
    {"fs_write_at_zero_truncates_synced_checksum", test_fs_write_at_zero_truncates_synced_checksum},
    {"fs_legacy_checksum_without_shadow_header", test_fs_legacy_checksum_without_shadow_header},
    {"fs_old_format_loads_via_restart", test_fs_old_format_loads_via_restart},
    {"fs_shadow_rejects_oversized_length", test_fs_shadow_rejects_oversized_length},
    {"fs_shadow_rejects_maximum_length", test_fs_shadow_rejects_maximum_length},
    {"fs_shadow_rejects_corrupt_content", test_fs_shadow_rejects_corrupt_content},
    {"fs_shadow_rejects_both_tuples_corrupt", test_fs_shadow_rejects_both_tuples_corrupt},
    {"fs_format_contract_new_chunk_layout", test_fs_format_contract_new_chunk_layout},
    {"fs_golden_legacy_chunk_loads", test_fs_golden_legacy_chunk_loads},
    {"fs_legacy_big_endian_wide_checksum_migrates", test_fs_legacy_big_endian_wide_checksum_migrates},
    {"fs_legacy_big_endian_wide_checksum_read_only", test_fs_legacy_big_endian_wide_checksum_read_only},
    {"fs_fluent_bit_storage_lifecycle", test_fs_fluent_bit_storage_lifecycle},
    {"fs_fluent_bit_delete_irrecoverable_on_load", test_fs_fluent_bit_delete_irrecoverable_on_load},
    {"fs_up_down_up_append", test_fs_up_down_up_append},
    {"fs_deep_hierachy", test_deep_hierarchy},
    {"legacy_success", test_legacy_success},
    {"legacy_failure", test_legacy_failure},
    {"metadata_unsigned_underflow", test_metadata_unsigned_underflow},
    { 0 }
};
