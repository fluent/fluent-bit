/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Chunk I/O
 *  =========
 *  Copyright 2023 Eduardo Silva <eduardo@calyptia.com>
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

static void tests_init(struct cio_options *opts)
{
    /* delete any previous temporary content directory */
    cio_utils_recursive_delete("tmp");

    /* initialize options */
    cio_options_init(opts);
    opts->root_path = "tmp";
    opts->log_cb = log_cb;
    opts->log_level = CIO_LOG_INFO;
}

/* test write overhead. This might need to increase the file descriptors limit (ulimit -n ABC) */
static void perf_write_realloc_hint(int realloc_hint, int up_down_mod)
{
    int i;
    int ret;
    int err;
    int chunk_id = 0;
    char name[64];
    char *in_data;
    size_t in_size;
    struct cio_ctx *ctx;
    struct cio_chunk *chunk;
    struct cio_stream *stream;
    struct cio_options cio_opts;

    tests_init(&cio_opts);
    cio_opts.realloc_size_hint = realloc_hint;
    
     /*
     * Load sample data file and with the same content through multiple write
     * operations generating other files.
     */
    ret = cio_utils_read_file(CIO_FILE_400KB, &in_data, &in_size);
    TEST_CHECK(ret == 0);
    if (ret == -1) {
        exit(EXIT_FAILURE);
    }

    ctx = cio_create(&cio_opts);
    stream = cio_stream_create(ctx, "test-perf", CIO_STORE_FS);

    snprintf(name, sizeof(name) - 1, "chunk-%03i", chunk_id);
    
    chunk = cio_chunk_open(ctx, stream, name, CIO_OPEN, 1000, &err);
    TEST_CHECK(chunk != NULL);
    if (!chunk) {
        printf("cannot open chunk\n");
        exit(1);
    }

    /* do not force a maximum of chunks up, we want to test writing overhead */
    cio_set_max_chunks_up(ctx, 1000000);

    for (i = 0; i < 5000000; i++) {
        ret = cio_chunk_write(chunk, in_data, 550);
        TEST_CHECK(ret == CIO_OK);

        ret = cio_chunk_write(chunk, in_data, 250);
        TEST_CHECK(ret == CIO_OK);

        if (up_down_mod && !(i % up_down_mod)) {
            ret = cio_chunk_down(chunk);
            TEST_CHECK(ret == CIO_OK);

            ret = cio_chunk_up(chunk);
            TEST_CHECK(ret == CIO_OK);
        }

        if (cio_chunk_get_content_size(chunk) > (2 * 1024 * 1000 /* 2MB */)) {
            ret = cio_chunk_down(chunk);

            /* create another chunk */
            chunk_id++;
            snprintf(name, sizeof(name) - 1, "chunk-%03i", chunk_id);

            chunk = cio_chunk_open(ctx, stream, name, CIO_OPEN_RW, 1000, &err);
            TEST_CHECK(chunk != NULL);
            if (!chunk) {
                printf("cannot open chunk\n");
                exit(1);
            }
        }
    }

    cio_destroy(ctx);
    free(in_data);
}

static void test_perf_write_realloc_32()
{
    int realloc_hint = 32 * 1024;
    int up_down_mod = 0;

    perf_write_realloc_hint(realloc_hint, up_down_mod);
}

static void test_perf_write_realloc_128()
{
    int realloc_hint = 128 * 1024;
    int up_down_mod = 0;

    perf_write_realloc_hint(realloc_hint, up_down_mod);
}

static void test_perf_write_realloc_512()
{
    int realloc_hint = 512 * 1024;
    int up_down_mod = 0;

    perf_write_realloc_hint(realloc_hint, up_down_mod);
}

static void test_write_up_down_500()
{
    int realloc_hint = 512 * 1024;
    int up_down_mod = 500;

    perf_write_realloc_hint(realloc_hint, up_down_mod);
}

static void test_write_up_down_1000()
{
    int realloc_hint = 512 * 1024;
    int up_down_mod = 1000;

    perf_write_realloc_hint(realloc_hint, up_down_mod);
}

static void test_write_up_down_10000()
{
    int realloc_hint = 512 * 1024;
    int up_down_mod = 10000;

    perf_write_realloc_hint(realloc_hint, up_down_mod);
}

TEST_LIST = {
    /* write with different realloc size hints */
    {"write_realloc_32" , test_perf_write_realloc_32},
    {"write_realloc_128", test_perf_write_realloc_128},
    {"write_realloc_512", test_perf_write_realloc_512},

    /* 
     * the tests performs (5000000 * 2) cio writes, the following tests uses realloc hint of 512k
     * and force the chunks to go down/up every specific loop intervals.
     */
    {"write_up_down_500"  , test_write_up_down_500},
    {"write_up_down_1000" , test_write_up_down_1000},
    {"write_up_down_10000", test_write_up_down_10000},

    { 0 }
};
