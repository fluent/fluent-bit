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
#include <stdlib.h>
#include <time.h>

#include <chunkio/chunkio.h>
#include <chunkio/cio_log.h>
#include <chunkio/cio_scan.h>
#include <chunkio/cio_file.h>
#include <chunkio/cio_meta.h>
#include <chunkio/cio_stream.h>
#include <chunkio/cio_utils.h>
#include <chunkio/cio_error.h>

#include "cio_tests_internal.h"

/* These tests are disabled by default because they are meant to
 * test a filesystem fragmentation issue that only affects XFS
 * under certain specific conditions.
 *
 * Environment setup instructions :
 *
 * mkdir chunks
 * dd if=/dev/zero of=xfs_filesystem bs=1024 count=9765625
 * export LOOP_DEVICE=$(losetup -f)
 * losetup /dev/$LOOP_DEVICE xfs_filesystem
 * mkfs.xfs -f -b size=4096 -d agcount=20 /dev/$LOOP_DEVICE
 * mkdir chunks
 * mount  /dev/$LOOP_DEVICE chunks
 */

#define CIO_ENV           "/tmp/cio-fs-test/"
#define CIO_FILE_400KB    CIO_TESTS_DATA_PATH "/data/400kb.txt"
#define CHUNK_FILE_COUNT  3500
#define CHUNK_SIZE_LIMIT  (2 * 1024 * 1000)
#define TEST_DURATION     (60 * 5)

/* Logging callback, once called it just turn on the log_check flag */
static int log_cb(struct cio_ctx *ctx, int level, const char *file, int line,
                  char *str)
{
    (void) ctx;

    printf("[cio-test-fs] %-60s => %s:%i\n",  str, file, line);

    return 0;
}

static void test_core(int trim_chunk_files)
{
    struct cio_chunk  *chunks[CHUNK_FILE_COUNT];
    int                failure_detected;
    int                chunk_file_full;
    char               chunk_name[64];
    time_t             current_time;
    time_t             elapsed_time;
    time_t             start_time;
    size_t             write_size;
    size_t             chunk_id;
    struct cio_options cio_opts;
    char              *in_data;
    size_t             in_size;
    struct cio_stream *stream;
    struct cio_chunk  *chunk;
    struct cio_ctx    *ctx;
    int                ret;

#ifndef EXECUTE_FS_FRAGMENTATION_TESTS
    return;
#endif

    srand(time(NULL));

    /* delete any previous temporary content directory */
    cio_utils_recursive_delete(CIO_ENV);

    /* initialize options */
    cio_options_init(&cio_opts);

    cio_opts.root_path = CIO_ENV;
    cio_opts.log_cb = log_cb;
    cio_opts.log_level = CIO_LOG_INFO;

    if (trim_chunk_files) {
        cio_opts.flags |= CIO_TRIM_FILES;
    }

     /*
     * Load sample data file and with the same content through multiple write
     * operations generating other files.
     */
    ret = cio_utils_read_file(CIO_FILE_400KB, &in_data, &in_size);
    TEST_CHECK(ret == 0);
    if (ret == -1) {
        exit(EXIT_FAILURE);
    }
    printf("in_size = %zu\n", in_size);

    ctx = cio_create(&cio_opts);
    stream = cio_stream_create(ctx, "test-fragmentation", CIO_STORE_FS);

    memset(chunks, 0, sizeof(chunks));

    /* do not force a maximum of chunks up, we want to test writing overhead */
    cio_set_max_chunks_up(ctx, 1000000);

    start_time = time(NULL);
    current_time = time(NULL);
    elapsed_time = current_time - start_time;
    failure_detected = CIO_FALSE;

    chunk_id = 0;

    while (elapsed_time < TEST_DURATION) {
        if (chunks[chunk_id] != NULL) {
            chunk = chunks[chunk_id];

            cio_chunk_close(chunk, CIO_TRUE);

            chunks[chunk_id] = NULL;
        }

        if (chunks[chunk_id] == NULL) {
            snprintf(chunk_name,
                     sizeof(chunk_name) - 1,
                     "chunk-%03zu",
                     chunk_id);

            chunks[chunk_id] = cio_chunk_open(ctx,
                                              stream,
                                              chunk_name,
                                              CIO_OPEN,
                                              1000,
                                              &ret);

            if (chunks[chunk_id] == NULL) {
                failure_detected = CIO_TRUE;

                break;
            }
        }

        chunk = chunks[chunk_id];

        chunk_file_full = CIO_FALSE;

        while (chunk_file_full != CIO_TRUE) {
            write_size  = rand() * 976;
            write_size %= (32 * 1024);

            if (!cio_chunk_is_up(chunk)) {
                ret = cio_chunk_up(chunk);
            }

            ret = cio_chunk_write(chunk, in_data, write_size);

            if (cio_chunk_get_content_size(chunk) > CHUNK_SIZE_LIMIT) {
                chunk_file_full = CIO_TRUE;
            }

            ret = cio_chunk_down(chunk);
        }

        chunk_id = (chunk_id + 1) % CHUNK_FILE_COUNT;

        current_time = time(NULL);
        elapsed_time = current_time - start_time;
    }

    cio_destroy(ctx);

    free(in_data);

    if (trim_chunk_files) {
        TEST_CHECK(failure_detected == CIO_TRUE);
    }
    else {
        TEST_CHECK(failure_detected == CIO_FALSE);
    }
}

static void test_no_trim()
{
    test_core(CIO_FALSE);
}

static void test_trim()
{
    test_core(CIO_TRUE);
}

TEST_LIST = {
    {"trim", test_trim},
    {"no_trim", test_no_trim},

    { 0 }
};
