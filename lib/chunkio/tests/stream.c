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

#include <chunkio/chunkio.h>
#include <chunkio/cio_log.h>
#include <chunkio/cio_scan.h>
#include <chunkio/cio_file.h>
#include <chunkio/cio_meta.h>
#include <chunkio/cio_stream.h>
#include <chunkio/cio_utils.h>

#include "cio_tests_internal.h"

#define CIO_ENV           "/tmp/cio-stream-test/"
#define CIO_FILE_400KB    CIO_TESTS_DATA_PATH "/data/400kb.txt"

/* Logging callback, once called it just turn on the log_check flag */
static int log_cb(struct cio_ctx *ctx, int level, const char *file, int line,
                  char *str)
{
    (void) ctx;

    printf("[cio-test-stream] %-60s => %s:%i\n",  str, file, line);
    return 0;
}

static void test_stream_delete()
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

    memset(&cio_opts, 0, sizeof(cio_opts));

    cio_opts.root_path = "tmp";
    cio_opts.log_cb = log_cb;
    cio_opts.log_level = CIO_LOG_DEBUG;
    cio_opts.flags = CIO_CHECKSUM;

    /* Create a temporal storage */
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
    }

    cio_stream_delete(stream);
    cio_destroy(ctx);
}

TEST_LIST = {
    {"stream_delete",   test_stream_delete},
    { 0 }
};
