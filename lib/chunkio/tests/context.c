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

#include "cio_tests_internal.h"

int log_check;

/* Logging callback, once called it just turn on the log_check flag */
static int log_cb(struct cio_ctx *ctx, int level, const char *file, int line,
                  char *str)
{
    (void) ctx;
    (void) file;
    (void) line;
    (void) str;

    log_check = 1;
    return 0;
}

/* Basic tests on context creation */
static void test_context()
{
    int flags;
    struct cio_ctx *ctx;
    struct cio_options cio_opts;

    flags = CIO_CHECKSUM;

    memset(&cio_opts, 0, sizeof(cio_opts));

    cio_opts.flags = flags;
    cio_opts.log_cb = NULL;

    /* Invalid path */
    cio_opts.root_path = "";
    cio_opts.log_level = CIO_LOG_INFO;

    ctx = cio_create(&cio_opts);
    TEST_CHECK(ctx == NULL);

    /* Invalid debug level -1 */
    cio_opts.root_path = "/tmp/";
    cio_opts.log_level = -1;

    ctx = cio_create(&cio_opts);
    TEST_CHECK(ctx == NULL);

    /* Invalid debug level 6 */
    cio_opts.log_level = 6;

    ctx = cio_create(&cio_opts);
    TEST_CHECK(ctx == NULL);

    /* Valid context without callback */
    log_check = 0;
    cio_opts.log_level = CIO_LOG_INFO;

    ctx = cio_create(&cio_opts);
    TEST_CHECK(ctx != NULL);
    cio_log_info(ctx, "test");
    TEST_CHECK(log_check == 0);
    cio_destroy(ctx);

    /* Valid with context callback */
    log_check = 0;
    cio_opts.log_cb = log_cb;

    ctx = cio_create(&cio_opts);
    TEST_CHECK(ctx != NULL);
    cio_log_info(ctx, "test");
    TEST_CHECK(log_check == 1);
    cio_destroy(ctx);
}

static void test_log_level()
{
    struct cio_ctx *ctx;
    struct cio_options cio_opts;

    memset(&cio_opts, 0, sizeof(cio_opts));

    cio_opts.flags = 0;
    cio_opts.log_cb = NULL;

    /* Logging with unset callback at creation, but set later */
    log_check = 0;
    cio_opts.root_path = "/tmp/";
    cio_opts.log_level = CIO_LOG_INFO;

    ctx = cio_create(&cio_opts);
    TEST_CHECK(ctx != NULL);
    cio_log_info(ctx, "test");
    TEST_CHECK(log_check == 0);

    /* Loggin callback enable */
    cio_set_log_callback(ctx, log_cb);
    cio_log_info(ctx, "test");
    TEST_CHECK(log_check == 1);

    /* Test: CIO_ERROR */
    cio_set_log_level(ctx, CIO_LOG_ERROR);
    log_check = 0;
    cio_log_warn(ctx, "test");
    TEST_CHECK(log_check == 0);
    cio_log_error(ctx, "test");
    TEST_CHECK(log_check == 1);

    /* Test: CIO_WARN */
    cio_set_log_level(ctx, CIO_LOG_WARN);
    log_check = 0;
    cio_log_info(ctx, "test");
    TEST_CHECK(log_check == 0);
    cio_log_warn(ctx, "test");
    TEST_CHECK(log_check == 1);

    /* Test: CIO_INFO */
    cio_set_log_level(ctx, CIO_LOG_INFO);
    log_check = 0;
    cio_log_debug(ctx, "test");
    TEST_CHECK(log_check == 0);
    cio_log_info(ctx, "test");
    TEST_CHECK(log_check == 1);

    /* Test: CIO_DEBUG */
    cio_set_log_level(ctx, CIO_LOG_DEBUG);
    log_check = 0;
    cio_log_trace(ctx, "test");
    TEST_CHECK(log_check == 0);
    cio_log_debug(ctx, "test");
    TEST_CHECK(log_check == 1);

    /* Test: CIO_TRACE */
    cio_set_log_level(ctx, CIO_LOG_TRACE);
    log_check = 0;
    cio_log_trace(ctx, "test");
    TEST_CHECK(log_check == 1);

    /* destroy context */
    cio_destroy(ctx);
}

TEST_LIST = {
    {"context",     test_context},
    {"log_level",   test_log_level},
    { 0 }
};
