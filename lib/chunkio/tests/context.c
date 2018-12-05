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
static int log_cb(struct cio_ctx *ctx, const char *file, int line,
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

    flags = CIO_CHECKSUM;

    /* Invalid path */
    ctx = cio_create("", NULL, CIO_INFO, flags);
    TEST_CHECK(ctx == NULL);

    /* Invalid debug level -1 */
    ctx = cio_create("/tmp/", NULL, -1, flags);
    TEST_CHECK(ctx == NULL);

    /* Invalid debug level 5 */
    ctx = cio_create("/tmp/", NULL, 5, flags);
    TEST_CHECK(ctx == NULL);

    /* Valid context without callback */
    log_check = 0;
    ctx = cio_create("/tmp/", NULL, CIO_INFO, flags);
    TEST_CHECK(ctx != NULL);
    cio_log_info(ctx, "test");
    TEST_CHECK(log_check == 0);
    cio_destroy(ctx);

    /* Valid with context callback */
    log_check = 0;
    ctx = cio_create("/tmp/", log_cb, CIO_INFO, flags);
    TEST_CHECK(ctx != NULL);
    cio_log_info(ctx, "test");
    TEST_CHECK(log_check == 1);
    cio_destroy(ctx);
}

static void test_log_level()
{
    struct cio_ctx *ctx;

    /* Logging with unset callback at creation, but set later */
    log_check = 0;
    ctx = cio_create("/tmp/", NULL, CIO_INFO, 0);
    TEST_CHECK(ctx != NULL);
    cio_log_info(ctx, "test");
    TEST_CHECK(log_check == 0);

    /* Loggin callback enable */
    cio_set_log_callback(ctx, log_cb);
    cio_log_info(ctx, "test");
    TEST_CHECK(log_check == 1);

    /* Test: CIO_ERROR */
    cio_set_log_level(ctx, CIO_ERROR);
    log_check = 0;
    cio_log_warn(ctx, "test");
    TEST_CHECK(log_check == 0);
    cio_log_error(ctx, "test");
    TEST_CHECK(log_check == 1);

    /* Test: CIO_WARN */
    cio_set_log_level(ctx, CIO_WARN);
    log_check = 0;
    cio_log_info(ctx, "test");
    TEST_CHECK(log_check == 0);
    cio_log_warn(ctx, "test");
    TEST_CHECK(log_check == 1);

    /* Test: CIO_INFO */
    cio_set_log_level(ctx, CIO_INFO);
    log_check = 0;
    cio_log_debug(ctx, "test");
    TEST_CHECK(log_check == 0);
    cio_log_info(ctx, "test");
    TEST_CHECK(log_check == 1);

    /* Test: CIO_DEBUG */
    cio_set_log_level(ctx, CIO_DEBUG);
    log_check = 0;
    cio_log_debug(ctx, "test");
    TEST_CHECK(log_check == 1);

    /* destroy context */
    cio_destroy(ctx);
}

TEST_LIST = {
    {"context",     test_context},
    {"log_level",   test_log_level},
    { 0 }
};
