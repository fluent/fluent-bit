/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2026 The Fluent Bit Authors
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

#include <fluent-bit.h>
#include <fluent-bit/flb_engine.h>
#include <fluent-bit/flb_time.h>
#include <string.h>

#include "flb_tests_runtime.h"

/*
 * Long enough that the periodic flush timer cannot plausibly fire during
 * the test window, so a record only arrives if flb_engine_flush_request()
 * actually dispatched it on demand.
 */
#define TEST_FLUSH_INTERVAL_SEC "60"
#define TEST_WAIT_TIMEOUT_MS    3000

static pthread_mutex_t result_mutex = PTHREAD_MUTEX_INITIALIZER;
static int result_count = 0;

static int get_result_count(void)
{
    int ret;

    pthread_mutex_lock(&result_mutex);
    ret = result_count;
    pthread_mutex_unlock(&result_mutex);

    return ret;
}

static void inc_result_count(void)
{
    pthread_mutex_lock(&result_mutex);
    result_count++;
    pthread_mutex_unlock(&result_mutex);
}

static int cb_count_record(void *record, size_t size, void *data)
{
    (void) size;
    (void) data;

    inc_result_count();
    flb_free(record);
    return 0;
}

static void wait_for_result(uint32_t timeout_ms, int *count)
{
    struct flb_time start_time;
    struct flb_time end_time;
    struct flb_time diff_time;
    uint64_t elapsed_ms;

    flb_time_get(&start_time);

    while (true) {
        *count = get_result_count();
        if (*count > 0) {
            return;
        }

        flb_time_msleep(20);
        flb_time_get(&end_time);
        flb_time_diff(&end_time, &start_time, &diff_time);
        elapsed_ms = flb_time_to_nanosec(&diff_time) / 1000000;

        if (elapsed_ms > timeout_ms) {
            return;
        }
    }
}

/*
 * flb_engine_flush_request() must dispatch a buffered record immediately,
 * without waiting for the (deliberately very long) periodic flush timer.
 */
void flb_test_flush_now_dispatches_immediately(void)
{
    flb_ctx_t *ctx;
    struct flb_lib_out_cb cb_data;
    int in_ffd;
    int out_ffd;
    int ret;
    int count = 0;
    char *input_json = "[1, {\"msg\": \"flush now test\"}]";

    ctx = flb_create();
    TEST_CHECK(ctx != NULL);

    TEST_CHECK(flb_service_set(ctx,
                               "Flush",     TEST_FLUSH_INTERVAL_SEC,
                               "Grace",     "1",
                               "Log_Level", "error",
                               NULL) == 0);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);

    cb_data.cb = cb_count_record;
    cb_data.data = NULL;

    out_ffd = flb_output(ctx, (char *) "lib", (void *) &cb_data);
    TEST_CHECK(out_ffd >= 0);
    TEST_CHECK(flb_output_set(ctx, out_ffd, "match", "*", NULL) == 0);

    ret = flb_start(ctx);
    TEST_CHECK_(ret == 0, "starting engine");

    ret = flb_lib_push(ctx, in_ffd, input_json, strlen(input_json));
    TEST_CHECK_(ret >= 0, "pushing record");

    TEST_CHECK(flb_engine_flush_request(ctx->config) >= 0);

    wait_for_result(TEST_WAIT_TIMEOUT_MS, &count);
    TEST_CHECK_(count > 0,
               "expected the record to arrive within %dms via on-demand "
               "flush (flush interval is %ss); got count=%d",
               TEST_WAIT_TIMEOUT_MS, TEST_FLUSH_INTERVAL_SEC, count);

    flb_stop(ctx);
    flb_destroy(ctx);
}

/* Test list */
TEST_LIST = {
    {"flush_now_dispatches_immediately", flb_test_flush_now_dispatches_immediately},
    {NULL, NULL}
};
