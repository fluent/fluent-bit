/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2022 The Fluent Bit Authors
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
#include "flb_tests_runtime.h"

#define ELAPSED_TIME_LIMIT 9

void flb_test_timeout_coroutine_recovery()
{
    int        output_instance_id;
    int        input_instance_id;
    time_t     elapsed_time;
    time_t     start_time;
    time_t     stop_time;
    flb_ctx_t *ctx;
    int64_t    ret;

    ctx = flb_create();

    TEST_CHECK(flb_service_set(ctx, "Flush", "0.5",
                                    "Grace", "10",
                                    NULL) == 0);

    ret = flb_service_set(ctx,
                          "Log_Level", "info",
                          NULL);

    TEST_CHECK_(ret == 0, "setting service options");

    input_instance_id = flb_input(ctx, (char *) "dummy", NULL);
    TEST_CHECK(input_instance_id >= 0);

    TEST_CHECK(flb_input_set(ctx, input_instance_id,
                             "samples", "1",
                             "rate"   , "1",
                             NULL) == 0);

    output_instance_id = flb_output(ctx, (char *) "tcp", NULL);
    TEST_CHECK(output_instance_id >= 0);
    TEST_CHECK(flb_output_set(ctx, output_instance_id,
                              "match", "*",
                              "retry_limit", "no_retries",
                              "host", "35.243.247.233",
                              "port", "54321",
                              "net.keepalive", "off",
                              "net.connect_timeout", "5s",
                              NULL) == 0);

    /* Start test */
    /* Start the engine */
    ret = flb_start(ctx);
    TEST_CHECK_(ret == 0, "starting engine");

    sleep(10);

    start_time = time(NULL);

    ret = flb_stop(ctx);
    TEST_CHECK_(ret == 0, "stopping engine");

    stop_time = time(NULL);

    if (ctx) {
        flb_destroy(ctx);
    }

    elapsed_time = stop_time - start_time;

    TEST_CHECK_(ELAPSED_TIME_LIMIT >= elapsed_time,
                "for hung coroutines");
}

/* Test list */
TEST_LIST = {
    {"timeout_coroutine_recovery", flb_test_timeout_coroutine_recovery},
    {NULL, NULL}
};
