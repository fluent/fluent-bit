/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2021 The Fluent Bit Authors
 *  Copyright (C) 2015-2018 Treasure Data Inc.
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
#include <fluent-bit/flb_time.h>
#include "flb_tests_runtime.h"
#include "data/common/json_long.h"    /* JSON_LONG    */

/* https://github.com/fluent/fluent-bit/issues/3968 */
void flb_test_json_long()
{
    int ret;
    int size = sizeof(JSON_LONG) - 1;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    int filter_ffd;

    /* Create context, flush every second (some checks omitted here) */
    ctx = flb_create();
    flb_service_set(ctx, "flush", "1", "grace", "1",
                    "log_level", "error",
                    NULL);

    /* Lib input mode */
    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);
    TEST_CHECK(in_ffd >= 0);

    out_ffd = flb_output(ctx, (char *) "null", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "test", NULL);

    filter_ffd = flb_filter(ctx, (char *) "record_modifier", NULL);
    TEST_CHECK(filter_ffd >= 0);
    flb_filter_set(ctx, filter_ffd, "match", "test", NULL);

    /* Start */
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Ingest data sample */
    flb_lib_push(ctx, in_ffd, (char *) JSON_LONG, size);

    flb_time_msleep(1500); /* waiting flush */
    flb_stop(ctx);
    flb_destroy(ctx);
}

/* test list */
TEST_LIST = {
    {"json_long"      , flb_test_json_long },
    {NULL, NULL}
};
