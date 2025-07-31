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
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_record_accessor.h>
#include <fluent-bit/flb_ra_key.h>

#include "flb_tests_runtime.h"

static void cb_check_cfl_variant_properties(void *ctx, int ffd,
                                            int res_ret, void *res_data, size_t res_size,
                                            void *data)
{
    flb_sds_t output;
    char *result = NULL;

    /* Convert from msgpack to JSON */
    output = flb_msgpack_raw_to_json_sds(res_data, res_size, FLB_TRUE);
    TEST_CHECK(output != NULL);

    result = strstr(output, "\"MESSAGE\":\"test native message with multiple values\"");
    if (TEST_CHECK(result != NULL)) {
        TEST_MSG("output:%s\n", output);
    }

    result = strstr(output, "\"KEY\":[\"value1\",\"value4\",\"another\"]");
    if (TEST_CHECK(result != NULL)) {
        TEST_MSG("output:%s\n", output);
    }

    result = strstr(output, "\"KEY2\":[\"value2\",\"value3\",\"value5\",\"value10\",\"final_field\"]");
    if (TEST_CHECK(result != NULL)) {
        TEST_MSG("output:%s\n", output);
    }

    result = strstr(output, "\"KEY3\":[\"howdy\",\"prettygood\",\"wow\"]");
    if (TEST_CHECK(result != NULL)) {
        TEST_MSG("output:%s\n", output);
    }

    flb_sds_destroy(output);
}

void flb_test_duplicated_keys()
{
    int ret;
    int in_ffd;
    int out_ffd;
    flb_ctx_t *ctx;
    char *message = "MESSAGE=test native message with multiple values\nKEY=value1\nKEY=value4\n"
        "KEY2=value2\nKEY=another\nKEY2=value3\nKEY2=value5\nKEY3=howdy\nKEY3=prettygood\nKEY2=value10\n"
        "KEY3=wow\nKEY2=final_field\n";

    /* Create context, flush every second (some checks omitted here) */
    ctx = flb_create();
    flb_service_set(ctx,
                    "flush", "2",
                    "grace", "1",
                    "Log_Level", "error",
                    NULL);

    /* Systemd */
    in_ffd = flb_input(ctx, (char *) "systemd", NULL);
    flb_input_set(ctx, in_ffd,
                  "tag", "test",
                  "Read_From_Tail", "On",
                  NULL);


    out_ffd = flb_output(ctx, (char *) "null", NULL);
    flb_output_set(ctx, out_ffd,
                   "match", "test",
                   NULL);

    /* Enable test mode */
    ret = flb_input_set_test(ctx, in_ffd, "formatter",
                             cb_check_cfl_variant_properties,
                             NULL);

    /* Start */
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Ingest data sample to run test formatter */
    ret = flb_lib_push(ctx, in_ffd, message, strlen(message));
    TEST_CHECK(ret == 0);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}

/* Test list */
TEST_LIST = {
    { "duplicated_keys", flb_test_duplicated_keys },
    { NULL, NULL}
};
