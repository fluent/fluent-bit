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
#include <fluent-bit/flb_sds.h>
#include "flb_tests_runtime.h"

#define JSON_BASIC "[12345678, {\"key\":\"value\"}]"
static void cb_check_basic(void *ctx, int ffd,
                           int res_ret, void *res_data, size_t res_size,
                           void *data)
{
    char *p;
    flb_sds_t out_js = res_data;
    char *index_line = "\"event\":{\"key\":\"value\"}";

    p = strstr(out_js, index_line);
    if (!TEST_CHECK(p != NULL)) {
      TEST_MSG("Given:%s", out_js);
    }

    flb_sds_destroy(out_js);
}

static void cb_check_send_raw(void *ctx, int ffd,
                              int res_ret, void *res_data, size_t res_size,
                              void *data)
{
    char *p;
    flb_sds_t out_js = res_data;
    char *not_match_line = "\"event\":{\"key\":\"value\"}";
    char *match_line     = "\"key\":\"value\"";

    p = strstr(out_js, not_match_line);
    if (!TEST_CHECK(p == NULL)) {
      TEST_MSG("Given:%s", out_js);
    }
    p = strstr(out_js, match_line);
    if (!TEST_CHECK(p != NULL)) {
      TEST_MSG("Given:%s", out_js);
    }

    flb_sds_destroy(out_js);
}

// Test "Splunk_Send_Raw" property.
void flb_test_send_raw()
{
    int ret;
    int size = sizeof(JSON_BASIC) - 1;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    /* Create context, flush every second (some checks omitted here) */
    ctx = flb_create();
    flb_service_set(ctx, "flush", "1", "grace", "1", NULL);

    /* Lib input mode */
    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    /* Elasticsearch output */
    out_ffd = flb_output(ctx, (char *) "splunk", NULL);
    flb_output_set(ctx, out_ffd,
                   "match", "test",
                   "http_user", "alice",
                   "splunk_send_raw", "true",
                   NULL);

    /* Enable test mode */
    ret = flb_output_set_test(ctx, out_ffd, "formatter",
                              cb_check_send_raw,
                              NULL, NULL);

    /* Start */
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Ingest data sample */
    flb_lib_push(ctx, in_ffd, (char *) JSON_BASIC, size);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_basic()
{
    int ret;
    int size = sizeof(JSON_BASIC) - 1;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    /* Create context, flush every second (some checks omitted here) */
    ctx = flb_create();
    flb_service_set(ctx, "flush", "1", "grace", "1", NULL);

    /* Lib input mode */
    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    /* Elasticsearch output */
    out_ffd = flb_output(ctx, (char *) "splunk", NULL);
    flb_output_set(ctx, out_ffd,
                   "match", "test",
                   "http_user", "alice",
                   NULL);

    /* Enable test mode */
    ret = flb_output_set_test(ctx, out_ffd, "formatter",
                              cb_check_basic,
                              NULL, NULL);

    /* Start */
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Ingest data sample */
    flb_lib_push(ctx, in_ffd, (char *) JSON_BASIC, size);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}

/* Test list */
TEST_LIST = {
    {"basic"            , flb_test_basic },
    {"send_raw"         , flb_test_send_raw},
    {NULL, NULL}
};
