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

#define JSON_TIME_NUM "[12345678, {\"key\":\"value\",\"event_time\":1700000000}]"
#define JSON_TIME_STR "[12345678, {\"key\":\"value\"," \
                      "\"event_time\":\"2024-01-02T03:04:05.123Z\"}]"

static void cb_check_time_key_num(void *ctx, int ffd,
                                  int res_ret, void *res_data, size_t res_size,
                                  void *data)
{
    char *p;
    flb_sds_t out_js = res_data;
    char *time_line = "\"time\":1700000000.0";

    p = strstr(out_js, time_line);
    if (!TEST_CHECK(p != NULL)) {
      TEST_MSG("Given:%s", out_js);
    }

    flb_sds_destroy(out_js);
}

static void cb_check_time_key_str(void *ctx, int ffd,
                                  int res_ret, void *res_data, size_t res_size,
                                  void *data)
{
    char *p;
    flb_sds_t out_js = res_data;
    char *time_line = "\"time\":1704164645.123";

    p = strstr(out_js, time_line);
    if (!TEST_CHECK(p != NULL)) {
      TEST_MSG("Given:%s", out_js);
    }

    flb_sds_destroy(out_js);
}

static void cb_check_time_key_fallback(void *ctx, int ffd,
                                       int res_ret, void *res_data,
                                       size_t res_size, void *data)
{
    char *p;
    flb_sds_t out_js = res_data;
    char *time_line = "\"time\":12345678.0";

    p = strstr(out_js, time_line);
    if (!TEST_CHECK(p != NULL)) {
      TEST_MSG("Given:%s", out_js);
    }

    flb_sds_destroy(out_js);
}

static void flb_test_time_key_run(char *json, size_t json_size,
                                  void (*cb)(void *, int, int, void *, size_t,
                                             void *),
                                  char *time_key, char *time_key_format)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    ctx = flb_create();
    flb_service_set(ctx, "flush", "1", "grace", "1", NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "splunk", NULL);
    flb_output_set(ctx, out_ffd,
                   "match", "test",
                   "http_user", "alice",
                   "time_key", time_key,
                   NULL);

    if (time_key_format) {
        flb_output_set(ctx, out_ffd, "time_key_format", time_key_format, NULL);
    }

    ret = flb_output_set_test(ctx, out_ffd, "formatter", cb, NULL, NULL);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    flb_lib_push(ctx, in_ffd, json, json_size);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}

/* A numeric record key is used as the HEC event time */
void flb_test_time_key_number()
{
    flb_test_time_key_run(JSON_TIME_NUM, sizeof(JSON_TIME_NUM) - 1,
                          cb_check_time_key_num, "event_time", NULL);
}

/* A record accessor pattern is also a valid 'time_key' value */
void flb_test_time_key_record_accessor()
{
    flb_test_time_key_run(JSON_TIME_NUM, sizeof(JSON_TIME_NUM) - 1,
                          cb_check_time_key_num, "$event_time", NULL);
}

/* A string record key is parsed using 'time_key_format' */
void flb_test_time_key_format()
{
    flb_test_time_key_run(JSON_TIME_STR, sizeof(JSON_TIME_STR) - 1,
                          cb_check_time_key_str, "event_time",
                          "%Y-%m-%dT%H:%M:%S.%LZ");
}

/* A missing 'time_key' falls back to the Fluent Bit event timestamp */
void flb_test_time_key_missing()
{
    flb_test_time_key_run(JSON_BASIC, sizeof(JSON_BASIC) - 1,
                          cb_check_time_key_fallback, "event_time", NULL);
}

/* An unparseable value falls back to the Fluent Bit event timestamp */
void flb_test_time_key_invalid()
{
    flb_test_time_key_run(JSON_TIME_STR, sizeof(JSON_TIME_STR) - 1,
                          cb_check_time_key_fallback, "event_time", NULL);
}

/*
 * On raw mode there is no HEC envelope to populate, so 'time_key' must be
 * ignored without preventing the output from starting.
 */
void flb_test_time_key_send_raw()
{
    int ret;
    int size = sizeof(JSON_BASIC) - 1;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    ctx = flb_create();
    flb_service_set(ctx, "flush", "1", "grace", "1", NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "splunk", NULL);
    flb_output_set(ctx, out_ffd,
                   "match", "test",
                   "http_user", "alice",
                   "splunk_send_raw", "true",
                   "time_key", "event_time",
                   "time_key_format", "%Y-%m-%dT%H:%M:%S.%LZ",
                   NULL);

    ret = flb_output_set_test(ctx, out_ffd, "formatter",
                              cb_check_send_raw,
                              NULL, NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    flb_lib_push(ctx, in_ffd, (char *) JSON_BASIC, size);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}

/* Test list */
TEST_LIST = {
    {"basic"            , flb_test_basic },
    {"send_raw"         , flb_test_send_raw},
    {"time_key_number"  , flb_test_time_key_number},
    {"time_key_record_accessor", flb_test_time_key_record_accessor},
    {"time_key_format"  , flb_test_time_key_format},
    {"time_key_missing" , flb_test_time_key_missing},
    {"time_key_invalid" , flb_test_time_key_invalid},
    {"time_key_send_raw", flb_test_time_key_send_raw},
    {NULL, NULL}
};
