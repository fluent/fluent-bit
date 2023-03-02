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

#define DPATH_LOKI FLB_TESTS_DATA_PATH "/data/loki"

pthread_mutex_t result_mutex = PTHREAD_MUTEX_INITIALIZER;
int num_output = 0;
static int get_output_num()
{
    int ret;
    pthread_mutex_lock(&result_mutex);
    ret = num_output;
    pthread_mutex_unlock(&result_mutex);

    return ret;
}

static void set_output_num(int num)
{
    pthread_mutex_lock(&result_mutex);
    num_output = num;
    pthread_mutex_unlock(&result_mutex);
}

static void clear_output_num()
{
    set_output_num(0);
}

#define JSON_BASIC "[12345678, {\"key\":\"value\"}]"
static void cb_check_basic(void *ctx, int ffd,
                           int res_ret, void *res_data, size_t res_size,
                           void *data)
{
    char *p;
    flb_sds_t out_js = res_data;
    char *index_line = "{\\\"key\\\":\\\"value\\\"}";

    p = strstr(out_js, index_line);
    if (!TEST_CHECK(p != NULL)) {
      TEST_MSG("Given:%s", out_js);
    }

    flb_sds_destroy(out_js);
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
    flb_service_set(ctx, "flush", "1", "grace", "1",
                    "log_level", "error",
                    NULL);

    /* Lib input mode */
    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    /* Elasticsearch output */
    out_ffd = flb_output(ctx, (char *) "loki", NULL);
    flb_output_set(ctx, out_ffd,
                   "match", "test",
                   NULL);

    /* Enable test mode */
    ret = flb_output_set_test(ctx, out_ffd, "formatter",
                              cb_check_basic,
                              NULL, NULL);

    /* Start */
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Ingest data sample */
    ret = flb_lib_push(ctx, in_ffd, (char *) JSON_BASIC, size);
    TEST_CHECK(ret >= 0);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}

static void cb_check_labels(void *ctx, int ffd,
                            int res_ret, void *res_data, size_t res_size,
                            void *data)
{
    char *p;
    flb_sds_t out_js = res_data;
    char *index_line = "\"stream\":{\"a\":\"b\"}";

    p = strstr(out_js, index_line);
    if (!TEST_CHECK(p != NULL)) {
      TEST_MSG("Given:%s", out_js);
    }

    flb_sds_destroy(out_js);
}

void flb_test_labels()
{
    int ret;
    int size = sizeof(JSON_BASIC) - 1;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    /* Create context, flush every second (some checks omitted here) */
    ctx = flb_create();
    flb_service_set(ctx, "flush", "1", "grace", "1",
                    "log_level", "error",
                    NULL);

    /* Lib input mode */
    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    /* Elasticsearch output */
    out_ffd = flb_output(ctx, (char *) "loki", NULL);
    flb_output_set(ctx, out_ffd,
                   "match", "test",
                   "labels", "a=b", /* "stream":{"a":"b"} */
                   NULL);

    /* Enable test mode */
    ret = flb_output_set_test(ctx, out_ffd, "formatter",
                              cb_check_labels,
                              NULL, NULL);

    /* Start */
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Ingest data sample */
    ret = flb_lib_push(ctx, in_ffd, (char *) JSON_BASIC, size);
    TEST_CHECK(ret >= 0);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}

static void cb_check_label_keys(void *ctx, int ffd,
                                int res_ret, void *res_data, size_t res_size,
                                void *data)
{
    char *p;
    flb_sds_t out_js = res_data;
    char *index_line = "{\"stream\":{\"data_l_key\":\"test\"}";

    p = strstr(out_js, index_line);
    if (!TEST_CHECK(p != NULL)) {
      TEST_MSG("Given:%s", out_js);
    }

    flb_sds_destroy(out_js);
}

#define JSON_LABEL_KEYS "[12345678, {\"key\":\"value\",\"foo\":\"bar\", \"data\":{\"l_key\":\"test\"}}]"
void flb_test_label_keys()
{
    int ret;
    int size = sizeof(JSON_LABEL_KEYS) - 1;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    /* Create context, flush every second (some checks omitted here) */
    ctx = flb_create();
    flb_service_set(ctx, "flush", "1", "grace", "1",
                    "log_level", "error",
                    NULL);

    /* Lib input mode */
    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    /* Elasticsearch output */
    out_ffd = flb_output(ctx, (char *) "loki", NULL);
    flb_output_set(ctx, out_ffd,
                   "match", "test",
                   "label_keys", "$data['l_key']", /* {"stream":{"data_l_key":"test"} */
                   NULL);

    /* Enable test mode */
    ret = flb_output_set_test(ctx, out_ffd, "formatter",
                              cb_check_label_keys,
                              NULL, NULL);

    /* Start */
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Ingest data sample */
    ret = flb_lib_push(ctx, in_ffd, (char *) JSON_LABEL_KEYS, size);
    TEST_CHECK(ret >= 0);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}

static void cb_check_line_format(void *ctx, int ffd,
                                 int res_ret, void *res_data, size_t res_size,
                                 void *data)
{
    char *p;
    flb_sds_t out_js = res_data;
    char *index_line = "key=\\\"value\\\"";

    p = strstr(out_js, index_line);
    if (!TEST_CHECK(p != NULL)) {
      TEST_MSG("Given:%s", out_js);
    }

    flb_sds_destroy(out_js);
}

void flb_test_line_format()
{
    int ret;
    int size = sizeof(JSON_BASIC) - 1;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    /* Create context, flush every second (some checks omitted here) */
    ctx = flb_create();
    flb_service_set(ctx, "flush", "1", "grace", "1",
                    "log_level", "error",
                    NULL);

    /* Lib input mode */
    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    /* Elasticsearch output */
    out_ffd = flb_output(ctx, (char *) "loki", NULL);
    flb_output_set(ctx, out_ffd,
                   "match", "test",
                   "line_format", "key_value",
                   NULL);

    /* Enable test mode */
    ret = flb_output_set_test(ctx, out_ffd, "formatter",
                              cb_check_line_format,
                              NULL, NULL);

    /* Start */
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Ingest data sample */
    ret = flb_lib_push(ctx, in_ffd, (char *) JSON_BASIC, size);
    TEST_CHECK(ret >= 0);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}


static void cb_check_line_format_remove_keys(void *ctx, int ffd,
                                             int res_ret, void *res_data,
                                             size_t res_size, void *data)
{
    char *p;
    flb_sds_t out_js = res_data;
    char *index_line = "value_nested";

    /* p == NULL is expected since it should be removed.*/
    p = strstr(out_js, index_line);
    if (!TEST_CHECK(p == NULL)) {
      TEST_MSG("Given:%s", out_js);
    }

    flb_sds_destroy(out_js);
}
#define JSON_BASIC_NEST "[12345678, {\"key\": {\"nest\":\"value_nested\"}} ]"
/* https://github.com/fluent/fluent-bit/issues/3875 */
void flb_test_remove_map()
{
    int ret;
    int size = sizeof(JSON_BASIC_NEST) - 1;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    /* Create context, flush every second (some checks omitted here) */
    ctx = flb_create();
    flb_service_set(ctx, "flush", "1", "grace", "1",
                    "log_level", "error",
                    NULL);

    /* Lib input mode */
    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    /* Elasticsearch output */
    out_ffd = flb_output(ctx, (char *) "loki", NULL);
    flb_output_set(ctx, out_ffd,
                   "match", "test",
                   "remove_keys", "key",
                   NULL);

    /* Enable test mode */
    ret = flb_output_set_test(ctx, out_ffd, "formatter",
                              cb_check_line_format_remove_keys,
                              NULL, NULL);

    /* Start */
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Ingest data sample */
    ret = flb_lib_push(ctx, in_ffd, (char *) JSON_BASIC_NEST, size);
    TEST_CHECK(ret >= 0);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}

static void cb_check_labels_ra(void *ctx, int ffd,
                               int res_ret, void *res_data, size_t res_size,
                               void *data)
{
    char *p;
    flb_sds_t out_js = res_data;
    char *index_line = "\\\"data\\\":{\\\"l_key\\\":\\\"test\\\"}";

    p = strstr(out_js, index_line);
    if (!TEST_CHECK(p != NULL)) {
      TEST_MSG("Given:%s", out_js);
    }

    flb_sds_destroy(out_js);
}

/* https://github.com/fluent/fluent-bit/issues/3867 */
void flb_test_labels_ra()
{
    int ret;
    int size = sizeof(JSON_LABEL_KEYS) - 1;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    /* Create context, flush every second (some checks omitted here) */
    ctx = flb_create();
    flb_service_set(ctx, "flush", "1", "grace", "1",
                    "log_level", "error",
                    NULL);

    /* Lib input mode */
    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    /* Elasticsearch output */
    out_ffd = flb_output(ctx, (char *) "loki", NULL);
    flb_output_set(ctx, out_ffd,
                   "match", "test",
                   "labels", "$data['l_key']",
                   NULL);

    /* Enable test mode */
    ret = flb_output_set_test(ctx, out_ffd, "formatter",
                              cb_check_labels_ra,
                              NULL, NULL);

    /* Start */
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Ingest data sample */
    flb_lib_push(ctx, in_ffd, (char *) JSON_LABEL_KEYS, size);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}

static void cb_check_remove_keys(void *ctx, int ffd,
                                int res_ret, void *res_data, size_t res_size,
                                void *data)
{
    char *p;
    flb_sds_t out_js = res_data;

    p = strstr(out_js, "foo");
    if (!TEST_CHECK(p == NULL)) {
      TEST_MSG("Given:%s", out_js);
    }

    p = strstr(out_js, "l_key");
    if (!TEST_CHECK(p == NULL)) {
      TEST_MSG("Given:%s", out_js);
    }

    flb_sds_destroy(out_js);
}

void flb_test_remove_keys()
{
    int ret;
    int size = sizeof(JSON_LABEL_KEYS) - 1;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    /* Create context, flush every second (some checks omitted here) */
    ctx = flb_create();
    flb_service_set(ctx, "flush", "1", "grace", "1",
                    "log_level", "error",
                    NULL);

    /* Lib input mode */
    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    /* Elasticsearch output */
    out_ffd = flb_output(ctx, (char *) "loki", NULL);
    flb_output_set(ctx, out_ffd,
                   "match", "test",
                   "remove_keys", "foo, $data['l_key']",
                   NULL);

    /* Enable test mode */
    ret = flb_output_set_test(ctx, out_ffd, "formatter",
                              cb_check_remove_keys,
                              NULL, NULL);

    /* Start */
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Ingest data sample */
    flb_lib_push(ctx, in_ffd, (char *) JSON_LABEL_KEYS, size);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}

static void cb_check_label_map_path(void *ctx, int ffd,
                                    int res_ret, void *res_data, size_t res_size,
                                    void *data)
{
    char *p;
    flb_sds_t out_log = res_data;
    char *expected[] = {
        "\"container\":\"promtail\"",
        "\"pod\":\"promtail-xxx\"",
        "\"namespace\":\"prod\"",
        "\"team\":\"lalala\"",
        NULL};
    int i = 0;

    set_output_num(1);

    while(expected[i] != NULL) {
        p = strstr(out_log, expected[i]);
        if (!TEST_CHECK(p != NULL)) {
            TEST_MSG("Given:%s Expect:%s", out_log, expected[i]);
        }
        i++;
    }

    flb_sds_destroy(out_log);
}

void flb_test_label_map_path()
{
    int ret;
    char *str = "[12345678, {\"kubernetes\":{\"container_name\":\"promtail\",\"pod_name\":\"promtail-xxx\",\"namespace_name\":\"prod\",\"labels\":{\"team\": \"lalala\"}},\"log\":\"log\"}]";
    int size = strlen(str);
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    clear_output_num();

    /* Create context, flush every second (some checks omitted here) */
    ctx = flb_create();
    flb_service_set(ctx, "flush", "1", "grace", "1",
                    "log_level", "error",
                    NULL);

    /* Lib input mode */
    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    /* Elasticsearch output */
    out_ffd = flb_output(ctx, (char *) "loki", NULL);
    flb_output_set(ctx, out_ffd,
                   "match", "test",
                   "label_map_path", DPATH_LOKI "/labelmap.json",
                   NULL);

    /* Enable test mode */
    ret = flb_output_set_test(ctx, out_ffd, "formatter",
                              cb_check_label_map_path,
                              NULL, NULL);

    /* Start */
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Ingest data sample */
    ret = flb_lib_push(ctx, in_ffd, str, size);
    TEST_CHECK(ret == size);

    sleep(2);

    ret = get_output_num();
    if (!TEST_CHECK(ret != 0)) {
        TEST_MSG("no output");
    }

    flb_stop(ctx);
    flb_destroy(ctx);
}

static void cb_check_float_value(void *ctx, int ffd,
                                 int res_ret, void *res_data, size_t res_size,
                                 void *data)
{
    char *p;
    flb_sds_t out_js = res_data;
    char *index_line = "\"float=1.3\"";

    p = strstr(out_js, index_line);
    if (!TEST_CHECK(p != NULL)) {
      TEST_MSG("Given:%s", out_js);
    }

    flb_sds_destroy(out_js);
}

#define JSON_FLOAT "[12345678, {\"float\":1.3}]"
void flb_test_float_value()
{
    int ret;
    int size = sizeof(JSON_FLOAT) - 1;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    /* Create context, flush every second (some checks omitted here) */
    ctx = flb_create();
    flb_service_set(ctx, "flush", "1", "grace", "1",
                    "log_level", "error",
                    NULL);

    /* Lib input mode */
    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    /* Elasticsearch output */
    out_ffd = flb_output(ctx, (char *) "loki", NULL);
    flb_output_set(ctx, out_ffd,
                   "match", "test",
                   "line_format", "key_value",
                   NULL);

    /* Enable test mode */
    ret = flb_output_set_test(ctx, out_ffd, "formatter",
                              cb_check_float_value,
                              NULL, NULL);

    /* Start */
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Ingest data sample */
    ret = flb_lib_push(ctx, in_ffd, (char *) JSON_FLOAT, size);
    TEST_CHECK(ret >= 0);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}


/* Test list */
TEST_LIST = {
    {"remove_keys_remove_map" , flb_test_remove_map},
    {"labels_ra"        , flb_test_labels_ra },
    {"remove_keys"      , flb_test_remove_keys },
    {"basic"            , flb_test_basic },
    {"labels"           , flb_test_labels },
    {"label_keys"       , flb_test_label_keys },
    {"line_format"      , flb_test_line_format },
    {"label_map_path"   , flb_test_label_map_path},
    {"float_value"      , flb_test_float_value},
    {NULL, NULL}
};
