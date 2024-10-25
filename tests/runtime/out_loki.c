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

    /* Loki output */
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

    /* Loki output */
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

    /* Loki output */
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

    /* Loki output */
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

static void cb_check_drop_single_key_off(void *ctx, int ffd,
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

void flb_test_drop_single_key_off()
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

    /* Loki output */
    out_ffd = flb_output(ctx, (char *) "loki", NULL);
    flb_output_set(ctx, out_ffd,
                   "match", "test",
                   "drop_single_key", "off",
                   NULL);

    /* Enable test mode */
    ret = flb_output_set_test(ctx, out_ffd, "formatter",
                              cb_check_drop_single_key_off,
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

static void cb_check_drop_single_key_on(void *ctx, int ffd,
                                         int res_ret, void *res_data, size_t res_size,
                                         void *data)
{
    char *p;
    flb_sds_t out_js = res_data;
    char *index_line = "\\\"value\\\"";

    p = strstr(out_js, index_line);
    if (!TEST_CHECK(p != NULL)) {
      TEST_MSG("Given:%s", out_js);
    }

    flb_sds_destroy(out_js);
}

void flb_test_drop_single_key_on()
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

    /* Loki output */
    out_ffd = flb_output(ctx, (char *) "loki", NULL);
    flb_output_set(ctx, out_ffd,
                   "match", "test",
                   "drop_single_key", "on",
                   NULL);

    /* Enable test mode */
    ret = flb_output_set_test(ctx, out_ffd, "formatter",
                              cb_check_drop_single_key_on,
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

static void cb_check_drop_single_key_raw(void *ctx, int ffd,
                                         int res_ret, void *res_data, size_t res_size,
                                         void *data)
{
    char *p;
    flb_sds_t out_js = res_data;
    char *index_line = "\"value\"";

    p = strstr(out_js, index_line);
    if (!TEST_CHECK(p != NULL)) {
      TEST_MSG("Given:%s", out_js);
    }

    flb_sds_destroy(out_js);
}

void flb_test_drop_single_key_raw()
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

    /* Loki output */
    out_ffd = flb_output(ctx, (char *) "loki", NULL);
    flb_output_set(ctx, out_ffd,
                   "match", "test",
                   "drop_single_key", "raw",
                   NULL);

    /* Enable test mode */
    ret = flb_output_set_test(ctx, out_ffd, "formatter",
                              cb_check_drop_single_key_raw,
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

    /* Loki output */
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

    /* Loki output */
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

    /* Loki output */
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

    /* Loki output */
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
    size_t size = sizeof(JSON_FLOAT) - 1;
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

    /* Loki output */
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

static void cb_check_structured_metadata_value(void *ctx, int ffd,
                                 int res_ret, void *res_data, size_t res_size,
                                 void *data)
{
    char *p;
    flb_sds_t out_js = res_data;
    if (!TEST_CHECK(out_js != NULL)) {
        TEST_MSG("out_js is NULL");
        return;
    }

    char *index_line = (char *) data;

    p = strstr(out_js, index_line);
    if (!TEST_CHECK(p != NULL)) {
      TEST_MSG("Expecting %s but Given:%s", index_line, out_js);
    }

    flb_sds_destroy(out_js);
}

#define JSON_MAP "[12345678, {\"log\": \"This is an interesting log message!\", " \
    "\"map1\": {\"key1\": \"value1\", \"key2\": \"value2\", \"key_nested_object_1\": " \
    "{\"sub_key1\": \"sub_value1\", \"sub_key2\": false}}, \"map2\": {\"key4\": " \
    "\"value1\", \"key5\": false}, \"map3\": {\"key1\": \"map3_value1\", \"key2\": " \
    "\"map3_value2\"}}]"
void flb_test_structured_metadata_map_params(char *remove_keys,
                                             char *structured_metadata,
                                             char *structured_metadata_map_keys,
                                             char *input_log_json,
                                             char *expected_sub_str)
{
    int ret;
    size_t size = strlen(input_log_json);
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

    /* Loki output */
    out_ffd = flb_output(ctx, (char *) "loki", NULL);
    flb_output_set(ctx, out_ffd,
                   "match", "test",
                   "line_format", "key_value",
                   "remove_keys", remove_keys,
                   "drop_single_key", "on",
                   "labels", "service_name=my_service_name",
                   "structured_metadata", structured_metadata,
                   "structured_metadata_map_keys", structured_metadata_map_keys,
                   NULL);

    /* Enable test mode */
    ret = flb_output_set_test(ctx, out_ffd, "formatter",
                              cb_check_structured_metadata_value,
                              expected_sub_str, NULL);

    /* Start */
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Ingest data sample */
    ret = flb_lib_push(ctx, in_ffd, (char *) input_log_json, size);
    TEST_CHECK(ret >= 0);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_structured_metadata_map_single_map() {
    flb_test_structured_metadata_map_params(
        "map1, map2, map3",
        "",
        "$map1",
        JSON_MAP,
        "{\"key1\":\"value1\",\"key2\":\"value2\","
        "\"key_nested_object_1\":\"{\\\"sub_key1\\\":\\\"sub_value1\\\","
        "\\\"sub_key2\\\":false}\"}");
}

void flb_test_structured_metadata_map_two_maps() {
    flb_test_structured_metadata_map_params(
        "map1, map2, map3",
        "",
        "$map1,$map2",
        JSON_MAP,
        "{\"key1\":\"value1\",\"key2\":\"value2\","
        "\"key_nested_object_1\":\"{\\\"sub_key1\\\":\\\"sub_value1\\\","
        "\\\"sub_key2\\\":false}\",\"key4\":\"value1\",\"key5\":\"false\"}");
}

void flb_test_structured_metadata_map_sub_map() {
    flb_test_structured_metadata_map_params(
        "map1, map2, map3",
        "",
        "$map1['key_nested_object_1']",
        JSON_MAP,
        "\"This is an interesting log message!\",{\"sub_key1\":\"sub_value1\","
        "\"sub_key2\":\"false\"}");
}

void flb_test_structured_metadata_map_both_with_non_map_value() {
    flb_test_structured_metadata_map_params(
        "map1, map2, map3",
        "$map2",
        "$map1,$map2",
        JSON_MAP,
        "{\"key1\":\"value1\",\"key2\":\"value2\","
        "\"key_nested_object_1\":\"{\\\"sub_key1\\\":\\\"sub_value1\\\","
        "\\\"sub_key2\\\":false}\",\"key4\":\"value1\",\"key5\":\"false\","
        "\"map2\":\"{\\\"key4\\\":\\\"value1\\\",\\\"key5\\\":false}\"}");
}

/* key1 is overridden by the explicit value given to structured_metadata */
void flb_test_structured_metadata_map_value_explicit_override_map_key() {
    flb_test_structured_metadata_map_params(
        "map1, map2, map3",
        "key1=value_explicit",
        "$map1,$map2",
        JSON_MAP,
        "{\"key2\":\"value2\","
        "\"key_nested_object_1\":\"{\\\"sub_key1\\\":\\\"sub_value1\\\","
        "\\\"sub_key2\\\":false}\",\"key4\":\"value1\",\"key5\":\"false\","
        "\"key1\":\"value_explicit\"}");
}

void flb_test_structured_metadata_explicit_only_no_map() {
    flb_test_structured_metadata_map_params(
        "map1, map2, map3",
        "key1=value_explicit",
        "",
        JSON_MAP,
        "[\"12345678000000000\","
        "\"This is an interesting log message!\",{\"key1\":\"value_explicit\"}]");
}

void flb_test_structured_metadata_explicit_only_map() {
    flb_test_structured_metadata_map_params(
        "map1, map2, map3",
        "$map2",
        "",
        JSON_MAP,
        "{\"map2\":\"{\\\"key4\\\":\\\"value1\\\",\\\"key5\\\":false}\"}");
}

void flb_test_structured_metadata_map_and_explicit() {
    flb_test_structured_metadata_map_params(
        "map1, map2, map3",
        "key_explicit=value_explicit",
        "$map1",
        JSON_MAP,
        "[\"12345678000000000\",\"This is an interesting log message!\","
        "{\"key1\":\"value1\",\"key2\":\"value2\","
        "\"key_nested_object_1\":\"{\\\"sub_key1\\\":\\\"sub_value1\\\","
        "\\\"sub_key2\\\":false}\",\"key_explicit\":\"value_explicit\"}]");
}

void flb_test_structured_metadata_map_single_missing_map() {
    flb_test_structured_metadata_map_params(
        "map1, map2, map3",
        "",
        "$missing_map",
        JSON_MAP,
        "[\"12345678000000000\",\"This is an interesting log message!\",{}]");
}

void flb_test_structured_metadata_map_invalid_ra_key() {
    flb_test_structured_metadata_map_params(
        "map1, map2, map3",
        "",
        "$",
        JSON_MAP,
        "[\"12345678000000000\",\"This is an interesting log message!\",{}]");
}

/* Test list */
TEST_LIST = {
    {"remove_keys_remove_map" , flb_test_remove_map},
    {"labels_ra"              , flb_test_labels_ra },
    {"remove_keys"            , flb_test_remove_keys },
    {"basic"                  , flb_test_basic },
    {"labels"                 , flb_test_labels },
    {"label_keys"             , flb_test_label_keys },
    {"line_format"            , flb_test_line_format },
    {"drop_single_key_off"    , flb_test_drop_single_key_off },
    {"drop_single_key_on"     , flb_test_drop_single_key_on },
    {"drop_single_key_raw"    , flb_test_drop_single_key_raw },
    {"label_map_path"         , flb_test_label_map_path},
    {"float_value"            , flb_test_float_value},
    {"structured_metadata_map_single_map",
        flb_test_structured_metadata_map_single_map},
    {"structured_metadata_map_two_maps",
        flb_test_structured_metadata_map_two_maps},
    {"structured_metadata_map_sub_map",
        flb_test_structured_metadata_map_sub_map},
    {"structured_metadata_map_both_with_non_map_value",
        flb_test_structured_metadata_map_both_with_non_map_value},
    {"structured_metadata_map_value_explicit_override_map_key",
        flb_test_structured_metadata_map_value_explicit_override_map_key},
    {"structured_metadata_explicit_only_no_map",
        flb_test_structured_metadata_explicit_only_no_map},
    {"structured_metadata_explicit_only_map",
        flb_test_structured_metadata_explicit_only_map},
    {"structured_metadata_map_and_explicit",
        flb_test_structured_metadata_map_and_explicit},
    {"structured_metadata_map_single_missing_map",
        flb_test_structured_metadata_map_single_missing_map},
    {"structured_metadata_map_invalid_ra_key",
        flb_test_structured_metadata_map_invalid_ra_key},
    {NULL, NULL}
};
