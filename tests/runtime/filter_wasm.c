/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2022 The Fluent Bit Authors
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
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "flb_tests_runtime.h"

#define DPATH_WASM       FLB_TESTS_DATA_PATH "/data/wasm"
#define FLUSH_INTERVAL "1.0"
#ifdef _WIN32
    #define TIME_EPSILON_MS 30
#else
    #define TIME_EPSILON_MS 10
#endif

pthread_mutex_t result_mutex = PTHREAD_MUTEX_INITIALIZER;
char *output = NULL;
int  num_output = 0;

void set_output(char *val)
{
    pthread_mutex_lock(&result_mutex);
    output = val;
    pthread_mutex_unlock(&result_mutex);
}

char *get_output(void)
{
    char *val;

    pthread_mutex_lock(&result_mutex);
    val = output;
    pthread_mutex_unlock(&result_mutex);

    return val;
}

static void clear_output()
{
    pthread_mutex_lock(&result_mutex);
    output = NULL;
    pthread_mutex_unlock(&result_mutex);
}

static void clear_output_num()
{
    pthread_mutex_lock(&result_mutex);
    num_output = 0;
    pthread_mutex_unlock(&result_mutex);
}

static int get_output_num()
{
    int ret;
    pthread_mutex_lock(&result_mutex);
    ret = num_output;
    pthread_mutex_unlock(&result_mutex);

    return ret;
}

static int cb_count_msgpack_events(void *record, size_t size, void *data)
{
    msgpack_unpacked result;
    size_t off = 0;

    if (!TEST_CHECK(data != NULL)) {
        flb_error("data is NULL");
    }

    /* Iterate each item array and apply rules */
    msgpack_unpacked_init(&result);
    while (msgpack_unpack_next(&result, record, size, &off) == MSGPACK_UNPACK_SUCCESS) {
        pthread_mutex_lock(&result_mutex);
        num_output++;
        pthread_mutex_unlock(&result_mutex);
    }
    msgpack_unpacked_destroy(&result);

    flb_free(record);
    return 0;
}

int callback_test(void* data, size_t size, void* cb_data)
{
    if (size > 0) {
        flb_debug("[test_filter_wasm] received message: %s", (char*)data);
        set_output(data); /* success */
    }
    return 0;
}

void wait_with_timeout(uint32_t timeout_ms, char **out_result)
{
    struct flb_time start_time;
    struct flb_time end_time;
    struct flb_time diff_time;
    uint64_t elapsed_time_flb = 0;
    char *output = NULL;

    flb_time_get(&start_time);

    while (true) {
        output = get_output();

        if (output != NULL) {
            *out_result = output;
            break;
        }

        flb_time_msleep(100);
        flb_time_get(&end_time);
        flb_time_diff(&end_time, &start_time, &diff_time);
        elapsed_time_flb = flb_time_to_nanosec(&diff_time) / 1000000;

        if (elapsed_time_flb > timeout_ms - TIME_EPSILON_MS) {
            flb_warn("[timeout] elapsed_time: %ld", elapsed_time_flb);
            // Reached timeout.
            break;
        }
    }
}


void flb_test_append_tag(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    int filter_ffd;
    char *output = NULL;
    char *input = "[0, {\"key\":\"val\"}]";
    char *result;
    struct flb_lib_out_cb cb_data;

    /* clear previous output */
    clear_output();

    /* Create context, flush every second (some checks omitted here) */
    ctx = flb_create();
    flb_service_set(ctx, "flush", FLUSH_INTERVAL, "grace", "1", NULL);

    /* Prepare output callback context*/
    cb_data.cb = callback_test;
    cb_data.data = NULL;

    /* Filter */
    filter_ffd = flb_filter(ctx, (char *) "wasm", NULL);
    TEST_CHECK(filter_ffd >= 0);
    ret = flb_filter_set(ctx, filter_ffd,
                         "Match", "*",
                         "wasm_path", DPATH_WASM "/append_tag.wasm",
                         "function_name", "filter_append_tag",
                         NULL);

    /* Input */
    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    flb_input_set(ctx, in_ffd, "tag", "test.wasm", NULL);
    TEST_CHECK(in_ffd >= 0);

    /* Lib output */
    out_ffd = flb_output(ctx, (char *) "lib", (void *)&cb_data);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd,
                   "match", "test.wasm",
                   "format", "json",
                   NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret==0);

    flb_lib_push(ctx, in_ffd, input, strlen(input));
    wait_with_timeout(2000, &output);
    result = strstr(output, "\"tag\":\"test.wasm\"");
    TEST_CHECK(result != NULL);

    /* clean up */
    flb_lib_free(output);

    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_helloworld(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    int filter_ffd;

    /* Create context, flush every second (some checks omitted here) */
    ctx = flb_create();
    flb_service_set(ctx, "flush", FLUSH_INTERVAL, "grace", "1", NULL);

    /* Filter */
    filter_ffd = flb_filter(ctx, (char *) "wasm", NULL);
    TEST_CHECK(filter_ffd >= 0);
    ret = flb_filter_set(ctx, filter_ffd,
                         "Match", "*",
                         "wasm_path", DPATH_WASM "/say_hello.wasm",
                         "function_name", "filter_say_hello",
                         NULL);
    /* Input */
    in_ffd = flb_input(ctx, (char *) "dummy", NULL);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);
    TEST_CHECK(in_ffd >= 0);

    /* Lib output */
    out_ffd = flb_output(ctx, (char *) "stdout", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd,
                   "match", "test",
                   NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret==0);

    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_numerics_records(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    int filter_ffd;
    char *output = NULL;
    char *input = "[0, {\"key\":\"val\"}]";
    char *result;
    struct flb_lib_out_cb cb_data;

    /* clear previous output */
    clear_output();

    /* Create context, flush every second (some checks omitted here) */
    ctx = flb_create();
    flb_service_set(ctx, "flush", FLUSH_INTERVAL, "grace", "1", NULL);

    /* Prepare output callback context*/
    cb_data.cb = callback_test;
    cb_data.data = NULL;

    /* Filter */
    filter_ffd = flb_filter(ctx, (char *) "wasm", NULL);
    TEST_CHECK(filter_ffd >= 0);
    ret = flb_filter_set(ctx, filter_ffd,
                         "Match", "*",
                         "wasm_path", DPATH_WASM "/numeric_records.wasm",
                         "function_name", "filter_numeric_records",
                         NULL);

    /* Input */
    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    flb_input_set(ctx, in_ffd, "tag", "test.wasm", NULL);
    TEST_CHECK(in_ffd >= 0);

    /* Lib output */
    out_ffd = flb_output(ctx, (char *) "lib", (void *)&cb_data);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd,
                   "match", "test.wasm",
                   "format", "json",
                   NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret==0);

    flb_lib_push(ctx, in_ffd, input, strlen(input));
    wait_with_timeout(2000, &output);

    /* check if float (for int keys)*/
    result = strstr(output, "\"wasm_int1\":10.");
    if (!TEST_CHECK(result == NULL)) {
        TEST_MSG("output:%s\n", output);
    }
    result = strstr(output, "\"wasm_int2\":100.");
    if (!TEST_CHECK(result == NULL)) {
        TEST_MSG("output:%s\n", output);
    }

    /* check if float (for float keys)*/
    result = strstr(output, "\"wasm_float1\":10.5");
    if (!TEST_CHECK(result != NULL)) {
        TEST_MSG("output:%s\n", output);
    }
    result = strstr(output, "\"wasm_float2\":100.5");
    if (!TEST_CHECK(result != NULL)) {
        TEST_MSG("output:%s\n", output);
    }

    /* check if float (for exp style float key)*/
    result = strstr(output, "\"wasm_exp_float\":0.00354");
    if (!TEST_CHECK(result != NULL)) {
        TEST_MSG("output:%s\n", output);
    }

    /* check if float (for truncated float key)*/
    result = strstr(output, "\"wasm_truncate_float\":120");
    if (!TEST_CHECK(result != NULL)) {
        TEST_MSG("output:%s\n", output);
    }
    result = strstr(output, "\"wasm_truncate_float\":120.");
    if (!TEST_CHECK(result == NULL)) {
        TEST_MSG("output:%s\n", output);
    }

    /* clean up */
    flb_lib_free(output);

    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_array_contains_null(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    int filter_ffd;
    char *output = NULL;
    char *input = "[0, {\"hello\": [1, null, \"world\"]}]";
    char *result;
    struct flb_lib_out_cb cb_data;

    /* clear previous output */
    clear_output();

    /* Create context, flush every second (some checks omitted here) */
    ctx = flb_create();
    flb_service_set(ctx, "flush", FLUSH_INTERVAL, "grace", "1", NULL);

    /* Prepare output callback context*/
    cb_data.cb = callback_test;
    cb_data.data = NULL;

    /* Filter */
    filter_ffd = flb_filter(ctx, (char *) "wasm", NULL);
    TEST_CHECK(filter_ffd >= 0);
    ret = flb_filter_set(ctx, filter_ffd,
                         "Match", "*",
                         "wasm_path", DPATH_WASM "/modify_record.wasm",
                         "function_name", "filter_modify_record",
                         NULL);

    /* Input */
    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    flb_input_set(ctx, in_ffd, "tag", "test.wasm", NULL);
    TEST_CHECK(in_ffd >= 0);

    /* Lib output */
    out_ffd = flb_output(ctx, (char *) "lib", (void *)&cb_data);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd,
                   "match", "test.wasm",
                   "format", "json",
                   NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret==0);

    flb_lib_push(ctx, in_ffd, input, strlen(input));
    wait_with_timeout(2000, &output);

    result = strstr(output, "[1,null,\"world\"]");
    if(!TEST_CHECK(result != NULL)) {
        TEST_MSG("output:%s\n", output);
    }
    result = strstr(output, "\"modify\":\"yes\"");
    if(!TEST_CHECK(result != NULL)) {
        TEST_MSG("output:%s\n", output);
    }

    /* clean up */
    flb_lib_free(output);

    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_drop_all_records(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    int filter_ffd;
    char *output = NULL;
    char *input = "[0, {\"key\":\"val\"}]";
    struct flb_lib_out_cb cb_data;

    clear_output_num();

    /* Create context, flush every second (some checks omitted here) */
    ctx = flb_create();
    flb_service_set(ctx, "flush", FLUSH_INTERVAL, "grace", "1", NULL);

    /* Prepare output callback context*/
    cb_data.cb = cb_count_msgpack_events;
    cb_data.data = NULL;

    /* Filter */
    filter_ffd = flb_filter(ctx, (char *) "wasm", NULL);
    TEST_CHECK(filter_ffd >= 0);
    ret = flb_filter_set(ctx, filter_ffd,
                         "Match", "*",
                         "wasm_path", DPATH_WASM "/drop_record.wasm",
                         "function_name", "filter_drop_record",
                         NULL);
    /* Input */
    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);
    TEST_CHECK(in_ffd >= 0);

    /* Lib output */
    out_ffd = flb_output(ctx, (char *) "lib", (void *)&cb_data);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd,
                   "match", "test",
                   NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret==0);

    flb_lib_push(ctx, in_ffd, input, strlen(input));
    wait_with_timeout(2000, &output); /* waiting flush */

    ret = get_output_num();
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("error. got %d expect 0", ret);
    }

    flb_stop(ctx);
    flb_destroy(ctx);
}


TEST_LIST = {
    {"hello_world", flb_test_helloworld},
    {"append_tag", flb_test_append_tag},
    {"numeric_records", flb_test_numerics_records},
    {"array_contains_null", flb_test_array_contains_null},
    {"drop_all_records", flb_test_drop_all_records},
    {NULL, NULL}
};
