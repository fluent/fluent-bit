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
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "flb_tests_runtime.h"

#define TMP_LUA_PATH "a.lua"
#define FLUSH_INTERVAL "1.0"

pthread_mutex_t result_mutex = PTHREAD_MUTEX_INITIALIZER;
char *output = NULL;
int  num_output = 0;

void set_output(char *val)
{
    pthread_mutex_lock(&result_mutex);
    output = val;
    pthread_mutex_unlock(&result_mutex);
}

void clear_output()
{
    pthread_mutex_lock(&result_mutex);
    output = NULL;
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
        flb_debug("[test_filter_lua] received message: %s", (char*)data);
        set_output(data); /* success */
    }
    return 0;
}

int callback_cat(void* data, size_t size, void* cb_data)
{
    flb_sds_t *outbuf = cb_data;
    if (size > 0) {
        flb_debug("[test_filter_lua] received message: %s", (char*)data);
        pthread_mutex_lock(&result_mutex);
        flb_sds_cat_safe(outbuf, data, size);
        flb_free(data);
        pthread_mutex_unlock(&result_mutex);
    }
    return 0;
}

void delete_script()
{
    unlink(TMP_LUA_PATH);
    flb_debug("remove script\n");
}


int create_script(char *script_body, size_t body_size)
{
    FILE *fp = NULL;
    fp = fopen(TMP_LUA_PATH, "w+");
    if (fp == NULL) {
        TEST_MSG("fopen error\n");
        return -1;
    }
    fwrite(script_body, body_size, 1, fp);
    fflush(fp);
    fclose(fp);
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

        if (elapsed_time_flb > timeout_ms) {
            flb_warn("[timeout] elapsed_time: %ld", elapsed_time_flb);
            // Reached timeout.
            break;
        }
    }
}


void flb_test_type_int_key(void)
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

    char *script_body = ""
      "function lua_main(tag, timestamp, record)\n"
      "    new_record = record\n"
      "    new_record[\"lua_int\"] = 10.2\n"
      "    return 1, timestamp, new_record\n"
      "end\n";

    clear_output();

    /* Create context, flush every second (some checks omitted here) */
    ctx = flb_create();
    flb_service_set(ctx, "flush", FLUSH_INTERVAL, "grace", "1", NULL);

    /* Prepare output callback context*/
    cb_data.cb = callback_test;
    cb_data.data = NULL;

    ret = create_script(script_body, strlen(script_body));
    TEST_CHECK(ret == 0);
    /* Filter */
    filter_ffd = flb_filter(ctx, (char *) "lua", NULL);
    TEST_CHECK(filter_ffd >= 0);
    ret = flb_filter_set(ctx, filter_ffd,
                         "Match", "*",
                         "call", "lua_main",
                         "type_int_key", "lua_int",
                         "script", TMP_LUA_PATH,
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
                   "format", "json",
                   NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret==0);

    flb_lib_push(ctx, in_ffd, input, strlen(input));
    wait_with_timeout(2000, &output);
    result = strstr(output, "\"lua_int\":10.");
    if(!TEST_CHECK(result == NULL)) {
        TEST_MSG("output:%s\n", output);
    }
    result = strstr(output, "\"lua_int\":10");
    if(!TEST_CHECK(result != NULL)) {
        TEST_MSG("output:%s\n", output);
    }

    /* clean up */
    flb_lib_free(output);
    delete_script();

    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_type_int_key_multi(void)
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

    char *script_body = ""
      "function lua_main(tag, timestamp, record)\n"
      "    new_record = record\n"
      "    new_record[\"lua_int_1\"] = 10.1\n"
      "    new_record[\"lua_int_2\"] = 100.2\n"
      "    return 1, timestamp, new_record\n"
      "end\n";

    clear_output();

    /* Create context, flush every second (some checks omitted here) */
    ctx = flb_create();
    flb_service_set(ctx, "flush", FLUSH_INTERVAL, "grace", "1", NULL);

    /* Prepare output callback context*/
    cb_data.cb = callback_test;
    cb_data.data = NULL;

    ret = create_script(script_body, strlen(script_body));
    TEST_CHECK(ret == 0);
    /* Filter */
    filter_ffd = flb_filter(ctx, (char *) "lua", NULL);
    TEST_CHECK(filter_ffd >= 0);
    ret = flb_filter_set(ctx, filter_ffd,
                         "Match", "*",
                         "call", "lua_main",
                         "type_int_key", "lua_int_1 lua_int_2",
                         "script", TMP_LUA_PATH,
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
                   "format", "json",
                   NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret==0);

    flb_lib_push(ctx, in_ffd, input, strlen(input));
    wait_with_timeout(2000, &output);

    /* check if float */
    result = strstr(output, "\"lua_int_1\":10.");
    if (!TEST_CHECK(result == NULL)) {
        TEST_MSG("output:%s\n", output);
    }
    result = strstr(output, "\"lua_int_2\":100.");
    if (!TEST_CHECK(result == NULL)) {
        TEST_MSG("output:%s\n", output);
    }

    /* check if int */
    result = strstr(output, "\"lua_int_1\":10");
    if (!TEST_CHECK(result != NULL)) {
        TEST_MSG("output:%s\n", output);
    }
    result = strstr(output, "\"lua_int_2\":100");
    if (!TEST_CHECK(result != NULL)) {
        TEST_MSG("output:%s\n", output);
    }

    /* clean up */
    flb_lib_free(output);
    delete_script();

    flb_stop(ctx);
    flb_destroy(ctx);
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

    char *script_body = ""
      "function lua_main(tag, timestamp, record)\n"
      "    new_record = record\n"
      "    new_record[\"tag\"] = tag\n"
      "    return 1, timestamp, new_record\n"
      "end\n";

    /* Create context, flush every second (some checks omitted here) */
    ctx = flb_create();
    flb_service_set(ctx, "flush", FLUSH_INTERVAL, "grace", "1", NULL);

    /* Prepare output callback context*/
    cb_data.cb = callback_test;
    cb_data.data = NULL;

    ret = create_script(script_body, strlen(script_body));
    TEST_CHECK(ret == 0);
    /* Filter */
    filter_ffd = flb_filter(ctx, (char *) "lua", NULL);
    TEST_CHECK(filter_ffd >= 0);
    ret = flb_filter_set(ctx, filter_ffd,
                         "Match", "*",
                         "call", "lua_main",
                         "script", TMP_LUA_PATH,
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
                   "format", "json",
                   NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret==0);

    flb_lib_push(ctx, in_ffd, input, strlen(input));
    wait_with_timeout(2000, &output);
    result = strstr(output, "\"tag\":\"test\"");
    TEST_CHECK(result != NULL);

    /* clean up */
    flb_lib_free(output);
    delete_script();

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

    char *script_body = ""
      "function lua_main(tag, timestamp, record)\n"
      "    print(\"hello world\")\n"
      "    return 0, timestamp, record\n"
      "end\n";

    /* Create context, flush every second (some checks omitted here) */
    ctx = flb_create();
    flb_service_set(ctx, "flush", FLUSH_INTERVAL, "grace", "1", NULL);

    ret = create_script(script_body, strlen(script_body));
    TEST_CHECK(ret == 0);
    /* Filter */
    filter_ffd = flb_filter(ctx, (char *) "lua", NULL);
    TEST_CHECK(filter_ffd >= 0);
    ret = flb_filter_set(ctx, filter_ffd,
                         "Match", "*",
                         "call", "lua_main",
                         "script", TMP_LUA_PATH,
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

    delete_script();
    flb_stop(ctx);
    flb_destroy(ctx);
}

// https://github.com/fluent/fluent-bit/issues/3343
void flb_test_type_array_key(void)
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

    char *script_body = ""
      "function lua_main(tag, timestamp, record)\n"
      "    new_record = record\n"
      "    new_record[\"lua_array\"] = {};\n"
      "    new_record[\"lua_array2\"] = {1,2,3};\n"
      "    return 1, timestamp, new_record\n"
      "end\n";

    clear_output();

    /* Create context, flush every second (some checks omitted here) */
    ctx = flb_create();
    flb_service_set(ctx, "flush", FLUSH_INTERVAL, "grace", "1", NULL);

    /* Prepare output callback context*/
    cb_data.cb = callback_test;
    cb_data.data = NULL;

    ret = create_script(script_body, strlen(script_body));
    TEST_CHECK(ret == 0);
    /* Filter */
    filter_ffd = flb_filter(ctx, (char *) "lua", NULL);
    TEST_CHECK(filter_ffd >= 0);
    ret = flb_filter_set(ctx, filter_ffd,
                         "Match", "*",
                         "call", "lua_main",
                         "type_array_key", "lua_array lua_array2",
                         "script", TMP_LUA_PATH,
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
                   "format", "json",
                   NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret==0);

    flb_lib_push(ctx, in_ffd, input, strlen(input));
    wait_with_timeout(2000, &output);
    result = strstr(output, "\"lua_array\":[]");
    if(!TEST_CHECK(result != NULL)) {
        TEST_MSG("output:%s\n", output);
    }
    result = strstr(output, "\"lua_array2\":[1,2,3]");
    if(!TEST_CHECK(result != NULL)) {
        TEST_MSG("output:%s\n", output);
    }

    /* clean up */
    flb_lib_free(output);
    delete_script();

    flb_stop(ctx);
    flb_destroy(ctx);
}

/* https://github.com/fluent/fluent-bit/issues/3433 */
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

    char *script_body = ""
      "function lua_main(tag, timestamp, record)\n"
      "    new_record = record\n"
      "    new_record[\"modify\"] = \"yes\"\n"
      "    return 1, timestamp, new_record\n"
      "end\n";

    clear_output();

    /* Create context, flush every second (some checks omitted here) */
    ctx = flb_create();
    flb_service_set(ctx, "flush", FLUSH_INTERVAL, "grace", "1", NULL);

    /* Prepare output callback context*/
    cb_data.cb = callback_test;
    cb_data.data = NULL;

    ret = create_script(script_body, strlen(script_body));
    TEST_CHECK(ret == 0);
    /* Filter */
    filter_ffd = flb_filter(ctx, (char *) "lua", NULL);
    TEST_CHECK(filter_ffd >= 0);
    ret = flb_filter_set(ctx, filter_ffd,
                         "Match", "*",
                         "call", "lua_main",
                         "script", TMP_LUA_PATH,
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
    delete_script();

    flb_stop(ctx);
    flb_destroy(ctx);
}

/* https://github.com/fluent/fluent-bit/issues/5251 */
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

    char *script_body = ""
      "function lua_main(tag, timestamp, record)\n"
      "    return -1, 0, 0\n"
      "end\n";

    clear_output_num();

    /* Create context, flush every second (some checks omitted here) */
    ctx = flb_create();
    flb_service_set(ctx, "flush", FLUSH_INTERVAL, "grace", "1", NULL);

    /* Prepare output callback context*/
    cb_data.cb = cb_count_msgpack_events;
    cb_data.data = NULL;

    ret = create_script(script_body, strlen(script_body));
    TEST_CHECK(ret == 0);
    /* Filter */
    filter_ffd = flb_filter(ctx, (char *) "lua", NULL);
    TEST_CHECK(filter_ffd >= 0);
    ret = flb_filter_set(ctx, filter_ffd,
                         "Match", "*",
                         "call", "lua_main",
                         "script", TMP_LUA_PATH,
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
    flb_time_msleep(1500); /* waiting flush */

    ret = get_output_num();
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("error. got %d expect 0", ret);
    }

    /* clean up */
    flb_lib_free(output);
    delete_script();

    flb_stop(ctx);
    flb_destroy(ctx);
}

/* https://github.com/fluent/fluent-bit/issues/5496 */
void flb_test_split_record(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    int filter_ffd;
    struct flb_lib_out_cb cb_data;
    char *output = NULL;
    flb_sds_t outbuf = flb_sds_create("");
    char *input = "[0, {\"x\": [ "
        "{\"a1\":\"aa\"}, "
        "{\"b1\":\"bb\"}, "
        "{\"c1\":\"cc\"} ]}]";
    const char *expected =
        "[5.000000,{\"a1\":\"aa\"}]"
        "[5.000000,{\"b1\":\"bb\"}]"
        "[5.000000,{\"c1\":\"cc\"}]";
    char *script_body = ""
      "function lua_main(tag, timestamp, record)\n"
      "    return 1, 5, record.x\n"
      "end\n";

    clear_output();

    /* Create context, flush every second (some checks omitted here) */
    ctx = flb_create();
    flb_service_set(ctx, "flush", FLUSH_INTERVAL, "grace", "1", NULL);

    /* Prepare output callback context*/
    cb_data.cb = callback_cat;
    cb_data.data = &outbuf;

    ret = create_script(script_body, strlen(script_body));
    TEST_CHECK(ret == 0);
    /* Filter */
    filter_ffd = flb_filter(ctx, (char *) "lua", NULL);
    TEST_CHECK(filter_ffd >= 0);
    ret = flb_filter_set(ctx, filter_ffd,
                         "Match", "*",
                         "call", "lua_main",
                         "script", TMP_LUA_PATH,
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
                   "format", "json",
                   NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret==0);

    flb_lib_push(ctx, in_ffd, input, strlen(input));
    wait_with_timeout(2000, &output);
    if (!TEST_CHECK(!strcmp(outbuf, expected))) {
        TEST_MSG("expected:\n%s\ngot:\n%s\n", expected, outbuf);
    }

    /* clean up */
    flb_lib_free(output);
    delete_script();

    flb_stop(ctx);
    flb_destroy(ctx);
    flb_sds_destroy(outbuf);
}

TEST_LIST = {
    {"hello_world",  flb_test_helloworld},
    {"append_tag",   flb_test_append_tag},
    {"type_int_key", flb_test_type_int_key},
    {"type_int_key_multi", flb_test_type_int_key_multi},
    {"type_array_key", flb_test_type_array_key},
    {"array_contains_null", flb_test_array_contains_null},
    {"drop_all_records", flb_test_drop_all_records},
    {"split_record", flb_test_split_record},
    {NULL, NULL}
};
