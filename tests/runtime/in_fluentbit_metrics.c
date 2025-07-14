/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2022 The Fluent Bit Authors
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
#include <fluent-bit/flb_compat.h>
#include <fluent-bit/flb_time.h>
#include <float.h>
#include "flb_tests_runtime.h"

struct test_ctx {
    flb_ctx_t *flb;    /* Fluent Bit library context */
    int i_ffd;         /* Input fd  */
    int f_ffd;         /* Filter fd (unused) */
    int o_ffd;         /* Output fd */
};


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

struct str_list {
    size_t size;
    char **lists;
};

void wait_with_timeout(uint32_t timeout_ms, int *output_num)
{
    struct flb_time start_time;
    struct flb_time end_time;
    struct flb_time diff_time;
    uint64_t elapsed_time_flb = 0;

    flb_time_get(&start_time);

    while (true) {
        *output_num = get_output_num();

        if (*output_num > 0) {
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

/* Callback to check expected results */
static int cb_check_json_str_list(void *record, size_t size, void *data)
{
    char *p;
    char *result;
    int num = get_output_num();
    size_t i;
    struct str_list *l = (struct str_list*)data;

    if (!TEST_CHECK(l != NULL)) {
        TEST_MSG("Data is NULL");
        flb_free(record);
        return 0;
    }

    set_output_num(num+1);

    result = (char *) record;

    for (i=0; i<l->size; i++) {
        p = strstr(result, l->lists[i]);
        if(!TEST_CHECK(p != NULL)) {
            TEST_MSG("Expected to find: '%s' in result '%s'",
                     l->lists[i], result);
        }
    }

    /*
     * If you want to debug your test
     *
     * printf("Expect: '%s' in result '%s'", expected, result);
     */
    flb_free(record);
    return 0;
}

static struct test_ctx *test_ctx_create(struct flb_lib_out_cb *data)
{
    int o_ffd;
    struct test_ctx *ctx = NULL;

    ctx = flb_malloc(sizeof(struct test_ctx));
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("malloc failed");
        flb_errno();
        return NULL;
    }

    /* Service config */
    ctx->flb = flb_create();
    flb_service_set(ctx->flb,
                    "Flush", "0.200000000",
                    "Grace", "1",
                    "Log_Level", "error",
                    NULL);

    ctx->i_ffd = flb_input(ctx->flb, (char *) "fluentbit_metrics", NULL);
    TEST_CHECK(ctx->i_ffd >= 0);

    /* Output */
    o_ffd = flb_output(ctx->flb, (char *) "lib", (void *) data);
    ctx->o_ffd = o_ffd;
    TEST_CHECK(ctx->o_ffd >= 0);

    return ctx;
}

static void test_ctx_destroy(struct test_ctx *ctx)
{
    TEST_CHECK(ctx != NULL);

    sleep(1);
    flb_stop(ctx->flb);
    flb_destroy(ctx->flb);
    flb_free(ctx);
}

#ifdef FLB_HAVE_METRICS
char *basic_expected_strs[] = {"\"uptime\"", "\"records_total\"", "\"bytes_total\"", "\"proc_records_total\"", "\"proc_bytes_total\"", "\"errors_total\"", "\"retries_total\"", "\"retries_failed_total\"", "\"dropped_records_total\"", "\"retried_records_total\"", "\"process_cpu_seconds_total\"", "\"process_resident_memory_bytes\""};

static double get_metric_value(const char *json, const char *name)
{
    char search[128];
    char *p;

    /* locate metric entry by name */
    snprintf(search, sizeof(search), "\"name\":\"%s\"", name);
    p = strstr(json, search);
    if (!p) {
        return -1.0;
    }

    /* find the value field after the name */
    p = strstr(p, "\"value\":");
    if (!p) {
        return -1.0;
    }
    p += strlen("\"value\":");
    return atof(p);
}

static int cb_check_metric_values(void *record, size_t size, void *data)
{
    char *result = (char *) record;
    double cpu;
    double mem;


    cpu = get_metric_value(result, "process_cpu_seconds_total");
    mem = get_metric_value(result, "process_resident_memory_bytes");

    if (!TEST_CHECK(cpu >= 0)) {
        TEST_MSG("invalid cpu seconds value");
    }

    if (!TEST_CHECK(mem > 0)) {
        TEST_MSG("invalid memory value");
    }

    set_output_num(get_output_num() + 1);
    flb_free(record);
    return 0;
}

static void test_basic(void)
{
    struct flb_lib_out_cb cb_data;
    struct test_ctx *ctx;
    int ret;
    int num;

    struct str_list expected = {
                                .size = sizeof(basic_expected_strs)/sizeof(char*),
                                .lists = &basic_expected_strs[0],
    };

    clear_output_num();

    cb_data.cb = cb_check_json_str_list;
    cb_data.data = &expected;

    ctx = test_ctx_create(&cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
        exit(EXIT_FAILURE);
    }
    /* Input */
    ret = flb_input_set(ctx->flb, ctx->i_ffd,
                        "scrape_interval", "1",
                        NULL);
    TEST_CHECK(ret == 0);

    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "format", "json",
                         NULL);
    TEST_CHECK(ret == 0);

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* waiting to flush */
    wait_with_timeout(3000, &num);

    if (!TEST_CHECK(num > 0))  {
        TEST_MSG("no outputs");
    }

    test_ctx_destroy(ctx);
}

static void test_values(void)
{
    struct flb_lib_out_cb cb_data;
    struct test_ctx *ctx;
    int ret;
    int num;

    clear_output_num();

    cb_data.cb = cb_check_metric_values;
    cb_data.data = NULL;

    ctx = test_ctx_create(&cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
        exit(EXIT_FAILURE);
    }

    ret = flb_input_set(ctx->flb, ctx->i_ffd,
                        "scrape_interval", "1",
                        NULL);
    TEST_CHECK(ret == 0);

    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "format", "json",
                         NULL);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    wait_with_timeout(3000, &num);

    if (!TEST_CHECK(num > 0)) {
        TEST_MSG("no outputs");
    }

    test_ctx_destroy(ctx);
}
#endif

TEST_LIST = {
#ifdef FLB_HAVE_METRICS
    {"basic", test_basic},
    {"values", test_values},
#endif
    {NULL, NULL}
};
