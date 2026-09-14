/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2025 The Fluent Bit Authors
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
#define JSON_K8S_DATASET                                                       \
    "[12345678, {\"log\":\"hello\","                                           \
    "\"kubernetes\":{\"annotations\":{\"parseable/dataset\":\"team-a\"},"      \
    "\"labels\":{\"app\":\"web\"},\"namespace_name\":\"default\","             \
    "\"pod_name\":\"web-1\",\"container_name\":\"web\"}}]"

/*
 * The formatter callback receives the JSON payload that out_parseable would
 * have sent to the upstream HTTP endpoint. Each test inspects the captured
 * payload and frees it (the runtime hands ownership to the test).
 */

static pthread_mutex_t result_mutex = PTHREAD_MUTEX_INITIALIZER;
static int result_hits;

static int get_hits(void)
{
    int n;
    pthread_mutex_lock(&result_mutex);
    n = result_hits;
    pthread_mutex_unlock(&result_mutex);
    return n;
}

static void clear_hits(void)
{
    pthread_mutex_lock(&result_mutex);
    result_hits = 0;
    pthread_mutex_unlock(&result_mutex);
}

static void inc_hits(void)
{
    pthread_mutex_lock(&result_mutex);
    result_hits++;
    pthread_mutex_unlock(&result_mutex);
}

/* Asserts the payload contains an expected substring. */
static void cb_check_contains(void *ctx, int ffd,
                              int res_ret, void *res_data, size_t res_size,
                              void *data)
{
    flb_sds_t out_js = res_data;
    const char *needle = (const char *) data;

    if (!TEST_CHECK(out_js != NULL)) {
        TEST_MSG("formatter returned NULL payload");
    }
    else {
        if (!TEST_CHECK(strstr(out_js, needle) != NULL)) {
            TEST_MSG("substring '%s' not found in payload: %.*s",
                     needle, (int) res_size, out_js);
        }
        flb_sds_destroy(out_js);
    }
    inc_hits();
}

/* Asserts the payload starts with a JSON array (default logs format). */
static void cb_check_json_array(void *ctx, int ffd,
                                int res_ret, void *res_data, size_t res_size,
                                void *data)
{
    flb_sds_t out_js = res_data;

    if (!TEST_CHECK(out_js != NULL)) {
        TEST_MSG("formatter returned NULL payload");
    }
    else {
        if (!TEST_CHECK(res_size > 0 && out_js[0] == '[')) {
            TEST_MSG("expected JSON array, got: %.*s",
                     (int) res_size, out_js);
        }
        if (!TEST_CHECK(strstr(out_js, "\"key\":\"value\"") != NULL)) {
            TEST_MSG("expected key/value pair, got: %.*s",
                     (int) res_size, out_js);
        }
        flb_sds_destroy(out_js);
    }
    inc_hits();
}

/*
 * Formatter test: default data_type=logs produces a plain JSON array
 * that contains the original record fields.
 */
void flb_test_format_logs_default(void)
{
    int ret;
    int size = sizeof(JSON_BASIC) - 1;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    clear_hits();

    ctx = flb_create();
    flb_service_set(ctx, "flush", "1", "grace", "1",
                    "log_level", "error", NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "parseable", NULL);
    flb_output_set(ctx, out_ffd,
                   "match", "test",
                   "stream", "test_stream",
                   NULL);

    ret = flb_output_set_test(ctx, out_ffd, "formatter",
                              cb_check_json_array,
                              NULL, NULL);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    ret = flb_lib_push(ctx, in_ffd, (char *) JSON_BASIC, size);
    TEST_CHECK(ret >= 0);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);

    TEST_CHECK(get_hits() > 0);
}

/*
 * Formatter test: when log_source contains "otel" the formatter switches
 * to the OTEL JSON encoding and emits "resourceLogs".
 */
void flb_test_format_otel_log_source(void)
{
    int ret;
    int size = sizeof(JSON_BASIC) - 1;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    clear_hits();

    ctx = flb_create();
    flb_service_set(ctx, "flush", "1", "grace", "1",
                    "log_level", "error", NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "parseable", NULL);
    flb_output_set(ctx, out_ffd,
                   "match", "test",
                   "stream", "test_stream",
                   "log_source", "otel-logs",
                   NULL);

    ret = flb_output_set_test(ctx, out_ffd, "formatter",
                              cb_check_contains,
                              "resourceLogs", NULL);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    ret = flb_lib_push(ctx, in_ffd, (char *) JSON_BASIC, size);
    TEST_CHECK(ret >= 0);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);

    TEST_CHECK(get_hits() > 0);
}

/*
 * Formatter test: data_type=metrics forces OTEL JSON output even without
 * an OTEL-flavoured log_source.
 */
void flb_test_format_data_type_metrics(void)
{
    int ret;
    int size = sizeof(JSON_BASIC) - 1;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    clear_hits();

    ctx = flb_create();
    flb_service_set(ctx, "flush", "1", "grace", "1",
                    "log_level", "error", NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "parseable", NULL);
    flb_output_set(ctx, out_ffd,
                   "match", "test",
                   "stream", "test_stream",
                   "data_type", "metrics",
                   NULL);

    ret = flb_output_set_test(ctx, out_ffd, "formatter",
                              cb_check_contains,
                              "resourceMetrics", NULL);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    ret = flb_lib_push(ctx, in_ffd, (char *) JSON_BASIC, size);
    TEST_CHECK(ret >= 0);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);

    TEST_CHECK(get_hits() > 0);
}

/*
 * Formatter test: dynamic_stream picks up a parseable/dataset annotation
 * inside a kubernetes block. The formatter still produces standard JSON
 * for the body, so we just confirm the kubernetes payload survives.
 */
void flb_test_format_dynamic_stream_annotation(void)
{
    int ret;
    int size = sizeof(JSON_K8S_DATASET) - 1;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    clear_hits();

    ctx = flb_create();
    flb_service_set(ctx, "flush", "1", "grace", "1",
                    "log_level", "error", NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "parseable", NULL);
    flb_output_set(ctx, out_ffd,
                   "match", "test",
                   "stream", "fallback",
                   "dynamic_stream", "true",
                   NULL);

    ret = flb_output_set_test(ctx, out_ffd, "formatter",
                              cb_check_contains,
                              "parseable/dataset", NULL);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    ret = flb_lib_push(ctx, in_ffd, (char *) JSON_K8S_DATASET, size);
    TEST_CHECK(ret >= 0);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);

    TEST_CHECK(get_hits() > 0);
}

/*
 * Init test: omitting the required "stream" property must fail plugin init
 * cleanly without leaking. Valgrind catches any leak that would slip through.
 */
void flb_test_init_missing_stream(void)
{
    int ret;
    flb_ctx_t *ctx;
    int out_ffd;

    ctx = flb_create();
    flb_service_set(ctx, "flush", "1", "grace", "1",
                    "log_level", "error", NULL);

    out_ffd = flb_output(ctx, (char *) "parseable", NULL);
    flb_output_set(ctx, out_ffd,
                   "match", "test",
                   NULL);

    /*
     * flb_start() should fail because the plugin's init callback
     * rejects a missing "stream" configuration.
     */
    ret = flb_start(ctx);
    TEST_CHECK(ret != 0);

    if (ret == 0) {
        flb_stop(ctx);
    }
    flb_destroy(ctx);
}

/*
 * Init test: a valid config with all common options must initialize, run,
 * and tear down without crashing or leaking. Designed for valgrind.
 */
void flb_test_init_full_config(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    ctx = flb_create();
    flb_service_set(ctx, "flush", "1", "grace", "1",
                    "log_level", "error", NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "parseable", NULL);
    flb_output_set(ctx, out_ffd,
                   "match", "test",
                   "stream", "team-a",
                   "log_source", "otel-logs",
                   "data_type", "logs",
                   "compress", "gzip",
                   "header", "X-Custom-Header value",
                   "auth_header", "Basic dXNlcjpwYXNz",
                   "dynamic_stream", "true",
                   "enrich_kubernetes", "false",
                   "batch_size", "1048576",
                   "retry_limit", "1",
                   NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    if (ret == 0) {
        sleep(1);
        flb_stop(ctx);
    }
    flb_destroy(ctx);
}

TEST_LIST = {
    {"format_logs_default",            flb_test_format_logs_default},
    {"format_otel_log_source",         flb_test_format_otel_log_source},
    {"format_data_type_metrics",       flb_test_format_data_type_metrics},
    {"format_dynamic_stream_annotation", flb_test_format_dynamic_stream_annotation},
    {"init_missing_stream",            flb_test_init_missing_stream},
    {"init_full_config",               flb_test_init_full_config},
    {NULL, NULL}
};
