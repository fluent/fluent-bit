/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2023 The Fluent Bit Authors
 *  Copyright (C) 2023 SAP SE
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

/*
* +-------------------------------+-------------------------------+
* |                               |                               |
* |   +--------------------+      |   +--------------------+      |
* |   | INPUTS             |      | ->| INPUT (IN_EMITTER  |      |
* |   |                    |      |/  |            METRICS)|      |
* |   +--------------------+      /   +--------------------+      |
* |            |                 /|            |                  |
* |            v                / |            |                  |
* |   +--------------------+    | |            |                  |
* |   | FILTER (KUBERNETES)|    | |            |                  |
* |   |  (NOT USED IN TEST)|    | |            |                  |
* |   +--------------------+    | |            |                  |
* |            |                | |            |                  |
* |            v                / |            |                  |
* |   +--------------------+   /  |            |                  |
* |   | FILTER (LOG METRIC)|  /   |            |                  |
* |   |                    |-/    |            |                  |
* |   +--------------------+      |            |                  |
* |            |                  |            |                  |
* |            v                  |            v                  |
* |   +--------------------+      |   +--------------------+      |
* |   | OUTPUT             |      |   | OUTPUT (METRICS)   |      |
* |   | (NONE IN THIS TEST)|      |   |                    |      |
* |   +--------------------+      |   +--------------------+      |
* |                               |                               |
* +-------------------------------+-------------------------------+
*/

/* Test functions */
void flb_test_log_to_metrics_counter_k8s(void);
void flb_test_log_to_metrics_counter(void);
void flb_test_log_to_metrics_counter_k8s_two_tuples(void);
void flb_test_log_to_metrics_gauge(void);
void flb_test_log_to_metrics_histogram(void);
void flb_test_log_to_metrics_reg(void);
void flb_test_log_to_metrics_empty_label_keys_regex(void);
void flb_test_log_to_metrics_label(void);


/* Test data */
#define JSON_MSG1	"["		                \
	"1448403340,"			                \
	"{"				                        \
	"\"message\": \"dummy\","		        \
    "\"kubernetes\":{"                      \
	"\"container_name\": \"mycontainer\","	\
	"\"namespace_name\": \"k8s-dummy\","	\
	"\"container_id\": \"abc123\","		    \
	"\"pod_name\": \"testpod\","		    \
	"\"pod_id\": \"def456\","	    	    \
    "},"                                    \
	"\"duration\": \"20\","		            \
    "\"color\": \"red\","                   \
    "\"direction\": \"right\""		        \
	"}]"

#define JSON_MSG2	"["		                \
	"1448403341,"		                    \
	"{"				                        \
	"\"message\": \"dummy\","		        \
    "\"kubernetes\":{"                      \
	"\"container_name\": \"mycontainer\","	\
	"\"namespace_name\": \"k8s-dummy\","	\
	"\"container_id\": \"abc123\","	    	\
	"\"pod_name\": \"testpod\","	        \
	"\"pod_id\": \"def456\","	    	    \
    "},"                                    \
	"\"duration\": \"20\","		            \
	"\"color\": \"red\","		            \
	"\"direction\": \"left\""		        \
	"}]"

#define JSON_MSG3	"["		                \
	"1448403341,"		                    \
	"{"				                        \
	"\"message\": \"hello\","		        \
    "\"kubernetes\":{"                      \
	"\"container_name\": \"mycontainer\","	\
	"\"namespace_name\": \"k8s-dummy\","	\
	"\"container_id\": \"abc123\","		    \
	"\"pod_name\": \"testpod\","	        \
	"\"pod_id\": \"def456\","	    	    \
    "},"                                    \
	"\"duration\": \"20\","		            \
	"\"color\": \"red\","		            \
	"\"direction\": \"left\""		        \
	"}]"

/* Test list */
TEST_LIST = {
    {"counter_k8s",            flb_test_log_to_metrics_counter_k8s            },
    {"counter",                flb_test_log_to_metrics_counter                },
    {"counter_k8s_two_tuples", flb_test_log_to_metrics_counter_k8s_two_tuples },
    {"gauge",                  flb_test_log_to_metrics_gauge                  },
    {"histogram",              flb_test_log_to_metrics_histogram              },
    {"counter_regex",          flb_test_log_to_metrics_reg                    },
    {"regex_empty_label_keys", flb_test_log_to_metrics_empty_label_keys_regex },
    {"label",                  flb_test_log_to_metrics_label                  },
    {NULL, NULL}
};

pthread_mutex_t result_mutex = PTHREAD_MUTEX_INITIALIZER;
int data_size = 0;
bool new_data = false;
char output[32768];


int callback_test(void* data, size_t size, void* cb_data)
{
    if (size > 0) {
        new_data = true;
        flb_debug("[test_filter_log_to_metrics] received message: %s", (char*)data);
        pthread_mutex_lock(&result_mutex);
            strncat(output, data, size);
            data_size = size;
        pthread_mutex_unlock(&result_mutex);
    }
    flb_free(data);
    return 0;
}

static void filter_test_destroy(flb_ctx_t *ctx)
{
    sleep(1);
    flb_stop(ctx);
    flb_destroy(ctx);
}

void wait_with_timeout(uint32_t timeout_ms, char *out_result)
{
    struct flb_time start_time;
    struct flb_time end_time;
    struct flb_time diff_time;
    uint64_t elapsed_time_flb = 0;
    flb_time_get(&start_time);

    while (true) {
        if(new_data){
            pthread_mutex_lock(&result_mutex);
            new_data = false;
            strcat(out_result, output);
            pthread_mutex_unlock(&result_mutex);

        }

        flb_time_msleep(100);
        flb_time_get(&end_time);
        flb_time_diff(&end_time, &start_time, &diff_time);
        elapsed_time_flb = flb_time_to_nanosec(&diff_time) / 1000000;

        if (elapsed_time_flb > timeout_ms) {
            // Reached timeout.
            break;
        }
    }
}

void flb_test_log_to_metrics_counter_k8s(void)
{
    int ret;
    int i;
    flb_ctx_t *ctx;
    int in_ffd;
    int filter_ffd;
    int out_ffd;
    char *result = NULL;
    struct flb_lib_out_cb cb_data;
    char *input = JSON_MSG1;
    char finalString[32768] = "";

    const char *expected = "\"value\":5.0,\"labels\":[\"k8s-dummy\","
                           "\"testpod\",\"mycontainer\",\"abc123\","
                           "\"def456\",\"red\",\"right\"]";
    const char *expected2 = "{\"ns\":\"log_metric\",\"ss\":\"counter\","
                            "\"name\":\"test\",\"desc\":\"Counts messages\"}";

    ctx = flb_create();
    flb_service_set(ctx, "Flush", "0.200000000", "Grace", "1", "Log_Level",
                    "error", NULL);

    cb_data.cb = callback_test;
    cb_data.data = NULL;

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    filter_ffd = flb_filter(ctx, (char *) "log_to_metrics", NULL);
    TEST_CHECK(filter_ffd >= 0);
    ret = flb_filter_set(ctx, filter_ffd,
                         "Match", "*",
                         "Tag", "test_metric",
                         "metric_mode", "counter",
                         "metric_name", "test",
                         "metric_description", "Counts messages",
                         "metric_subsystem", "",
                         "kubernetes_mode", "on",
                         "label_field", "color",
                         "label_field", "direction",
                         NULL);

    out_ffd = flb_output(ctx, (char *) "lib", (void *)&cb_data);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd,
                   "match", "*",
                   "format", "json",
                   NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    for (i = 0; i < 5; i++){
        flb_lib_push(ctx, in_ffd, input, strlen(input));
    }
    wait_with_timeout(2000, finalString);
    result = strstr(finalString, expected);
    if (!TEST_CHECK(result != NULL)) {
        TEST_MSG("expected substring:\n%s\ngot:\n%s\n", expected, finalString);
    }
    result = strstr(finalString, expected2);
    if (!TEST_CHECK(result != NULL)) {
        TEST_MSG("expected substring:\n%s\ngot:\n%s\n", expected, finalString);
    }

    filter_test_destroy(ctx);

}

void flb_test_log_to_metrics_counter(void)
{
    int ret;
    int i;
    flb_ctx_t *ctx;
    int in_ffd;
    int filter_ffd;
    int out_ffd;
    char *result = NULL;
    struct flb_lib_out_cb cb_data;
    char *input = JSON_MSG1;
    char finalString[32768] = "";
    const char *expected = "\"value\":5.0,\"labels\":[\"red\",\"right\"]";
    const char *expected2 = "{\"ns\":\"myns\",\"ss\":\"subsystem\","
                            "\"name\":\"test\",\"desc\":\"Counts messages\"}";

    ctx = flb_create();
    flb_service_set(ctx, "Flush", "0.200000000", "Grace", "1", "Log_Level",
                    "error", NULL);

    cb_data.cb = callback_test;
    cb_data.data = NULL;

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    filter_ffd = flb_filter(ctx, (char *) "log_to_metrics", NULL);
    TEST_CHECK(filter_ffd >= 0);
    ret = flb_filter_set(ctx, filter_ffd,
                         "Match", "*",
                         "Tag", "test_metric",
                         "metric_mode", "counter",
                         "metric_name", "test",
                         "metric_description", "Counts messages",
                         "metric_subsystem", "subsystem",
                         "metric_namespace", "myns",
                         "kubernetes_mode", "off",
                         "label_field", "color",
                         "label_field", "direction",
                         NULL);

    out_ffd = flb_output(ctx, (char *) "lib", (void *)&cb_data);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd,
                   "match", "*",
                   "format", "json",
                   NULL);
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    for (i = 0; i < 5; i++){
        flb_lib_push(ctx, in_ffd, input, strlen(input));
    }
    wait_with_timeout(2000, finalString);
    result = strstr(finalString, expected);
    if (!TEST_CHECK(result != NULL)) {
        TEST_MSG("expected substring:\n%s\ngot:\n%s\n", expected, finalString);
    }
    result = strstr(finalString, expected2);
    if (!TEST_CHECK(result != NULL)) {
        TEST_MSG("expected substring:\n%s\ngot:\n%s\n", expected, finalString);
    }
    filter_test_destroy(ctx);

}

void flb_test_log_to_metrics_counter_k8s_two_tuples(void)
{
    int ret;
    int i;
    flb_ctx_t *ctx;
    int in_ffd;
    int filter_ffd;
    int out_ffd;
    char *result = NULL;
    struct flb_lib_out_cb cb_data;
    char *input1 = JSON_MSG1;
    char *input2 = JSON_MSG2;
    char finalString[32768] = "";
    const char *expected1 = "\"value\":5.0,\"labels\":[\"k8s-dummy\","
                           "\"testpod\",\"mycontainer\",\"abc123\","
                           "\"def456\",\"red\",\"right\"]";
    const char *expected2 = "\"value\":3.0,\"labels\":[\"k8s-dummy\","
                           "\"testpod\",\"mycontainer\",\"abc123\","
                           "\"def456\",\"red\",\"left\"]";


    ctx = flb_create();
    flb_service_set(ctx, "Flush", "0.200000000", "Grace", "1", "Log_Level",
                    "error", NULL);

    cb_data.cb = callback_test;
    cb_data.data = NULL;

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    filter_ffd = flb_filter(ctx, (char *) "log_to_metrics", NULL);
    TEST_CHECK(filter_ffd >= 0);
    ret = flb_filter_set(ctx, filter_ffd,
                         "Match", "*",
                         "Tag", "test_metric",
                         "metric_mode", "counter",
                         "metric_name", "test",
                         "metric_description", "Counts two different messages",
                         "metric_subsystem", "",
                         "kubernetes_mode", "on",
                         "label_field", "color",
                         "label_field", "direction",
                         NULL);

    out_ffd = flb_output(ctx, (char *) "lib", (void *)&cb_data);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd,
                   "match", "*",
                   "format", "json",
                   NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    for (i = 0; i < 5; i++){
        flb_lib_push(ctx, in_ffd, input1, strlen(input1));
    }
    for (i = 0; i < 3; i++){
        flb_lib_push(ctx, in_ffd, input2, strlen(input2));
    }
    wait_with_timeout(2000, finalString);
    result = strstr(finalString, expected1);
    if (!TEST_CHECK(result != NULL)) {
        TEST_MSG("expected substring:\n%s\ngot:\n%s\n", expected1, finalString);
    }

    result = strstr(finalString, expected2);
    if (!TEST_CHECK(result != NULL)) {
        TEST_MSG("expected substring:\n%s\ngot:\n%s\n", expected2, finalString);
    }

    filter_test_destroy(ctx);

}

void flb_test_log_to_metrics_gauge(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int filter_ffd;
    int out_ffd;
    char *result = NULL;
    struct flb_lib_out_cb cb_data;
    char *input = JSON_MSG1;
    char finalString[32768] = "";
    const char *expected = "\"value\":20.0,\"labels\":[\"red\",\"right\"]";

    ctx = flb_create();
    flb_service_set(ctx, "Flush", "0.200000000", "Grace", "1", "Log_Level",
                    "error", NULL);

    cb_data.cb = callback_test;
    cb_data.data = NULL;

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    filter_ffd = flb_filter(ctx, (char *) "log_to_metrics", NULL);
    TEST_CHECK(filter_ffd >= 0);
    ret = flb_filter_set(ctx, filter_ffd,
                         "Match", "*",
                         "Tag", "test_metric",
                         "metric_mode", "gauge",
                         "metric_name", "test",
                         "metric_description", "Reports gauge from messages",
                         "metric_subsystem", "",
                         "kubernetes_mode", "off",
                         "value_field", "duration",
                         "label_field", "color",
                         "label_field", "direction",
                         NULL);

    out_ffd = flb_output(ctx, (char *) "lib", (void *)&cb_data);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd,
                   "match", "*",
                   "format", "json",
                   NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    flb_lib_push(ctx, in_ffd, input, strlen(input));

    wait_with_timeout(2000, finalString);
    result = strstr(finalString, expected);
    if (!TEST_CHECK(result != NULL)) {
        TEST_MSG("expected substring:\n%s\ngot:\n%s\n", expected, finalString);
    }

    filter_test_destroy(ctx);

}


void flb_test_log_to_metrics_histogram(void)
{
    int ret;
    int i;
    flb_ctx_t *ctx;
    int in_ffd;
    int filter_ffd;
    int out_ffd;
    char *result = NULL;
    struct flb_lib_out_cb cb_data;
    char *input = JSON_MSG1;
    char finalString[32768] = "";
    const char *expected = "\"histogram\":{\"buckets\":" \
                           "[0,0,0,0,0,0,0,0,0,0,0,5],\"" \
                           "sum\":100.0,\"count\":5},\"" \
                           "labels\":[\"red\",\"right\"]";
    ctx = flb_create();
    flb_service_set(ctx, "Flush", "0.200000000", "Grace", "1", "Log_Level",
                    "error", NULL);

    cb_data.cb = callback_test;
    cb_data.data = NULL;

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    filter_ffd = flb_filter(ctx, (char *) "log_to_metrics", NULL);
    TEST_CHECK(filter_ffd >= 0);
    ret = flb_filter_set(ctx, filter_ffd,
                         "Match", "*",
                         "Tag", "test_metric",
                         "metric_mode", "histogram",
                         "metric_name", "test",
                         "metric_description", "Histogram of duration",
                         "metric_subsystem", "",
                         "kubernetes_mode", "off",
                         "value_field", "duration",
                         "label_field", "color",
                         "label_field", "direction",
                         NULL);

    out_ffd = flb_output(ctx, (char *) "lib", (void *)&cb_data);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd,
                   "match", "*",
                   "format", "json",
                   NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    for(i = 0; i < 5; i++){
        flb_lib_push(ctx, in_ffd, input, strlen(input));
    }

    wait_with_timeout(2000, finalString);
    result = strstr(finalString, expected);
    if (!TEST_CHECK(result != NULL)) {
        TEST_MSG("expected substring:\n%s\ngot:\n%s\n", expected, finalString);
    }
    filter_test_destroy(ctx);

}

void flb_test_log_to_metrics_reg(void)
{
    int ret;
    int i;
    flb_ctx_t *ctx;
    int in_ffd;
    int filter_ffd;
    int out_ffd;
    char *result = NULL;
    struct flb_lib_out_cb cb_data;
    char *input1 = JSON_MSG1;
    char *input2 = JSON_MSG3;
    char finalString[32768] = "";
    const char *expected = "\"value\":3.0,\"labels\":[\"red\",\"left\"]";


    ctx = flb_create();
    flb_service_set(ctx, "Flush", "0.200000000", "Grace", "1", "Log_Level",
                    "error", NULL);

    cb_data.cb = callback_test;
    cb_data.data = NULL;

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    filter_ffd = flb_filter(ctx, (char *) "log_to_metrics", NULL);
    TEST_CHECK(filter_ffd >= 0);
    ret = flb_filter_set(ctx, filter_ffd,
                         "Match", "*",
                         "Tag", "test_metric",
                         "metric_mode", "counter",
                         "metric_name", "test",
                         "metric_description", "Counts messages with regex",
                         "metric_subsystem", "",
                         "kubernetes_mode", "off",
                         "label_field", "color",
                         "label_field", "direction",
                         "regex", "message .*el.*",
                         NULL);

    out_ffd = flb_output(ctx, (char *) "lib", (void *)&cb_data);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd,
                   "match", "*",
                   "format", "json",
                   NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);


    for (i = 0; i < 3; i++){
        flb_lib_push(ctx, in_ffd, input1, strlen(input1));
        flb_lib_push(ctx, in_ffd, input2, strlen(input2));
    }
    wait_with_timeout(2000, finalString);
    result = strstr(finalString, expected);
    if (!TEST_CHECK(result != NULL)) {
        TEST_MSG("expected substring:\n%s\ngot:\n%s\n", expected, finalString);
    }

    filter_test_destroy(ctx);

}

void flb_test_log_to_metrics_empty_label_keys_regex(void)
{
    int ret;
    int i;
    flb_ctx_t *ctx;
    int in_ffd;
    int filter_ffd;
    int out_ffd;
    char *result = NULL;
    struct flb_lib_out_cb cb_data;
    char *input = JSON_MSG3;
    char finalString[32768] = "";
    const char *expected = "\"value\":3.0,";


    ctx = flb_create();
    flb_service_set(ctx, "Flush", "0.200000000", "Grace", "1", "Log_Level",
                    "error", NULL);

    cb_data.cb = callback_test;
    cb_data.data = NULL;

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    filter_ffd = flb_filter(ctx, (char *) "log_to_metrics", NULL);
    TEST_CHECK(filter_ffd >= 0);
    ret = flb_filter_set(ctx, filter_ffd,
                         "Match", "*",
                         "Tag", "test_metric",
                         "metric_mode", "counter",
                         "metric_name", "test",
                         "metric_description", "Counts messages with regex",
                         "metric_subsystem", "",
                         "kubernetes_mode", "off",
                         "regex", "message .*el.*",
                         NULL);

    out_ffd = flb_output(ctx, (char *) "lib", (void *)&cb_data);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd,
                   "match", "*",
                   "format", "json",
                   NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);


    for (i = 0; i < 3; i++){
        flb_lib_push(ctx, in_ffd, input, strlen(input));
    }
    wait_with_timeout(2000, finalString);
    result = strstr(finalString, expected);
    if (!TEST_CHECK(result != NULL)) {
        TEST_MSG("expected substring:\n%s\ngot:\n%s\n", expected, finalString);
    }

    filter_test_destroy(ctx);
}

void flb_test_log_to_metrics_label(void)
{
    int ret;
    int i;
    flb_ctx_t *ctx;
    int in_ffd;
    int filter_ffd;
    int out_ffd;
    char *result = NULL;
    struct flb_lib_out_cb cb_data;
    char *input = JSON_MSG1;
    char finalString[32768] = "";
    const char *expected_label_name = ",\"labels\":[\"pod_name\"],";
    const char *expected_label_value = "\"value\":2.0,\"labels\":[\"testpod\"]";

    ctx = flb_create();
    flb_service_set(ctx, "Flush", "0.200000000", "Grace", "1", "Log_Level",
                    "error", NULL);

    cb_data.cb = callback_test;
    cb_data.data = NULL;

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    filter_ffd = flb_filter(ctx, (char *) "log_to_metrics", NULL);
    TEST_CHECK(filter_ffd >= 0);
    ret = flb_filter_set(ctx, filter_ffd,
                         "Match", "*",
                         "Tag", "test_metric",
                         "metric_mode", "counter",
                         "metric_name", "test",
                         "metric_description", "Counts messages",
                         "metric_subsystem", "",
                         "kubernetes_mode", "off",
                         "add_label", "pod_name $kubernetes['pod_name']",
                         NULL);

    out_ffd = flb_output(ctx, (char *) "lib", (void *)&cb_data);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd,
                   "match", "*",
                   "format", "json",
                   NULL);
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    for (i = 0; i < 2; i++){
        flb_lib_push(ctx, in_ffd, input, strlen(input));
    }
    wait_with_timeout(2000, finalString);
    result = strstr(finalString, expected_label_name);
    if (!TEST_CHECK(result != NULL)) {
        TEST_MSG("expected substring:\n%s\ngot:\n%s\n", expected_label_name, finalString);
    }
    result = strstr(finalString, expected_label_value);
    if (!TEST_CHECK(result != NULL)) {
        TEST_MSG("expected substring:\n%s\ngot:\n%s\n", expected_label_value, finalString);
    }
    filter_test_destroy(ctx);
}
