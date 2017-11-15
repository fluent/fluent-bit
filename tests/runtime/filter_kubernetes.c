/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit.h>
#include "flb_tests_runtime.h"

/* Test data */

/* Test functions */
void flb_test_filter_kubernetes_merged_json(void);
void flb_test_filter_kubernetes_merged_json_with_invalid_json(void);

/* Test list */
TEST_LIST = {
    {"kubernetes_merged_json", flb_test_filter_kubernetes_merged_json },
    {"kubernetes_merged_json_with_invalid_json", flb_test_filter_kubernetes_merged_json_with_invalid_json },
    {NULL, NULL}
};

pthread_mutex_t result_mutex = PTHREAD_MUTEX_INITIALIZER;
char *output = NULL;

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

int callback_test(void* data, size_t size)
{
    if (size > 0) {
        flb_debug("[test_filter_kubernetes] received message: %s", data);
        set_output(data); /* success */
    }
    return 0;
}

void flb_test_filter_kubernetes_merged_json(void)
{
    int ret;
    int bytes;
    char *p, *output, *expected;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    int filter_ffd;

    ctx = flb_create();

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "Tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "lib", (void*)callback_test);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "Match", "*", "format", "json", NULL);

    flb_service_set(ctx, "Flush", "1", "Log_Level", "debug", NULL);

    filter_ffd = flb_filter(ctx, (char *) "kubernetes", NULL);
    TEST_CHECK(filter_ffd >= 0);
    ret = flb_filter_set(ctx, filter_ffd, "Match", "test", "dummy_meta", "true", "Merge_JSON_Log", "On", NULL);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    p = "[1448403340, {\"log\":\"{\\\"@timestamp\\\":\\\"2017-11-01T22:25:21.648+00:00\\\",\\\"message\\\":\\\"Started admin@53830483{HTTP/1.1,[http/1.1]}{0.0.0.0:8081}\\\",\\\"logger_name\\\":\\\"org.eclipse.jetty.server.AbstractConnector\\\",\\\"thread_name\\\":\\\"main\\\",\\\"level\\\":\\\"INFO\\\",\\\"level_value\\\":20000}\\n\",\"stream\":\"stdout\",\"time\":\"2017-11-01 T22:25:21.648509972Z\"}]";
    bytes = flb_lib_push(ctx, in_ffd, p, strlen(p));
    TEST_CHECK(bytes == strlen(p));

    sleep(1); /* waiting flush */
    output = get_output(); /* 1sec passed, data should be flushed */
    TEST_CHECK_(output != NULL, "Expected output to not be NULL");
    if (output != NULL) {
        /* check the embedded json fields were merged */
        expected = "\"message\":\"Started admin@53830483{HTTP/1.1,[http/1.1]}{0.0.0.0:8081}\"";
        TEST_CHECK_(strstr(output, expected) != NULL, "Expected output to contain '%s', got '%s'", expected, output);
        expected = "\"logger_name\":\"org.eclipse.jetty.server.AbstractConnector\"";
        TEST_CHECK_(strstr(output, expected) != NULL, "Expected output to contain '%s', got '%s'", expected, output);
        expected = "\"level\":\"INFO\"";
        TEST_CHECK_(strstr(output, expected) != NULL, "Expected output to contain '%s', got '%s'", expected, output);
        free(output);
    }

    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_filter_kubernetes_merged_json_with_invalid_json(void)
{
    int ret;
    int bytes;
    char *p, *output, *expected;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    int filter_ffd;

    ctx = flb_create();

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "Tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "lib", (void*)callback_test);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "Match", "*", "format", "json", NULL);

    flb_service_set(ctx, "Flush", "1", "Log_Level", "debug", NULL);

    filter_ffd = flb_filter(ctx, (char *) "kubernetes", NULL);
    TEST_CHECK(filter_ffd >= 0);
    ret = flb_filter_set(ctx, filter_ffd, "Match", "test", "dummy_meta", "true", "Merge_JSON_Log", "On", NULL);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    p = "[1448403340, {\"log\":\"{no json here}\", \"stream\":\"stdout\", \"time\":\"2017-11-01 T22:25:21.648509972Z\"}]";
    bytes = flb_lib_push(ctx, in_ffd, p, strlen(p));
    TEST_CHECK(bytes == strlen(p));

    sleep(1); /* waiting flush */
    output = get_output(); /* 1sec passed, data should be flushed */
    TEST_CHECK_(output != NULL, "Expected output to not be NULL");
    if (output != NULL) {
        /* invalid json should be ignored and passed through as-is */
        expected = "\"log\":\"{no json here}\"";
        TEST_CHECK_(strstr(output, expected) != NULL, "Expected output to contain '%s', got '%s'", expected, output);
        free(output);
    }

    flb_stop(ctx);
    flb_destroy(ctx);
}
