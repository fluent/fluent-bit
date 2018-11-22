/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit.h>
#include <fluent-bit/flb_parser.h>
#include "flb_tests_runtime.h"

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

int callback_test(void* data, size_t size, void* cb_data)
{
    if (size > 0) {
        flb_debug("[test_filter_parser] received message: %s", data);
        set_output(data); /* success */
    }
    return 0;
}

void flb_test_filter_parser_extract_fields()
{
    int ret;
    int bytes;
    char *p, *output, *expected;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    int filter_ffd;
    struct flb_parser *parser;

    struct flb_lib_out_cb cb;
    cb.cb   = callback_test;
    cb.data = NULL;

    ctx = flb_create();

    /* Configure service */
    flb_service_set(ctx, "Flush", "1", "Grace" "1", "Log_Level", "debug", NULL);

    /* Input */
    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd,
                  "Tag", "test",
                  NULL);

    /* Parser */
    parser = flb_parser_create("dummy_test", "regex", "^(?<INT>[^ ]+) (?<FLOAT>[^ ]+) (?<BOOL>[^ ]+) (?<STRING>.+)$",
                               NULL, NULL, NULL, MK_FALSE, NULL, 0,
                               NULL, ctx->config);
    TEST_CHECK(parser != NULL);

    /* Filter */
    filter_ffd = flb_filter(ctx, (char *) "parser", NULL);
    TEST_CHECK(filter_ffd >= 0);
    ret = flb_filter_set(ctx, filter_ffd,
                         "Match", "test",
                         "Key_Name", "data",
                         "Parser", "dummy_test",
                         "Reserve_Data", "On",
                         "Preserve_Key", "Off",
                         NULL);
    TEST_CHECK(ret == 0);

    /* Output */
    out_ffd = flb_output(ctx, (char *) "lib", &cb);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd,
                   "Match", "*",
                   "format", "json",
                   NULL);

    /* Start the engine */
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Ingest data */
    p = "[1448403340, {\"data\":\"100 0.5 true This is an example\", \"extra\":\"Some more data\"}]";
    bytes = flb_lib_push(ctx, in_ffd, p, strlen(p));
    TEST_CHECK(bytes == strlen(p));

    sleep(1); /* waiting flush */
    output = get_output(); /* 1sec passed, data should be flushed */
    TEST_CHECK_(output != NULL, "Expected output to not be NULL");
    if (output != NULL) {
        /* check timestamp */
        expected = "[1448403340.000000, {";
        TEST_CHECK_(strstr(output, expected) != NULL, "Expected output to contain '%s', got '%s'", expected, output);
        /* check fields were extracted */
        expected = "\"INT\":\"100\", \"FLOAT\":\"0.5\", \"BOOL\":\"true\", \"STRING\":\"This is an example\"";
        TEST_CHECK_(strstr(output, expected) != NULL, "Expected output to contain '%s', got '%s'", expected, output);
        /* check original field was not preserved */
        expected = "\"data\":\"100 0.5 true This is an example\"";
        TEST_CHECK_(strstr(output, expected) == NULL, "Expected output to not contain '%s', got '%s'", expected, output);
        /* check extra data was preserved */
        expected = "\"extra\":\"Some more data\"";
        TEST_CHECK_(strstr(output, expected) != NULL, "Expected output to preserve extra field, got '%s'", output);
        free(output);
    }

    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_filter_parser_reserve_data_off()
{
    int ret;
    int bytes;
    char *p, *output, *expected;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    int filter_ffd;
    struct flb_parser *parser;

    struct flb_lib_out_cb cb;
    cb.cb   = callback_test;
    cb.data = NULL;

    ctx = flb_create();

    /* Configure service */
    flb_service_set(ctx, "Flush", "1", "Grace", "1", "Log_Level", "debug", NULL);

    /* Input */
    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd,
                  "Tag", "test",
                  NULL);

    /* Parser */
    parser = flb_parser_create("dummy_test", "regex", "^(?<INT>[^ ]+) (?<FLOAT>[^ ]+) (?<BOOL>[^ ]+) (?<STRING>.+)$",
                               NULL, NULL, NULL, MK_FALSE, NULL, 0,
                               NULL, ctx->config);
    TEST_CHECK(parser != NULL);

    /* Filter */
    filter_ffd = flb_filter(ctx, (char *) "parser", NULL);
    TEST_CHECK(filter_ffd >= 0);
    ret = flb_filter_set(ctx, filter_ffd,
                         "Match", "test",
                         "Key_Name", "data",
                         "Parser", "dummy_test",
                         "Reserve_Data", "Off",
                         NULL);
    TEST_CHECK(ret == 0);

    /* Output */
    out_ffd = flb_output(ctx, (char *) "lib", &cb);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd,
                   "Match", "*",
                   "format", "json",
                   NULL);

    /* Start the engine */
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Ingest data */
    p = "[1448403340, {\"data\":\"100 0.5 true This is an example\", \"extra\":\"Some more data\"}]";
    bytes = flb_lib_push(ctx, in_ffd, p, strlen(p));
    TEST_CHECK(bytes == strlen(p));

    sleep(1); /* waiting flush */
    output = get_output(); /* 1sec passed, data should be flushed */
    TEST_CHECK_(output != NULL, "Expected output to not be NULL");
    if (output != NULL) {
        /* check extra data was not preserved */
        expected = "\"extra\":\"Some more data\"";
        TEST_CHECK_(strstr(output, expected) == NULL, "Expected output to not preserve extra field, got '%s'", output);
        free(output);
    }

    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_filter_parser_handle_time_key()
{
    int ret;
    int bytes;
    char *p, *output, *expected;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    int filter_ffd;
    struct flb_parser *parser;

    struct flb_lib_out_cb cb;
    cb.cb   = callback_test;
    cb.data = NULL;

    ctx = flb_create();

    /* Configure service */
    flb_service_set(ctx, "Flush", "1", "Grace", "1", "Log_Level", "debug", NULL);

    /* Input */
    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd,
                  "Tag", "test",
                  NULL);

    /* Parser */
    parser = flb_parser_create("timestamp", "regex", "^(?<time>.*)$", "%Y-%m-%dT%H:%M:%S.%L",
                               "time",
                               NULL, MK_FALSE,
                               NULL, 0, NULL, ctx->config);
    TEST_CHECK(parser != NULL);

    /* Filter */
    filter_ffd = flb_filter(ctx, (char *) "parser", NULL);
    TEST_CHECK(filter_ffd >= 0);
    ret = flb_filter_set(ctx, filter_ffd,
                         "Match", "test",
                         "Key_Name", "@timestamp",
                         "Parser", "timestamp",
                         "Reserve_Data", "On",
                         NULL);
    TEST_CHECK(ret == 0);

    /* Output */
    out_ffd = flb_output(ctx, (char *) "lib", &cb);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd,
                   "Match", "*",
                   "format", "json",
                   NULL);

    /* Start the engine */
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Ingest data */
    p = "[1448403340, {\"@timestamp\":\"2017-11-01T22:25:21.648+00:00\", \"message\":\"This is an example\"}]";
    bytes = flb_lib_push(ctx, in_ffd, p, strlen(p));
    TEST_CHECK(bytes == strlen(p));

    sleep(1); /* waiting flush */
    output = get_output(); /* 1sec passed, data should be flushed */
    TEST_CHECK_(output != NULL, "Expected output to not be NULL");
    if (output != NULL) {
        /* check the timestamp field was updated correctly */
        /* this is in fluent-bits extended timestamp format */
        expected = "[1509575121.648000, {";
        TEST_CHECK_(strstr(output, expected) != NULL, "Expected output to contain '%s', got '%s'", expected, output);
        /* check additional field is preserved */
        expected = "\"message\":\"This is an example\"";
        TEST_CHECK_(strstr(output, expected) != NULL, "Expected output to contain '%s', got '%s'", expected, output);
        free(output);
    }

    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_filter_parser_handle_time_key_with_fractional_timestamp()
{
    int ret;
    int bytes;
    char *p, *output, *expected;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    int filter_ffd;
    struct flb_parser *parser;

    ctx = flb_create();

    /* Configure service */
    flb_service_set(ctx, "Flush", "1", "Grace", "1", "Log_Level", "debug", NULL);

    /* Input */
    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd,
                  "Tag", "test",
                  NULL);

    /* Parser */
    parser = flb_parser_create("timestamp", "regex", "^(?<time>.*)$", "%s.%L",
                               "time",
                               NULL, MK_FALSE,
                               NULL, 0, NULL, ctx->config);
    TEST_CHECK(parser != NULL);

    /* Filter */
    filter_ffd = flb_filter(ctx, (char *) "parser", NULL);
    TEST_CHECK(filter_ffd >= 0);
    ret = flb_filter_set(ctx, filter_ffd,
                         "Match", "test",
                         "Key_Name", "@timestamp",
                         "Parser", "timestamp",
                         "Reserve_Data", "On",
                         NULL);
    TEST_CHECK(ret == 0);

    /* Output */
    out_ffd = flb_output(ctx, (char *) "lib", (void*)callback_test);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd,
                   "Match", "*",
                   "format", "json",
                   NULL);

    /* Start the engine */
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Ingest data */
    p = "[1448403340, {\"@timestamp\":\"1509575121.648\", \"message\":\"This is an example\"}]";
    bytes = flb_lib_push(ctx, in_ffd, p, strlen(p));
    TEST_CHECK(bytes == strlen(p));

    sleep(1); /* waiting flush */
    output = get_output(); /* 1sec passed, data should be flushed */
    TEST_CHECK_(output != NULL, "Expected output to not be NULL");
    if (output != NULL) {
        /* check the timestamp field was updated correctly */
        /* this is in fluent-bits extended timestamp format */
        expected = "[\"\\x59\\xfffffffa\\x49\\xffffffd1\\x26\\xffffff9f\\xffffffb2\\x00\", {";
        TEST_CHECK_(strstr(output, expected) != NULL, "Expected output to contain '%s', got '%s'", expected, output);
        /* check additional field is preserved */
        expected = "\"message\":\"This is an example\"";
        TEST_CHECK_(strstr(output, expected) != NULL, "Expected output to contain '%s', got '%s'", expected, output);
        free(output);
    }

    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_filter_parser_ignore_malformed_time()
{
    int ret;
    int bytes;
    char *p, *output, *expected;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    int filter_ffd;
    struct flb_parser *parser;

    struct flb_lib_out_cb cb;
    cb.cb   = callback_test;
    cb.data = NULL;

    ctx = flb_create();

    /* Configure service */
    flb_service_set(ctx, "Flush", "1", "Grace", "1", "Log_Level", "debug", NULL);

    /* Input */
    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd,
                  "Tag", "test",
                  NULL);

    /* Parser */
    parser = flb_parser_create("timestamp", "regex",
                               "^(?<time>.*)$", "%Y-%m-%dT%H:%M:%S.%L", "time",
                               NULL, FLB_FALSE,
                               NULL, 0, NULL, ctx->config);
    TEST_CHECK(parser != NULL);

    /* Filter */
    filter_ffd = flb_filter(ctx, (char *) "parser", NULL);
    TEST_CHECK(filter_ffd >= 0);
    ret = flb_filter_set(ctx, filter_ffd,
                         "Match", "test",
                         "Key_Name", "@timestamp",
                         "Parser", "timestamp",
                         "Reserve_Data", "On",
                         "Preserve_Key", "On",
                         NULL);
    TEST_CHECK(ret == 0);

    /* Output */
    out_ffd = flb_output(ctx, (char *) "lib", &cb);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd,
                   "Match", "*",
                   "format", "json",
                   NULL);

    /* Start the engine */
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Ingest data */
    p = "[1448403340, {\"@timestamp\":\"2017_$!^-11-01T22:25:21.648\", \"log\":\"An example\"}]";
    bytes = flb_lib_push(ctx, in_ffd, p, strlen(p));
    TEST_CHECK(bytes == strlen(p));

    sleep(1); /* waiting flush */
    output = get_output(); /* 1sec passed, data should be flushed */
    TEST_CHECK_(output != NULL, "Expected output to not be NULL");
    if (output != NULL) {
        /* check the timestamp field was ignored and we received everything else */
        expected = "[1448403340.000000, {\"@timestamp\":\"2017_$!^-11-01T22:25:21.648\", \"log\":\"An example\"}]";
        TEST_CHECK_(strcmp(output, expected) == 0, "Expected output to be '%s', got '%s'", expected, output);
        free(output);
    }

    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_filter_parser_preserve_original_field()
{
    int ret;
    int bytes;
    char *p, *output, *expected;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    int filter_ffd;
    struct flb_parser *parser;

    struct flb_lib_out_cb cb;
    cb.cb   = callback_test;
    cb.data = NULL;

    ctx = flb_create();

    /* Configure service */
    flb_service_set(ctx, "Flush", "1", "Grace", "1", "Log_Level", "debug", NULL);

    /* Input */
    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd,
                  "Tag", "test",
                  NULL);

    /* Parser */
    parser = flb_parser_create("dummy_test", "regex", "^(?<INT>[^ ]+) (?<FLOAT>[^ ]+) (?<BOOL>[^ ]+) (?<STRING>.+)$",
                               NULL, NULL, NULL, MK_FALSE, NULL, 0,
                               NULL, ctx->config);
    TEST_CHECK(parser != NULL);

    /* Filter */
    filter_ffd = flb_filter(ctx, (char *) "parser", NULL);
    TEST_CHECK(filter_ffd >= 0);
    ret = flb_filter_set(ctx, filter_ffd,
                         "Match", "test",
                         "Key_Name", "data",
                         "Parser", "dummy_test",
                         "Reserve_Data", "On",
                         "Preserve_Key", "On",
                         NULL);
    TEST_CHECK(ret == 0);

    /* Output */
    out_ffd = flb_output(ctx, (char *) "lib", &cb);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd,
                   "Match", "*",
                   "format", "json",
                   NULL);

    /* Start the engine */
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Ingest data */
    p = "[1448403340, {\"data\":\"100 0.5 true This is an example\", \"log\":\"An example\"}]";
    bytes = flb_lib_push(ctx, in_ffd, p, strlen(p));
    TEST_CHECK(bytes == strlen(p));

    sleep(1); /* waiting flush */
    output = get_output(); /* 1sec passed, data should be flushed */
    TEST_CHECK_(output != NULL, "Expected output to not be NULL");
    if (output != NULL) {
        /* check original field is preserved */
        expected = "\"data\":\"100 0.5 true This is an example\"";
        TEST_CHECK_(strstr(output, expected) != NULL, "Expected output to contain '%s', got '%s'", expected, output);
        /* check fields were extracted */
        expected = "\"INT\":\"100\", \"FLOAT\":\"0.5\", \"BOOL\":\"true\", \"STRING\":\"This is an example\"";
        TEST_CHECK_(strstr(output, expected) != NULL, "Expected output to contain '%s', got '%s'", expected, output);
        /* check other fields are preserved */
        expected = "\"log\":\"An example\"";
        TEST_CHECK_(strstr(output, expected) != NULL, "Expected output to contain '%s', got '%s'", expected, output);
        free(output);
    }

    flb_stop(ctx);
    flb_destroy(ctx);
}

TEST_LIST = {
    {"filter_parser_extract_fields", flb_test_filter_parser_extract_fields },
    {"filter_parser_reserve_data_off", flb_test_filter_parser_reserve_data_off },
    {"filter_parser_handle_time_key", flb_test_filter_parser_handle_time_key },
    {"filter_parser_ignore_malformed_time", flb_test_filter_parser_ignore_malformed_time },
    {"filter_parser_preserve_original_field", flb_test_filter_parser_preserve_original_field },
    {NULL, NULL}
};
