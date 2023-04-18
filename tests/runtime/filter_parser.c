/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_parser.h>
#include "flb_tests_runtime.h"

#define FLUSH_INTERVAL "1.0"

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

void clear_output()
{
    pthread_mutex_lock(&result_mutex);
    output = NULL;
    pthread_mutex_unlock(&result_mutex);
}

int callback_test(void* data, size_t size, void* cb_data)
{
    if (size > 0) {
        flb_debug("[test_filter_parser] received message: %s", (char*)data);
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

        if (elapsed_time_flb > timeout_ms) {
            flb_warn("[timeout] elapsed_time: %ld", elapsed_time_flb);
            // Reached timeout.
            break;
        }
    }
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

    clear_output();

    ctx = flb_create();

    /* Configure service */
    flb_service_set(ctx, "Flush", FLUSH_INTERVAL, "Grace" "1", "Log_Level", "debug", NULL);

    /* Input */
    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd,
                  "Tag", "test",
                  NULL);

    /* Parser */
    parser = flb_parser_create("dummy_test", "regex", "^(?<INT>[^ ]+) (?<FLOAT>[^ ]+) (?<BOOL>[^ ]+) (?<STRING>.+)$",
                               FLB_TRUE,
                               NULL, NULL, NULL, MK_FALSE, MK_TRUE, FLB_FALSE, NULL, 0,
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

    wait_with_timeout(2000, &output); /* waiting flush and ensuring data flush */
    TEST_CHECK_(output != NULL, "Expected output to not be NULL");
    if (output != NULL) {
        /* check timestamp */
        expected = "[1448403340.000000,{";
        TEST_CHECK_(strstr(output, expected) != NULL, "Expected output to contain '%s', got '%s'", expected, output);
        /* check fields were extracted */
        expected = "\"INT\":\"100\",\"FLOAT\":\"0.5\",\"BOOL\":\"true\",\"STRING\":\"This is an example\"";
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

    clear_output();

    ctx = flb_create();

    /* Configure service */
    flb_service_set(ctx, "Flush", FLUSH_INTERVAL, "Grace", "1", "Log_Level", "debug", NULL);

    /* Input */
    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd,
                  "Tag", "test",
                  NULL);

    /* Parser */
    parser = flb_parser_create("dummy_test", "regex", "^(?<INT>[^ ]+) (?<FLOAT>[^ ]+) (?<BOOL>[^ ]+) (?<STRING>.+)$",
                               FLB_TRUE,
                               NULL, NULL, NULL, MK_FALSE, MK_TRUE, FLB_FALSE, NULL, 0,
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
    p = "[1448403340,{\"data\":\"100 0.5 true This is an example\",\"extra\":\"Some more data\"}]";
    bytes = flb_lib_push(ctx, in_ffd, p, strlen(p));
    TEST_CHECK(bytes == strlen(p));

    wait_with_timeout(2000, &output); /* waiting flush and ensuring data flush */
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

    clear_output();

    ctx = flb_create();

    /* Configure service */
    flb_service_set(ctx, "Flush", FLUSH_INTERVAL, "Grace", "1", "Log_Level", "debug", NULL);

    /* Input */
    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd,
                  "Tag", "test",
                  NULL);

    /* Parser */
    parser = flb_parser_create("timestamp", "regex", "^(?<time>.*)$", FLB_TRUE,
                               "%Y-%m-%dT%H:%M:%S.%L",
                               "time",
                               NULL, MK_FALSE, MK_TRUE, FLB_FALSE,
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

    wait_with_timeout(2000, &output); /* waiting flush and ensuring data flush */
    TEST_CHECK_(output != NULL, "Expected output to not be NULL");
    if (output != NULL) {
        /* check the timestamp field was updated correctly */
        /* this is in fluent-bits extended timestamp format */
        expected = "[1509575121.648000,{";
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

    clear_output();

    ctx = flb_create();

    /* Configure service */
    flb_service_set(ctx, "Flush", FLUSH_INTERVAL, "Grace", "1", "Log_Level", "debug", NULL);

    /* Input */
    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd,
                  "Tag", "test",
                  NULL);

    /* Parser */
    parser = flb_parser_create("timestamp", "regex", "^(?<time>.*)$", FLB_TRUE,
                               "%s.%L",
                               "time",
                               NULL, MK_FALSE, MK_TRUE, FLB_FALSE,
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

    wait_with_timeout(2000, &output); /* waiting flush and ensuring data flush */
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

void flb_test_filter_parser_handle_time_key_with_time_zone()
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

    clear_output();

    ctx = flb_create();

    /* Configure service */
    flb_service_set(ctx, "Flush", FLUSH_INTERVAL, "Grace", "1", "Log_Level", "debug", NULL);

    /* Input */
    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd,
                  "Tag", "test",
                  NULL);

    /* Parser */
    parser = flb_parser_create("timestamp", // name
                               "regex", // format
                               "^(?<time>.*)$", // regex
                               FLB_TRUE, // skip_empty
                               "%Y-%m-%dT%H:%M:%S.%L %z", // time_fmt
                               "time", // time_key
                               NULL, // time_offset
                               MK_FALSE, // time_keep
                               MK_TRUE, // time_strict
                               MK_FALSE, // logfmt_no_bare_keys
                               NULL, // types
                               0, // types_len
                               NULL, // decoders
                               ctx->config); // config
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
    p = "[1448403340, {\"@timestamp\":\"2017-11-01T22:25:21.648-04:00\", \"message\":\"This is an example\"}]";
    bytes = flb_lib_push(ctx, in_ffd, p, strlen(p));
    TEST_CHECK(bytes == strlen(p));

    wait_with_timeout(2000, &output); /* waiting flush and ensuring data flush */
    TEST_CHECK_(output != NULL, "Expected output to not be NULL");
    if (output != NULL) {
        /* check the timestamp field was updated correctly */
        /* this is in fluent-bits extended timestamp format */
        expected = "[1509589521.648000,{";
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

    clear_output();

    ctx = flb_create();

    /* Configure service */
    flb_service_set(ctx, "Flush", FLUSH_INTERVAL, "Grace", "1", "Log_Level", "debug", NULL);

    /* Input */
    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd,
                  "Tag", "test",
                  NULL);

    /* Parser */
    parser = flb_parser_create("timestamp", "regex",
                               "^(?<time>.*)$", FLB_TRUE,
                               "%Y-%m-%dT%H:%M:%S.%L", "time",
                               NULL, FLB_FALSE, MK_TRUE, FLB_FALSE,
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

    wait_with_timeout(2000, &output); /* waiting flush and ensuring data flush */
    TEST_CHECK_(output != NULL, "Expected output to not be NULL");
    if (output != NULL) {
        /* check the timestamp field was ignored and we received everything else */
        expected = "[1448403340.000000,{\"@timestamp\":\"2017_$!^-11-01T22:25:21.648\",\"log\":\"An example\"}]";
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

    clear_output();

    ctx = flb_create();

    /* Configure service */
    flb_service_set(ctx, "Flush", FLUSH_INTERVAL, "Grace", "1", "Log_Level", "debug", NULL);

    /* Input */
    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd,
                  "Tag", "test",
                  NULL);

    /* Parser */
    parser = flb_parser_create("dummy_test", "regex", "^(?<INT>[^ ]+) (?<FLOAT>[^ ]+) (?<BOOL>[^ ]+) (?<STRING>.+)$",
                               FLB_TRUE,
                               NULL, NULL, NULL, MK_FALSE, MK_TRUE, FLB_FALSE, NULL, 0,
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
    p = "[1448403340,{\"data\":\"100 0.5 true This is an example\",\"log\":\"An example\"}]";
    bytes = flb_lib_push(ctx, in_ffd, p, strlen(p));
    TEST_CHECK(bytes == strlen(p));

    wait_with_timeout(2000, &output); /* waiting flush and ensuring data flush */
    TEST_CHECK_(output != NULL, "Expected output to not be NULL");
    if (output != NULL) {
        /* check original field is preserved */
        expected = "\"data\":\"100 0.5 true This is an example\"";
        TEST_CHECK_(strstr(output, expected) != NULL, "Expected output to contain '%s', got '%s'", expected, output);
        /* check fields were extracted */
        expected = "\"INT\":\"100\",\"FLOAT\":\"0.5\",\"BOOL\":\"true\",\"STRING\":\"This is an example\"";
        TEST_CHECK_(strstr(output, expected) != NULL, "Expected output to contain '%s', got '%s'", expected, output);
        /* check other fields are preserved */
        expected = "\"log\":\"An example\"";
        TEST_CHECK_(strstr(output, expected) != NULL, "Expected output to contain '%s', got '%s'", expected, output);
        free(output);
    }

    flb_stop(ctx);
    flb_destroy(ctx);
}

// https://github.com/fluent/fluent-bit/issues/2250
void flb_test_filter_parser_first_matched_when_mutilple_parser()
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

    clear_output();

    ctx = flb_create();

    /* Configure service */
    flb_service_set(ctx, "Flush", FLUSH_INTERVAL, "Grace" "1", "Log_Level", "debug", NULL);

    /* Input */
    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd,
                  "Tag", "test",
                  NULL);

    /* Parser */
    parser = flb_parser_create("one", "regex", "^(?<one>.+?)$",
                               FLB_TRUE,
                               NULL, NULL, NULL, MK_FALSE, MK_TRUE, FLB_FALSE,
                               NULL, 0, NULL, ctx->config);
    TEST_CHECK(parser != NULL);

    parser = flb_parser_create("two", "regex", "^(?<two>.+?)$",
                               FLB_TRUE,
                               NULL, NULL, NULL, MK_FALSE, MK_TRUE, FLB_FALSE,
                               NULL, 0, NULL, ctx->config);
    TEST_CHECK(parser != NULL);

    /* Filter */
    filter_ffd = flb_filter(ctx, (char *) "parser", NULL);
    TEST_CHECK(filter_ffd >= 0);
    ret = flb_filter_set(ctx, filter_ffd,
                         "Match", "test",
                         "Key_Name", "data",
                         "Parser", "one",
                         "Parser", "two",
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
    p = "[1,{\"data\":\"hoge\"}]";
    bytes = flb_lib_push(ctx, in_ffd, p, strlen(p));
    TEST_CHECK(bytes == strlen(p));

    wait_with_timeout(2000, &output); /* waiting flush and ensuring data flush */
    TEST_CHECK_(output != NULL, "Expected output to not be NULL");
    if (output != NULL) {
        /* check extra data was not preserved */
        expected = "\"one\":\"hoge\",\"data\":\"hoge\"";
        TEST_CHECK_(strstr(output, expected) != NULL, "Expected output to contain key one , got '%s'", output);
        free(output);
    }

    flb_stop(ctx);
    flb_destroy(ctx);
}

// https://github.com/fluent/fluent-bit/issues/1486
// https://github.com/fluent/fluent-bit/issues/2939
void flb_test_filter_parser_skip_empty_values_false()
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

    clear_output();

    ctx = flb_create();

    /* Configure service */
    flb_service_set(ctx, "Flush", FLUSH_INTERVAL, "Grace" "1", "Log_Level", "debug", NULL);

    /* Input */
    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd,
                  "Tag", "test",
                  NULL);

    /* Parser */
    parser = flb_parser_create("one", "regex", "^(?<one>.+?)$",
                               FLB_FALSE,
                               NULL, NULL, NULL, MK_FALSE, MK_TRUE, FLB_FALSE,
                               NULL, 0, NULL, ctx->config);
    TEST_CHECK(parser != NULL);

    /* Filter */
    filter_ffd = flb_filter(ctx, (char *) "parser", NULL);
    TEST_CHECK(filter_ffd >= 0);
    ret = flb_filter_set(ctx, filter_ffd,
                         "Match", "test",
                         "Key_Name", "data",
                         "Parser", "one",
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
    p = "[1,{\"data\":\"\"}]";
    bytes = flb_lib_push(ctx, in_ffd, p, strlen(p));
    TEST_CHECK(bytes == strlen(p));

    wait_with_timeout(1500, &output); /* waiting flush and ensuring data flush */
    TEST_CHECK_(output != NULL, "Expected output to not be NULL");
    if (output != NULL) {
        /* check extra data was not preserved */
        expected = "\"data\":\"\"";
        TEST_CHECK_(strstr(output, expected) != NULL, "Expected output to contain key one , got '%s'", output);
        free(output);
    }

    flb_stop(ctx);
    flb_destroy(ctx);
}


TEST_LIST = {
    {"filter_parser_extract_fields", flb_test_filter_parser_extract_fields },
    {"filter_parser_reserve_data_off", flb_test_filter_parser_reserve_data_off },
    {"filter_parser_handle_time_key", flb_test_filter_parser_handle_time_key },
    {"filter_parser_handle_time_key_with_time_zone", flb_test_filter_parser_handle_time_key_with_time_zone },
    {"filter_parser_ignore_malformed_time", flb_test_filter_parser_ignore_malformed_time },
    {"filter_parser_preserve_original_field", flb_test_filter_parser_preserve_original_field },
    {"filter_parser_first_matched_when_multiple_parser", flb_test_filter_parser_first_matched_when_mutilple_parser },
    {"filter_parser_skip_empty_values_false", flb_test_filter_parser_skip_empty_values_false},
    {NULL, NULL}
};

