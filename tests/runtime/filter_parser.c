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
                               NULL, NULL, NULL, MK_FALSE, MK_TRUE, FLB_FALSE, FLB_FALSE, NULL, 0,
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

void flb_test_filter_parser_record_accessor()
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
                               NULL, NULL, NULL, MK_FALSE, MK_TRUE, FLB_FALSE, FLB_FALSE, NULL, 0,
                               NULL, ctx->config);
    TEST_CHECK(parser != NULL);

    /* Filter */
    filter_ffd = flb_filter(ctx, (char *) "parser", NULL);
    TEST_CHECK(filter_ffd >= 0);
    ret = flb_filter_set(ctx, filter_ffd,
                         "Match", "test",
                         "Key_Name", "$log['data']",
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
    p = "[1448403340,{\"log\":{\"data\":\"100 0.5 true This is an example\"},\"extra\":\"Some more data\"}]";
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
        /* check original nested key */
        expected = "\"log\":{\"data\":\"100 0.5 true This is an example\"}";
        TEST_CHECK_(strstr(output, expected) != NULL, "Expected output to contain '%s', got '%s'", expected, output);
        /* check extra data preserved */
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
                               NULL, NULL, NULL, MK_FALSE, MK_TRUE, FLB_FALSE, FLB_FALSE, NULL, 0,
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
                               NULL, MK_FALSE, MK_TRUE, FLB_FALSE, FLB_FALSE,
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
                               NULL, MK_FALSE, MK_TRUE, FLB_FALSE, FLB_FALSE,
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
                               FLB_FALSE, // time_system_timezone
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

void test_parser_timestamp_timezone(char *tz,
                                  char *time_fmt,
                                  char *timestamp,
                                  char *expected_epoch,
                                  int use_system_timezone)
{
    int ret;
    int bytes;
    char *output, *original_tz = NULL;
    char *saved_tz = NULL;
    char p[256];
    char expected[256];
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    int filter_ffd;
    struct flb_parser *parser;
    struct flb_lib_out_cb *cb;

    /* Allocate and initialize callback */
    cb = flb_malloc(sizeof(struct flb_lib_out_cb));
    if (!cb) {
        flb_errno();
        return;
    }
    cb->cb = callback_test;
    cb->data = NULL;

    clear_output();

    /* Save current TZ if exists */
    original_tz = getenv("TZ");
    if (original_tz) {
        saved_tz = strdup(original_tz);
        if (!saved_tz) {
            flb_free(cb);
            return;
        }
    }

    /* Set new timezone if provided */
    if (tz) {
        ret = setenv("TZ", tz, 1);
        TEST_CHECK(ret == 0);
        tzset(); /* Make sure timezone changes take effect */
    }

    ctx = flb_create();
    TEST_CHECK(ctx != NULL);

    /* Configure service */
    flb_service_set(ctx,
                    "Flush", FLUSH_INTERVAL,
                    "Grace", "1",
                    "Log_Level", "debug",
                    NULL);

    /* Input */
    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd,
                  "Tag", "test",
                  NULL);

    /* Parser */
    parser = flb_parser_create("timestamp",
                             "regex",
                             "^(?<time>.*)$",
                             FLB_TRUE,
                             time_fmt,
                             "time",
                             NULL,
                             MK_FALSE,
                             MK_TRUE,
                             use_system_timezone,
                             MK_FALSE,
                             NULL, 0,
                             NULL,
                             ctx->config);
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
    out_ffd = flb_output(ctx, (char *) "lib", cb);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd,
                   "Match", "*",
                   "format", "json",
                   NULL);

    /* Start the engine */
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Ingest data */
    snprintf(p, sizeof(p), "[1448403340, {\"@timestamp\":\"%s\", \"message\":\"This is an example\"}]",
             timestamp);
    bytes = flb_lib_push(ctx, in_ffd, p, strlen(p));
    TEST_CHECK(bytes > 0);

    wait_with_timeout(2000, &output);
    TEST_CHECK(output != NULL);

    if (output != NULL) {
        snprintf(expected, sizeof(expected), "[%s", expected_epoch);
        TEST_CHECK_(strstr(output, expected) != NULL,
                   "Expected output to contain '%s', got '%s'", expected, output);
        free(output);
    }

    flb_stop(ctx);
    flb_destroy(ctx);
    flb_free(cb);

    /* Restore original timezone */
    if (saved_tz) {
        setenv("TZ", saved_tz, 1);
        free(saved_tz);
    } else if (original_tz == NULL) {
        unsetenv("TZ");
    }
    tzset();
}

void flb_test_filter_parser_use_system_timezone()
{
    int i;
    struct test_case {
        char *tz;
        char *timestamp;
        char *expected_epoch;
    } test_cases[] = {
        /* Confirm that daylight savings time is properly detected. */
        {"EST5EDT", "2023-02-14 12:00:00", "1676394000"}, /* Should be ST */
        {"EST5EDT", "2023-10-17 05:00:00", "1697533200"}, /* Should be DST */

        /* Examples from https://github.com/fluent/fluent-bit/issues/9197. */
        {"Europe/London", "2024-01-20 10:00:00", "1705744800"}, /* Should be ST */
        {"Europe/London", "2024-08-20 11:00:00", "1724148000"},

        {NULL, NULL, NULL}
    };

    for (i = 0; test_cases[i].tz != NULL; i++) {
        test_parser_timestamp_timezone(
            test_cases[i].tz,
            "%Y-%m-%d %H:%M:%S",
            test_cases[i].timestamp,
            test_cases[i].expected_epoch,
            FLB_TRUE
        );
    }
}

void flb_test_filter_parser_use_system_timezone_zone_in_timestamp()
{
    test_parser_timestamp_timezone("EST5EDT", /* char *tz */
                                   "%Y-%m-%d %H:%M:%S%z", /* char *time_fmt */ 
                                   "2023-10-17 05:00:00-0700", /* char *timestamp */
                                   "1697536800", /* char *expected_epoch */
                                   FLB_TRUE); /* int use_system_timezone */
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
                               NULL, FLB_FALSE, MK_TRUE, FLB_FALSE, FLB_FALSE,
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
                               NULL, NULL, NULL, MK_FALSE, MK_TRUE, FLB_FALSE, FLB_FALSE, NULL, 0,
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
                               NULL, NULL, NULL, MK_FALSE, MK_TRUE, FLB_FALSE, FLB_FALSE,
                               NULL, 0, NULL, ctx->config);
    TEST_CHECK(parser != NULL);

    parser = flb_parser_create("two", "regex", "^(?<two>.+?)$",
                               FLB_TRUE,
                               NULL, NULL, NULL, MK_FALSE, MK_TRUE, FLB_FALSE, FLB_FALSE,
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
                               NULL, NULL, NULL, MK_FALSE, MK_TRUE, FLB_FALSE, FLB_FALSE,
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

struct test_ctx {
    flb_ctx_t *flb;
    int i_ffd;
    int f_ffd;
    int o_ffd;
    struct flb_lib_out_cb *cb;  /* Store callback pointer */
};

static struct test_ctx *test_ctx_create(char *reserve_data, char *preserve_key)
{
    struct test_ctx *ctx = flb_malloc(sizeof(struct test_ctx));
    struct flb_parser *parser;
    int ret;

    if (!ctx) {
        flb_errno();
        return NULL;
    }

    /* Create callback structure */
    ctx->cb = flb_malloc(sizeof(struct flb_lib_out_cb));
    if (!ctx->cb) {
        flb_free(ctx);
        return NULL;
    }

    ctx->cb->cb = callback_test;
    ctx->cb->data = NULL;

    /* Create Fluent Bit context */
    ctx->flb = flb_create();
    if (!ctx->flb) {
        flb_free(ctx->cb);
        flb_free(ctx);
        return NULL;
    }

    /* Service config */
    flb_service_set(ctx->flb,
                    "Flush", FLUSH_INTERVAL,
                    "Grace", "1",
                    "Log_Level", "debug",
                    NULL);

    /* Input */
    ctx->i_ffd = flb_input(ctx->flb, (char *) "lib", NULL);
    if (ctx->i_ffd < 0) {
        flb_destroy(ctx->flb);
        flb_free(ctx->cb);
        flb_free(ctx);
        return NULL;
    }
    flb_input_set(ctx->flb, ctx->i_ffd, "Tag", "test", NULL);

    /* Parser */
    parser = flb_parser_create("dummy_test",
                              "regex",
                              "^(?<INT>[^ ]+) (?<FLOAT>[^ ]+) (?<BOOL>[^ ]+) (?<STRING>.+)$",
                              FLB_TRUE,
                              NULL, NULL, NULL,
                              MK_FALSE, MK_TRUE,
                              FLB_FALSE, FLB_FALSE,
                              NULL, 0,
                              NULL, ctx->flb->config);
    if (!parser) {
        flb_destroy(ctx->flb);
        flb_free(ctx->cb);
        flb_free(ctx);
        return NULL;
    }

    /* Filter */
    ctx->f_ffd = flb_filter(ctx->flb, (char *) "parser", NULL);
    if (ctx->f_ffd < 0) {
        flb_destroy(ctx->flb);
        flb_free(ctx->cb);
        flb_free(ctx);
        return NULL;
    }

    ret = flb_filter_set(ctx->flb, ctx->f_ffd,
                        "Match", "test",
                        "Key_Name", "data",
                        "Parser", "dummy_test",
                        "Reserve_Data", reserve_data,
                        "Preserve_Key", preserve_key,
                        NULL);
    if (ret != 0) {
        flb_destroy(ctx->flb);
        flb_free(ctx->cb);
        flb_free(ctx);
        return NULL;
    }

    /* Output with properly aligned callback */
    ctx->o_ffd = flb_output(ctx->flb, (char *) "lib", ctx->cb);
    if (ctx->o_ffd < 0) {
        flb_destroy(ctx->flb);
        flb_free(ctx->cb);
        flb_free(ctx);
        return NULL;
    }

    flb_output_set(ctx->flb, ctx->o_ffd,
                   "Match", "*",
                   "format", "json",
                   NULL);

    return ctx;
}

static void test_ctx_destroy(struct test_ctx *ctx)
{
    if (!ctx) {
        return;
    }

    if (ctx->flb) {
        flb_stop(ctx->flb);
        flb_destroy(ctx->flb);
    }

    if (ctx->cb) {
        flb_free(ctx->cb);
    }

    flb_free(ctx);
}

/* Test case 1: Reserve_Data=Off, Preserve_Key=Off */
void flb_test_filter_parser_reserve_off_preserve_off()
{
    char *output = NULL;
    struct test_ctx *ctx;

    ctx = test_ctx_create("Off", "Off");
    TEST_CHECK(ctx != NULL);
    clear_output();

    int ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* Ingest data */
    int bytes = flb_lib_push(ctx->flb, ctx->i_ffd,
                            "[1448403340,{\"data\":\"100 0.5 true This is an example\", \"extra\":\"should not appear\"}]",
                            strlen("[1448403340,{\"data\":\"100 0.5 true This is an example\", \"extra\":\"should not appear\"}]"));
    TEST_CHECK(bytes > 0);

    wait_with_timeout(2000, &output);
    TEST_CHECK(output != NULL);

    if (output != NULL) {
        /* Positive checks: should contain parsed fields */
        TEST_CHECK_(strstr(output, "\"INT\":\"100\"") != NULL,
                   "Expected output to contain INT field");
        TEST_CHECK_(strstr(output, "\"FLOAT\":\"0.5\"") != NULL,
                   "Expected output to contain FLOAT field");
        TEST_CHECK_(strstr(output, "\"BOOL\":\"true\"") != NULL,
                   "Expected output to contain BOOL field");
        TEST_CHECK_(strstr(output, "\"STRING\":\"This is an example\"") != NULL,
                   "Expected output to contain STRING field");

        /* Negative checks: should not contain original fields */
        TEST_CHECK_(strstr(output, "\"data\":") == NULL,
                   "Expected output to not contain original data field");
        TEST_CHECK_(strstr(output, "\"extra\":") == NULL,
                   "Expected output to not contain extra field");

        free(output);
    }

    test_ctx_destroy(ctx);
}

/* Test case 2: Reserve_Data=Off, Preserve_Key=On */
void flb_test_filter_parser_reserve_off_preserve_on()
{
    char *output = NULL;
    struct test_ctx *ctx;

    ctx = test_ctx_create("Off", "On");
    TEST_CHECK(ctx != NULL);
    clear_output();

    int ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* Ingest data */
    int bytes = flb_lib_push(ctx->flb, ctx->i_ffd,
                            "[1448403340,{\"data\":\"100 0.5 true This is an example\", \"extra\":\"should not appear\"}]",
                            strlen("[1448403340,{\"data\":\"100 0.5 true This is an example\", \"extra\":\"should not appear\"}]"));
    TEST_CHECK(bytes > 0);

    wait_with_timeout(2000, &output);
    TEST_CHECK(output != NULL);

    if (output != NULL) {
        /* Positive checks */
        TEST_CHECK_(strstr(output, "\"data\":\"100 0.5 true This is an example\"") != NULL,
                   "Expected output to contain original data field");
        TEST_CHECK_(strstr(output, "\"INT\":\"100\"") != NULL,
                   "Expected output to contain INT field");
        TEST_CHECK_(strstr(output, "\"FLOAT\":\"0.5\"") != NULL,
                   "Expected output to contain FLOAT field");
        TEST_CHECK_(strstr(output, "\"BOOL\":\"true\"") != NULL,
                   "Expected output to contain BOOL field");
        TEST_CHECK_(strstr(output, "\"STRING\":\"This is an example\"") != NULL,
                   "Expected output to contain STRING field");

        /* Negative checks */
        TEST_CHECK_(strstr(output, "\"extra\":") == NULL,
                   "Expected output to not contain extra field");

        free(output);
    }

    test_ctx_destroy(ctx);
}

/* Test case 3: Reserve_Data=On, Preserve_Key=Off */
void flb_test_filter_parser_reserve_on_preserve_off()
{
    char *output = NULL;
    struct test_ctx *ctx;

    ctx = test_ctx_create("On", "Off");
    TEST_CHECK(ctx != NULL);
    clear_output();

    int ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* Ingest data */
    int bytes = flb_lib_push(ctx->flb, ctx->i_ffd,
                            "[1448403340,{\"data\":\"100 0.5 true This is an example\", \"extra\":\"should appear\"}]",
                            strlen("[1448403340,{\"data\":\"100 0.5 true This is an example\", \"extra\":\"should appear\"}]"));
    TEST_CHECK(bytes > 0);

    wait_with_timeout(2000, &output);
    TEST_CHECK(output != NULL);

    if (output != NULL) {
        /* Positive checks */
        TEST_CHECK_(strstr(output, "\"extra\":\"should appear\"") != NULL,
                   "Expected output to contain extra field");
        TEST_CHECK_(strstr(output, "\"INT\":\"100\"") != NULL,
                   "Expected output to contain INT field");
        TEST_CHECK_(strstr(output, "\"FLOAT\":\"0.5\"") != NULL,
                   "Expected output to contain FLOAT field");
        TEST_CHECK_(strstr(output, "\"BOOL\":\"true\"") != NULL,
                   "Expected output to contain BOOL field");
        TEST_CHECK_(strstr(output, "\"STRING\":\"This is an example\"") != NULL,
                   "Expected output to contain STRING field");

        /* Negative checks */
        TEST_CHECK_(strstr(output, "\"data\":") == NULL,
                   "Expected output to not contain original data field");

        free(output);
    }

    test_ctx_destroy(ctx);
}

/* Test case 4: Reserve_Data=On, Preserve_Key=On */
void flb_test_filter_parser_reserve_on_preserve_on()
{
    char *output = NULL;
    struct test_ctx *ctx;

    ctx = test_ctx_create("On", "On");
    TEST_CHECK(ctx != NULL);
    clear_output();

    int ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* Ingest data */
    int bytes = flb_lib_push(ctx->flb, ctx->i_ffd,
                            "[1448403340,{\"data\":\"100 0.5 true This is an example\", \"extra\":\"should appear\"}]",
                            strlen("[1448403340,{\"data\":\"100 0.5 true This is an example\", \"extra\":\"should appear\"}]"));
    TEST_CHECK(bytes > 0);

    wait_with_timeout(2000, &output);
    TEST_CHECK(output != NULL);

    if (output != NULL) {
        /* Positive checks - all fields should be present */
        TEST_CHECK_(strstr(output, "\"data\":\"100 0.5 true This is an example\"") != NULL,
                   "Expected output to contain original data field");
        TEST_CHECK_(strstr(output, "\"extra\":\"should appear\"") != NULL,
                   "Expected output to contain extra field");
        TEST_CHECK_(strstr(output, "\"INT\":\"100\"") != NULL,
                   "Expected output to contain INT field");
        TEST_CHECK_(strstr(output, "\"FLOAT\":\"0.5\"") != NULL,
                   "Expected output to contain FLOAT field");
        TEST_CHECK_(strstr(output, "\"BOOL\":\"true\"") != NULL,
                   "Expected output to contain BOOL field");
        TEST_CHECK_(strstr(output, "\"STRING\":\"This is an example\"") != NULL,
                   "Expected output to contain STRING field");

        free(output);
    }

    test_ctx_destroy(ctx);
}

TEST_LIST = {
    {"filter_parser_extract_fields", flb_test_filter_parser_extract_fields },
    {"filter_parser_record_accessor", flb_test_filter_parser_record_accessor },
    {"filter_parser_reserve_data_off", flb_test_filter_parser_reserve_data_off },
    {"filter_parser_handle_time_key", flb_test_filter_parser_handle_time_key },
    {"filter_parser_handle_time_key_with_time_zone", flb_test_filter_parser_handle_time_key_with_time_zone },
    {"filter_parser_use_system_timezone", flb_test_filter_parser_use_system_timezone },
    {"filter_parser_ignore_malformed_time", flb_test_filter_parser_ignore_malformed_time },
    {"filter_parser_preserve_original_field", flb_test_filter_parser_preserve_original_field },
    {"filter_parser_first_matched_when_multiple_parser", flb_test_filter_parser_first_matched_when_mutilple_parser },
    {"filter_parser_skip_empty_values_false", flb_test_filter_parser_skip_empty_values_false},
    {"filter_parser_reserve_off_preserve_off", flb_test_filter_parser_reserve_off_preserve_off},
    {"filter_parser_reserve_off_preserve_on", flb_test_filter_parser_reserve_off_preserve_on},
    {"filter_parser_reserve_on_preserve_off", flb_test_filter_parser_reserve_on_preserve_off},
    {"filter_parser_reserve_on_preserve_on", flb_test_filter_parser_reserve_on_preserve_on},
    {NULL, NULL}
};

