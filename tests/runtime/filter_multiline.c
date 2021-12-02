/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit.h>
#include <fluent-bit/flb_sds.h>
#include "flb_tests_runtime.h"

struct filter_test {
    flb_ctx_t *flb;    /* Fluent Bit library context */
    int i_ffd;         /* Input fd  */
    int f_ffd;         /* Filter fd */
};

struct filter_test_result {
    char *expected_pattern;     /* string that must occur in output */
    int expected_pattern_index; /* which record to check for the pattern */
    int expected_records;       /* expected number of outputted records */
    int actual_records;         /* actual number of outputted records */
};

/* Callback to check expected results */
static int cb_check_result(void *record, size_t size, void *data)
{
    char *p;
    struct filter_test_result *expected;
    char *result;

    expected = (struct filter_test_result *) data;
    result = (char *) record;

    if (expected->expected_pattern_index == expected->actual_records) {
        p = strstr(result, expected->expected_pattern);
        TEST_CHECK(p != NULL);

        if (!p) {
            flb_error("Expected to find: '%s' in result '%s'",
                    expected->expected_pattern, result);
        }
        /*
        * If you want to debug your test
        *
        * printf("Expect: '%s' in result '%s'\n", expected->expected_pattern, result);
        */
    }

    expected->actual_records++;

    flb_free(record);
    return 0;
}



static struct filter_test *filter_test_create(struct flb_lib_out_cb *data)
{
    int i_ffd;
    int f_ffd;
    int o_ffd;
    struct filter_test *ctx;

    ctx = flb_malloc(sizeof(struct filter_test));
    if (!ctx) {
        flb_errno();
        return NULL;
    }

    /* Service config */
    ctx->flb = flb_create();
    flb_service_set(ctx->flb,
                    "Flush", "0.200000000",
                    "Grace", "1",
                    NULL);

    /* Input */
    i_ffd = flb_input(ctx->flb, (char *) "lib", NULL);
    TEST_CHECK(i_ffd >= 0);
    flb_input_set(ctx->flb, i_ffd, "tag", "test", NULL);
    ctx->i_ffd = i_ffd;

    /* Filter configuration */
    f_ffd = flb_filter(ctx->flb, (char *) "multiline", NULL);
    TEST_CHECK(f_ffd >= 0);
    flb_filter_set(ctx->flb, f_ffd, "match", "*", NULL);
    ctx->f_ffd = f_ffd;

    /* Output */
    o_ffd = flb_output(ctx->flb, (char *) "lib", (void *) data);
    TEST_CHECK(o_ffd >= 0);
    flb_output_set(ctx->flb, o_ffd,
                   "match", "test",
                   "format", "json",
                   NULL);

    return ctx;
}

static void filter_test_destroy(struct filter_test *ctx)
{
    flb_stop(ctx->flb);
    flb_destroy(ctx->flb);
    flb_free(ctx);
}

static void flb_test_multiline_buffered_two_output_record()
{
    int len;
    int ret;
    int bytes;
    char *p;
    struct flb_lib_out_cb cb_data;
    struct filter_test *ctx;
    struct filter_test_result expected = { 0 };

    /* Create test context */
    ctx = filter_test_create((void *) &cb_data);
    if (!ctx) {
        exit(EXIT_FAILURE);
    }

    /* Configure filter */
    ret = flb_filter_set(ctx->flb, ctx->f_ffd,
                         "multiline.key_content", "log",
                         "multiline.parser", "go",
                         "buffer", "on",
                         "debug_flush", "on",
                         NULL);
    TEST_CHECK(ret == 0);

    /* Prepare output callback with expected result */
    expected.expected_records = 1; /* 1 record with all lines concatenated */
    expected.expected_pattern = "main.main.func1(0xc420024120)";
    expected.expected_pattern_index = 0;
    cb_data.cb = cb_check_result;
    cb_data.data = (void *) &expected;

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* Ingest data samples */
    p = "[0, {\"log\":\"panic: my panic\"}]";
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);
    p = "[0, {\"log\":\"\n\"}]";
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);
    p = "[0, {\"log\":\"goroutine 4 [running]:\"}]";
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);
    p = "[0, {\"log\":\"panic(0x45cb40, 0x47ad70)\"}]";
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);
    sleep(1); /* ensure records get sent separately */
    p = "[0, {\"log\":\"  /usr/local/go/src/runtime/panic.go:542 +0x46c fp=0xc42003f7b8 sp=0xc42003f710 pc=0x422f7c\"}]";
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);
    p = "[0, {\"log\":\"main.main.func1(0xc420024120)\"}]";
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);

    /* check number of outputted records */
    sleep(2);
    TEST_CHECK(expected.actual_records == expected.expected_records);
    filter_test_destroy(ctx);
}

static void flb_test_multiline_buffered_one_output_record()
{
    int len;
    int ret;
    int bytes;
    char *p;
    struct flb_lib_out_cb cb_data;
    struct filter_test *ctx;
    struct filter_test_result expected = { 0 };

    /* Create test context */
    ctx = filter_test_create((void *) &cb_data);
    if (!ctx) {
        exit(EXIT_FAILURE);
    }

    /* Configure filter */
    ret = flb_filter_set(ctx->flb, ctx->f_ffd,
                         "multiline.key_content", "log",
                         "multiline.parser", "go",
                         "buffer", "on",
                         "debug_flush", "on",
                         NULL);
    TEST_CHECK(ret == 0);

    /* Prepare output callback with expected result */
    expected.expected_records = 2; /* 1 record with all lines concatenated */
    expected.expected_pattern = "main.main.func1(0xc420024120)";
    cb_data.cb = cb_check_result;
    cb_data.data = (void *) &expected;

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* Ingest data samples */
    p = "[0, {\"log\":\"panic: my panic\"}]";
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);
    p = "[0, {\"log\":\"\n\"}]";
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);
    p = "[0, {\"log\":\"goroutine 4 [running]:\"}]";
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);
    p = "[0, {\"log\":\"panic(0x45cb40, 0x47ad70)\"}]";
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);
    sleep(1); /* ensure records get sent separately */
    p = "[0, {\"log\":\"  /usr/local/go/src/runtime/panic.go:542 +0x46c fp=0xc42003f7b8 sp=0xc42003f710 pc=0x422f7c\"}]";
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);
    p = "[0, {\"log\":\"main.main.func1(0xc420024120)\"}]";
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);
    p = "[0, {\"log\":\"one more line, no multiline\"}]";
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);

    /* check number of outputted records */
    sleep(2);
    TEST_CHECK(expected.actual_records == expected.expected_records);
    filter_test_destroy(ctx);
}

static void flb_test_multiline_unbuffered()
{
    int len;
    int ret;
    int bytes;
    char *p;
    struct flb_lib_out_cb cb_data;
    struct filter_test *ctx;
    struct filter_test_result expected = { 0 };

    /* Create test context */
    ctx = filter_test_create((void *) &cb_data);
    if (!ctx) {
        exit(EXIT_FAILURE);
    }

    /* Configure filter */
    ret = flb_filter_set(ctx->flb, ctx->f_ffd,
                         "multiline.key_content", "log",
                         "multiline.parser", "go",
                         "buffer", "off",
                         "debug_flush", "on",
                         NULL);
    TEST_CHECK(ret == 0);

    /* Prepare output callback with expected result */
    expected.expected_records = 6; /* no concatenation */
    expected.expected_pattern = "panic";
    expected.expected_pattern_index = 0;
    cb_data.cb = cb_check_result;
    cb_data.data = (void *) &expected;

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* Ingest data samples */
    p = "[0, {\"log\":\"panic: my panic\"}]";
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);
    sleep(1); /* ensure records get sent one by one */
    p = "[0, {\"log\":\"\n\"}]";
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);
    sleep(1); /* ensure records get sent one by one */
    p = "[0, {\"log\":\"goroutine 4 [running]:\"}]";
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);
    sleep(1); /* ensure records get sent one by one */
    p = "[0, {\"log\":\"panic(0x45cb40, 0x47ad70)\"}]";
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);
    sleep(1); /* ensure records get sent one by one */
    p = "[0, {\"log\":\"  /usr/local/go/src/runtime/panic.go:542 +0x46c fp=0xc42003f7b8 sp=0xc42003f710 pc=0x422f7c\"}]";
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);
    sleep(1); /* ensure records get sent one by one */
    p = "[0, {\"log\":\"main.main.func1(0xc420024120)\"}]";
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);

    /* check number of outputted records */
    sleep(2);
    TEST_CHECK(expected.actual_records == expected.expected_records);
    filter_test_destroy(ctx);
}

TEST_LIST = {
    {"multiline_buffered_one_record"            , flb_test_multiline_buffered_one_output_record },
    {"multiline_buffered_two_record"            , flb_test_multiline_buffered_two_output_record },
    {"flb_test_multiline_unbuffered"            , flb_test_multiline_unbuffered },

    {NULL, NULL}
};