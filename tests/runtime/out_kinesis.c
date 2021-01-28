/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
#include <fluent-bit.h>
#include "flb_tests_runtime.h"

/* Test data */
#include "data/td/json_td.h" /* JSON_TD */

#define ERROR_THROUGHPUT "{\"__type\":\"ServiceUnavailableException\"}"
/* not a real error code, but tests that the code can respond to any error */
#define ERROR_UNKNOWN "{\"__type\":\"UNKNOWN\"}"

/* It writes a big JSON message (copied from TD test) */
void flb_test_firehose_success(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    /* mocks calls- signals that we are in test mode */
    setenv("FLB_KINESIS_PLUGIN_UNDER_TEST", "true", 1);

    ctx = flb_create();

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx,in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "kinesis_streams", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd,"match", "*", NULL);
    flb_output_set(ctx, out_ffd,"region", "us-west-2", NULL);
    flb_output_set(ctx, out_ffd,"stream", "fluent", NULL);
    flb_output_set(ctx, out_ffd,"time_key", "time", NULL);
    flb_output_set(ctx, out_ffd,"Retry_Limit", "1", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    flb_lib_push(ctx, in_ffd, (char *) JSON_TD , (int) sizeof(JSON_TD) - 1);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_firehose_partial_success(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    /* mocks calls- signals that we are in test mode */
    setenv("FLB_KINESIS_PLUGIN_UNDER_TEST", "true", 1);
    setenv("PARTIAL_SUCCESS_CASE", "true", 1);

    ctx = flb_create();

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx,in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "kinesis_streams", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd,"match", "*", NULL);
    flb_output_set(ctx, out_ffd,"region", "us-west-2", NULL);
    flb_output_set(ctx, out_ffd,"stream", "fluent", NULL);
    flb_output_set(ctx, out_ffd,"time_key", "time", NULL);
    flb_output_set(ctx, out_ffd,"Retry_Limit", "1", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    flb_lib_push(ctx, in_ffd, (char *) JSON_TD , (int) sizeof(JSON_TD) - 1);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
    unsetenv("PARTIAL_SUCCESS_CASE");
}

void flb_test_firehose_throughput_error(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    /* mocks calls- signals that we are in test mode */
    setenv("FLB_KINESIS_PLUGIN_UNDER_TEST", "true", 1);
    setenv("TEST_PUT_RECORDS_ERROR", ERROR_THROUGHPUT, 1);

    ctx = flb_create();

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx,in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "kinesis_streams", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd,"match", "*", NULL);
    flb_output_set(ctx, out_ffd,"region", "us-west-2", NULL);
    flb_output_set(ctx, out_ffd,"stream", "fluent", NULL);
    flb_output_set(ctx, out_ffd,"time_key", "time", NULL);
    flb_output_set(ctx, out_ffd,"Retry_Limit", "1", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    flb_lib_push(ctx, in_ffd, (char *) JSON_TD , (int) sizeof(JSON_TD) - 1);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
    unsetenv("TEST_PUT_RECORDS_ERROR");
}

void flb_test_firehose_error_unknown(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    /* mocks calls- signals that we are in test mode */
    setenv("FLB_KINESIS_PLUGIN_UNDER_TEST", "true", 1);
    setenv("TEST_PUT_RECORDS_ERROR", ERROR_UNKNOWN, 1);

    ctx = flb_create();

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx,in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "kinesis_streams", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd,"match", "*", NULL);
    flb_output_set(ctx, out_ffd,"region", "us-west-2", NULL);
    flb_output_set(ctx, out_ffd,"stream", "fluent", NULL);
    flb_output_set(ctx, out_ffd,"time_key", "time", NULL);
    flb_output_set(ctx, out_ffd,"Retry_Limit", "1", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    flb_lib_push(ctx, in_ffd, (char *) JSON_TD , (int) sizeof(JSON_TD) - 1);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
    unsetenv("TEST_PUT_RECORDS_ERROR");
}

void flb_test_firehose_nonsense_error(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    /* mocks calls- signals that we are in test mode */
    setenv("FLB_KINESIS_PLUGIN_UNDER_TEST", "true", 1);
    setenv("TEST_PUT_RECORDS_ERROR", "\tbadresponse\nnotparsable{}", 1);

    ctx = flb_create();

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx,in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "kinesis_streams", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd,"match", "*", NULL);
    flb_output_set(ctx, out_ffd,"region", "us-west-2", NULL);
    flb_output_set(ctx, out_ffd,"stream", "fluent", NULL);
    flb_output_set(ctx, out_ffd,"time_key", "time", NULL);
    flb_output_set(ctx, out_ffd,"Retry_Limit", "1", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    flb_lib_push(ctx, in_ffd, (char *) JSON_TD , (int) sizeof(JSON_TD) - 1);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
    unsetenv("TEST_PUT_RECORDS_ERROR");
}


/* Test list */
TEST_LIST = {
    {"success", flb_test_firehose_success },
    {"partial_success", flb_test_firehose_partial_success },
    {"throughput_error", flb_test_firehose_throughput_error },
    {"unknown_error", flb_test_firehose_error_unknown },
    {"nonsense_error", flb_test_firehose_nonsense_error },
    {NULL, NULL}
};
