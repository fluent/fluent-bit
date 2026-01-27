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
    setenv("FLB_FIREHOSE_PLUGIN_UNDER_TEST", "true", 1);

    ctx = flb_create();

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx,in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "kinesis_firehose", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd,"match", "*", NULL);
    flb_output_set(ctx, out_ffd,"region", "us-west-2", NULL);
    flb_output_set(ctx, out_ffd,"delivery_stream", "fluent", NULL);
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
    setenv("FLB_FIREHOSE_PLUGIN_UNDER_TEST", "true", 1);
    setenv("PARTIAL_SUCCESS_CASE", "true", 1);

    ctx = flb_create();

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx,in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "kinesis_firehose", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd,"match", "*", NULL);
    flb_output_set(ctx, out_ffd,"region", "us-west-2", NULL);
    flb_output_set(ctx, out_ffd,"delivery_stream", "fluent", NULL);
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
    setenv("FLB_FIREHOSE_PLUGIN_UNDER_TEST", "true", 1);
    setenv("TEST_PUT_RECORD_BATCH_ERROR", ERROR_THROUGHPUT, 1);

    ctx = flb_create();

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx,in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "kinesis_firehose", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd,"match", "*", NULL);
    flb_output_set(ctx, out_ffd,"region", "us-west-2", NULL);
    flb_output_set(ctx, out_ffd,"delivery_stream", "fluent", NULL);
    flb_output_set(ctx, out_ffd,"time_key", "time", NULL);
    flb_output_set(ctx, out_ffd,"Retry_Limit", "1", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    flb_lib_push(ctx, in_ffd, (char *) JSON_TD , (int) sizeof(JSON_TD) - 1);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
    unsetenv("TEST_PUT_RECORD_BATCH_ERROR");
}

void flb_test_firehose_error_unknown(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    /* mocks calls- signals that we are in test mode */
    setenv("FLB_FIREHOSE_PLUGIN_UNDER_TEST", "true", 1);
    setenv("TEST_PUT_RECORD_BATCH_ERROR", ERROR_UNKNOWN, 1);

    ctx = flb_create();

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx,in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "kinesis_firehose", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd,"match", "*", NULL);
    flb_output_set(ctx, out_ffd,"region", "us-west-2", NULL);
    flb_output_set(ctx, out_ffd,"delivery_stream", "fluent", NULL);
    flb_output_set(ctx, out_ffd,"time_key", "time", NULL);
    flb_output_set(ctx, out_ffd,"Retry_Limit", "1", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    flb_lib_push(ctx, in_ffd, (char *) JSON_TD , (int) sizeof(JSON_TD) - 1);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
    unsetenv("TEST_PUT_RECORD_BATCH_ERROR");
}

void flb_test_firehose_nonsense_error(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    /* mocks calls- signals that we are in test mode */
    setenv("FLB_FIREHOSE_PLUGIN_UNDER_TEST", "true", 1);
    setenv("TEST_PUT_RECORD_BATCH_ERROR", "\tbadresponse\nnotparsable{}", 1);

    ctx = flb_create();

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx,in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "kinesis_firehose", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd,"match", "*", NULL);
    flb_output_set(ctx, out_ffd,"region", "us-west-2", NULL);
    flb_output_set(ctx, out_ffd,"delivery_stream", "fluent", NULL);
    flb_output_set(ctx, out_ffd,"time_key", "time", NULL);
    flb_output_set(ctx, out_ffd,"Retry_Limit", "1", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    flb_lib_push(ctx, in_ffd, (char *) JSON_TD , (int) sizeof(JSON_TD) - 1);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
    unsetenv("TEST_PUT_RECORD_BATCH_ERROR");
}


void flb_test_firehose_simple_aggregation(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    setenv("FLB_FIREHOSE_PLUGIN_UNDER_TEST", "true", 1);

    ctx = flb_create();

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "kinesis_firehose", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "*", NULL);
    flb_output_set(ctx, out_ffd, "region", "us-west-2", NULL);
    flb_output_set(ctx, out_ffd, "delivery_stream", "fluent", NULL);
    flb_output_set(ctx, out_ffd, "simple_aggregation", "On", NULL);
    flb_output_set(ctx, out_ffd, "Retry_Limit", "1", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Push multiple small records */
    flb_lib_push(ctx, in_ffd, (char *) "[1, {\"message\":\"test1\"}]", 25);
    flb_lib_push(ctx, in_ffd, (char *) "[1, {\"message\":\"test2\"}]", 25);
    flb_lib_push(ctx, in_ffd, (char *) "[1, {\"message\":\"test3\"}]", 25);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_firehose_aggregation_with_time_key(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    setenv("FLB_FIREHOSE_PLUGIN_UNDER_TEST", "true", 1);

    ctx = flb_create();

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "kinesis_firehose", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "*", NULL);
    flb_output_set(ctx, out_ffd, "region", "us-west-2", NULL);
    flb_output_set(ctx, out_ffd, "delivery_stream", "fluent", NULL);
    flb_output_set(ctx, out_ffd, "simple_aggregation", "On", NULL);
    flb_output_set(ctx, out_ffd, "time_key", "timestamp", NULL);
    flb_output_set(ctx, out_ffd, "Retry_Limit", "1", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Push records with time_key enabled */
    flb_lib_push(ctx, in_ffd, (char *) "[1, {\"message\":\"with_time1\"}]", 30);
    flb_lib_push(ctx, in_ffd, (char *) "[1, {\"message\":\"with_time2\"}]", 30);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_firehose_aggregation_with_log_key(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    const char *record = "[1, {\"message\":\"with_log_key\"}]";

    setenv("FLB_FIREHOSE_PLUGIN_UNDER_TEST", "true", 1);

    ctx = flb_create();

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "kinesis_firehose", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "*", NULL);
    flb_output_set(ctx, out_ffd, "region", "us-west-2", NULL);
    flb_output_set(ctx, out_ffd, "delivery_stream", "fluent", NULL);
    flb_output_set(ctx, out_ffd, "simple_aggregation", "On", NULL);
    flb_output_set(ctx, out_ffd, "log_key", "log", NULL);
    flb_output_set(ctx, out_ffd, "Retry_Limit", "1", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Push records with log_key enabled */
    flb_lib_push(ctx, in_ffd, (char *) record, strlen(record));

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_firehose_aggregation_many_records(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    int i;
    char record[100];

    setenv("FLB_FIREHOSE_PLUGIN_UNDER_TEST", "true", 1);

    ctx = flb_create();

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "kinesis_firehose", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "*", NULL);
    flb_output_set(ctx, out_ffd, "region", "us-west-2", NULL);
    flb_output_set(ctx, out_ffd, "delivery_stream", "fluent", NULL);
    flb_output_set(ctx, out_ffd, "simple_aggregation", "On", NULL);
    flb_output_set(ctx, out_ffd, "Retry_Limit", "1", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Push many small records to test aggregation efficiency */
    for (i = 0; i < 50; i++) {
        ret = snprintf(record, sizeof(record), "[1, {\"id\":%d,\"msg\":\"test\"}]", i);
        TEST_CHECK(ret < sizeof(record));
        flb_lib_push(ctx, in_ffd, record, strlen(record));
    }

    sleep(3);
    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_firehose_aggregation_with_compression(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    const char *record1 = "[1, {\"message\":\"compressed1\"}]";
    const char *record2 = "[1, {\"message\":\"compressed2\"}]";

    setenv("FLB_FIREHOSE_PLUGIN_UNDER_TEST", "true", 1);

    ctx = flb_create();

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "kinesis_firehose", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "*", NULL);
    flb_output_set(ctx, out_ffd, "region", "us-west-2", NULL);
    flb_output_set(ctx, out_ffd, "delivery_stream", "fluent", NULL);
    flb_output_set(ctx, out_ffd, "simple_aggregation", "On", NULL);
    flb_output_set(ctx, out_ffd, "compression", "gzip", NULL);
    flb_output_set(ctx, out_ffd, "Retry_Limit", "1", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Push records with compression enabled */
    flb_lib_push(ctx, in_ffd, (char *) record1, strlen(record1));
    flb_lib_push(ctx, in_ffd, (char *) record2, strlen(record2));

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_firehose_compression_zstd(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    const char *record1 = "[1, {\"message\":\"zstd_test1\"}]";
    const char *record2 = "[1, {\"message\":\"zstd_test2\"}]";

    setenv("FLB_FIREHOSE_PLUGIN_UNDER_TEST", "true", 1);

    ctx = flb_create();

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "kinesis_firehose", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "*", NULL);
    flb_output_set(ctx, out_ffd, "region", "us-west-2", NULL);
    flb_output_set(ctx, out_ffd, "delivery_stream", "fluent", NULL);
    flb_output_set(ctx, out_ffd, "compression", "zstd", NULL);
    flb_output_set(ctx, out_ffd, "Retry_Limit", "1", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Push records with ZSTD compression */
    flb_lib_push(ctx, in_ffd, (char *) record1, strlen(record1));
    flb_lib_push(ctx, in_ffd, (char *) record2, strlen(record2));

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_firehose_compression_snappy(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    const char *record1 = "[1, {\"message\":\"snappy_test1\"}]";
    const char *record2 = "[1, {\"message\":\"snappy_test2\"}]";

    setenv("FLB_FIREHOSE_PLUGIN_UNDER_TEST", "true", 1);

    ctx = flb_create();

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "kinesis_firehose", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "*", NULL);
    flb_output_set(ctx, out_ffd, "region", "us-west-2", NULL);
    flb_output_set(ctx, out_ffd, "delivery_stream", "fluent", NULL);
    flb_output_set(ctx, out_ffd, "compression", "snappy", NULL);
    flb_output_set(ctx, out_ffd, "Retry_Limit", "1", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Push records with Snappy compression */
    flb_lib_push(ctx, in_ffd, (char *) record1, strlen(record1));
    flb_lib_push(ctx, in_ffd, (char *) record2, strlen(record2));

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_firehose_compression_snappy_with_aggregation(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    int i;
    char record[100];

    setenv("FLB_FIREHOSE_PLUGIN_UNDER_TEST", "true", 1);

    ctx = flb_create();

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "kinesis_firehose", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "*", NULL);
    flb_output_set(ctx, out_ffd, "region", "us-west-2", NULL);
    flb_output_set(ctx, out_ffd, "delivery_stream", "fluent", NULL);
    flb_output_set(ctx, out_ffd, "simple_aggregation", "On", NULL);
    flb_output_set(ctx, out_ffd, "compression", "snappy", NULL);
    flb_output_set(ctx, out_ffd, "Retry_Limit", "1", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Push many records with Snappy compression and aggregation */
    for (i = 0; i < 20; i++) {
        ret = snprintf(record, sizeof(record), "[1, {\"id\":%d,\"msg\":\"snappy_agg\"}]", i);
        TEST_CHECK(ret < sizeof(record));
        flb_lib_push(ctx, in_ffd, record, strlen(record));
    }

    sleep(3);
    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_firehose_aggregation_combined_params(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    const char *record = "[1, {\"message\":\"combined_test\"}]";

    setenv("FLB_FIREHOSE_PLUGIN_UNDER_TEST", "true", 1);

    ctx = flb_create();

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "kinesis_firehose", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "*", NULL);
    flb_output_set(ctx, out_ffd, "region", "us-west-2", NULL);
    flb_output_set(ctx, out_ffd, "delivery_stream", "fluent", NULL);
    flb_output_set(ctx, out_ffd, "simple_aggregation", "On", NULL);
    flb_output_set(ctx, out_ffd, "time_key", "timestamp", NULL);
    flb_output_set(ctx, out_ffd, "time_key_format", "%Y-%m-%d %H:%M:%S", NULL);
    flb_output_set(ctx, out_ffd, "compression", "gzip", NULL);
    flb_output_set(ctx, out_ffd, "Retry_Limit", "1", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Test with all features combined */
    flb_lib_push(ctx, in_ffd, (char *) record, strlen(record));

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_firehose_aggregation_empty_records(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    setenv("FLB_FIREHOSE_PLUGIN_UNDER_TEST", "true", 1);

    ctx = flb_create();

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "kinesis_firehose", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "*", NULL);
    flb_output_set(ctx, out_ffd, "region", "us-west-2", NULL);
    flb_output_set(ctx, out_ffd, "delivery_stream", "fluent", NULL);
    flb_output_set(ctx, out_ffd, "simple_aggregation", "On", NULL);
    flb_output_set(ctx, out_ffd, "Retry_Limit", "1", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Push empty and minimal records */
    flb_lib_push(ctx, in_ffd, (char *) "[1, {}]", 7);
    flb_lib_push(ctx, in_ffd, (char *) "[1, {\"a\":\"\"}]", 13);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_firehose_aggregation_error_handling(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    const char *record1 = "[1, {\"message\":\"error_test1\"}]";
    const char *record2 = "[1, {\"message\":\"error_test2\"}]";

    setenv("FLB_FIREHOSE_PLUGIN_UNDER_TEST", "true", 1);
    setenv("TEST_PUT_RECORD_BATCH_ERROR", ERROR_THROUGHPUT, 1);

    ctx = flb_create();

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "kinesis_firehose", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "*", NULL);
    flb_output_set(ctx, out_ffd, "region", "us-west-2", NULL);
    flb_output_set(ctx, out_ffd, "delivery_stream", "fluent", NULL);
    flb_output_set(ctx, out_ffd, "simple_aggregation", "On", NULL);
    flb_output_set(ctx, out_ffd, "Retry_Limit", "1", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Test error handling with aggregation enabled */
    flb_lib_push(ctx, in_ffd, (char *) record1, strlen(record1));
    flb_lib_push(ctx, in_ffd, (char *) record2, strlen(record2));

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
    unsetenv("TEST_PUT_RECORD_BATCH_ERROR");
}

void flb_test_firehose_aggregation_custom_time_format(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    const char *record = "[1, {\"message\":\"unix_time\"}]";

    setenv("FLB_FIREHOSE_PLUGIN_UNDER_TEST", "true", 1);

    ctx = flb_create();

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "kinesis_firehose", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "*", NULL);
    flb_output_set(ctx, out_ffd, "region", "us-west-2", NULL);
    flb_output_set(ctx, out_ffd, "delivery_stream", "fluent", NULL);
    flb_output_set(ctx, out_ffd, "simple_aggregation", "On", NULL);
    flb_output_set(ctx, out_ffd, "time_key", "ts", NULL);
    flb_output_set(ctx, out_ffd, "time_key_format", "%s", NULL);
    flb_output_set(ctx, out_ffd, "Retry_Limit", "1", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Test with Unix timestamp format */
    flb_lib_push(ctx, in_ffd, (char *) record, strlen(record));

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}

/* Test list */
TEST_LIST = {
    {"success", flb_test_firehose_success },
    {"partial_success", flb_test_firehose_partial_success },
    {"throughput_error", flb_test_firehose_throughput_error },
    {"unknown_error", flb_test_firehose_error_unknown },
    {"nonsense_error", flb_test_firehose_nonsense_error },
    {"simple_aggregation", flb_test_firehose_simple_aggregation },
    {"aggregation_with_time_key", flb_test_firehose_aggregation_with_time_key },
    {"aggregation_with_log_key", flb_test_firehose_aggregation_with_log_key },
    {"aggregation_many_records", flb_test_firehose_aggregation_many_records },
    {"aggregation_with_compression", flb_test_firehose_aggregation_with_compression },
    {"compression_zstd", flb_test_firehose_compression_zstd },
    {"compression_snappy", flb_test_firehose_compression_snappy },
    {"compression_snappy_with_aggregation", flb_test_firehose_compression_snappy_with_aggregation },
    {"aggregation_combined_params", flb_test_firehose_aggregation_combined_params },
    {"aggregation_empty_records", flb_test_firehose_aggregation_empty_records },
    {"aggregation_error_handling", flb_test_firehose_aggregation_error_handling },
    {"aggregation_custom_time_format", flb_test_firehose_aggregation_custom_time_format },
    {NULL, NULL}
};
