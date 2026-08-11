/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
#include <fluent-bit.h>
#include "flb_tests_runtime.h"

/* Test data */
#include "data/td/json_td.h" /* JSON_TD */

/* Kinesis Streams API constants */
#include "../../plugins/out_kinesis_streams/kinesis_api.h"

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

void flb_test_kinesis_default_port(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    struct flb_output_instance *out;

    /* mocks calls- signals that we are in test mode */
    setenv("FLB_KINESIS_PLUGIN_UNDER_TEST", "true", 1);

    ctx = flb_create();
    TEST_CHECK(ctx != NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "kinesis_streams", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "*", NULL);
    flb_output_set(ctx, out_ffd, "region", "us-west-2", NULL);
    flb_output_set(ctx, out_ffd, "stream", "fluent", NULL);
    flb_output_set(ctx, out_ffd, "time_key", "time", NULL);

    /* Start the engine */
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Get the output instance */
    out = flb_output_get_instance(ctx->config, out_ffd);
    TEST_CHECK(out != NULL);

    /* Check if the port is set to the default value */
    const char* port = flb_output_get_property("port", out);
    TEST_CHECK(port == NULL || strcmp(port, "443") == 0);
    TEST_MSG("Default port should be 443 or not set, but got %s", port ? port : "NULL");

    flb_stop(ctx);
    flb_destroy(ctx);
}


void flb_test_kinesis_custom_port(void)
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
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "kinesis_streams", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "*", NULL);
    flb_output_set(ctx, out_ffd, "region", "us-west-2", NULL);
    flb_output_set(ctx, out_ffd, "stream", "fluent", NULL);
    flb_output_set(ctx, out_ffd, "time_key", "time", NULL);
    flb_output_set(ctx, out_ffd, "port", "8443", NULL);
    flb_output_set(ctx, out_ffd, "Retry_Limit", "1", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_kinesis_invalid_port(void)
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
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "kinesis_streams", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "*", NULL);
    flb_output_set(ctx, out_ffd, "region", "us-west-2", NULL);
    flb_output_set(ctx, out_ffd, "stream", "fluent", NULL);
    flb_output_set(ctx, out_ffd, "port", "99999", NULL);  // Invalid port

    ret = flb_start(ctx);
    TEST_CHECK(ret != 0);  // Expect failure

    if (ret == 0) {
        flb_stop(ctx);
    }
    flb_destroy(ctx);
}

void flb_test_kinesis_simple_aggregation(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    setenv("FLB_KINESIS_PLUGIN_UNDER_TEST", "true", 1);

    ctx = flb_create();

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "kinesis_streams", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "*", NULL);
    flb_output_set(ctx, out_ffd, "region", "us-west-2", NULL);
    flb_output_set(ctx, out_ffd, "stream", "fluent", NULL);
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

void flb_test_kinesis_aggregation_with_time_key(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    setenv("FLB_KINESIS_PLUGIN_UNDER_TEST", "true", 1);

    ctx = flb_create();

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "kinesis_streams", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "*", NULL);
    flb_output_set(ctx, out_ffd, "region", "us-west-2", NULL);
    flb_output_set(ctx, out_ffd, "stream", "fluent", NULL);
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

void flb_test_kinesis_aggregation_with_log_key(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    const char *record = "[1, {\"message\":\"with_log_key\"}]";

    setenv("FLB_KINESIS_PLUGIN_UNDER_TEST", "true", 1);

    ctx = flb_create();

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "kinesis_streams", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "*", NULL);
    flb_output_set(ctx, out_ffd, "region", "us-west-2", NULL);
    flb_output_set(ctx, out_ffd, "stream", "fluent", NULL);
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

void flb_test_kinesis_aggregation_many_records(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    int i;
    char record[100];

    setenv("FLB_KINESIS_PLUGIN_UNDER_TEST", "true", 1);

    ctx = flb_create();

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "kinesis_streams", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "*", NULL);
    flb_output_set(ctx, out_ffd, "region", "us-west-2", NULL);
    flb_output_set(ctx, out_ffd, "stream", "fluent", NULL);
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

void flb_test_kinesis_compression_gzip(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    const char *record1 = "[1, {\"message\":\"gzip_test1\"}]";
    const char *record2 = "[1, {\"message\":\"gzip_test2\"}]";

    setenv("FLB_KINESIS_PLUGIN_UNDER_TEST", "true", 1);

    ctx = flb_create();

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "kinesis_streams", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "*", NULL);
    flb_output_set(ctx, out_ffd, "region", "us-west-2", NULL);
    flb_output_set(ctx, out_ffd, "stream", "fluent", NULL);
    flb_output_set(ctx, out_ffd, "compression", "gzip", NULL);
    flb_output_set(ctx, out_ffd, "Retry_Limit", "1", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Push records with GZIP compression */
    flb_lib_push(ctx, in_ffd, (char *) record1, strlen(record1));
    flb_lib_push(ctx, in_ffd, (char *) record2, strlen(record2));

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_kinesis_compression_zstd(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    const char *record1 = "[1, {\"message\":\"zstd_test1\"}]";
    const char *record2 = "[1, {\"message\":\"zstd_test2\"}]";

    setenv("FLB_KINESIS_PLUGIN_UNDER_TEST", "true", 1);

    ctx = flb_create();

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "kinesis_streams", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "*", NULL);
    flb_output_set(ctx, out_ffd, "region", "us-west-2", NULL);
    flb_output_set(ctx, out_ffd, "stream", "fluent", NULL);
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

void flb_test_kinesis_compression_snappy(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    const char *record1 = "[1, {\"message\":\"snappy_test1\"}]";
    const char *record2 = "[1, {\"message\":\"snappy_test2\"}]";

    setenv("FLB_KINESIS_PLUGIN_UNDER_TEST", "true", 1);

    ctx = flb_create();

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "kinesis_streams", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "*", NULL);
    flb_output_set(ctx, out_ffd, "region", "us-west-2", NULL);
    flb_output_set(ctx, out_ffd, "stream", "fluent", NULL);
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

void flb_test_kinesis_compression_snappy_with_aggregation(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    int i;
    char record[100];

    setenv("FLB_KINESIS_PLUGIN_UNDER_TEST", "true", 1);

    ctx = flb_create();

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "kinesis_streams", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "*", NULL);
    flb_output_set(ctx, out_ffd, "region", "us-west-2", NULL);
    flb_output_set(ctx, out_ffd, "stream", "fluent", NULL);
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

/*
 * Helper function to create a log-event record in [timestamp, {"message":"..."}]
 * format with a message payload of the specified target_json_size.
 * target_json_size is the desired size of the inner JSON object {"message":"..."}.
 * Returns a malloc'd string the caller must free, and sets *out_len.
 */
static char* create_large_log_event(size_t target_json_size, size_t *out_len)
{
    const char *prefix = "[1, {\"message\":\"";
    const char *suffix = "\"}]";
    size_t prefix_len = strlen(prefix);
    size_t suffix_len = strlen(suffix);
    size_t json_prefix_len = strlen("{\"message\":\"");
    size_t json_suffix_len = strlen("\"}");
    size_t json_overhead = json_prefix_len + json_suffix_len;
    size_t fill_size;
    size_t total_len;
    char *record;

    if (target_json_size < json_overhead + 1) {
        return NULL;
    }

    fill_size = target_json_size - json_overhead;
    total_len = prefix_len + fill_size + suffix_len;

    record = flb_malloc(total_len + 1);
    if (!record) {
        return NULL;
    }

    memcpy(record, prefix, prefix_len);
    memset(record + prefix_len, 'A', fill_size);
    memcpy(record + prefix_len + fill_size, suffix, suffix_len);
    record[total_len] = '\0';

    *out_len = total_len;
    return record;
}

/* Helper to setup and run a Kinesis Streams test with custom record data */
static void run_kinesis_test_with_data(char *data, size_t data_len)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    setenv("FLB_KINESIS_PLUGIN_UNDER_TEST", "true", 1);

    ctx = flb_create();
    TEST_CHECK(ctx != NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "kinesis_streams", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "*", NULL);
    flb_output_set(ctx, out_ffd, "region", "us-west-2", NULL);
    flb_output_set(ctx, out_ffd, "stream", "fluent", NULL);
    flb_output_set(ctx, out_ffd, "Retry_Limit", "1", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    if (data) {
        flb_lib_push(ctx, in_ffd, data, data_len);
    }

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}

/*
 * Test event size just under the maximum allowed limit (should succeed).
 * MAX_EVENT_SIZE is 1048556 (1 MiB - 20 bytes for partition key).
 * The plugin discards when (written + 1) >= MAX_EVENT_SIZE, so the maximum
 * accepted JSON size is MAX_EVENT_SIZE - 2.
 */
void flb_test_kinesis_event_size_at_limit(void)
{
    char *record;
    size_t record_len;

    record = create_large_log_event(MAX_EVENT_SIZE - 2, &record_len);
    TEST_CHECK(record != NULL);

    if (record) {
        run_kinesis_test_with_data(record, record_len);
        flb_free(record);
    }
}

/*
 * Test event size exceeding limit (should be discarded by the plugin).
 * The plugin logs a warning and drops the record without crashing.
 */
void flb_test_kinesis_event_size_over_limit(void)
{
    char *record;
    size_t record_len;

    record = create_large_log_event(MAX_EVENT_SIZE + 100, &record_len);
    TEST_CHECK(record != NULL);

    if (record) {
        run_kinesis_test_with_data(record, record_len);
        flb_free(record);
    }
}

/*
 * Test event with backslash escape sequences near the size boundary.
 * Validates the plugin handles special characters correctly when the
 * record exceeds the limit.
 */
void flb_test_kinesis_event_size_with_backslash(void)
{
    char *record;
    size_t record_len;
    size_t prefix_len = strlen("[1, {\"message\":\"");
    size_t suffix_len = strlen("\"}]");
    size_t fill_size;
    size_t boundary;
    size_t i;

    record = create_large_log_event(MAX_EVENT_SIZE + 100, &record_len);
    TEST_CHECK(record != NULL);

    if (record) {
        fill_size = record_len - prefix_len - suffix_len;

        /* Replace pairs of characters with valid escape sequence "\\" */
        for (i = 98; i < fill_size - 1; i += 100) {
            record[prefix_len + i] = '\\';
            record[prefix_len + i + 1] = '\\';
        }

        /* Ensure a backslash pair is near the MAX_EVENT_SIZE boundary */
        boundary = MAX_EVENT_SIZE - 1;
        if (boundary + 1 < record_len - suffix_len) {
            record[boundary] = '\\';
            record[boundary + 1] = '\\';
        }

        run_kinesis_test_with_data(record, record_len);
        flb_free(record);
    }
}

/* Test list */
TEST_LIST = {
    {"success", flb_test_firehose_success },
    {"partial_success", flb_test_firehose_partial_success },
    {"throughput_error", flb_test_firehose_throughput_error },
    {"unknown_error", flb_test_firehose_error_unknown },
    {"nonsense_error", flb_test_firehose_nonsense_error },
    {"default_port", flb_test_kinesis_default_port },
    {"custom_port", flb_test_kinesis_custom_port },
    {"invalid_port", flb_test_kinesis_invalid_port },
    {"simple_aggregation", flb_test_kinesis_simple_aggregation },
    {"aggregation_with_time_key", flb_test_kinesis_aggregation_with_time_key },
    {"aggregation_with_log_key", flb_test_kinesis_aggregation_with_log_key },
    {"aggregation_many_records", flb_test_kinesis_aggregation_many_records },
    {"compression_gzip", flb_test_kinesis_compression_gzip },
    {"compression_zstd", flb_test_kinesis_compression_zstd },
    {"compression_snappy", flb_test_kinesis_compression_snappy },
    {"compression_snappy_with_aggregation", flb_test_kinesis_compression_snappy_with_aggregation },
    {"event_size_at_limit", flb_test_kinesis_event_size_at_limit },
    {"event_size_over_limit", flb_test_kinesis_event_size_over_limit },
    {"event_size_with_backslash", flb_test_kinesis_event_size_with_backslash },
    {NULL, NULL}
};
