/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
#include <fluent-bit.h>
#include "flb_tests_runtime.h"

/* Test data */
#include "data/td/json_td.h" /* JSON_TD */

/* CloudWatch API constants */
#include "../../plugins/out_cloudwatch_logs/cloudwatch_api.h"

#define ERROR_ALREADY_EXISTS "{\"__type\":\"ResourceAlreadyExistsException\"}"
/* not a real error code, but tests that the code can respond to any error */
#define ERROR_UNKNOWN "{\"__type\":\"UNKNOWN\"}"

/* JSON structure constants for test message generation */
static const char *TEST_JSON_PREFIX = "{\"message\":\"";
static const char *TEST_JSON_SUFFIX = "\"}";

/* It writes a big JSON message (copied from TD test) */
void flb_test_cloudwatch_success(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    /* mocks calls- signals that we are in test mode */
    setenv("FLB_CLOUDWATCH_PLUGIN_UNDER_TEST", "true", 1);

    ctx = flb_create();

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx,in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "cloudwatch_logs", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd,"match", "test", NULL);
    flb_output_set(ctx, out_ffd,"region", "us-west-2", NULL);
    flb_output_set(ctx, out_ffd,"log_group_name", "fluent", NULL);
    flb_output_set(ctx, out_ffd,"log_stream_prefix", "from-fluent-", NULL);
    flb_output_set(ctx, out_ffd,"auto_create_group", "On", NULL);
    flb_output_set(ctx, out_ffd,"net.keepalive", "Off", NULL);
    flb_output_set(ctx, out_ffd,"Retry_Limit", "1", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    flb_lib_push(ctx, in_ffd, (char *) JSON_TD , (int) sizeof(JSON_TD) - 1);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}

/* It writes a json/emf formatted metrics */
void flb_test_cloudwatch_success_with_metrics(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    /* mocks calls- signals that we are in test mode */
    setenv("FLB_CLOUDWATCH_PLUGIN_UNDER_TEST", "true", 1);

    ctx = flb_create();
    flb_service_set(ctx,
                    "Flush", "0.200000000",
                    "Grace", "1",
                    NULL);

    /* Input */
    in_ffd = flb_input(ctx, (char *) "fluentbit_metrics", NULL);
    TEST_CHECK(in_ffd >= 0);
    ret = flb_input_set(ctx, in_ffd, "tag", "test", NULL);
    TEST_CHECK(ret == 0);
    ret = flb_input_set(ctx, in_ffd, "scrape_on_start", "true", NULL);
    TEST_CHECK(ret == 0);
    ret = flb_input_set(ctx, in_ffd, "scrape_interval", "1", NULL);
    TEST_CHECK(ret == 0);

    out_ffd = flb_output(ctx, (char *) "cloudwatch_logs", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd,"match", "test", NULL);
    flb_output_set(ctx, out_ffd,"region", "us-west-2", NULL);
    flb_output_set(ctx, out_ffd,"log_format", "json_emf", NULL);
    flb_output_set(ctx, out_ffd,"log_group_name", "fluent-health", NULL);
    flb_output_set(ctx, out_ffd,"log_stream_prefix", "from-cmetrics-", NULL);
    flb_output_set(ctx, out_ffd,"auto_create_group", "On", NULL);
    flb_output_set(ctx, out_ffd,"net.keepalive", "Off", NULL);
    flb_output_set(ctx, out_ffd,"Retry_Limit", "1", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_cloudwatch_already_exists_create_group(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    /* mocks calls- signals that we are in test mode */
    setenv("FLB_CLOUDWATCH_PLUGIN_UNDER_TEST", "true", 1);
    setenv("TEST_CREATE_LOG_GROUP_ERROR", ERROR_ALREADY_EXISTS, 1);

    ctx = flb_create();

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx,in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "cloudwatch_logs", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd,"match", "test", NULL);
    flb_output_set(ctx, out_ffd,"region", "us-west-2", NULL);
    flb_output_set(ctx, out_ffd,"log_group_name", "fluent", NULL);
    flb_output_set(ctx, out_ffd,"log_stream_prefix", "from-fluent-", NULL);
    flb_output_set(ctx, out_ffd,"auto_create_group", "On", NULL);
    flb_output_set(ctx, out_ffd,"net.keepalive", "Off", NULL);
    flb_output_set(ctx, out_ffd,"Retry_Limit", "1", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    flb_lib_push(ctx, in_ffd, (char *) JSON_TD , (int) sizeof(JSON_TD) - 1);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_cloudwatch_already_exists_create_stream(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    /* mocks calls- signals that we are in test mode */
    setenv("FLB_CLOUDWATCH_PLUGIN_UNDER_TEST", "true", 1);
    setenv("TEST_CREATE_LOG_STREAM_ERROR", ERROR_ALREADY_EXISTS, 1);

    ctx = flb_create();

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx,in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "cloudwatch_logs", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd,"match", "test", NULL);
    flb_output_set(ctx, out_ffd,"region", "us-west-2", NULL);
    flb_output_set(ctx, out_ffd,"log_group_name", "fluent", NULL);
    flb_output_set(ctx, out_ffd,"log_stream_prefix", "from-fluent-", NULL);
    flb_output_set(ctx, out_ffd,"auto_create_group", "On", NULL);
    flb_output_set(ctx, out_ffd,"net.keepalive", "Off", NULL);
    flb_output_set(ctx, out_ffd,"Retry_Limit", "1", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    flb_lib_push(ctx, in_ffd, (char *) JSON_TD , (int) sizeof(JSON_TD) - 1);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_cloudwatch_error_create_group(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    /* mocks calls- signals that we are in test mode */
    setenv("FLB_CLOUDWATCH_PLUGIN_UNDER_TEST", "true", 1);
    setenv("TEST_CREATE_LOG_GROUP_ERROR", ERROR_UNKNOWN, 1);

    ctx = flb_create();

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx,in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "cloudwatch_logs", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd,"match", "test", NULL);
    flb_output_set(ctx, out_ffd,"region", "us-west-2", NULL);
    flb_output_set(ctx, out_ffd,"log_group_name", "fluent", NULL);
    flb_output_set(ctx, out_ffd,"log_stream_prefix", "from-fluent-", NULL);
    flb_output_set(ctx, out_ffd,"auto_create_group", "On", NULL);
    flb_output_set(ctx, out_ffd,"net.keepalive", "Off", NULL);
    flb_output_set(ctx, out_ffd,"Retry_Limit", "1", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    flb_lib_push(ctx, in_ffd, (char *) JSON_TD , (int) sizeof(JSON_TD) - 1);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_cloudwatch_error_create_stream(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    /* mocks calls- signals that we are in test mode */
    setenv("FLB_CLOUDWATCH_PLUGIN_UNDER_TEST", "true", 1);
    setenv("TEST_CREATE_LOG_STREAM_ERROR", ERROR_UNKNOWN, 1);

    ctx = flb_create();

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx,in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "cloudwatch_logs", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd,"match", "test", NULL);
    flb_output_set(ctx, out_ffd,"region", "us-west-2", NULL);
    flb_output_set(ctx, out_ffd,"log_group_name", "fluent", NULL);
    flb_output_set(ctx, out_ffd,"log_stream_prefix", "from-fluent-", NULL);
    flb_output_set(ctx, out_ffd,"auto_create_group", "On", NULL);
    flb_output_set(ctx, out_ffd,"net.keepalive", "Off", NULL);
    flb_output_set(ctx, out_ffd,"Retry_Limit", "1", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    flb_lib_push(ctx, in_ffd, (char *) JSON_TD , (int) sizeof(JSON_TD) - 1);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_cloudwatch_error_put_log_events(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    /* mocks calls- signals that we are in test mode */
    setenv("FLB_CLOUDWATCH_PLUGIN_UNDER_TEST", "true", 1);
    setenv("TEST_PUT_LOG_EVENTS_ERROR", ERROR_UNKNOWN, 1);

    ctx = flb_create();

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx,in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "cloudwatch_logs", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd,"match", "test", NULL);
    flb_output_set(ctx, out_ffd,"region", "us-west-2", NULL);
    flb_output_set(ctx, out_ffd,"log_group_name", "fluent", NULL);
    flb_output_set(ctx, out_ffd,"log_stream_prefix", "from-fluent-", NULL);
    flb_output_set(ctx, out_ffd,"auto_create_group", "On", NULL);
    flb_output_set(ctx, out_ffd,"net.keepalive", "Off", NULL);
    flb_output_set(ctx, out_ffd,"Retry_Limit", "1", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    flb_lib_push(ctx, in_ffd, (char *) JSON_TD , (int) sizeof(JSON_TD) - 1);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_cloudwatch_put_retention_policy_success(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    /* mocks calls- signals that we are in test mode */
    setenv("FLB_CLOUDWATCH_PLUGIN_UNDER_TEST", "true", 1);

    ctx = flb_create();

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx,in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "cloudwatch_logs", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd,"match", "test", NULL);
    flb_output_set(ctx, out_ffd,"region", "us-west-2", NULL);
    flb_output_set(ctx, out_ffd,"log_group_name", "fluent", NULL);
    flb_output_set(ctx, out_ffd,"log_stream_prefix", "from-fluent-", NULL);
    flb_output_set(ctx, out_ffd,"auto_create_group", "On", NULL);
    flb_output_set(ctx, out_ffd,"log_retention_days", "14", NULL);
    flb_output_set(ctx, out_ffd,"net.keepalive", "Off", NULL);
    flb_output_set(ctx, out_ffd,"Retry_Limit", "1", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    flb_lib_push(ctx, in_ffd, (char *) JSON_TD , (int) sizeof(JSON_TD) - 1);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_cloudwatch_already_exists_create_group_put_retention_policy(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    /* mocks calls- signals that we are in test mode */
    setenv("FLB_CLOUDWATCH_PLUGIN_UNDER_TEST", "true", 1);
    setenv("TEST_CREATE_LOG_GROUP_ERROR", ERROR_ALREADY_EXISTS, 1);

    /* PutRetentionPolicy is not called if the group already exists */
    setenv("TEST_PUT_RETENTION_POLICY_ERROR", ERROR_UNKNOWN, 1);

    ctx = flb_create();

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx,in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "cloudwatch_logs", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd,"match", "test", NULL);
    flb_output_set(ctx, out_ffd,"region", "us-west-2", NULL);
    flb_output_set(ctx, out_ffd,"log_group_name", "fluent", NULL);
    flb_output_set(ctx, out_ffd,"log_stream_prefix", "from-fluent-", NULL);
    flb_output_set(ctx, out_ffd,"auto_create_group", "On", NULL);
    flb_output_set(ctx, out_ffd,"log_retention_days", "14", NULL);
    flb_output_set(ctx, out_ffd,"net.keepalive", "Off", NULL);
    flb_output_set(ctx, out_ffd,"Retry_Limit", "1", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    flb_lib_push(ctx, in_ffd, (char *) JSON_TD , (int) sizeof(JSON_TD) - 1);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_cloudwatch_error_put_retention_policy(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    /* mocks calls- signals that we are in test mode */
    setenv("FLB_CLOUDWATCH_PLUGIN_UNDER_TEST", "true", 1);
    setenv("TEST_PUT_RETENTION_POLICY_ERROR", ERROR_UNKNOWN, 1);

    ctx = flb_create();

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx,in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "cloudwatch_logs", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd,"match", "test", NULL);
    flb_output_set(ctx, out_ffd,"region", "us-west-2", NULL);
    flb_output_set(ctx, out_ffd,"log_group_name", "fluent", NULL);
    flb_output_set(ctx, out_ffd,"log_stream_prefix", "from-fluent-", NULL);
    flb_output_set(ctx, out_ffd,"auto_create_group", "On", NULL);
    flb_output_set(ctx, out_ffd,"log_retention_days", "14", NULL);
    flb_output_set(ctx, out_ffd,"net.keepalive", "Off", NULL);
    flb_output_set(ctx, out_ffd,"Retry_Limit", "1", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    flb_lib_push(ctx, in_ffd, (char *) JSON_TD , (int) sizeof(JSON_TD) - 1);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}

/* Helper function to create a large JSON message of specified size */
static char* create_large_json_message(size_t target_size)
{
    size_t prefix_len = strlen(TEST_JSON_PREFIX);
    size_t suffix_len = strlen(TEST_JSON_SUFFIX);
    size_t overhead = prefix_len + suffix_len;
    size_t data_size;
    char *json;

    /* Reject target_size too small for valid JSON structure */
    if (target_size < overhead + 1) {
        return NULL;
    }

    json = flb_malloc(target_size + 1);
    if (!json) {
        return NULL;
    }

    /* Build JSON: prefix + data + suffix */
    memcpy(json, TEST_JSON_PREFIX, prefix_len);
    data_size = target_size - overhead;

    /* Fill with 'A' characters */
    memset(json + prefix_len, 'A', data_size);

    /* Close JSON object */
    memcpy(json + prefix_len + data_size, TEST_JSON_SUFFIX, suffix_len);
    json[target_size] = '\0';

    /* Caller must free */
    return json;
}

/* Helper to setup and run a CloudWatch test with custom JSON data */
static void run_cloudwatch_test_with_data(char *data, size_t data_len)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    setenv("FLB_CLOUDWATCH_PLUGIN_UNDER_TEST", "true", 1);

    ctx = flb_create();
    TEST_CHECK(ctx != NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "cloudwatch_logs", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "test", NULL);
    flb_output_set(ctx, out_ffd, "region", "us-west-2", NULL);
    flb_output_set(ctx, out_ffd, "log_group_name", "fluent", NULL);
    flb_output_set(ctx, out_ffd, "log_stream_prefix", "from-fluent-", NULL);
    flb_output_set(ctx, out_ffd, "auto_create_group", "On", NULL);
    flb_output_set(ctx, out_ffd, "net.keepalive", "Off", NULL);
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

/* Test event size at maximum allowed limit (should succeed without truncation) */
void flb_test_cloudwatch_event_size_at_limit(void)
{
    char *large_json;

    /* Create message at MAX_EVENT_LEN */
    large_json = create_large_json_message(MAX_EVENT_LEN);
    TEST_CHECK(large_json != NULL);

    if (large_json) {
        run_cloudwatch_test_with_data(large_json, strlen(large_json));
        flb_free(large_json);
    }
}

/* Test event size exceeding limit (should be truncated to MAX_EVENT_LEN) */
void flb_test_cloudwatch_event_size_over_limit(void)
{
    char *large_json;

    /* Create message exceeding MAX_EVENT_LEN by 1 byte to test truncation */
    large_json = create_large_json_message(MAX_EVENT_LEN + 1);
    TEST_CHECK(large_json != NULL);

    if (large_json) {
        run_cloudwatch_test_with_data(large_json, strlen(large_json));
        flb_free(large_json);
    }
}

/* Test event with trailing backslash at truncation boundary */
void flb_test_cloudwatch_event_truncation_with_backslash(void)
{
    char *large_json;
    size_t prefix_len = strlen(TEST_JSON_PREFIX);
    size_t suffix_len = strlen(TEST_JSON_SUFFIX);
    size_t total_len;
    size_t data_len;
    size_t i;

    /* Create base message exceeding MAX_EVENT_LEN */
    large_json = create_large_json_message(MAX_EVENT_LEN + 100);
    TEST_CHECK(large_json != NULL);

    if (large_json) {
        total_len = strlen(large_json);
        data_len = total_len - prefix_len - suffix_len;

        /* Replace pairs of characters with valid escape sequence "\\" */
        for (i = 98; i < data_len - 1; i += 100) {
            large_json[prefix_len + i] = '\\';
            large_json[prefix_len + i + 1] = '\\';
        }

        size_t boundary = MAX_EVENT_LEN - 1; /* index in full JSON string */
        /* Ensure a backslash is at the exact truncation boundary */
        if (boundary + 1 < total_len - suffix_len) {
            large_json[boundary] = '\\';
            large_json[boundary + 1] = '\\';
        }

        run_cloudwatch_test_with_data(large_json, strlen(large_json));
        flb_free(large_json);
    }
}

/* Test list */
TEST_LIST = {
    {"success", flb_test_cloudwatch_success },
    {"success_with_metrics", flb_test_cloudwatch_success_with_metrics},
    {"group_already_exists", flb_test_cloudwatch_already_exists_create_group },
    {"stream_already_exists", flb_test_cloudwatch_already_exists_create_stream },
    {"create_group_error", flb_test_cloudwatch_error_create_group },
    {"create_stream_error", flb_test_cloudwatch_error_create_stream },
    {"put_log_events_error", flb_test_cloudwatch_error_put_log_events },
    {"put_retention_policy_success", flb_test_cloudwatch_put_retention_policy_success },
    {"already_exists_create_group_put_retention_policy", flb_test_cloudwatch_already_exists_create_group_put_retention_policy },
    {"error_put_retention_policy", flb_test_cloudwatch_error_put_retention_policy },
    {"event_size_at_limit", flb_test_cloudwatch_event_size_at_limit },
    {"event_size_over_limit", flb_test_cloudwatch_event_size_over_limit },
    {"event_truncation_with_backslash", flb_test_cloudwatch_event_truncation_with_backslash },
    {NULL, NULL}
};
