/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
#include <fluent-bit.h>
#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_thread_pool.h>
#include "flb_tests_runtime.h"

/* Test data */
#include "data/td/json_td.h" /* JSON_TD */

/* CloudWatch API constants */
#include "../../plugins/out_cloudwatch_logs/cloudwatch_api.h"

#ifdef FLB_SYSTEM_WINDOWS
#define setenv(name, value, overwrite) _putenv_s(name, value)
#define unsetenv(name) _putenv_s(name, "")
#endif

#define CLOUDWATCH_ERROR_ALREADY_EXISTS "{\"__type\":\"ResourceAlreadyExistsException\"}"
#define CLOUDWATCH_ERROR_NOT_FOUND "{\"__type\":\"ResourceNotFoundException\"}"
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
    setenv("TEST_CREATE_LOG_GROUP_ERROR", CLOUDWATCH_ERROR_ALREADY_EXISTS, 1);

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
    setenv("TEST_CREATE_LOG_STREAM_ERROR", CLOUDWATCH_ERROR_ALREADY_EXISTS, 1);

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

void flb_test_cloudwatch_error_put_log_events_not_found(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    /* ResourceNotFoundException must reject the chunk without retrying it. */
    setenv("FLB_CLOUDWATCH_PLUGIN_UNDER_TEST", "true", 1);
    setenv("TEST_PUT_LOG_EVENTS_ERROR", CLOUDWATCH_ERROR_NOT_FOUND, 1);
    cloudwatch_mock_call_count_reset();

    ctx = flb_create();

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

    flb_lib_push(ctx, in_ffd, (char *) JSON_TD, (int) sizeof(JSON_TD) - 1);

    sleep(2);
    TEST_CHECK(cloudwatch_mock_call_count_get("PutLogEvents") == 1);
    TEST_CHECK(cloudwatch_mock_create_after_put_count_get() == 0);

    flb_lib_push(ctx, in_ffd, (char *) JSON_TD, (int) sizeof(JSON_TD) - 1);

    sleep(2);
    flb_stop(ctx);
    TEST_CHECK(cloudwatch_mock_call_count_get("PutLogEvents") == 2);
    TEST_CHECK(cloudwatch_mock_create_after_put_count_get() == 1);
    flb_destroy(ctx);
    unsetenv("TEST_PUT_LOG_EVENTS_ERROR");
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
    setenv("TEST_CREATE_LOG_GROUP_ERROR", CLOUDWATCH_ERROR_ALREADY_EXISTS, 1);

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

void flb_test_cloudwatch_create_stream_escapes_json(void)
{
    struct log_stream stream;
    flb_sds_t body;
    char *expected;
    int ret;

    memset(&stream, 0, sizeof(struct log_stream));
    stream.group = flb_sds_create("fluent");
    stream.name = flb_sds_create("systemd-fsck@dev-disk-by\\x2dlabel-BOOT.service");
    TEST_CHECK(stream.group != NULL);
    TEST_CHECK(stream.name != NULL);

    if (stream.group && stream.name) {
        body = flb_cloudwatch_create_log_stream_body(&stream);
        TEST_CHECK(body != NULL);

        if (body) {
            expected = "{\"logGroupName\":\"fluent\","
                       "\"logStreamName\":\"systemd-fsck@dev-disk-by\\\\x2dlabel-BOOT.service\"}";
            ret = strcmp(body, expected);
            TEST_CHECK(ret == 0);
            flb_sds_destroy(body);
        }
    }

    flb_sds_destroy(stream.group);
    flb_sds_destroy(stream.name);
}

void flb_test_cloudwatch_put_events_escapes_stream_name(void)
{
    struct flb_cloudwatch ctx;
    struct log_stream stream;
    struct cw_flush buf;
    char out_buf[512];
    char *expected_stream_name;
    char *expected;
    int offset;
    int ret;

    memset(&ctx, 0, sizeof(struct flb_cloudwatch));
    memset(&stream, 0, sizeof(struct log_stream));
    memset(&buf, 0, sizeof(struct cw_flush));

    stream.group = flb_sds_create("fluent");
    stream.name = flb_sds_create("systemd-fsck@dev-disk-by\\x2dlabel-BOOT.service");
    TEST_CHECK(stream.group != NULL);
    TEST_CHECK(stream.name != NULL);

    if (stream.group && stream.name) {
        offset = 0;
        buf.out_buf = out_buf;
        buf.out_buf_size = sizeof(out_buf);
        buf.current_stream = &stream;

        ret = flb_cloudwatch_init_put_payload(&ctx, &buf, &stream, &offset);
        TEST_CHECK(ret == 0);

        if (ret == 0) {
            expected = "{\"logGroupName\":\"fluent\","
                       "\"logStreamName\":\"systemd-fsck@dev-disk-by\\\\x2dlabel-BOOT.service\","
                       "\"logEvents\":[";
            TEST_CHECK(offset == strlen(expected));
            TEST_CHECK(strncmp(out_buf, expected, offset) == 0);
        }

        expected_stream_name = "systemd-fsck@dev-disk-by\\\\x2dlabel-BOOT.service";
        reset_flush_buf(&ctx, &buf);
        TEST_CHECK(buf.data_size == PUT_LOG_EVENTS_HEADER_LEN +
                                    PUT_LOG_EVENTS_FOOTER_LEN +
                                    strlen("fluent") +
                                    strlen(expected_stream_name));
    }

    flb_sds_destroy(stream.group);
    flb_sds_destroy(stream.name);
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

/* Create a real output context, but leave its workers idle while inspecting caches. */
static flb_ctx_t *create_stream_cache_test_context(const char *workers, int *out_id)
{
    flb_ctx_t *ctx;
    int in_id;
    int ret;

    setenv("FLB_CLOUDWATCH_PLUGIN_UNDER_TEST", "true", 1);
    unsetenv("TEST_CREATE_LOG_STREAM_ERROR");
    ctx = flb_create();
    TEST_CHECK(ctx != NULL);
    if (!ctx) {
        return NULL;
    }
    in_id = flb_input(ctx, "lib", NULL);
    TEST_CHECK(in_id >= 0);
    *out_id = flb_output(ctx, "cloudwatch_logs", NULL);
    TEST_CHECK(*out_id >= 0);
    flb_service_set(ctx, "Grace", "1", NULL);
    flb_output_set(ctx, *out_id, "match", "*", "region", "us-east-1",
                   "log_group_name", "cache-test", "log_stream_prefix", "prefix-",
                   "workers", workers, NULL);
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);
    if (ret != 0) {
        flb_destroy(ctx);
        return NULL;
    }
    return ctx;
}

static void check_stream_cache_mode(const char *workers, int threaded)
{
    flb_ctx_t *ctx;
    struct flb_output_instance *ins;
    struct flb_cloudwatch *cw;
    struct flb_out_thread_instance worker;
    struct flb_out_thread_instance *saved_worker;
    struct flb_tp_thread thread;
    struct log_stream *stream;
    struct mk_list *cache;
    msgpack_object map;
    flb_sds_t tag;
    int out_id;

    ctx = create_stream_cache_test_context(workers, &out_id);
    if (!ctx) {
        return;
    }
    ins = flb_output_get_instance(ctx->config, out_id);
    cw = ins->context;
    memset(&worker, 0, sizeof(worker));
    memset(&thread, 0, sizeof(thread));
    memset(&map, 0, sizeof(map));
    map.type = MSGPACK_OBJECT_MAP;
    saved_worker = NULL;
    if (threaded) {
        saved_worker = flb_output_thread_instance_get();
        worker.ins = ins;
        worker.th = &thread;
        flb_output_thread_instance_set(&worker);
        cache = &cw->worker_streams[0];
    }
    else {
        cache = &cw->streams;
    }
    tag = flb_sds_create("mode");
    stream = get_log_stream(cw, tag, map);
    TEST_CHECK(stream != NULL);
    if (stream) {
        TEST_CHECK(get_log_stream(cw, tag, map) == stream);
        TEST_CHECK(mk_list_size(cache) == 1);
        stream->expiration = 0;
        stream = get_log_stream(cw, tag, map);
        TEST_CHECK(stream != NULL);
        TEST_CHECK(mk_list_size(cache) == 1);
    }
    if (threaded) {
        TEST_CHECK(mk_list_size(&cw->streams) == 0);
        flb_output_thread_instance_set(saved_worker);
    }
    flb_sds_destroy(tag);
    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_cloudwatch_stream_cache_no_workers(void)
{
    check_stream_cache_mode("0", FLB_FALSE);
}

void flb_test_cloudwatch_stream_cache_one_worker(void)
{
    check_stream_cache_mode("1", FLB_TRUE);
}

void flb_test_cloudwatch_stream_cache_worker_expiry(void)
{
    flb_ctx_t *ctx;
    struct flb_output_instance *ins;
    struct flb_cloudwatch *cw;
    struct flb_out_thread_instance worker;
    struct flb_out_thread_instance *saved_worker;
    struct flb_tp_thread thread;
    struct log_stream *first;
    struct log_stream *second;
    msgpack_object map;
    flb_sds_t tag;
    int out_id;
    int i;

    ctx = create_stream_cache_test_context("2", &out_id);
    if (!ctx) {
        return;
    }
    ins = flb_output_get_instance(ctx->config, out_id);
    cw = ins->context;
    memset(&worker, 0, sizeof(worker));
    memset(&thread, 0, sizeof(thread));
    memset(&map, 0, sizeof(map));
    map.type = MSGPACK_OBJECT_MAP;
    worker.ins = ins;
    worker.th = &thread;
    saved_worker = flb_output_thread_instance_get();
    flb_output_thread_instance_set(&worker);
    tag = flb_sds_create("shared-name");

    first = get_log_stream(cw, tag, map);
    thread.id = 1;
    second = get_log_stream(cw, tag, map);
    TEST_CHECK(first != NULL && second != NULL);
    TEST_CHECK(first != second);
    if (!first || !second || first == second) {
        goto cleanup;
    }

    /* Expiry on one worker must not invalidate another worker's stream. */
    for (i = 0; i < 32; i++) {
        thread.id = 0;
        first->expiration = 0;
        first = get_log_stream(cw, tag, map);
        TEST_CHECK(first != NULL);
        if (!first) {
            goto cleanup;
        }
        thread.id = 1;
        TEST_CHECK(get_log_stream(cw, tag, map) == second);
        TEST_CHECK(strcmp(second->name, "prefix-shared-name") == 0);
        TEST_CHECK(strcmp(second->group, "cache-test") == 0);
    }
    TEST_CHECK(mk_list_size(&cw->streams) == 0);
    TEST_CHECK(mk_list_size(&cw->worker_streams[0]) == 1);
    TEST_CHECK(mk_list_size(&cw->worker_streams[1]) == 1);

cleanup:
    flb_output_thread_instance_set(saved_worker);
    flb_sds_destroy(tag);
    flb_stop(ctx);
    flb_destroy(ctx);
}

/* Test list */
TEST_LIST = {
    {"stream_cache_no_workers", flb_test_cloudwatch_stream_cache_no_workers},
    {"stream_cache_one_worker", flb_test_cloudwatch_stream_cache_one_worker},
    {"stream_cache_worker_expiry", flb_test_cloudwatch_stream_cache_worker_expiry},
    {"success", flb_test_cloudwatch_success },
    {"success_with_metrics", flb_test_cloudwatch_success_with_metrics},
    {"group_already_exists", flb_test_cloudwatch_already_exists_create_group },
    {"stream_already_exists", flb_test_cloudwatch_already_exists_create_stream },
    {"create_group_error", flb_test_cloudwatch_error_create_group },
    {"create_stream_error", flb_test_cloudwatch_error_create_stream },
    {"put_log_events_error", flb_test_cloudwatch_error_put_log_events },
    {"put_log_events_not_found", flb_test_cloudwatch_error_put_log_events_not_found },
    {"put_retention_policy_success", flb_test_cloudwatch_put_retention_policy_success },
    {"already_exists_create_group_put_retention_policy", flb_test_cloudwatch_already_exists_create_group_put_retention_policy },
    {"error_put_retention_policy", flb_test_cloudwatch_error_put_retention_policy },
    {"create_stream_escapes_json", flb_test_cloudwatch_create_stream_escapes_json },
    {"put_events_escapes_stream_name", flb_test_cloudwatch_put_events_escapes_stream_name },
    {"event_size_at_limit", flb_test_cloudwatch_event_size_at_limit },
    {"event_size_over_limit", flb_test_cloudwatch_event_size_over_limit },
    {"event_truncation_with_backslash", flb_test_cloudwatch_event_truncation_with_backslash },
    {NULL, NULL}
};
