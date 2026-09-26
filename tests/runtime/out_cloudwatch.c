/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
#include <time.h>
#include <fluent-bit.h>
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
static const char *TEST_JSON_SUFFIX = "\"}]";

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

/* Create a lib input record with a message of the specified escaped size. */
static char* create_large_json_message(size_t target_size)
{
    int ret;
    size_t prefix_len;
    size_t suffix_len = strlen(TEST_JSON_SUFFIX);
    size_t total_size;
    char prefix[64];
    char *json;

    ret = snprintf(prefix, sizeof(prefix), "[%lld,{\"message\":\"", (long long) time(NULL));
    if (ret < 0 || ret >= sizeof(prefix)) {
        return NULL;
    }
    prefix_len = ret;
    total_size = prefix_len + target_size + suffix_len;

    json = flb_malloc(total_size + 1);
    if (!json) {
        return NULL;
    }

    /* Build JSON: prefix + data + suffix */
    memcpy(json, prefix, prefix_len);

    /* Fill with 'A' characters */
    memset(json + prefix_len, 'A', target_size);

    /* Close JSON object */
    memcpy(json + prefix_len + target_size, TEST_JSON_SUFFIX, suffix_len);
    json[total_size] = '\0';

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

    cloudwatch_mock_call_count_reset();

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

    flb_output_set(ctx, out_ffd, "log_key", "message", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    if (data) {
        ret = flb_lib_push(ctx, in_ffd, data, data_len);
        TEST_CHECK(ret == data_len);
    }

    sleep(2);
    flb_stop(ctx);
    TEST_CHECK(cloudwatch_mock_call_count_get("PutLogEvents") > 0);
    flb_destroy(ctx);
    unsetenv("FLB_CLOUDWATCH_PLUGIN_UNDER_TEST");
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
    size_t prefix_len;
    size_t suffix_len = strlen(TEST_JSON_SUFFIX);
    size_t total_len;
    size_t boundary;

    /* Create base message exceeding MAX_EVENT_LEN */
    large_json = create_large_json_message(MAX_EVENT_LEN + 100);
    TEST_CHECK(large_json != NULL);

    if (large_json) {
        total_len = strlen(large_json);
        prefix_len = total_len - suffix_len - (MAX_EVENT_LEN + 100);

        boundary = prefix_len + MAX_EVENT_LEN - 1;
        /* Ensure a backslash is at the exact truncation boundary */
        if (boundary + 1 < total_len - suffix_len) {
            large_json[boundary] = '\\';
            large_json[boundary + 1] = '\\';
        }

        run_cloudwatch_test_with_data(large_json, strlen(large_json));
        flb_free(large_json);
    }
}

/* Exercise per-record entity allocations under a memory checker. */
static void run_cloudwatch_entity_records(const char *log_key, int add_entity, int root_entity)
{
    flb_ctx_t *ctx;
    struct flb_output_instance *out;
    struct flb_cloudwatch *cloudwatch;
    const char *root_fields;
    char record[512];
    int in_ffd;
    int out_ffd;
    int record_len;
    int ret;
    int i;

    root_fields = root_entity ? "\"aws_entity_account_id\":\"000000000000\","
                               "\"aws_entity_ec2_instance_id\":\"i-test\"," : "";
    setenv("FLB_CLOUDWATCH_PLUGIN_UNDER_TEST", "true", 1);
    unsetenv("TEST_CREATE_LOG_GROUP_ERROR");
    unsetenv("TEST_CREATE_LOG_STREAM_ERROR");
    unsetenv("TEST_PUT_LOG_EVENTS_ERROR");
    cloudwatch_mock_call_count_reset();

    ctx = flb_create();
    TEST_CHECK(ctx != NULL);
    if (ctx == NULL) {
        goto cleanup;
    }

    flb_service_set(ctx, "Flush", "0.1", "Grace", "1", "Log_Level", "error", NULL);
    in_ffd = flb_input(ctx, "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, "cloudwatch_logs", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd,
                   "match", "test",
                   "region", "us-west-2",
                   "log_group_name", "fluent",
                   "log_stream_name", "entity-records",
                   "add_entity", add_entity ? "true" : "false",
                   "workers", "1",
                   "Retry_Limit", "False", NULL);
    if (log_key != NULL) {
        flb_output_set(ctx, out_ffd, "log_key", log_key, NULL);
    }

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);
    if (ret != 0) {
        flb_destroy(ctx);
        goto cleanup;
    }

    out = flb_output_get_instance(ctx->config, out_ffd);
    cloudwatch = out ? out->context : NULL;
    TEST_CHECK(cloudwatch != NULL);
    if (cloudwatch != NULL) {
        /* The fixture supplies metadata normally produced by the Kubernetes filter. */
        cloudwatch->kubernete_metadata_enabled = FLB_TRUE;

        record_len = snprintf(record, sizeof(record),
                              "[%lld,{\"log\":\"entity cleanup regression\",%s"
                              "\"kubernetes\":{\"namespace_name\":\"test\","
                              "\"aws_entity_service_name\":\"test-service\"}}]",
                              (long long) time(NULL), root_fields);
        TEST_CHECK(record_len > 0 && record_len < sizeof(record));
        if (record_len > 0 && record_len < sizeof(record)) {
            for (i = 0; i < 16; i++) {
                ret = flb_lib_push(ctx, in_ffd, record, record_len);
                TEST_CHECK(ret == record_len);
            }
        }
        sleep(2);
    }

    flb_stop(ctx);
    if (log_key != NULL && strcmp(log_key, "missing") == 0) {
        TEST_CHECK(cloudwatch_mock_call_count_get("PutLogEvents") == 0);
    }
    else {
        /* The existing mock lacks the request-id header required for acknowledgement. */
        TEST_CHECK(cloudwatch_mock_call_count_get("PutLogEvents") > 0);
    }
    flb_destroy(ctx);

cleanup:
    unsetenv("FLB_CLOUDWATCH_PLUGIN_UNDER_TEST");
}

void flb_test_cloudwatch_entity_log_key(void)
{
    run_cloudwatch_entity_records("log", FLB_TRUE, FLB_FALSE);
}

void flb_test_cloudwatch_entity_missing_log_key(void)
{
    run_cloudwatch_entity_records("missing", FLB_TRUE, FLB_FALSE);
}

void flb_test_cloudwatch_entity_without_log_key(void)
{
    run_cloudwatch_entity_records(NULL, FLB_TRUE, FLB_FALSE);
}

void flb_test_cloudwatch_log_key_without_entity(void)
{
    run_cloudwatch_entity_records("log", FLB_FALSE, FLB_TRUE);
}

void flb_test_cloudwatch_entity_root_log_key(void)
{
    run_cloudwatch_entity_records("log", FLB_TRUE, FLB_TRUE);
}

void flb_test_cloudwatch_entity_root_missing_log_key(void)
{
    run_cloudwatch_entity_records("missing", FLB_TRUE, FLB_TRUE);
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
    {"put_log_events_not_found", flb_test_cloudwatch_error_put_log_events_not_found },
    {"put_retention_policy_success", flb_test_cloudwatch_put_retention_policy_success },
    {"already_exists_create_group_put_retention_policy", flb_test_cloudwatch_already_exists_create_group_put_retention_policy },
    {"error_put_retention_policy", flb_test_cloudwatch_error_put_retention_policy },
    {"create_stream_escapes_json", flb_test_cloudwatch_create_stream_escapes_json },
    {"put_events_escapes_stream_name", flb_test_cloudwatch_put_events_escapes_stream_name },
    {"event_size_at_limit", flb_test_cloudwatch_event_size_at_limit },
    {"event_size_over_limit", flb_test_cloudwatch_event_size_over_limit },
    {"event_truncation_with_backslash", flb_test_cloudwatch_event_truncation_with_backslash },
    {"entity_log_key", flb_test_cloudwatch_entity_log_key},
    {"entity_missing_log_key", flb_test_cloudwatch_entity_missing_log_key},
    {"entity_without_log_key", flb_test_cloudwatch_entity_without_log_key},
    {"log_key_without_entity", flb_test_cloudwatch_log_key_without_entity},
    {"entity_root_log_key", flb_test_cloudwatch_entity_root_log_key},
    {"entity_root_missing_log_key", flb_test_cloudwatch_entity_root_missing_log_key},
    {NULL, NULL}
};
