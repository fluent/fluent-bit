/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit.h>
#include "flb_tests_runtime.h"


pthread_mutex_t result_mutex = PTHREAD_MUTEX_INITIALIZER;
int num_invoked = 0;
static const char *callback_error = NULL;

static int get_output_invoked()
{
    int ret;

    pthread_mutex_lock(&result_mutex);
    ret = num_invoked;
    pthread_mutex_unlock(&result_mutex);

    return ret;
}

static int increment_output_invoked()
{
    int ret;

    pthread_mutex_lock(&result_mutex);
    num_invoked++;
    ret = num_invoked;
    pthread_mutex_unlock(&result_mutex);

    return ret;
}

static void set_callback_error(const char *message)
{
    pthread_mutex_lock(&result_mutex);
    if (callback_error == NULL) {
        callback_error = message;
    }
    pthread_mutex_unlock(&result_mutex);
}

static void clear_output_invoked()
{
    pthread_mutex_lock(&result_mutex);
    num_invoked = 0;
    callback_error = NULL;
    pthread_mutex_unlock(&result_mutex);
}

static void check_callback_error()
{
    const char *message;

    pthread_mutex_lock(&result_mutex);
    message = callback_error;
    pthread_mutex_unlock(&result_mutex);

    if (!TEST_CHECK(message == NULL)) {
        TEST_MSG("%s", message);
    }
}

static void stop_and_check(flb_ctx_t *ctx, int expected_invocations)
{
    int invocations;

    flb_stop(ctx);

    invocations = get_output_invoked();
    if (!TEST_CHECK(invocations == expected_invocations)) {
        TEST_MSG("got %d formatter callbacks, expected %d",
                 invocations, expected_invocations);
    }
    check_callback_error();

    flb_destroy(ctx);
}

static void cb_check_format_no_log_key(void *ctx, int ffd,
                                       int res_ret, void *res_data,
                                       size_t res_size, void *data)
{
    char *out_json = res_data;
    char *p;

    if (res_ret != 0 || out_json == NULL) {
        set_callback_error("formatter returned an error or no output");
        flb_sds_destroy(res_data);
        return;
    }

    p = strstr(out_json, "\"customer_id\":\"test-customer\"");
    if (p == NULL) {
        set_callback_error("expected customer_id was not found");
    }

    p = strstr(out_json, "\"log_type\":\"TEST_LOG\"");
    if (p == NULL) {
        set_callback_error("expected log_type was not found");
    }

    p = strstr(out_json, "\"entries\":[");
    if (p == NULL) {
        set_callback_error("entries array was not found");
    }

    p = strstr(out_json, "\"log_text\":\"{\\\"message\\\":\\\"hello world\\\"}\"");
    if (p == NULL) {
        set_callback_error("expected log_text was not found");
    }

    p = strstr(out_json, "\"ts_rfc3339\":");
    if (p == NULL) {
        set_callback_error("expected ts_rfc3339 key was not found");
    }

    increment_output_invoked();
    flb_sds_destroy(res_data);
}

static void cb_check_format_subsecond_timestamp(void *ctx, int ffd,
                                                int res_ret, void *res_data,
                                                size_t res_size, void *data)
{
    char *out_json = res_data;
    char *p;

    if (res_ret != 0 || out_json == NULL) {
        set_callback_error("formatter returned an error or no output");
        flb_sds_destroy(res_data);
        return;
    }

    /* The fraction of 1700000000.0625 must keep its leading zero */
    p = strstr(out_json, "\"ts_rfc3339\":\"2023-11-14T22:13:20.062500000Z\"");
    if (p == NULL) {
        set_callback_error("expected sub-second timestamp was not found");
    }

    increment_output_invoked();
    flb_sds_destroy(res_data);
}

static void cb_check_format_with_log_key(void *ctx, int ffd,
                                         int res_ret, void *res_data,
                                         size_t res_size, void *data)
{
    char *out_json = res_data;
    char *p;

    if (out_json == NULL) {
        return;
    }

    if (res_ret != 0) {
        set_callback_error("formatter returned an error");
    }

    p = strstr(out_json, "\"log_text\":\"This is the target message.\"");
    if (p == NULL) {
        set_callback_error("expected log_text value was not found");
    }

    p = strstr(out_json, "other_key");
    if (p != NULL) {
        set_callback_error("unexpected other_key was found");
    }

    increment_output_invoked();
    flb_sds_destroy(res_data);
}

static void cb_check_format_multiple_records(void *ctx, int ffd,
                                             int res_ret, void *res_data,
                                             size_t res_size, void *data)
{
    char *out_json = res_data;
    char *p1, *p2;

    if (res_ret != 0 || out_json == NULL) {
        set_callback_error("formatter returned an error or no output");
        flb_sds_destroy(res_data);
        return;
    }

    p1 = strstr(out_json, "\"log_text\":\"{\\\"message\\\":\\\"record one\\\"}\"");
    if (p1 == NULL) {
        set_callback_error("first record was not found");
    }

    p2 = strstr(out_json, "\"log_text\":\"{\\\"message\\\":\\\"record two\\\"}\"");
    if (p2 == NULL) {
        set_callback_error("second record was not found");
    }

    increment_output_invoked();
    flb_sds_destroy(res_data);
}

static void cb_check_format_log_key_error(void *ctx, int ffd,
                                          int res_ret, void *res_data,
                                          size_t res_size, void *data)
{
    if (res_ret == 0) {
        set_callback_error("log_key conversion failure was not propagated");
    }
    if (res_data != NULL || res_size != 0) {
        set_callback_error("failed extraction returned a partial payload");
    }

    increment_output_invoked();
    flb_sds_destroy(res_data);
}

static void cb_check_format_partially_succeeded_records(void *ctx, int ffd,
                                                        int res_ret, void *res_data,
                                                        size_t res_size, void *data)
{
    char *out_json = res_data;
    char *p1, *p2;

    if (res_ret != 0 || out_json == NULL) {
        set_callback_error("formatter returned an error or no output");
        flb_sds_destroy(res_data);
        return;
    }

    p1 = strstr(out_json, "\"log_text\":\"record one\"");
    if (p1 == NULL) {
        set_callback_error("expected log_text value was not found");
    }

    p2 = strstr(out_json, "\"test\"");
    if (p2 != NULL) {
        set_callback_error("unexpected test field was found");
    }

    increment_output_invoked();
    flb_sds_destroy(res_data);
}

static void cb_check_format_namespace_and_labels(void *ctx, int ffd,
                                                 int res_ret, void *res_data,
                                                 size_t res_size, void *data)
{
    char *out_json = res_data;
    char *p;

    if (res_ret != 0 || out_json == NULL) {
        set_callback_error("formatter returned an error or no output");
        flb_sds_destroy(res_data);
        return;
    }

    p = strstr(out_json, "\"namespace\":\"tenant-a\"");
    if (p == NULL) {
        set_callback_error("expected namespace was not found");
    }

    p = strstr(out_json, "\"labels\":[");
    if (p == NULL) {
        set_callback_error("expected labels array was not found");
    }

    p = strstr(out_json, "\"key\":\"env\"");
    if (p == NULL) {
        set_callback_error("expected static label key was not found");
    }

    p = strstr(out_json, "\"value\":\"production\"");
    if (p == NULL) {
        set_callback_error("expected static label value was not found");
    }

    p = strstr(out_json, "\"key\":\"cluster_name\"");
    if (p == NULL) {
        set_callback_error("expected dynamic label key was not found");
    }

    p = strstr(out_json, "\"value\":\"blue\"");
    if (p == NULL) {
        set_callback_error("expected dynamic label value was not found");
    }

    increment_output_invoked();
    flb_sds_destroy(res_data);
}

static void cb_check_format_namespace_fallback_and_missing_label(void *ctx, int ffd,
                                                                 int res_ret, void *res_data,
                                                                 size_t res_size, void *data)
{
    char *out_json = res_data;
    char *p;

    if (res_ret != 0 || out_json == NULL) {
        set_callback_error("formatter returned an error or no output");
        flb_sds_destroy(res_data);
        return;
    }

    p = strstr(out_json, "\"namespace\":\"fallback-namespace\"");
    if (p == NULL) {
        set_callback_error("expected fallback namespace was not found");
    }

    p = strstr(out_json, "\"key\":\"missing\"");
    if (p != NULL) {
        set_callback_error("unexpected missing label was found");
    }

    p = strstr(out_json, "\"log_text\":\"{\\\"message\\\":\\\"hello world\\\"}\"");
    if (p == NULL) {
        set_callback_error("expected log_text was not found");
    }

    increment_output_invoked();
    flb_sds_destroy(res_data);
}

static void cb_check_format_split_on_metadata_change(void *ctx, int ffd,
                                                     int res_ret, void *res_data,
                                                     size_t res_size, void *data)
{
    char *out_json = res_data;
    char *p;
    int invocation;

    if (res_ret != 0 || out_json == NULL) {
        set_callback_error("formatter returned an error or no output");
        flb_sds_destroy(res_data);
        return;
    }

    invocation = increment_output_invoked();

    if (invocation == 1) {
        p = strstr(out_json, "\"namespace\":\"tenant-a\"");
        if (p == NULL) {
            set_callback_error("expected first namespace was not found");
        }

        p = strstr(out_json, "\"value\":\"blue\"");
        if (p == NULL) {
            set_callback_error("expected first dynamic label value was not found");
        }

        p = strstr(out_json, "\"log_text\":\"{\\\"message\\\":\\\"record one\\\"");
        if (p == NULL) {
            set_callback_error("expected first record was not found");
        }

        p = strstr(out_json, "tenant-b");
        if (p != NULL) {
            set_callback_error("unexpected second namespace was found");
        }

        p = strstr(out_json, "green");
        if (p != NULL) {
            set_callback_error("unexpected second dynamic label value was found");
        }

        p = strstr(out_json, "record two");
        if (p != NULL) {
            set_callback_error("unexpected second record was found");
        }
    }
    else if (invocation == 2) {
        p = strstr(out_json, "\"namespace\":\"tenant-b\"");
        if (p == NULL) {
            set_callback_error("expected second namespace was not found");
        }

        p = strstr(out_json, "\"value\":\"green\"");
        if (p == NULL) {
            set_callback_error("expected second dynamic label value was not found");
        }

        p = strstr(out_json, "\"log_text\":\"{\\\"message\\\":\\\"record two\\\"");
        if (p == NULL) {
            set_callback_error("expected second record was not found");
        }
    }
    else {
        set_callback_error("formatter was invoked more than twice");
    }

    flb_sds_destroy(res_data);
}

static void cb_check_format_chronicle_api(void *ctx, int ffd,
                                          int res_ret, void *res_data,
                                          size_t res_size, void *data)
{
    char *out_json = res_data;
    char *p;

    if (res_ret != 0 || out_json == NULL) {
        set_callback_error("formatter returned an error or no output");
        flb_sds_destroy(res_data);
        return;
    }

    p = strstr(out_json, "{\"inlineSource\":{\"logs\":[{");
    if (p != out_json) {
        set_callback_error("expected inlineSource.logs root was not found");
    }

    /* base64 of {"message":"hello world"} */
    p = strstr(out_json, "\"data\":\"eyJtZXNzYWdlIjoiaGVsbG8gd29ybGQifQ==\"");
    if (p == NULL) {
        set_callback_error("expected base64 encoded data was not found");
    }

    p = strstr(out_json, "\"logEntryTime\":\"2023-11-14T22:13:20.062500000Z\"");
    if (p == NULL) {
        set_callback_error("expected logEntryTime was not found");
    }

    p = strstr(out_json, "\"collectionTime\":\"");
    if (p == NULL) {
        set_callback_error("expected collectionTime was not found");
    }

    p = strstr(out_json, "customer_id");
    if (p != NULL) {
        set_callback_error("unexpected legacy customer_id was found");
    }

    p = strstr(out_json, "log_text");
    if (p != NULL) {
        set_callback_error("unexpected legacy log_text was found");
    }

    p = strstr(out_json, "environmentNamespace");
    if (p != NULL) {
        set_callback_error("unexpected environmentNamespace was found");
    }

    p = strstr(out_json, "labels");
    if (p != NULL) {
        set_callback_error("unexpected labels were found");
    }

    increment_output_invoked();
    flb_sds_destroy(res_data);
}

static void cb_check_format_chronicle_api_log_key(void *ctx, int ffd,
                                                  int res_ret, void *res_data,
                                                  size_t res_size, void *data)
{
    char *out_json = res_data;
    char *p;

    if (res_ret != 0 || out_json == NULL) {
        set_callback_error("formatter returned an error or no output");
        flb_sds_destroy(res_data);
        return;
    }

    /* base64 of: This is the target message. */
    p = strstr(out_json, "\"data\":\"VGhpcyBpcyB0aGUgdGFyZ2V0IG1lc3NhZ2Uu\"");
    if (p == NULL) {
        set_callback_error("expected base64 encoded log_key value was not found");
    }

    increment_output_invoked();
    flb_sds_destroy(res_data);
}

static void cb_check_format_chronicle_api_namespace_and_labels(void *ctx, int ffd,
                                                               int res_ret,
                                                               void *res_data,
                                                               size_t res_size,
                                                               void *data)
{
    char *out_json = res_data;
    char *p;

    if (res_ret != 0 || out_json == NULL) {
        set_callback_error("formatter returned an error or no output");
        flb_sds_destroy(res_data);
        return;
    }

    p = strstr(out_json, "\"environmentNamespace\":\"tenant-a\"");
    if (p == NULL) {
        set_callback_error("expected environmentNamespace was not found");
    }

    p = strstr(out_json,
               "\"labels\":{\"env\":{\"value\":\"production\"},"
               "\"cluster_name\":{\"value\":\"blue\"}}");
    if (p == NULL) {
        set_callback_error("expected labels map was not found");
    }

    increment_output_invoked();
    flb_sds_destroy(res_data);
}

static void cb_check_format_chronicle_api_future_timestamp(void *ctx, int ffd,
                                                           int res_ret,
                                                           void *res_data,
                                                           size_t res_size,
                                                           void *data)
{
    char *out_json = res_data;
    char *p;

    if (res_ret != 0 || out_json == NULL) {
        set_callback_error("formatter returned an error or no output");
        flb_sds_destroy(res_data);
        return;
    }

    p = strstr(out_json, "\"logEntryTime\":\"2100-01-01T00:00:00.999755859Z\"");
    if (p == NULL) {
        set_callback_error("expected logEntryTime was not found");
    }

    /* The collection time must be later than the log entry time */
    p = strstr(out_json, "\"collectionTime\":\"2100-01-01T00:00:01.000755859Z\"");
    if (p == NULL) {
        set_callback_error("collectionTime is not later than logEntryTime");
    }

    increment_output_invoked();
    flb_sds_destroy(res_data);
}

void test_format_no_log_key()
{
    flb_ctx_t *ctx;
    int in_ffd, out_ffd;
    char record[1024];

    ctx = flb_create();
    flb_service_set(ctx, "flush", "0.2", "grace", "1", "log_level", "error", NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "chronicle", NULL);
    flb_output_set(ctx, out_ffd,
                   "match", "test",
                   "customer_id", "test-customer",
                   "project_id", "TESTING_FORMAT",
                   "log_type", "TEST_LOG",
                   NULL);

    flb_output_set_test(ctx, out_ffd, "formatter", cb_check_format_no_log_key, NULL, NULL);

    flb_start(ctx);
    clear_output_invoked();

    snprintf(record, sizeof(record) - 1, "[%ld, {\"message\": \"hello world\"}]", (long) time(NULL));
    flb_lib_push(ctx, in_ffd, record, strlen(record));

    sleep(1);

    stop_and_check(ctx, 1);
}

void test_format_subsecond_timestamp()
{
    flb_ctx_t *ctx;
    int in_ffd, out_ffd;
    char *record = "[1700000000.0625, {\"message\": \"hello world\"}]";

    ctx = flb_create();
    flb_service_set(ctx, "flush", "0.2", "grace", "1", "log_level", "error", NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "chronicle", NULL);
    flb_output_set(ctx, out_ffd,
                   "match", "test",
                   "customer_id", "test-customer",
                   "project_id", "TESTING_FORMAT",
                   "log_type", "TEST_LOG",
                   NULL);

    flb_output_set_test(ctx, out_ffd, "formatter",
                        cb_check_format_subsecond_timestamp, NULL, NULL);

    flb_start(ctx);
    clear_output_invoked();

    flb_lib_push(ctx, in_ffd, record, strlen(record));

    sleep(1);

    stop_and_check(ctx, 1);
}

void test_format_with_log_key_found()
{
    flb_ctx_t *ctx;
    int in_ffd, out_ffd;
    char record[1024];

    ctx = flb_create();
    flb_service_set(ctx, "flush", "0.2", "grace", "1", "log_level", "error", NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "chronicle", NULL);
    flb_output_set(ctx, out_ffd,
                   "match", "test",
                   "customer_id", "test-customer",
                   "project_id", "TESTING_FORMAT",
                   "log_type", "TEST_LOG",
                   "log_key", "message",
                   NULL);

    flb_output_set_test(ctx, out_ffd, "formatter", cb_check_format_with_log_key, NULL, NULL);

    flb_start(ctx);
    clear_output_invoked();

    snprintf(record, sizeof(record) - 1,
             "[%ld, {\"other_key\": \"some value\", \"message\": \"This is the target message.\"}]",
             (long) time(NULL));
    flb_lib_push(ctx, in_ffd, record, strlen(record));

    sleep(1);

    stop_and_check(ctx, 1);
}

void test_format_with_log_key_not_found()
{
    flb_ctx_t *ctx;
    int in_ffd, out_ffd;
    char record[1024];

    ctx = flb_create();
    flb_service_set(ctx, "flush", "0.2", "grace", "1", "log_level", "error", NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "chronicle", NULL);
    flb_output_set(ctx, out_ffd,
                   "match", "test",
                   "customer_id", "test-customer",
                   "project_id", "TESTING_FORMAT",
                   "log_type", "TEST_LOG",
                   "log_key", "non_existent_key",
                   NULL);

    flb_output_set_test(ctx, out_ffd, "formatter", cb_check_format_with_log_key, NULL, NULL);

    flb_start(ctx);
    clear_output_invoked();

    snprintf(record, sizeof(record) - 1, "[%ld, {\"some_other_key\": \"some_value\"}]", (long) time(NULL));
    flb_lib_push(ctx, in_ffd, record, strlen(record));

    sleep(1);

    stop_and_check(ctx, 0);
}


void test_format_multiple_records()
{
    flb_ctx_t *ctx;
    int in_ffd, out_ffd;
    int ret;
    char records[2048];
    time_t now = time(NULL);

    ctx = flb_create();
    flb_service_set(ctx, "flush", "0.2", "grace", "1", "log_level", "error", NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "chronicle", NULL);
    flb_output_set(ctx, out_ffd,
                   "match", "test",
                   "customer_id", "test-customer",
                   "project_id", "TESTING_FORMAT",
                   "log_type", "TEST_LOG",
                   NULL);

    flb_output_set_test(ctx, out_ffd, "formatter", cb_check_format_multiple_records, NULL, NULL);

    flb_start(ctx);
    clear_output_invoked();

    snprintf(records, sizeof(records),
             "[%ld, {\"message\": \"record one\"}]"
             "[%ld, {\"message\": \"record two\"}]",
             (long) now, (long) now + 1);

    /* Submit one batch so a flush cannot run between the records. */
    ret = flb_lib_push(ctx, in_ffd, records, strlen(records));
    TEST_CHECK(ret == strlen(records));

    sleep(1);

    stop_and_check(ctx, 1);
}

void test_format_with_log_key_conversion_error()
{
    flb_ctx_t *ctx;
    int in_ffd, out_ffd;
    int ret;
    int i;
    size_t offset;
    char records[4096];

    ctx = flb_create();
    flb_service_set(ctx, "flush", "0.2", "grace", "1", "log_level", "error", NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "chronicle", NULL);
    flb_output_set(ctx, out_ffd,
                   "match", "test",
                   "customer_id", "test-customer",
                   "project_id", "TESTING_FORMAT",
                   "log_type", "TEST_LOG",
                   "log_key", "message",
                   "namespace", "tenant-a",
                   "label", "env production",
                   NULL);
    flb_output_set_test(ctx, out_ffd, "formatter", cb_check_format_log_key_error, NULL, NULL);

    flb_start(ctx);
    clear_output_invoked();

    /* JSON escaping exceeds the extraction buffer sized from MessagePack. */
    offset = snprintf(records, sizeof(records),
                      "[1, {\"message\": \"record one\"}][2, {\"message\": [\"");
    for (i = 0; i < 256; i++) {
        memcpy(records + offset, "\\u0001", 6);
        offset += 6;
    }
    snprintf(records + offset, sizeof(records) - offset,
             "\"]}][3, {\"message\": \"record three\"}]");

    /* The failing middle record must abort the batch, preserving it for retry. */
    ret = flb_lib_push(ctx, in_ffd, records, strlen(records));
    TEST_CHECK(ret == strlen(records));

    sleep(1);

    stop_and_check(ctx, 1);
}

void test_format_partially_suceeded_records()
{
    flb_ctx_t *ctx;
    int in_ffd, out_ffd;
    int ret;
    char records[2048];
    time_t now = time(NULL);

    ctx = flb_create();
    flb_service_set(ctx, "flush", "0.2", "grace", "1", "log_level", "error", NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "chronicle", NULL);
    flb_output_set(ctx, out_ffd,
                   "match", "test",
                   "customer_id", "test-customer",
                   "project_id", "TESTING_FORMAT",
                   "log_key", "message",
                   "log_type", "TEST_LOG",
                   NULL);

    flb_output_set_test(ctx, out_ffd, "formatter", cb_check_format_partially_succeeded_records, NULL, NULL);

    flb_start(ctx);
    clear_output_invoked();

    snprintf(records, sizeof(records),
             "[%ld, {\"message\": \"record one\"}]"
             "[%ld, {\"test\": \"record two\"}]",
             (long) now, (long) now + 1);

    /* Keep the valid and invalid records in the same formatter input. */
    ret = flb_lib_push(ctx, in_ffd, records, strlen(records));
    TEST_CHECK(ret == strlen(records));

    sleep(1);

    stop_and_check(ctx, 1);
}

void test_format_namespace_and_labels()
{
    flb_ctx_t *ctx;
    int in_ffd, out_ffd;
    char record[1024];

    ctx = flb_create();
    flb_service_set(ctx, "flush", "0.2", "grace", "1", "log_level", "error", NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "chronicle", NULL);
    flb_output_set(ctx, out_ffd,
                   "match", "test",
                   "customer_id", "test-customer",
                   "project_id", "TESTING_FORMAT",
                   "log_type", "TEST_LOG",
                   "namespace_key", "$tenant_namespace",
                   "namespace", "fallback-namespace",
                   "label", "env production",
                   "label", "cluster_name $cluster['name']",
                   NULL);

    flb_output_set_test(ctx, out_ffd, "formatter",
                        cb_check_format_namespace_and_labels, NULL, NULL);

    flb_start(ctx);
    clear_output_invoked();

    snprintf(record, sizeof(record) - 1,
             "[%ld, {\"message\": \"hello world\", \"tenant_namespace\": \"tenant-a\", "
             "\"cluster\": {\"name\": \"blue\"}}]",
             (long) time(NULL));
    flb_lib_push(ctx, in_ffd, record, strlen(record));

    sleep(1);

    stop_and_check(ctx, 1);
}

void test_format_namespace_fallback_and_missing_label()
{
    flb_ctx_t *ctx;
    int in_ffd, out_ffd;
    char record[1024];

    ctx = flb_create();
    flb_service_set(ctx, "flush", "0.2", "grace", "1", "log_level", "error", NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "chronicle", NULL);
    flb_output_set(ctx, out_ffd,
                   "match", "test",
                   "customer_id", "test-customer",
                   "project_id", "TESTING_FORMAT",
                   "log_type", "TEST_LOG",
                   "namespace", "fallback-namespace",
                   "namespace_key", "$tenant_namespace",
                   "label", "missing $cluster['name']",
                   NULL);

    flb_output_set_test(ctx, out_ffd, "formatter",
                        cb_check_format_namespace_fallback_and_missing_label, NULL, NULL);

    flb_start(ctx);
    clear_output_invoked();

    snprintf(record, sizeof(record) - 1,
             "[%ld, {\"message\": \"hello world\"}]",
             (long) time(NULL));
    flb_lib_push(ctx, in_ffd, record, strlen(record));

    sleep(1);

    stop_and_check(ctx, 1);
}

void test_format_split_on_metadata_change()
{
    flb_ctx_t *ctx;
    int in_ffd, out_ffd;
    int ret;
    char records[2048];
    time_t now = time(NULL);

    ctx = flb_create();
    flb_service_set(ctx, "flush", "0.2", "grace", "1", "log_level", "error", NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "chronicle", NULL);
    flb_output_set(ctx, out_ffd,
                   "match", "test",
                   "customer_id", "test-customer",
                   "project_id", "TESTING_FORMAT",
                   "log_type", "TEST_LOG",
                   "namespace_key", "$tenant_namespace",
                   "label", "cluster_name $cluster['name']",
                   NULL);

    flb_output_set_test(ctx, out_ffd, "formatter",
                        cb_check_format_split_on_metadata_change, NULL, NULL);

    flb_start(ctx);
    clear_output_invoked();

    snprintf(records, sizeof(records),
             "[%ld, {\"message\": \"record one\", \"tenant_namespace\": \"tenant-a\", "
             "\"cluster\": {\"name\": \"blue\"}}]"
             "[%ld, {\"message\": \"record two\", \"tenant_namespace\": \"tenant-b\", "
             "\"cluster\": {\"name\": \"green\"}}]",
             (long) now, (long) now + 1);

    /* Exercise metadata splitting within one formatter input. */
    ret = flb_lib_push(ctx, in_ffd, records, strlen(records));
    TEST_CHECK(ret == strlen(records));

    sleep(1);

    stop_and_check(ctx, 2);
}

void test_format_chronicle_api()
{
    flb_ctx_t *ctx;
    int in_ffd, out_ffd;
    char *record = "[1700000000.0625, {\"message\": \"hello world\"}]";

    ctx = flb_create();
    flb_service_set(ctx, "flush", "0.2", "grace", "1", "log_level", "error", NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "chronicle", NULL);
    flb_output_set(ctx, out_ffd,
                   "match", "test",
                   "api", "chronicle",
                   "region", "EUROPE-WEST2",
                   "customer_id", "test-customer",
                   "project_id", "TESTING_FORMAT",
                   "log_type", "TEST_LOG",
                   NULL);

    flb_output_set_test(ctx, out_ffd, "formatter",
                        cb_check_format_chronicle_api, NULL, NULL);

    flb_start(ctx);
    clear_output_invoked();

    flb_lib_push(ctx, in_ffd, record, strlen(record));

    sleep(1);

    stop_and_check(ctx, 1);
}

void test_format_chronicle_api_log_key()
{
    flb_ctx_t *ctx;
    int in_ffd, out_ffd;
    char record[1024];

    ctx = flb_create();
    flb_service_set(ctx, "flush", "0.2", "grace", "1", "log_level", "error", NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "chronicle", NULL);
    flb_output_set(ctx, out_ffd,
                   "match", "test",
                   "api", "chronicle",
                   "customer_id", "test-customer",
                   "project_id", "TESTING_FORMAT",
                   "log_type", "TEST_LOG",
                   "log_key", "message",
                   NULL);

    flb_output_set_test(ctx, out_ffd, "formatter",
                        cb_check_format_chronicle_api_log_key, NULL, NULL);

    flb_start(ctx);
    clear_output_invoked();

    snprintf(record, sizeof(record) - 1,
             "[%ld, {\"other_key\": \"some value\", \"message\": \"This is the target message.\"}]",
             (long) time(NULL));
    flb_lib_push(ctx, in_ffd, record, strlen(record));

    sleep(1);

    stop_and_check(ctx, 1);
}

void test_format_chronicle_api_namespace_and_labels()
{
    flb_ctx_t *ctx;
    int in_ffd, out_ffd;
    char record[1024];

    ctx = flb_create();
    flb_service_set(ctx, "flush", "0.2", "grace", "1", "log_level", "error", NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "chronicle", NULL);
    flb_output_set(ctx, out_ffd,
                   "match", "test",
                   "api", "chronicle",
                   "customer_id", "test-customer",
                   "project_id", "TESTING_FORMAT",
                   "log_type", "TEST_LOG",
                   "namespace_key", "$tenant_namespace",
                   "namespace", "fallback-namespace",
                   "label", "env production",
                   "label", "cluster_name $cluster['name']",
                   NULL);

    flb_output_set_test(ctx, out_ffd, "formatter",
                        cb_check_format_chronicle_api_namespace_and_labels,
                        NULL, NULL);

    flb_start(ctx);
    clear_output_invoked();

    snprintf(record, sizeof(record) - 1,
             "[%ld, {\"message\": \"hello world\", \"tenant_namespace\": \"tenant-a\", "
             "\"cluster\": {\"name\": \"blue\"}}]",
             (long) time(NULL));
    flb_lib_push(ctx, in_ffd, record, strlen(record));

    sleep(1);

    stop_and_check(ctx, 1);
}

void test_format_chronicle_api_future_timestamp()
{
    flb_ctx_t *ctx;
    int in_ffd, out_ffd;
    /* A future record whose collection time crosses a second boundary */
    char *record = "[4102444800.999755859375, {\"message\": \"hello world\"}]";

    ctx = flb_create();
    flb_service_set(ctx, "flush", "0.2", "grace", "1", "log_level", "error", NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "chronicle", NULL);
    flb_output_set(ctx, out_ffd,
                   "match", "test",
                   "api", "chronicle",
                   "customer_id", "test-customer",
                   "project_id", "TESTING_FORMAT",
                   "log_type", "TEST_LOG",
                   NULL);

    flb_output_set_test(ctx, out_ffd, "formatter",
                        cb_check_format_chronicle_api_future_timestamp, NULL, NULL);

    flb_start(ctx);
    clear_output_invoked();

    flb_lib_push(ctx, in_ffd, record, strlen(record));

    sleep(1);

    stop_and_check(ctx, 1);
}

static flb_ctx_t *create_chronicle_api_ctx(int *out_ffd)
{
    flb_ctx_t *ctx;
    int in_ffd;

    ctx = flb_create();
    flb_service_set(ctx, "flush", "0.2", "grace", "1", "log_level", "error", NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    *out_ffd = flb_output(ctx, (char *) "chronicle", NULL);
    flb_output_set(ctx, *out_ffd,
                   "match", "test",
                   "customer_id", "test-customer",
                   "project_id", "TESTING_FORMAT",
                   NULL);

    return ctx;
}

static void check_start_error(flb_ctx_t *ctx, int out_ffd, const char *reason)
{
    int ret;

    /* The test formatter enables the test mode, so credentials are skipped */
    flb_output_set_test(ctx, out_ffd, "formatter",
                        cb_check_format_chronicle_api, NULL, NULL);

    ret = flb_start(ctx);
    if (!TEST_CHECK(ret != 0)) {
        TEST_MSG("%s", reason);
        flb_stop(ctx);
    }

    flb_destroy(ctx);
}

void test_chronicle_api_invalid_api()
{
    flb_ctx_t *ctx;
    int out_ffd;

    ctx = create_chronicle_api_ctx(&out_ffd);
    flb_output_set(ctx, out_ffd,
                   "api", "backstory",
                   "log_type", "TEST_LOG",
                   NULL);

    check_start_error(ctx, out_ffd, "an unknown api must be rejected");
}

void test_chronicle_api_invalid_region()
{
    flb_ctx_t *ctx;
    int out_ffd;

    ctx = create_chronicle_api_ctx(&out_ffd);
    flb_output_set(ctx, out_ffd,
                   "api", "chronicle",
                   "region", "us.example.com/",
                   "log_type", "TEST_LOG",
                   NULL);

    check_start_error(ctx, out_ffd, "a region that is not a hostname label must be rejected");
}

void test_chronicle_api_invalid_log_type()
{
    flb_ctx_t *ctx;
    int out_ffd;

    ctx = create_chronicle_api_ctx(&out_ffd);
    flb_output_set(ctx, out_ffd,
                   "api", "chronicle",
                   "log_type", "TEST_LOG/../../other",
                   NULL);

    check_start_error(ctx, out_ffd, "a log_type that is not a path segment must be rejected");
}

struct response_case {
    int status;
    int result;
};

static int last_response_result = -1;

static void cb_store_response_result(void *ctx, int ffd,
                                     int res_ret, void *res_data,
                                     size_t res_size, void *data)
{
    pthread_mutex_lock(&result_mutex);
    last_response_result = res_ret;
    pthread_mutex_unlock(&result_mutex);
}

static void check_response_results(const char *api,
                                   struct response_case *cases, int count)
{
    flb_ctx_t *ctx;
    int i;
    int ret;
    int in_ffd, out_ffd;
    int result;

    ctx = flb_create();
    flb_service_set(ctx, "flush", "0.2", "grace", "1", "log_level", "error", NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "chronicle", NULL);
    flb_output_set(ctx, out_ffd,
                   "match", "test",
                   "api", api,
                   "customer_id", "test-customer",
                   "project_id", "TESTING_FORMAT",
                   "log_type", "TEST_LOG",
                   NULL);

    ret = flb_output_set_http_test(ctx, out_ffd, "response",
                                   cb_store_response_result, NULL);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    for (i = 0; i < count; i++) {
        ret = flb_lib_response(ctx, out_ffd, cases[i].status, "{}", 2);
        TEST_CHECK(ret == 0);

        pthread_mutex_lock(&result_mutex);
        result = last_response_result;
        pthread_mutex_unlock(&result_mutex);

        if (!TEST_CHECK(result == cases[i].result)) {
            TEST_MSG("api=%s status=%d: got %d, expected %d",
                     api, cases[i].status, result, cases[i].result);
        }
    }

    flb_stop(ctx);
    flb_destroy(ctx);
}

void test_chronicle_api_response_status()
{
    /* Client errors are not retried, except for auth, timeout and quota */
    struct response_case cases[] = {
        { 200, FLB_OK },
        { 400, FLB_ERROR },
        { 401, FLB_RETRY },
        { 403, FLB_ERROR },
        { 404, FLB_ERROR },
        { 408, FLB_RETRY },
        { 429, FLB_RETRY },
        { 500, FLB_RETRY },
        { 503, FLB_RETRY },
    };

    check_response_results("chronicle", cases, sizeof(cases) / sizeof(cases[0]));
}

void test_legacy_api_response_status()
{
    /* The legacy API keeps retrying every failed request */
    struct response_case cases[] = {
        { 200, FLB_OK },
        { 400, FLB_RETRY },
        { 404, FLB_RETRY },
        { 503, FLB_RETRY },
    };

    check_response_results("legacy", cases, sizeof(cases) / sizeof(cases[0]));
}

void test_chronicle_api_duplicate_label()
{
    flb_ctx_t *ctx;
    int out_ffd;

    ctx = create_chronicle_api_ctx(&out_ffd);
    flb_output_set(ctx, out_ffd,
                   "api", "chronicle",
                   "log_type", "TEST_LOG",
                   "label", "env production",
                   "label", "env staging",
                   NULL);

    check_start_error(ctx, out_ffd, "duplicate label keys must be rejected");
}


TEST_LIST = {
    { "format_no_log_key",           test_format_no_log_key },
    { "format_subsecond_timestamp",  test_format_subsecond_timestamp },
    { "format_with_log_key_found",   test_format_with_log_key_found },
    { "format_with_log_key_not_found", test_format_with_log_key_not_found },
    { "format_with_log_key_conversion_error", test_format_with_log_key_conversion_error },
    { "format_multiple_records",     test_format_multiple_records },
    { "format_partially_suceeded_records", test_format_partially_suceeded_records },
    { "format_namespace_and_labels", test_format_namespace_and_labels },
    { "format_namespace_fallback_and_missing_label",
      test_format_namespace_fallback_and_missing_label },
    { "format_split_on_metadata_change", test_format_split_on_metadata_change },
    { "format_chronicle_api",        test_format_chronicle_api },
    { "format_chronicle_api_log_key", test_format_chronicle_api_log_key },
    { "format_chronicle_api_namespace_and_labels",
      test_format_chronicle_api_namespace_and_labels },
    { "format_chronicle_api_future_timestamp",
      test_format_chronicle_api_future_timestamp },
    { "chronicle_api_invalid_api",   test_chronicle_api_invalid_api },
    { "chronicle_api_invalid_region", test_chronicle_api_invalid_region },
    { "chronicle_api_invalid_log_type", test_chronicle_api_invalid_log_type },
    { "chronicle_api_duplicate_label", test_chronicle_api_duplicate_label },
    { "chronicle_api_response_status", test_chronicle_api_response_status },
    { "legacy_api_response_status",  test_legacy_api_response_status },
    { NULL, NULL }
};
