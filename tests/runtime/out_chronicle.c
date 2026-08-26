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
    char record1[1024];
    char record2[1024];
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

    snprintf(record1, sizeof(record1) - 1, "[%ld, {\"message\": \"record one\"}]", (long) now);
    snprintf(record2, sizeof(record2) - 1, "[%ld, {\"message\": \"record two\"}]", (long) now + 1);

    flb_lib_push(ctx, in_ffd, record1, strlen(record1));
    flb_lib_push(ctx, in_ffd, record2, strlen(record2));

    sleep(1);

    stop_and_check(ctx, 1);
}

void test_format_partially_suceeded_records()
{
    flb_ctx_t *ctx;
    int in_ffd, out_ffd;
    char record1[1024];
    char record2[1024];
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

    snprintf(record1, sizeof(record1) - 1, "[%ld, {\"message\": \"record one\"}]", (long) now);
    snprintf(record2, sizeof(record2) - 1, "[%ld, {\"test\": \"record two\"}]", (long) now + 1);

    flb_lib_push(ctx, in_ffd, record1, strlen(record1));
    flb_lib_push(ctx, in_ffd, record2, strlen(record2));

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
    char record1[1024];
    char record2[1024];
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

    snprintf(record1, sizeof(record1) - 1,
             "[%ld, {\"message\": \"record one\", \"tenant_namespace\": \"tenant-a\", "
             "\"cluster\": {\"name\": \"blue\"}}]",
             (long) now);
    snprintf(record2, sizeof(record2) - 1,
             "[%ld, {\"message\": \"record two\", \"tenant_namespace\": \"tenant-b\", "
             "\"cluster\": {\"name\": \"green\"}}]",
             (long) now + 1);

    flb_lib_push(ctx, in_ffd, record1, strlen(record1));
    flb_lib_push(ctx, in_ffd, record2, strlen(record2));

    sleep(1);

    stop_and_check(ctx, 1);
}


TEST_LIST = {
    { "format_no_log_key",           test_format_no_log_key },
    { "format_with_log_key_found",   test_format_with_log_key_found },
    { "format_with_log_key_not_found", test_format_with_log_key_not_found },
    { "format_multiple_records",     test_format_multiple_records },
    { "format_partially_suceeded_records", test_format_partially_suceeded_records },
    { "format_namespace_and_labels", test_format_namespace_and_labels },
    { "format_namespace_fallback_and_missing_label",
      test_format_namespace_fallback_and_missing_label },
    { "format_split_on_metadata_change", test_format_split_on_metadata_change },
    { NULL, NULL }
};
