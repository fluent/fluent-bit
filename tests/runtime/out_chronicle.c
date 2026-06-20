/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit.h>
#include "flb_tests_runtime.h"


pthread_mutex_t result_mutex = PTHREAD_MUTEX_INITIALIZER;
int num_invoked = 0;
static int get_output_invoked()
{
    int ret;
    pthread_mutex_lock(&result_mutex);
    ret = num_invoked;
    pthread_mutex_unlock(&result_mutex);

    return ret;
}

static void set_output_invoked(int num)
{
    pthread_mutex_lock(&result_mutex);
    num_invoked = num;
    pthread_mutex_unlock(&result_mutex);
}

static void clear_output_invoked()
{
    set_output_invoked(0);
}

static void cb_check_format_no_log_key(void *ctx, int ffd,
                                       int res_ret, void *res_data,
                                       size_t res_size, void *data)
{
    char *out_json = res_data;
    char *p;

    set_output_invoked(1);

    p = strstr(out_json, "\"customer_id\":\"test-customer\"");
    if (!TEST_CHECK(p != NULL)) {
        TEST_MSG("Expected customer_id not found. Got: %s", out_json);
    }

    p = strstr(out_json, "\"log_type\":\"TEST_LOG\"");
    if (!TEST_CHECK(p != NULL)) {
        TEST_MSG("Expected log_type not found. Got: %s", out_json);
    }

    p = strstr(out_json, "\"entries\":[");
    if (!TEST_CHECK(p != NULL)) {
        TEST_MSG("Entries array not found. Got: %s", out_json);
    }

    p = strstr(out_json, "\"log_text\":\"{\\\"message\\\":\\\"hello world\\\"}\"");
    if (!TEST_CHECK(p != NULL)) {
        TEST_MSG("Expected log_text not found. Got: %s", out_json);
    }

    p = strstr(out_json, "\"ts_rfc3339\":");
    if (!TEST_CHECK(p != NULL)) {
        TEST_MSG("Expected ts_rfc3339 key not found. Got: %s", out_json);
    }

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

    set_output_invoked(1);

    p = strstr(out_json, "\"log_text\":\"This is the target message.\"");
    if (!TEST_CHECK(p != NULL)) {
        TEST_MSG("Expected log_text with specific value not found. Got: %s", out_json);
    }

    p = strstr(out_json, "other_key");
    TEST_CHECK(p == NULL);

    flb_sds_destroy(res_data);
}

static void cb_check_format_multiple_records(void *ctx, int ffd,
                                             int res_ret, void *res_data,
                                             size_t res_size, void *data)
{
    char *out_json = res_data;
    char *p1, *p2;

    set_output_invoked(1);

    p1 = strstr(out_json, "\"log_text\":\"{\\\"message\\\":\\\"record one\\\"}\"");
    if (!TEST_CHECK(p1 != NULL)) {
        TEST_MSG("First record not found. Got: %s", out_json);
    }

    p2 = strstr(out_json, "\"log_text\":\"{\\\"message\\\":\\\"record two\\\"}\"");
    if (!TEST_CHECK(p2 != NULL)) {
        TEST_MSG("Second record not found. Got: %s", out_json);
    }

    flb_sds_destroy(res_data);
}

static void cb_check_format_partially_succeeded_records(void *ctx, int ffd,
                                                        int res_ret, void *res_data,
                                                        size_t res_size, void *data)
{
    char *out_json = res_data;
    char *p1, *p2;

    set_output_invoked(1);

    p1 = strstr(out_json, "\"log_text\":\"record one\"");
    if (!TEST_CHECK(p1 != NULL)) {
        TEST_MSG("Expected log_text with specific value not found. Got: %s", out_json);
    }

    p2 = strstr(out_json, "\"test\"");
    TEST_CHECK(p2 == NULL);

    flb_sds_destroy(res_data);
}

static void cb_check_format_namespace_and_labels(void *ctx, int ffd,
                                                 int res_ret, void *res_data,
                                                 size_t res_size, void *data)
{
    char *out_json = res_data;
    char *p;

    set_output_invoked(1);

    p = strstr(out_json, "\"namespace\":\"tenant-a\"");
    if (!TEST_CHECK(p != NULL)) {
        TEST_MSG("Expected namespace not found. Got: %s", out_json);
    }

    p = strstr(out_json, "\"labels\":[");
    if (!TEST_CHECK(p != NULL)) {
        TEST_MSG("Expected labels array not found. Got: %s", out_json);
    }

    p = strstr(out_json, "\"key\":\"env\"");
    if (!TEST_CHECK(p != NULL)) {
        TEST_MSG("Expected static label key not found. Got: %s", out_json);
    }

    p = strstr(out_json, "\"value\":\"production\"");
    if (!TEST_CHECK(p != NULL)) {
        TEST_MSG("Expected static label value not found. Got: %s", out_json);
    }

    p = strstr(out_json, "\"key\":\"cluster_name\"");
    if (!TEST_CHECK(p != NULL)) {
        TEST_MSG("Expected dynamic label key not found. Got: %s", out_json);
    }

    p = strstr(out_json, "\"value\":\"blue\"");
    if (!TEST_CHECK(p != NULL)) {
        TEST_MSG("Expected dynamic label value not found. Got: %s", out_json);
    }

    flb_sds_destroy(res_data);
}

static void cb_check_format_namespace_fallback_and_missing_label(void *ctx, int ffd,
                                                                 int res_ret, void *res_data,
                                                                 size_t res_size, void *data)
{
    char *out_json = res_data;
    char *p;

    set_output_invoked(1);

    p = strstr(out_json, "\"namespace\":\"fallback-namespace\"");
    if (!TEST_CHECK(p != NULL)) {
        TEST_MSG("Expected fallback namespace not found. Got: %s", out_json);
    }

    p = strstr(out_json, "\"key\":\"missing\"");
    TEST_CHECK(p == NULL);

    p = strstr(out_json, "\"log_text\":\"{\\\"message\\\":\\\"hello world\\\"}\"");
    if (!TEST_CHECK(p != NULL)) {
        TEST_MSG("Expected log_text not found. Got: %s", out_json);
    }

    flb_sds_destroy(res_data);
}

static void cb_check_format_split_on_metadata_change(void *ctx, int ffd,
                                                     int res_ret, void *res_data,
                                                     size_t res_size, void *data)
{
    char *out_json = res_data;
    char *p;
    int invocation;

    invocation = get_output_invoked() + 1;
    set_output_invoked(invocation);

    if (invocation == 1) {
        p = strstr(out_json, "\"namespace\":\"tenant-a\"");
        if (!TEST_CHECK(p != NULL)) {
            TEST_MSG("Expected first namespace not found. Got: %s", out_json);
        }

        p = strstr(out_json, "\"value\":\"blue\"");
        if (!TEST_CHECK(p != NULL)) {
            TEST_MSG("Expected first dynamic label value not found. Got: %s", out_json);
        }

        p = strstr(out_json, "\"log_text\":\"{\\\"message\\\":\\\"record one\\\"");
        if (!TEST_CHECK(p != NULL)) {
            TEST_MSG("Expected first record not found. Got: %s", out_json);
        }

        p = strstr(out_json, "tenant-b");
        TEST_CHECK(p == NULL);

        p = strstr(out_json, "green");
        TEST_CHECK(p == NULL);

        p = strstr(out_json, "record two");
        TEST_CHECK(p == NULL);
    }
    else if (invocation == 2) {
        p = strstr(out_json, "\"namespace\":\"tenant-b\"");
        if (!TEST_CHECK(p != NULL)) {
            TEST_MSG("Expected second namespace not found. Got: %s", out_json);
        }

        p = strstr(out_json, "\"value\":\"green\"");
        if (!TEST_CHECK(p != NULL)) {
            TEST_MSG("Expected second dynamic label value not found. Got: %s", out_json);
        }

        p = strstr(out_json, "\"log_text\":\"{\\\"message\\\":\\\"record two\\\"");
        if (!TEST_CHECK(p != NULL)) {
            TEST_MSG("Expected second record not found. Got: %s", out_json);
        }
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

    TEST_CHECK(get_output_invoked() == 1);
    flb_stop(ctx);
    flb_destroy(ctx);
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

    TEST_CHECK(get_output_invoked() == 1);
    flb_stop(ctx);
    flb_destroy(ctx);
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

    TEST_CHECK(get_output_invoked() == 0);
    flb_stop(ctx);
    flb_destroy(ctx);
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

    TEST_CHECK(get_output_invoked() == 1);
    flb_stop(ctx);
    flb_destroy(ctx);
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

    TEST_CHECK(get_output_invoked() == 1);
    flb_stop(ctx);
    flb_destroy(ctx);
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

    TEST_CHECK(get_output_invoked() == 1);
    flb_stop(ctx);
    flb_destroy(ctx);
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

    TEST_CHECK(get_output_invoked() == 1);
    flb_stop(ctx);
    flb_destroy(ctx);
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

    TEST_CHECK(get_output_invoked() == 1);
    flb_stop(ctx);
    flb_destroy(ctx);
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
