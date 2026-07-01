/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
#include <fluent-bit.h>
#include "flb_tests_runtime.h"

#include "data/td/json_td.h"

/* Local 'test' credentials file */
#define SERVICE_CREDENTIALS \
    FLB_TESTS_DATA_PATH "/data/stackdriver/stackdriver-credentials.json"

void flb_test_gcs_upload_success(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    char *call_count_str;
    int call_count;
    char store_dir[] = "/tmp/flb-gcs-test-success-XXXXXX";

    TEST_CHECK(mkdtemp(store_dir) != NULL);

    setenv("FLB_GCS_PLUGIN_UNDER_TEST", "true", 1);

    ctx = flb_create();

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "gcs", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "*", NULL);
    flb_output_set(ctx, out_ffd, "bucket", "fluent", NULL);
    flb_output_set(ctx, out_ffd, "google_service_credentials", SERVICE_CREDENTIALS, NULL);
    flb_output_set(ctx, out_ffd, "upload_timeout", "3s", NULL);
    flb_output_set(ctx, out_ffd, "store_dir", store_dir, NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    flb_lib_push(ctx, in_ffd, (char *) JSON_TD, (int) sizeof(JSON_TD) - 1);
    sleep(5);

    call_count_str = getenv("TEST_GCS_UploadObject_CALL_COUNT");
    call_count = call_count_str ? atoi(call_count_str) : 0;
    TEST_CHECK_(call_count == 1,
                "Expected 1 UploadObject call, got %d", call_count);

    flb_stop(ctx);
    flb_destroy(ctx);

    unsetenv("FLB_GCS_PLUGIN_UNDER_TEST");
    unsetenv("TEST_GCS_UploadObject_CALL_COUNT");
}

void flb_test_gcs_upload_error(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    char *call_count_str;
    int call_count;
    char store_dir[] = "/tmp/flb-gcs-test-error-XXXXXX";

    TEST_CHECK(mkdtemp(store_dir) != NULL);

    setenv("FLB_GCS_PLUGIN_UNDER_TEST", "true", 1);
    setenv("TEST_GCS_UPLOAD_ERROR", "true", 1);

    ctx = flb_create();

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "gcs", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "*", NULL);
    flb_output_set(ctx, out_ffd, "bucket", "fluent", NULL);
    flb_output_set(ctx, out_ffd, "google_service_credentials", SERVICE_CREDENTIALS, NULL);
    flb_output_set(ctx, out_ffd, "upload_timeout", "3s", NULL);
    flb_output_set(ctx, out_ffd, "store_dir", store_dir, NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    flb_lib_push(ctx, in_ffd, (char *) JSON_TD, (int) sizeof(JSON_TD) - 1);
    sleep(6);

    call_count_str = getenv("TEST_GCS_UploadObject_CALL_COUNT");
    call_count = call_count_str ? atoi(call_count_str) : 0;
    TEST_CHECK_(call_count >= 1,
                "Expected >=1 UploadObject calls, got %d", call_count);

    flb_stop(ctx);
    flb_destroy(ctx);

    unsetenv("FLB_GCS_PLUGIN_UNDER_TEST");
    unsetenv("TEST_GCS_UPLOAD_ERROR");
    unsetenv("TEST_GCS_UploadObject_CALL_COUNT");
}

TEST_LIST = {
    {"upload_success", flb_test_gcs_upload_success},
    {"upload_error", flb_test_gcs_upload_error},
    {NULL, NULL}
};
