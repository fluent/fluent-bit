/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
#include <fluent-bit.h>
#include "flb_tests_runtime.h"

/* Test data */
#include "data/td/json_td.h" /* JSON_TD */

/* not a real error code, but tests that the code can respond to any error */
#define ERROR_ACCESS_DENIED "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
                            <Error>\
                            <Code>AccessDenied</Code>\
                            <Message>Access Denied</Message>\
                            <RequestId>656c76696e6727732072657175657374</RequestId>\
                            <HostId>Uuag1LuByRx9e6j5Onimru9pO4ZVKnJ2Qz7/C1NPcfTWAtRPfTaOFg==</HostId>\
                            </Error>"

void flb_test_s3_multipart_success(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    char *call_count_str;
    int call_count;
    char store_dir[] = "/tmp/flb-s3-test-XXXXXX";

    TEST_CHECK(mkdtemp(store_dir) != NULL);

    /* mocks calls- signals that we are in test mode */
    setenv("FLB_S3_PLUGIN_UNDER_TEST", "true", 1);

    ctx = flb_create();

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx,in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "s3", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd,"match", "*", NULL);
    flb_output_set(ctx, out_ffd,"region", "us-west-2", NULL);
    flb_output_set(ctx, out_ffd,"bucket", "fluent", NULL);
    flb_output_set(ctx, out_ffd,"upload_timeout", "6s", NULL);
    flb_output_set(ctx, out_ffd,"store_dir", store_dir, NULL);
    flb_output_set(ctx, out_ffd,"Retry_Limit", "1", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    flb_lib_push(ctx, in_ffd, (char *) JSON_TD , (int) sizeof(JSON_TD) - 1);

    sleep(10);

    call_count_str = getenv("TEST_CompleteMultipartUpload_CALL_COUNT");
    call_count = call_count_str ? atoi(call_count_str) : 0;
    TEST_CHECK_(call_count == 1,
                "Expected 1 CompleteMultipartUpload call, got %d", call_count);

    flb_stop(ctx);
    flb_destroy(ctx);
    unsetenv("FLB_S3_PLUGIN_UNDER_TEST");
    unsetenv("TEST_CreateMultipartUpload_CALL_COUNT");
    unsetenv("TEST_UploadPart_CALL_COUNT");
    unsetenv("TEST_CompleteMultipartUpload_CALL_COUNT");
    unsetenv("TEST_PutObject_CALL_COUNT");
}

void flb_test_s3_putobject_success(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    char *call_count_str;
    int call_count;

    /* mocks calls- signals that we are in test mode */
    setenv("FLB_S3_PLUGIN_UNDER_TEST", "true", 1);

    ctx = flb_create();

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx,in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "s3", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd,"match", "*", NULL);
    flb_output_set(ctx, out_ffd,"region", "us-west-2", NULL);
    flb_output_set(ctx, out_ffd,"bucket", "fluent", NULL);
    flb_output_set(ctx, out_ffd,"use_put_object", "true", NULL);
    flb_output_set(ctx, out_ffd,"total_file_size", "5M", NULL);
    flb_output_set(ctx, out_ffd,"upload_timeout", "6s", NULL);
    flb_output_set(ctx, out_ffd,"Retry_Limit", "1", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    flb_lib_push(ctx, in_ffd, (char *) JSON_TD , (int) sizeof(JSON_TD) - 1);


    sleep(10);

    call_count_str = getenv("TEST_PutObject_CALL_COUNT");
    call_count = call_count_str ? atoi(call_count_str) : 0;
    TEST_CHECK_(call_count == 1,
                "Expected 1 PutObject call, got %d", call_count);

    flb_stop(ctx);
    flb_destroy(ctx);
    unsetenv("FLB_S3_PLUGIN_UNDER_TEST");
    unsetenv("TEST_PutObject_CALL_COUNT");
}

void flb_test_s3_putobject_error(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    char *call_count_str;
    int call_count;

    /* mocks calls- signals that we are in test mode */
    setenv("FLB_S3_PLUGIN_UNDER_TEST", "true", 1);
    setenv("TEST_PUT_OBJECT_ERROR", ERROR_ACCESS_DENIED, 1);

    ctx = flb_create();

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx,in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "s3", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd,"match", "*", NULL);
    flb_output_set(ctx, out_ffd,"region", "us-west-2", NULL);
    flb_output_set(ctx, out_ffd,"bucket", "fluent", NULL);
    flb_output_set(ctx, out_ffd,"use_put_object", "true", NULL);
    flb_output_set(ctx, out_ffd,"total_file_size", "5M", NULL);
    flb_output_set(ctx, out_ffd,"upload_timeout", "6s", NULL);
    flb_output_set(ctx, out_ffd,"Retry_Limit", "1", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    flb_lib_push(ctx, in_ffd, (char *) JSON_TD , (int) sizeof(JSON_TD) - 1);


    sleep(10);

    call_count_str = getenv("TEST_PutObject_CALL_COUNT");
    call_count = call_count_str ? atoi(call_count_str) : 0;
    TEST_CHECK_(call_count >= 1,
                "Expected >= 1 PutObject calls, got %d", call_count);

    flb_stop(ctx);
    flb_destroy(ctx);
    unsetenv("FLB_S3_PLUGIN_UNDER_TEST");
    unsetenv("TEST_PUT_OBJECT_ERROR");
    unsetenv("TEST_PutObject_CALL_COUNT");

}

void flb_test_s3_create_upload_error(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    char *call_count_str;
    int call_count;
    char store_dir[] = "/tmp/flb-s3-test-XXXXXX";

    TEST_CHECK(mkdtemp(store_dir) != NULL);

    /* mocks calls- signals that we are in test mode */
    setenv("FLB_S3_PLUGIN_UNDER_TEST", "true", 1);
    setenv("TEST_CREATE_MULTIPART_UPLOAD_ERROR", ERROR_ACCESS_DENIED, 1);

    ctx = flb_create();

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx,in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "s3", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd,"match", "*", NULL);
    flb_output_set(ctx, out_ffd,"region", "us-west-2", NULL);
    flb_output_set(ctx, out_ffd,"bucket", "fluent", NULL);
    flb_output_set(ctx, out_ffd,"upload_timeout", "6s", NULL);
    flb_output_set(ctx, out_ffd,"store_dir", store_dir, NULL);
    flb_output_set(ctx, out_ffd,"Retry_Limit", "1", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    flb_lib_push(ctx, in_ffd, (char *) JSON_TD , (int) sizeof(JSON_TD) - 1);

    sleep(10);

    call_count_str = getenv("TEST_CreateMultipartUpload_CALL_COUNT");
    call_count = call_count_str ? atoi(call_count_str) : 0;
    TEST_CHECK_(call_count >= 1,
                "Expected >= 1 CreateMultipartUpload calls, got %d", call_count);

    call_count_str = getenv("TEST_UploadPart_CALL_COUNT");
    call_count = call_count_str ? atoi(call_count_str) : 0;
    TEST_CHECK_(call_count == 0,
                "Expected 0 UploadPart calls, got %d", call_count);

    flb_stop(ctx);
    flb_destroy(ctx);
    unsetenv("FLB_S3_PLUGIN_UNDER_TEST");
    unsetenv("TEST_CREATE_MULTIPART_UPLOAD_ERROR");
    unsetenv("TEST_CreateMultipartUpload_CALL_COUNT");
    unsetenv("TEST_UploadPart_CALL_COUNT");
    unsetenv("TEST_CompleteMultipartUpload_CALL_COUNT");
    unsetenv("TEST_PutObject_CALL_COUNT");
}

void flb_test_s3_upload_part_error(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    char *call_count_str;
    int call_count;
    char store_dir[] = "/tmp/flb-s3-test-XXXXXX";

    TEST_CHECK(mkdtemp(store_dir) != NULL);

    /* mocks calls- signals that we are in test mode */
    setenv("FLB_S3_PLUGIN_UNDER_TEST", "true", 1);
    setenv("TEST_UPLOAD_PART_ERROR", ERROR_ACCESS_DENIED, 1);

    ctx = flb_create();

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx,in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "s3", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd,"match", "*", NULL);
    flb_output_set(ctx, out_ffd,"region", "us-west-2", NULL);
    flb_output_set(ctx, out_ffd,"bucket", "fluent", NULL);
    flb_output_set(ctx, out_ffd,"upload_timeout", "6s", NULL);
    flb_output_set(ctx, out_ffd,"store_dir", store_dir, NULL);
    flb_output_set(ctx, out_ffd,"Retry_Limit", "1", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    flb_lib_push(ctx, in_ffd, (char *) JSON_TD , (int) sizeof(JSON_TD) - 1);

    sleep(10);

    call_count_str = getenv("TEST_UploadPart_CALL_COUNT");
    call_count = call_count_str ? atoi(call_count_str) : 0;
    TEST_CHECK_(call_count >= 1,
                "Expected >= 1 UploadPart calls, got %d", call_count);

    call_count_str = getenv("TEST_CompleteMultipartUpload_CALL_COUNT");
    call_count = call_count_str ? atoi(call_count_str) : 0;
    TEST_CHECK_(call_count == 0,
                "Expected 0 CompleteMultipartUpload calls, got %d", call_count);

    flb_stop(ctx);
    flb_destroy(ctx);
    unsetenv("FLB_S3_PLUGIN_UNDER_TEST");
    unsetenv("TEST_UPLOAD_PART_ERROR");
    unsetenv("TEST_CreateMultipartUpload_CALL_COUNT");
    unsetenv("TEST_UploadPart_CALL_COUNT");
    unsetenv("TEST_CompleteMultipartUpload_CALL_COUNT");
    unsetenv("TEST_PutObject_CALL_COUNT");
}

void flb_test_s3_complete_upload_error(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    char *call_count_str;
    int call_count;
    char store_dir[] = "/tmp/flb-s3-test-XXXXXX";

    TEST_CHECK(mkdtemp(store_dir) != NULL);

    /* mocks calls- signals that we are in test mode */
    setenv("FLB_S3_PLUGIN_UNDER_TEST", "true", 1);
    setenv("TEST_COMPLETE_MULTIPART_UPLOAD_ERROR", ERROR_ACCESS_DENIED, 1);

    ctx = flb_create();

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx,in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "s3", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd,"match", "*", NULL);
    flb_output_set(ctx, out_ffd,"region", "us-west-2", NULL);
    flb_output_set(ctx, out_ffd,"bucket", "fluent", NULL);
    flb_output_set(ctx, out_ffd,"upload_timeout", "6s", NULL);
    flb_output_set(ctx, out_ffd,"store_dir", store_dir, NULL);
    flb_output_set(ctx, out_ffd,"Retry_Limit", "1", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    flb_lib_push(ctx, in_ffd, (char *) JSON_TD , (int) sizeof(JSON_TD) - 1);

    sleep(10);

    call_count_str = getenv("TEST_CompleteMultipartUpload_CALL_COUNT");
    call_count = call_count_str ? atoi(call_count_str) : 0;
    TEST_CHECK_(call_count >= 2,
                "Expected >= 2 CompleteMultipartUpload calls (retried), got %d",
                call_count);

    flb_stop(ctx);
    flb_destroy(ctx);
    unsetenv("FLB_S3_PLUGIN_UNDER_TEST");
    unsetenv("TEST_COMPLETE_MULTIPART_UPLOAD_ERROR");
    unsetenv("TEST_CreateMultipartUpload_CALL_COUNT");
    unsetenv("TEST_UploadPart_CALL_COUNT");
    unsetenv("TEST_CompleteMultipartUpload_CALL_COUNT");
    unsetenv("TEST_PutObject_CALL_COUNT");
}

void flb_test_s3_compression_gzip(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    char *call_count_str;
    int call_count;

    /* mocks calls- signals that we are in test mode */
    setenv("FLB_S3_PLUGIN_UNDER_TEST", "true", 1);

    ctx = flb_create();

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx,in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "s3", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd,"match", "*", NULL);
    flb_output_set(ctx, out_ffd,"region", "us-west-2", NULL);
    flb_output_set(ctx, out_ffd,"bucket", "fluent", NULL);
    flb_output_set(ctx, out_ffd,"compression", "gzip", NULL);
    flb_output_set(ctx, out_ffd,"upload_timeout", "6s", NULL);
    flb_output_set(ctx, out_ffd,"Retry_Limit", "1", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    flb_lib_push(ctx, in_ffd, (char *) JSON_TD , (int) sizeof(JSON_TD) - 1);

    sleep(10);

    call_count_str = getenv("TEST_CompleteMultipartUpload_CALL_COUNT");
    call_count = call_count_str ? atoi(call_count_str) : 0;
    TEST_CHECK_(call_count == 1,
                "Expected 1 CompleteMultipartUpload call, got %d", call_count);

    flb_stop(ctx);
    flb_destroy(ctx);
    unsetenv("FLB_S3_PLUGIN_UNDER_TEST");
    unsetenv("TEST_CreateMultipartUpload_CALL_COUNT");
    unsetenv("TEST_UploadPart_CALL_COUNT");
    unsetenv("TEST_CompleteMultipartUpload_CALL_COUNT");
    unsetenv("TEST_PutObject_CALL_COUNT");
}

void flb_test_s3_compression_gzip_putobject(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    char *call_count_str;
    int call_count;

    /* mocks calls- signals that we are in test mode */
    setenv("FLB_S3_PLUGIN_UNDER_TEST", "true", 1);

    ctx = flb_create();

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx,in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "s3", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd,"match", "*", NULL);
    flb_output_set(ctx, out_ffd,"region", "us-west-2", NULL);
    flb_output_set(ctx, out_ffd,"bucket", "fluent", NULL);
    flb_output_set(ctx, out_ffd,"compression", "gzip", NULL);
    flb_output_set(ctx, out_ffd,"use_put_object", "true", NULL);
    flb_output_set(ctx, out_ffd,"total_file_size", "5M", NULL);
    flb_output_set(ctx, out_ffd,"upload_timeout", "6s", NULL);
    flb_output_set(ctx, out_ffd,"Retry_Limit", "1", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    flb_lib_push(ctx, in_ffd, (char *) JSON_TD , (int) sizeof(JSON_TD) - 1);

    sleep(10);

    call_count_str = getenv("TEST_PutObject_CALL_COUNT");
    call_count = call_count_str ? atoi(call_count_str) : 0;
    TEST_CHECK_(call_count == 1,
                "Expected 1 PutObject call, got %d", call_count);

    flb_stop(ctx);
    flb_destroy(ctx);
    unsetenv("FLB_S3_PLUGIN_UNDER_TEST");
    unsetenv("TEST_PutObject_CALL_COUNT");
}

void flb_test_s3_compression_zstd(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    char *call_count_str;
    int call_count;

    /* mocks calls- signals that we are in test mode */
    setenv("FLB_S3_PLUGIN_UNDER_TEST", "true", 1);

    ctx = flb_create();

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx,in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "s3", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd,"match", "*", NULL);
    flb_output_set(ctx, out_ffd,"region", "us-west-2", NULL);
    flb_output_set(ctx, out_ffd,"bucket", "fluent", NULL);
    flb_output_set(ctx, out_ffd,"compression", "zstd", NULL);
    flb_output_set(ctx, out_ffd,"upload_timeout", "6s", NULL);
    flb_output_set(ctx, out_ffd,"Retry_Limit", "1", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    flb_lib_push(ctx, in_ffd, (char *) JSON_TD , (int) sizeof(JSON_TD) - 1);

    sleep(10);

    call_count_str = getenv("TEST_CompleteMultipartUpload_CALL_COUNT");
    call_count = call_count_str ? atoi(call_count_str) : 0;
    TEST_CHECK_(call_count == 1,
                "Expected 1 CompleteMultipartUpload call, got %d", call_count);

    flb_stop(ctx);
    flb_destroy(ctx);
    unsetenv("FLB_S3_PLUGIN_UNDER_TEST");
    unsetenv("TEST_CreateMultipartUpload_CALL_COUNT");
    unsetenv("TEST_UploadPart_CALL_COUNT");
    unsetenv("TEST_CompleteMultipartUpload_CALL_COUNT");
    unsetenv("TEST_PutObject_CALL_COUNT");
}

void flb_test_s3_compression_zstd_putobject(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    char *call_count_str;
    int call_count;

    /* mocks calls- signals that we are in test mode */
    setenv("FLB_S3_PLUGIN_UNDER_TEST", "true", 1);

    ctx = flb_create();

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx,in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "s3", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd,"match", "*", NULL);
    flb_output_set(ctx, out_ffd,"region", "us-west-2", NULL);
    flb_output_set(ctx, out_ffd,"bucket", "fluent", NULL);
    flb_output_set(ctx, out_ffd,"compression", "zstd", NULL);
    flb_output_set(ctx, out_ffd,"use_put_object", "true", NULL);
    flb_output_set(ctx, out_ffd,"total_file_size", "5M", NULL);
    flb_output_set(ctx, out_ffd,"upload_timeout", "6s", NULL);
    flb_output_set(ctx, out_ffd,"Retry_Limit", "1", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    flb_lib_push(ctx, in_ffd, (char *) JSON_TD , (int) sizeof(JSON_TD) - 1);

    sleep(10);

    call_count_str = getenv("TEST_PutObject_CALL_COUNT");
    call_count = call_count_str ? atoi(call_count_str) : 0;
    TEST_CHECK_(call_count == 1,
                "Expected 1 PutObject call, got %d", call_count);

    flb_stop(ctx);
    flb_destroy(ctx);
    unsetenv("FLB_S3_PLUGIN_UNDER_TEST");
    unsetenv("TEST_PutObject_CALL_COUNT");
}

void flb_test_s3_compression_snappy(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    char *call_count_str;
    int call_count;

    /* mocks calls- signals that we are in test mode */
    setenv("FLB_S3_PLUGIN_UNDER_TEST", "true", 1);

    ctx = flb_create();

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx,in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "s3", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd,"match", "*", NULL);
    flb_output_set(ctx, out_ffd,"region", "us-west-2", NULL);
    flb_output_set(ctx, out_ffd,"bucket", "fluent", NULL);
    flb_output_set(ctx, out_ffd,"compression", "snappy", NULL);
    flb_output_set(ctx, out_ffd,"upload_timeout", "6s", NULL);
    flb_output_set(ctx, out_ffd,"Retry_Limit", "1", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    flb_lib_push(ctx, in_ffd, (char *) JSON_TD , (int) sizeof(JSON_TD) - 1);

    sleep(10);

    call_count_str = getenv("TEST_CompleteMultipartUpload_CALL_COUNT");
    call_count = call_count_str ? atoi(call_count_str) : 0;
    TEST_CHECK_(call_count == 1,
                "Expected 1 CompleteMultipartUpload call, got %d", call_count);

    flb_stop(ctx);
    flb_destroy(ctx);
    unsetenv("FLB_S3_PLUGIN_UNDER_TEST");
    unsetenv("TEST_CreateMultipartUpload_CALL_COUNT");
    unsetenv("TEST_UploadPart_CALL_COUNT");
    unsetenv("TEST_CompleteMultipartUpload_CALL_COUNT");
    unsetenv("TEST_PutObject_CALL_COUNT");
}

void flb_test_s3_compression_snappy_putobject(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    char *call_count_str;
    int call_count;

    /* mocks calls- signals that we are in test mode */
    setenv("FLB_S3_PLUGIN_UNDER_TEST", "true", 1);

    ctx = flb_create();

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx,in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "s3", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd,"match", "*", NULL);
    flb_output_set(ctx, out_ffd,"region", "us-west-2", NULL);
    flb_output_set(ctx, out_ffd,"bucket", "fluent", NULL);
    flb_output_set(ctx, out_ffd,"compression", "snappy", NULL);
    flb_output_set(ctx, out_ffd,"use_put_object", "true", NULL);
    flb_output_set(ctx, out_ffd,"total_file_size", "5M", NULL);
    flb_output_set(ctx, out_ffd,"upload_timeout", "6s", NULL);
    flb_output_set(ctx, out_ffd,"Retry_Limit", "1", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    flb_lib_push(ctx, in_ffd, (char *) JSON_TD , (int) sizeof(JSON_TD) - 1);

    sleep(10);

    call_count_str = getenv("TEST_PutObject_CALL_COUNT");
    call_count = call_count_str ? atoi(call_count_str) : 0;
    TEST_CHECK_(call_count == 1,
                "Expected 1 PutObject call, got %d", call_count);

    flb_stop(ctx);
    flb_destroy(ctx);
    unsetenv("FLB_S3_PLUGIN_UNDER_TEST");
    unsetenv("TEST_PutObject_CALL_COUNT");
}

void flb_test_s3_preserve_data_ordering(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    char *call_count_str;
    int call_count;
    char store_dir[] = "/tmp/flb-s3-test-XXXXXX";

    TEST_CHECK(mkdtemp(store_dir) != NULL);

    setenv("FLB_S3_PLUGIN_UNDER_TEST", "true", 1);

    ctx = flb_create();

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "s3", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "*", NULL);
    flb_output_set(ctx, out_ffd, "region", "us-west-2", NULL);
    flb_output_set(ctx, out_ffd, "bucket", "fluent", NULL);
    flb_output_set(ctx, out_ffd, "use_put_object", "true", NULL);
    flb_output_set(ctx, out_ffd, "total_file_size", "5M", NULL);
    flb_output_set(ctx, out_ffd, "preserve_data_ordering", "true", NULL);
    flb_output_set(ctx, out_ffd, "upload_timeout", "6s", NULL);
    flb_output_set(ctx, out_ffd, "store_dir", store_dir, NULL);
    flb_output_set(ctx, out_ffd, "Retry_Limit", "1", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    flb_lib_push(ctx, in_ffd, (char *) JSON_TD, (int) sizeof(JSON_TD) - 1);

    sleep(10);

    call_count_str = getenv("TEST_PutObject_CALL_COUNT");
    call_count = call_count_str ? atoi(call_count_str) : 0;
    TEST_CHECK_(call_count == 1,
                "Expected 1 PutObject call, got %d", call_count);

    flb_stop(ctx);
    flb_destroy(ctx);
    unsetenv("FLB_S3_PLUGIN_UNDER_TEST");
    unsetenv("TEST_PutObject_CALL_COUNT");
}


/*
 * Test that retry_limit=1 allows 1 initial attempt + 1 retry = 2 total PutObject calls.
 */
void flb_test_s3_putobject_retry_limit_semantics(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    char *call_count_str;
    int call_count;
    char store_dir[] = "/tmp/flb-s3-test-retry-XXXXXX";

    TEST_CHECK(mkdtemp(store_dir) != NULL);

    /* Use mocks without flush bypass so the plugin's internal retry runs */
    setenv("FLB_S3_PLUGIN_UNDER_TEST", "true", 1);
    setenv("TEST_PUT_OBJECT_ERROR", ERROR_ACCESS_DENIED, 1);

    ctx = flb_create();

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "s3", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "*", NULL);
    flb_output_set(ctx, out_ffd, "region", "us-west-2", NULL);
    flb_output_set(ctx, out_ffd, "bucket", "fluent", NULL);
    flb_output_set(ctx, out_ffd, "use_put_object", "true", NULL);
    flb_output_set(ctx, out_ffd, "total_file_size", "5M", NULL);
    flb_output_set(ctx, out_ffd, "upload_timeout", "6s", NULL);
    flb_output_set(ctx, out_ffd, "store_dir", store_dir, NULL);
    flb_output_set(ctx, out_ffd, "Retry_Limit", "1", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Reset counter after startup so we only count test-driven attempts */
    unsetenv("TEST_PutObject_CALL_COUNT");

    /*
     * Push 1 chunk then wait for upload_timeout (6s) + 2 timer ticks (1s each).
     * Chunk must age past upload_timeout before cb_s3_upload will attempt it.
     * Tick after ~6s: PutObject attempt 1 fails (failures=1)
     * Tick after ~7s: failures(1) not > retry_limit(1), attempt 2 fails (failures=2)
     * Next tick: failures(2) > retry_limit(1), chunk discarded
     */
    flb_lib_push(ctx, in_ffd, (char *) JSON_TD, (int) sizeof(JSON_TD) - 1);
    sleep(10);

    flb_stop(ctx);
    flb_destroy(ctx);

    call_count_str = getenv("TEST_PutObject_CALL_COUNT");
    call_count = call_count_str ? atoi(call_count_str) : 0;

    /* retry_limit=1: 1 initial attempt + 1 retry = 2 PutObject calls */
    TEST_CHECK_(call_count == 2,
                "Expected 2 PutObject calls (1 attempt + 1 retry), got %d",
                call_count);

    unsetenv("FLB_S3_PLUGIN_UNDER_TEST");
    unsetenv("TEST_PUT_OBJECT_ERROR");
    unsetenv("TEST_PutObject_CALL_COUNT");
}

/*
 * Test that the S3 plugin defaults retry_limit to 5 when not explicitly set.
 */
void flb_test_s3_default_retry_limit(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    char *call_count_str;
    int call_count;
    char store_dir[] = "/tmp/flb-s3-test-default-XXXXXX";

    TEST_CHECK(mkdtemp(store_dir) != NULL);

    setenv("FLB_S3_PLUGIN_UNDER_TEST", "true", 1);
    setenv("TEST_PUT_OBJECT_ERROR", ERROR_ACCESS_DENIED, 1);

    ctx = flb_create();

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "s3", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "*", NULL);
    flb_output_set(ctx, out_ffd, "region", "us-west-2", NULL);
    flb_output_set(ctx, out_ffd, "bucket", "fluent", NULL);
    flb_output_set(ctx, out_ffd, "use_put_object", "true", NULL);
    flb_output_set(ctx, out_ffd, "total_file_size", "5M", NULL);
    flb_output_set(ctx, out_ffd, "upload_timeout", "6s", NULL);
    flb_output_set(ctx, out_ffd, "store_dir", store_dir, NULL);
    /* No Retry_Limit — should default to 5 (MAX_UPLOAD_ERRORS) */

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    unsetenv("TEST_PutObject_CALL_COUNT");

    /*
     * Push 1 chunk, wait for upload_timeout (6s) + 6 timer ticks (1s each).
     * Default retry_limit=5: 1 initial attempt + 5 retries = 6 PutObject calls.
     */
    flb_lib_push(ctx, in_ffd, (char *) JSON_TD, (int) sizeof(JSON_TD) - 1);
    sleep(14);

    flb_stop(ctx);
    flb_destroy(ctx);

    call_count_str = getenv("TEST_PutObject_CALL_COUNT");
    call_count = call_count_str ? atoi(call_count_str) : 0;

    TEST_CHECK_(call_count == 6,
                "Expected 6 PutObject calls (default retry_limit=5), got %d",
                call_count);

    unsetenv("FLB_S3_PLUGIN_UNDER_TEST");
    unsetenv("TEST_PUT_OBJECT_ERROR");
    unsetenv("TEST_PutObject_CALL_COUNT");
}

/* Test list */
TEST_LIST = {
    {"multipart_success", flb_test_s3_multipart_success },
    {"putobject_success", flb_test_s3_putobject_success },
    {"putobject_error", flb_test_s3_putobject_error },
    {"putobject_retry_limit_semantics", flb_test_s3_putobject_retry_limit_semantics },
    {"default_retry_limit", flb_test_s3_default_retry_limit },
    {"create_upload_error", flb_test_s3_create_upload_error },
    {"upload_part_error", flb_test_s3_upload_part_error },
    {"complete_upload_error", flb_test_s3_complete_upload_error },
    {"compression_gzip", flb_test_s3_compression_gzip },
    {"compression_gzip_putobject", flb_test_s3_compression_gzip_putobject },
    {"compression_zstd", flb_test_s3_compression_zstd },
    {"compression_zstd_putobject", flb_test_s3_compression_zstd_putobject },
    {"compression_snappy", flb_test_s3_compression_snappy },
    {"compression_snappy_putobject", flb_test_s3_compression_snappy_putobject },
    {"preserve_data_ordering", flb_test_s3_preserve_data_ordering },
    {NULL, NULL}
};
