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
    flb_output_set(ctx, out_ffd,"s3_object_tag", "key1", "value1", NULL);
    flb_output_set(ctx, out_ffd,"s3_object_tag", "key2", "value2", NULL);
    flb_output_set(ctx, out_ffd,"Retry_Limit", "1", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    flb_lib_push(ctx, in_ffd, (char *) JSON_TD , (int) sizeof(JSON_TD) - 1);


    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_s3_putobject_success(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

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
    flb_output_set(ctx, out_ffd,"Retry_Limit", "1", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    flb_lib_push(ctx, in_ffd, (char *) JSON_TD , (int) sizeof(JSON_TD) - 1);


    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_s3_putobject_error(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

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
    flb_output_set(ctx, out_ffd,"Retry_Limit", "1", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    flb_lib_push(ctx, in_ffd, (char *) JSON_TD , (int) sizeof(JSON_TD) - 1);


    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
    unsetenv("TEST_PUT_OBJECT_ERROR");

}

void flb_test_s3_create_upload_error(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

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
    flb_output_set(ctx, out_ffd,"Retry_Limit", "1", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    flb_lib_push(ctx, in_ffd, (char *) JSON_TD , (int) sizeof(JSON_TD) - 1);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
    unsetenv("TEST_CREATE_MULTIPART_UPLOAD_ERROR");
}

void flb_test_s3_upload_part_error(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

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
    flb_output_set(ctx, out_ffd,"Retry_Limit", "1", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    flb_lib_push(ctx, in_ffd, (char *) JSON_TD , (int) sizeof(JSON_TD) - 1);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
    unsetenv("TEST_UPLOAD_PART_ERROR");
}

void flb_test_s3_complete_upload_error(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

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
    flb_output_set(ctx, out_ffd,"s3_object_tag", "key", "value with spaces", NULL);
    flb_output_set(ctx, out_ffd,"Retry_Limit", "1", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    flb_lib_push(ctx, in_ffd, (char *) JSON_TD , (int) sizeof(JSON_TD) - 1);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
    unsetenv("TEST_COMPLETE_MULTIPART_UPLOAD_ERROR");
}


/* Test list */
TEST_LIST = {
    {"multipart_success", flb_test_s3_multipart_success },
    {"putobject_success", flb_test_s3_putobject_success },
    {"putobject_error", flb_test_s3_putobject_error },
    {"create_upload_error", flb_test_s3_create_upload_error },
    {"upload_part_error", flb_test_s3_upload_part_error },
    {"complete_upload_error", flb_test_s3_complete_upload_error },
    {NULL, NULL}
};
