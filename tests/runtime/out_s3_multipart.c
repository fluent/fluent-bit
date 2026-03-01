/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_aws_util.h>
#include "flb_tests_runtime.h"
#include "../include/aws_client_mock.h"

#include "../include/s3_test_helpers.h"
#include "../../plugins/out_s3/s3.h"
#include "../../plugins/out_s3/s3_multipart.h"
#include "data/td/json_td.h"

/* Test: Basic multipart upload flow */
void flb_test_create_multipart_basic(void)
{
    S3_TEST_DECLARE_VARS();
    S3_TEST_SIMPLE("test", "create_multipart_basic",
                   "upload_chunk_size", "5M");
}

/* Test: Multipart with metadata (ACL, storage class) */
void flb_test_create_multipart_with_metadata(void)
{
    S3_TEST_DECLARE_VARS();


    chain = FLB_AWS_CLIENT_MOCK(
        response(expect(METHOD, FLB_HTTP_POST),
                 expect(HEADER, "x-amz-acl", "bucket-owner-full-control"),
                 expect(HEADER, "x-amz-storage-class", "STANDARD_IA"),
                 set(STATUS, 200), set(PAYLOAD, S3_TEST_MOCK_CREATE_RESP), 
                 set(PAYLOAD_SIZE, sizeof(S3_TEST_MOCK_CREATE_RESP) - 1)),
        response(expect(METHOD, FLB_HTTP_PUT), set(STATUS, 200), 
                 set(DATA, S3_TEST_MOCK_UPLOAD_PART_RESP), 
                 set(DATA_SIZE, sizeof(S3_TEST_MOCK_UPLOAD_PART_RESP) - 1)),
        response(expect(METHOD, FLB_HTTP_POST), set(STATUS, 200), 
                 set(PAYLOAD, S3_TEST_MOCK_COMPLETE_RESP), 
                 set(PAYLOAD_SIZE, sizeof(S3_TEST_MOCK_COMPLETE_RESP) - 1))
    );

    flb_aws_client_mock_configure_generator(chain);
    init_options.client_generator = flb_aws_client_get_mock_generator();

    S3_TEST_CREATE_PATHS("mp");
    S3_TEST_INIT_CONTEXT();
    S3_TEST_SETUP_INPUT("test");
    S3_TEST_SETUP_OUTPUT_BASIC();
    flb_output_set(ctx, out_ffd, 
                   "upload_chunk_size", "5M",
                   "canned_acl", "bucket-owner-full-control",
                   "storage_class", "STANDARD_IA", NULL);

    S3_TEST_START_AND_PUSH((char *)JSON_TD, sizeof(JSON_TD) - 1);
    S3_TEST_WAIT_MOCK_EXHAUSTED(10, "create_multipart_with_metadata");
    s3_test_cleanup(ctx, db_path, store_dir);
}

/* Test: CreateMultipartUpload failure (500 error) */
void flb_test_create_multipart_failure(void)
{
    S3_TEST_DECLARE_VARS();

    S3_TEST_ERROR_WITH_MOCK_N("create_multipart_failure",
        FLB_AWS_CLIENT_MOCK(
            response(expect(METHOD, FLB_HTTP_POST), set(STATUS, 500), 
                     set(PAYLOAD, S3_TEST_MOCK_ERROR_RESP), 
                     set(PAYLOAD_SIZE, sizeof(S3_TEST_MOCK_ERROR_RESP) - 1))
        ),
        "bucket", S3_TEST_DEFAULT_BUCKET, 
        "total_file_size", "10M", 
        "upload_chunk_size", "5M"
    );
}

/* Test: UploadPart failure (no automatic retry at part level) */
void flb_test_upload_part_failure_retry(void)
{
    S3_TEST_DECLARE_VARS();

    /* UploadPart fails (500) - file is removed from queue after failure
     * Note: The S3 plugin removes files from queue after first failure,
     * retry happens at the file level (re-enqueue), not at the part level */
    S3_TEST_ERROR_WITH_MOCK_N("upload_part_failure_retry",
        FLB_AWS_CLIENT_MOCK(
            response(expect(METHOD, FLB_HTTP_POST), set(STATUS, 200), 
                     set(PAYLOAD, S3_TEST_MOCK_CREATE_RESP), 
                     set(PAYLOAD_SIZE, sizeof(S3_TEST_MOCK_CREATE_RESP) - 1)),
            response(expect(METHOD, FLB_HTTP_PUT), set(STATUS, 500), 
                     set(PAYLOAD, S3_TEST_MOCK_ERROR_RESP), 
                     set(PAYLOAD_SIZE, sizeof(S3_TEST_MOCK_ERROR_RESP) - 1))
        ),
        "bucket", S3_TEST_DEFAULT_BUCKET,
        "total_file_size", "10M",
        "upload_chunk_size", "5M"
    );
}

/* Test: CompleteMultipartUpload failure */
void flb_test_complete_multipart_failure(void)
{
    S3_TEST_DECLARE_VARS();


    /* Complete fails (500) - tests error handling, then abort succeeds */
    chain = FLB_AWS_CLIENT_MOCK(
        response(expect(METHOD, FLB_HTTP_POST), set(STATUS, 200), 
                 set(PAYLOAD, S3_TEST_MOCK_CREATE_RESP), 
                 set(PAYLOAD_SIZE, sizeof(S3_TEST_MOCK_CREATE_RESP) - 1)),
        response(expect(METHOD, FLB_HTTP_PUT), set(STATUS, 200), 
                 set(DATA, S3_TEST_MOCK_UPLOAD_PART_RESP), 
                 set(DATA_SIZE, sizeof(S3_TEST_MOCK_UPLOAD_PART_RESP) - 1)),
        response(expect(METHOD, FLB_HTTP_POST), set(STATUS, 500), 
                 set(PAYLOAD, S3_TEST_MOCK_ERROR_RESP), 
                 set(PAYLOAD_SIZE, sizeof(S3_TEST_MOCK_ERROR_RESP) - 1)),
        response(expect(METHOD, FLB_HTTP_DELETE), set(STATUS, 204))
    );

    flb_aws_client_mock_configure_generator(chain);
    init_options.client_generator = flb_aws_client_get_mock_generator();

    S3_TEST_CREATE_PATHS("mp");
    S3_TEST_INIT_CONTEXT();
    S3_TEST_SETUP_INPUT("test");
    S3_TEST_SETUP_OUTPUT_BASIC();
    flb_output_set(ctx, out_ffd, "upload_chunk_size", "5M", NULL);

    S3_TEST_START_AND_PUSH((char *)JSON_TD, sizeof(JSON_TD) - 1);
    S3_TEST_WAIT_MOCK_EXHAUSTED(10, "complete_multipart_failure");
    s3_test_cleanup(ctx, db_path, store_dir);
}

/* Test: AbortMultipartUpload success */
void flb_test_abort_multipart_success(void)
{
    S3_TEST_DECLARE_VARS();


    /* Abort is triggered when CompleteMultipartUpload fails (not UploadPart)
     * Flow: Create succeeds -> UploadPart succeeds -> Complete fails -> Abort */
    chain = FLB_AWS_CLIENT_MOCK(
        response(expect(METHOD, FLB_HTTP_POST), set(STATUS, 200), 
                 set(PAYLOAD, S3_TEST_MOCK_CREATE_RESP), 
                 set(PAYLOAD_SIZE, sizeof(S3_TEST_MOCK_CREATE_RESP) - 1)),
        response(expect(METHOD, FLB_HTTP_PUT), set(STATUS, 200), 
                 set(DATA, S3_TEST_MOCK_UPLOAD_PART_RESP), 
                 set(DATA_SIZE, sizeof(S3_TEST_MOCK_UPLOAD_PART_RESP) - 1)),
        response(expect(METHOD, FLB_HTTP_POST), set(STATUS, 500), 
                 set(PAYLOAD, S3_TEST_MOCK_ERROR_RESP), 
                 set(PAYLOAD_SIZE, sizeof(S3_TEST_MOCK_ERROR_RESP) - 1)),
        response(expect(METHOD, FLB_HTTP_DELETE), set(STATUS, 204))
    );

    flb_aws_client_mock_configure_generator(chain);
    init_options.client_generator = flb_aws_client_get_mock_generator();

    S3_TEST_CREATE_PATHS("mp");
    S3_TEST_INIT_CONTEXT();
    S3_TEST_SETUP_INPUT("test");
    S3_TEST_SETUP_OUTPUT_BASIC();
    flb_output_set(ctx, out_ffd, "upload_chunk_size", "5M", NULL);

    S3_TEST_START_AND_PUSH((char *)JSON_TD, sizeof(JSON_TD) - 1);
    S3_TEST_WAIT_MOCK_EXHAUSTED(15, "abort_multipart_success");
    s3_test_cleanup(ctx, db_path, store_dir);
}

/* Test: Multiple data pushes */
void flb_test_multiple_data_pushes(void)
{
    S3_TEST_DECLARE_VARS();
    int i;

    S3_TEST_RUN_AND_CLEANUP("test", "multiple_data_pushes");
    flb_output_set(ctx, out_ffd, 
                   "upload_chunk_size", "5M", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    for (i = 0; i < 3; i++) {
        ret = flb_lib_push(ctx, in_ffd, (char *)JSON_TD, sizeof(JSON_TD) - 1);
        TEST_CHECK(ret >= 0);
        S3_TEST_SLEEP_MS(100);
    }

    S3_TEST_WAIT_MOCK_EXHAUSTED(10, "multiple_data_pushes");
    s3_test_cleanup(ctx, db_path, store_dir);
}

/* Test List */
TEST_LIST = {
    {"create_multipart_basic", flb_test_create_multipart_basic},
    {"create_multipart_with_metadata", flb_test_create_multipart_with_metadata},
    {"create_multipart_failure", flb_test_create_multipart_failure},
    {"upload_part_failure_retry", flb_test_upload_part_failure_retry},
    {"complete_multipart_failure", flb_test_complete_multipart_failure},
    {"abort_multipart_success", flb_test_abort_multipart_success},
    {"multiple_data_pushes", flb_test_multiple_data_pushes},
    {NULL, NULL}
};