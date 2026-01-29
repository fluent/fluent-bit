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

/* AWS Error Response Templates */
#define AWS_ERROR_ACCESS_DENIED \
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" \
    "<Error><Code>AccessDenied</Code><Message>Access Denied</Message></Error>"

#define AWS_ERROR_NO_SUCH_BUCKET \
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" \
    "<Error><Code>NoSuchBucket</Code><Message>The specified bucket does not exist</Message></Error>"

#define AWS_ERROR_NO_SUCH_UPLOAD \
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" \
    "<Error><Code>NoSuchUpload</Code><Message>The specified upload does not exist</Message></Error>"

#define AWS_ERROR_INVALID_ACCESS_KEY \
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" \
    "<Error><Code>InvalidAccessKeyId</Code><Message>The AWS access key ID does not exist</Message></Error>"

#define AWS_ERROR_SIGNATURE_MISMATCH \
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" \
    "<Error><Code>SignatureDoesNotMatch</Code><Message>The request signature does not match</Message></Error>"

#define AWS_ERROR_SLOW_DOWN \
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" \
    "<Error><Code>SlowDown</Code><Message>Please reduce your request rate</Message></Error>"

#define AWS_ERROR_INTERNAL_ERROR \
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" \
    "<Error><Code>InternalError</Code><Message>Internal Server Error</Message></Error>"

/* Test: AccessDenied error on CreateMultipartUpload */
void flb_test_error_access_denied(void)
{
    S3_TEST_DECLARE_VARS();

    S3_TEST_ERROR_WITH_MOCK_0("error_access_denied",
        FLB_AWS_CLIENT_MOCK(
            response(expect(METHOD, FLB_HTTP_POST), set(STATUS, 403),
                     set(PAYLOAD, AWS_ERROR_ACCESS_DENIED),
                     set(PAYLOAD_SIZE, sizeof(AWS_ERROR_ACCESS_DENIED) - 1))
        )
    );
}

/* Test: NoSuchBucket error on CreateMultipartUpload */
void flb_test_error_no_such_bucket(void)
{
    S3_TEST_DECLARE_VARS();

    S3_TEST_ERROR_WITH_MOCK_N("error_no_such_bucket",
        FLB_AWS_CLIENT_MOCK(
            response(expect(METHOD, FLB_HTTP_POST), set(STATUS, 404),
                     set(PAYLOAD, AWS_ERROR_NO_SUCH_BUCKET),
                     set(PAYLOAD_SIZE, sizeof(AWS_ERROR_NO_SUCH_BUCKET) - 1))
        ),
        "bucket", "nonexistent-bucket", "total_file_size", "1M"
    );
}

/* Test: NoSuchUpload error on CompleteMultipartUpload */
void flb_test_error_no_such_upload(void)
{
    S3_TEST_DECLARE_VARS();

    /* CreateMultipartUpload succeeds, UploadPart succeeds, CompleteMultipartUpload returns NoSuchUpload */
    chain = FLB_AWS_CLIENT_MOCK(
        response(expect(METHOD, FLB_HTTP_POST), set(STATUS, 200),
                 set(PAYLOAD, S3_TEST_MOCK_CREATE_RESP),
                 set(PAYLOAD_SIZE, sizeof(S3_TEST_MOCK_CREATE_RESP) - 1)),
        response(expect(METHOD, FLB_HTTP_PUT), set(STATUS, 200),
                 set(DATA, S3_TEST_MOCK_UPLOAD_PART_RESP),
                 set(DATA_SIZE, sizeof(S3_TEST_MOCK_UPLOAD_PART_RESP) - 1)),
        response(expect(METHOD, FLB_HTTP_POST), set(STATUS, 404),
                 set(PAYLOAD, AWS_ERROR_NO_SUCH_UPLOAD),
                 set(PAYLOAD_SIZE, sizeof(AWS_ERROR_NO_SUCH_UPLOAD) - 1))
    );

    flb_aws_client_mock_configure_generator(chain);
    init_options.client_generator = flb_aws_client_get_mock_generator();

    S3_TEST_CREATE_PATHS("err");
    S3_TEST_INIT_CONTEXT();
    S3_TEST_SETUP_INPUT("test");
    S3_TEST_SETUP_OUTPUT_BASIC();
    ret = flb_output_set(ctx, out_ffd, "upload_chunk_size", "5M", NULL);
    TEST_CHECK(ret >= 0);

    S3_TEST_START_AND_PUSH((char *)JSON_TD, sizeof(JSON_TD) - 1);
    S3_TEST_WAIT_MOCK_EXHAUSTED(5, "error_no_such_upload");
    s3_test_cleanup(ctx, db_path, store_dir);
}

/* Test: InvalidAccessKeyId error */
void flb_test_error_invalid_access_key(void)
{
    S3_TEST_DECLARE_VARS();

    S3_TEST_ERROR_WITH_MOCK_0("error_invalid_access_key",
        FLB_AWS_CLIENT_MOCK(
            response(expect(METHOD, FLB_HTTP_POST), set(STATUS, 403),
                     set(PAYLOAD, AWS_ERROR_INVALID_ACCESS_KEY),
                     set(PAYLOAD_SIZE, sizeof(AWS_ERROR_INVALID_ACCESS_KEY) - 1))
        )
    );
}

/* Test: SignatureDoesNotMatch error */
void flb_test_error_signature_mismatch(void)
{
    S3_TEST_DECLARE_VARS();

    S3_TEST_ERROR_WITH_MOCK_0("error_signature_mismatch",
        FLB_AWS_CLIENT_MOCK(
            response(expect(METHOD, FLB_HTTP_POST), set(STATUS, 403),
                     set(PAYLOAD, AWS_ERROR_SIGNATURE_MISMATCH),
                     set(PAYLOAD_SIZE, sizeof(AWS_ERROR_SIGNATURE_MISMATCH) - 1))
        )
    );
}

/* Test: SlowDown throttling error on UploadPart - verifies error is logged */
void flb_test_error_slow_down_throttling(void)
{
    S3_TEST_DECLARE_VARS();

    /* CreateMultipartUpload succeeds, UploadPart returns 503 SlowDown
     * Note: S3 plugin removes file from queue on first failure without retry */
    S3_TEST_ERROR_WITH_MOCK_N("error_slow_down_throttling",
        FLB_AWS_CLIENT_MOCK(
            response(expect(METHOD, FLB_HTTP_POST), set(STATUS, 200),
                     set(PAYLOAD, S3_TEST_MOCK_CREATE_RESP),
                     set(PAYLOAD_SIZE, sizeof(S3_TEST_MOCK_CREATE_RESP) - 1)),
            response(expect(METHOD, FLB_HTTP_PUT), set(STATUS, 503),
                     set(PAYLOAD, AWS_ERROR_SLOW_DOWN),
                     set(PAYLOAD_SIZE, sizeof(AWS_ERROR_SLOW_DOWN) - 1))
        ),
        "bucket", S3_TEST_DEFAULT_BUCKET,
        "total_file_size", "10M",
        "upload_chunk_size", "5M"
    );
}

/* Test: 500 Internal Server Error on CreateMultipartUpload - verifies error is logged */
void flb_test_error_internal_server_error(void)
{
    S3_TEST_DECLARE_VARS();

    S3_TEST_ERROR_WITH_MOCK_N("error_internal_server_error",
        FLB_AWS_CLIENT_MOCK(
            response(expect(METHOD, FLB_HTTP_POST), set(STATUS, 500),
                     set(PAYLOAD, AWS_ERROR_INTERNAL_ERROR),
                     set(PAYLOAD_SIZE, sizeof(AWS_ERROR_INTERNAL_ERROR) - 1))
        ),
        "bucket", S3_TEST_DEFAULT_BUCKET, "total_file_size", "10M", "upload_chunk_size", "5M"
    );
}

/* Test: auto_retry_requests enabled */
void flb_test_auto_retry_enabled(void)
{
    S3_TEST_DECLARE_VARS();

    /* With auto_retry enabled, transient failures should be retried
     * Sequence: CreateMultipartUpload (200) -> UploadPart (503) -> UploadPart retry (200) -> CompleteMultipartUpload (200) */
    chain = FLB_AWS_CLIENT_MOCK(
        response(expect(METHOD, FLB_HTTP_POST), set(STATUS, 200),
                 set(PAYLOAD, S3_TEST_MOCK_CREATE_RESP),
                 set(PAYLOAD_SIZE, sizeof(S3_TEST_MOCK_CREATE_RESP) - 1)),
        response(expect(METHOD, FLB_HTTP_PUT), set(STATUS, 503),
                 set(PAYLOAD, AWS_ERROR_SLOW_DOWN),
                 set(PAYLOAD_SIZE, sizeof(AWS_ERROR_SLOW_DOWN) - 1)),
        response(expect(METHOD, FLB_HTTP_PUT), set(STATUS, 200),
                 set(DATA, S3_TEST_MOCK_UPLOAD_PART_RESP),
                 set(DATA_SIZE, sizeof(S3_TEST_MOCK_UPLOAD_PART_RESP) - 1)),
        response(expect(METHOD, FLB_HTTP_POST), set(STATUS, 200),
                 set(PAYLOAD, S3_TEST_MOCK_COMPLETE_RESP),
                 set(PAYLOAD_SIZE, sizeof(S3_TEST_MOCK_COMPLETE_RESP) - 1))
    );

    flb_aws_client_mock_configure_generator(chain);
    init_options.client_generator = flb_aws_client_get_mock_generator();

    S3_TEST_CREATE_PATHS("err");
    S3_TEST_INIT_CONTEXT();
    S3_TEST_SETUP_INPUT("test");
    S3_TEST_SETUP_OUTPUT_BASIC();
    ret = flb_output_set(ctx, out_ffd, 
                   "upload_chunk_size", "5M",
                   "auto_retry_requests", "true", NULL);
    TEST_CHECK(ret == 0);

    S3_TEST_START_AND_PUSH((char *)JSON_TD, sizeof(JSON_TD) - 1);
    S3_TEST_WAIT_MOCK_EXHAUSTED(5, "auto_retry_enabled");
    s3_test_cleanup(ctx, db_path, store_dir);
}

/* Test: auto_retry_requests disabled */
void flb_test_auto_retry_disabled(void)
{
    S3_TEST_DECLARE_VARS();

    /* With auto_retry disabled, transient failures should NOT be retried
     * Sequence: CreateMultipartUpload (200) -> UploadPart (503) - no retry, file removed from queue */
    S3_TEST_ERROR_WITH_MOCK_N("auto_retry_disabled",
        FLB_AWS_CLIENT_MOCK(
            response(expect(METHOD, FLB_HTTP_POST), set(STATUS, 200),
                     set(PAYLOAD, S3_TEST_MOCK_CREATE_RESP),
                     set(PAYLOAD_SIZE, sizeof(S3_TEST_MOCK_CREATE_RESP) - 1)),
            response(expect(METHOD, FLB_HTTP_PUT), set(STATUS, 503),
                     set(PAYLOAD, AWS_ERROR_SLOW_DOWN),
                     set(PAYLOAD_SIZE, sizeof(AWS_ERROR_SLOW_DOWN) - 1))
        ),
        "bucket", S3_TEST_DEFAULT_BUCKET,
        "total_file_size", "10M",
        "upload_chunk_size", "5M",
        "auto_retry_requests", "false"
    );
}

/* Test: UploadPart failure - verifies file is removed from queue */
void flb_test_failure_cleanup_and_abort(void)
{
    S3_TEST_DECLARE_VARS();

    /* Create succeeds, UploadPart fails
     * Note: S3 plugin removes file from queue on first failure without retry or abort */
    S3_TEST_ERROR_WITH_MOCK_N("failure_cleanup_and_abort",
        FLB_AWS_CLIENT_MOCK(
            response(expect(METHOD, FLB_HTTP_POST), set(STATUS, 200),
                     set(PAYLOAD, S3_TEST_MOCK_CREATE_RESP),
                     set(PAYLOAD_SIZE, sizeof(S3_TEST_MOCK_CREATE_RESP) - 1)),
            response(expect(METHOD, FLB_HTTP_PUT), set(STATUS, 500),
                     set(PAYLOAD, AWS_ERROR_INTERNAL_ERROR),
                     set(PAYLOAD_SIZE, sizeof(AWS_ERROR_INTERNAL_ERROR) - 1))
        ),
        "bucket", S3_TEST_DEFAULT_BUCKET,
        "total_file_size", "10M",
        "upload_chunk_size", "5M"
    );
}

/* Test List */
TEST_LIST = {
    {"error_access_denied", flb_test_error_access_denied},
    {"error_no_such_bucket", flb_test_error_no_such_bucket},
    {"error_no_such_upload", flb_test_error_no_such_upload},
    {"error_invalid_access_key", flb_test_error_invalid_access_key},
    {"error_signature_mismatch", flb_test_error_signature_mismatch},
    {"error_slow_down_throttling", flb_test_error_slow_down_throttling},
    {"error_internal_server_error", flb_test_error_internal_server_error},
    {"auto_retry_enabled", flb_test_auto_retry_enabled},
    {"auto_retry_disabled", flb_test_auto_retry_disabled},
    {"failure_cleanup_and_abort", flb_test_failure_cleanup_and_abort},
    {NULL, NULL}
};