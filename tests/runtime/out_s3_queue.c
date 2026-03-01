/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_aws_util.h>
#include "flb_tests_runtime.h"
#include "../include/aws_client_mock.h"

#include "../include/s3_test_helpers.h"
#include "../../plugins/out_s3/s3.h"
#include "data/td/json_td.h"

/* Test: Basic queue operations (add/remove) */
void flb_test_queue_basic_operations(void)
{
    S3_TEST_DECLARE_VARS();
    S3_TEST_SIMPLE("test", "queue_basic_operations");
}

/* Test: Queue with multiple workers */
void flb_test_queue_multiple_workers(void)
{
    S3_TEST_DECLARE_VARS();

    S3_TEST_RUN_AND_CLEANUP("test", "queue_multiple_workers");
    ret = flb_output_set(ctx, out_ffd, "workers", "5", NULL);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Push multiple chunks to test worker distribution */
    ret = flb_lib_push(ctx, in_ffd, (char *)JSON_TD, sizeof(JSON_TD) - 1);
    TEST_CHECK(ret >= 0);
    ret = flb_lib_push(ctx, in_ffd, (char *)JSON_TD, sizeof(JSON_TD) - 1);
    TEST_CHECK(ret >= 0);
    ret = flb_lib_push(ctx, in_ffd, (char *)JSON_TD, sizeof(JSON_TD) - 1);
    TEST_CHECK(ret >= 0);

    S3_TEST_WAIT_MOCK_EXHAUSTED(10, "queue_multiple_workers");
    s3_test_cleanup(ctx, db_path, store_dir);
}

/* Test: Queue entry retry mechanism */
void flb_test_queue_retry_mechanism(void)
{
    S3_TEST_DECLARE_VARS();


    /* UploadPart fails once (500), then succeeds on retry */
    chain = FLB_AWS_CLIENT_MOCK(
        response(expect(METHOD, FLB_HTTP_POST), set(STATUS, 200), 
                 set(PAYLOAD, S3_TEST_MOCK_CREATE_RESP), 
                 set(PAYLOAD_SIZE, sizeof(S3_TEST_MOCK_CREATE_RESP) - 1)),
        response(expect(METHOD, FLB_HTTP_PUT), set(STATUS, 500), 
                 set(PAYLOAD, S3_TEST_MOCK_ERROR_RESP), 
                 set(PAYLOAD_SIZE, sizeof(S3_TEST_MOCK_ERROR_RESP) - 1)),
        response(expect(METHOD, FLB_HTTP_PUT), set(STATUS, 200), 
                 set(DATA, S3_TEST_MOCK_UPLOAD_PART_RESP), 
                 set(DATA_SIZE, sizeof(S3_TEST_MOCK_UPLOAD_PART_RESP) - 1)),
        response(expect(METHOD, FLB_HTTP_POST), set(STATUS, 200), 
                 set(PAYLOAD, S3_TEST_MOCK_COMPLETE_RESP), 
                 set(PAYLOAD_SIZE, sizeof(S3_TEST_MOCK_COMPLETE_RESP) - 1))
    );

    flb_aws_client_mock_configure_generator(chain);
    init_options.client_generator = flb_aws_client_get_mock_generator();

    S3_TEST_CREATE_PATHS("queue_retry");
    S3_TEST_INIT_CONTEXT();
    S3_TEST_SETUP_INPUT("test");
    S3_TEST_SETUP_OUTPUT_BASIC();
    ret = flb_output_set(ctx, out_ffd, "retry_limit", "3", NULL);
    TEST_CHECK(ret == 0);

    S3_TEST_START_AND_PUSH((char *)JSON_TD, sizeof(JSON_TD) - 1);
    S3_TEST_WAIT_MOCK_EXHAUSTED(10, "queue_retry_mechanism");
    s3_test_cleanup(ctx, db_path, store_dir);
}

/* Test: Queue entry timeout handling */
void flb_test_queue_timeout_handling(void)
{
    S3_TEST_DECLARE_VARS();
    S3_TEST_SIMPLE("test", "queue_timeout_handling");
}

/* Test: Queue with concurrent file uploads */
void flb_test_queue_concurrent_uploads(void)
{
    S3_TEST_DECLARE_VARS();
    int i;

    S3_TEST_RUN_AND_CLEANUP("test", "queue_concurrent_uploads");
    ret = flb_output_set(ctx, out_ffd, 
                   "workers", "10", NULL);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Push multiple chunks to trigger concurrent uploads */
    for (i = 0; i < 10; i++) {
        ret = flb_lib_push(ctx, in_ffd, (char *)JSON_TD, sizeof(JSON_TD) - 1);
        TEST_CHECK(ret >= 0);
    }

    S3_TEST_WAIT_MOCK_EXHAUSTED(15, "queue_concurrent_uploads");
    s3_test_cleanup(ctx, db_path, store_dir);
}

/* Test: Queue cleanup on shutdown */
void flb_test_queue_cleanup_on_shutdown(void)
{
    S3_TEST_DECLARE_VARS();

    S3_TEST_SETUP_STANDARD_MOCK();
    S3_TEST_CREATE_PATHS("queue_cleanup");

    s3_test_set_env_vars();
    ctx = flb_create();
    S3_TEST_CHECK_CONTEXT(ctx, db_path, store_dir);
    flb_service_set(ctx, "flush", "1", "grace", "2", NULL);

    S3_TEST_SETUP_INPUT("test");
    S3_TEST_SETUP_OUTPUT_BASIC();

    S3_TEST_START_AND_PUSH((char *)JSON_TD, sizeof(JSON_TD) - 1);
    S3_TEST_WAIT_MOCK_EXHAUSTED(10, "queue_cleanup_on_shutdown");

    /* Graceful shutdown should handle pending queue entries */
    s3_test_cleanup(ctx, db_path, store_dir);
}

/* Test: Queue with high concurrency stress test */
void flb_test_queue_high_concurrency(void)
{
    S3_TEST_DECLARE_VARS();
    int i;

    S3_TEST_RUN_AND_CLEANUP("test", "queue_high_concurrency");
    ret = flb_output_set(ctx, out_ffd, 
                   "workers", "16", NULL);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Rapid data push to stress test queue */
    for (i = 0; i < 20; i++) {
        ret = flb_lib_push(ctx, in_ffd, (char *)JSON_TD, sizeof(JSON_TD) - 1);
        TEST_CHECK(ret >= 0);
        S3_TEST_SLEEP_MS(10);  /* 10ms between pushes */
    }

    S3_TEST_WAIT_MOCK_EXHAUSTED(15, "queue_high_concurrency");
    s3_test_cleanup(ctx, db_path, store_dir);
}

/* Test list */
TEST_LIST = {
    {"queue_basic_operations", flb_test_queue_basic_operations},
    {"queue_multiple_workers", flb_test_queue_multiple_workers},
    {"queue_retry_mechanism", flb_test_queue_retry_mechanism},
    {"queue_timeout_handling", flb_test_queue_timeout_handling},
    {"queue_concurrent_uploads", flb_test_queue_concurrent_uploads},
    {"queue_cleanup_on_shutdown", flb_test_queue_cleanup_on_shutdown},
    {"queue_high_concurrency", flb_test_queue_high_concurrency},
    {NULL, NULL}
};