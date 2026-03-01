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

/* ============================================================================
 * blob_database_file Configuration Tests
 * ============================================================================ */

/* Test: blob_database_file basic configuration */
void flb_test_blob_database_file_config(void)
{
    S3_TEST_DECLARE_VARS();

    S3_TEST_RUN_AND_CLEANUP("test.blob", "blob_database_file_config");
    S3_TEST_FINISH("blob_database_file_config");
}

/* Test: blob_database_file with custom path */
void flb_test_blob_database_custom_path(void)
{
    flb_ctx_t *ctx;
    int in_ffd, out_ffd, ret;
    char *db_path, *store_dir;
    struct flb_out_s3_init_options init_options = {0};
    struct flb_aws_client_mock_request_chain *chain;
    struct stat st;


    chain = FLB_AWS_CLIENT_MOCK(
        response(expect(METHOD, FLB_HTTP_POST),
                 set(STATUS, 200), set(PAYLOAD, S3_TEST_MOCK_CREATE_RESP),
                 set(PAYLOAD_SIZE, sizeof(S3_TEST_MOCK_CREATE_RESP) - 1)),
        response(expect(METHOD, FLB_HTTP_PUT),
                 set(STATUS, 200), set(DATA, S3_TEST_MOCK_UPLOAD_PART_RESP),
                 set(DATA_SIZE, sizeof(S3_TEST_MOCK_UPLOAD_PART_RESP) - 1)),
        response(expect(METHOD, FLB_HTTP_POST),
                 set(STATUS, 200), set(PAYLOAD, S3_TEST_MOCK_COMPLETE_RESP),
                 set(PAYLOAD_SIZE, sizeof(S3_TEST_MOCK_COMPLETE_RESP) - 1))
    );

    flb_aws_client_mock_configure_generator(chain);
    init_options.client_generator = flb_aws_client_get_mock_generator();

    db_path = s3_test_create_temp_db_path("blob_custom");
    if (db_path == NULL) {
        TEST_CHECK(0);
        TEST_MSG("Failed to create temp db_path");
        return;
    }
    
    store_dir = s3_test_create_temp_store_dir("blob_custom");
    if (store_dir == NULL) {
        TEST_CHECK(0);
        TEST_MSG("Failed to create temp store_dir");
        flb_free(db_path);
        return;
    }

    s3_test_set_env_vars();
    ctx = flb_create();
    S3_TEST_CHECK_CONTEXT(ctx, db_path, store_dir);
    flb_service_set(ctx, "flush", "1", "grace", "1", NULL);

    in_ffd = flb_input(ctx, (char *)"lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test.blob", NULL);

    out_ffd = flb_output(ctx, (char *)"s3", (struct flb_lib_out_cb *)&init_options);
    TEST_CHECK(out_ffd >= 0);
    ret = flb_output_set(ctx, out_ffd, "match", "*",
                         "region", S3_TEST_DEFAULT_REGION,
                         "bucket", S3_TEST_DEFAULT_BUCKET,
                         "blob_database_file", db_path,
                         "store_dir", store_dir,
                         "total_file_size", "1M",
                         "upload_timeout", "1s", NULL);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Verify database file was created - retry to avoid race with async DB creation */
    {
        int retry_count = 0;
        int max_retries = 10;
        while (retry_count < max_retries) {
            ret = stat(db_path, &st);
            if (ret == 0) {
                break;
            }
            S3_TEST_SLEEP_MS(100);
            retry_count++;
        }
        TEST_CHECK(ret == 0);
        TEST_MSG("blob_database_file should be created at: %s", db_path);
    }

    ret = flb_lib_push(ctx, in_ffd, (char *)JSON_TD, sizeof(JSON_TD) - 1);
    TEST_CHECK(ret >= 0);

    S3_TEST_WAIT_MOCK_EXHAUSTED(5, "blob_database_custom_path");
    s3_test_cleanup(ctx, db_path, store_dir);
}

/* ============================================================================
 * Delivery Attempt Limits Tests
 * ============================================================================
 * These tests verify that delivery attempt limit configuration parameters
 * are correctly accepted. Actual retry behavior is handled by the recovery
 * mechanism which processes ABORTED files in subsequent cycles.
 */

/* Test: file_delivery_attempt_limit configuration */
void flb_test_file_delivery_attempt_limit(void)
{
    S3_TEST_DECLARE_VARS();
    S3_TEST_SIMPLE("test.blob", "file_delivery_attempt_limit",
                   "file_delivery_attempt_limit", "3");
}

/* Test: part_delivery_attempt_limit configuration */
void flb_test_part_delivery_attempt_limit(void)
{
    S3_TEST_DECLARE_VARS();
    S3_TEST_SIMPLE("test.blob", "part_delivery_attempt_limit",
                   "part_delivery_attempt_limit", "5");
}

/* Test: unlimited delivery attempts (-1) */
void flb_test_unlimited_delivery_attempts(void)
{
    S3_TEST_DECLARE_VARS();
    S3_TEST_SIMPLE("test.blob", "unlimited_delivery_attempts",
                   "file_delivery_attempt_limit", "-1");
}

/* ============================================================================
 * Upload Parts Freshness Threshold Tests
 * ============================================================================ */

/* Test: upload_part_freshness_limit configuration */
void flb_test_upload_part_freshness_limit(void)
{
    S3_TEST_DECLARE_VARS();
    S3_TEST_SIMPLE("test.blob", "upload_part_freshness_limit",
                   "upload_part_freshness_limit", "600");
}

/* Test: short freshness limit (quick stale detection) */
void flb_test_short_freshness_limit(void)
{
    S3_TEST_DECLARE_VARS();
    S3_TEST_SIMPLE("test.blob", "short_freshness_limit",
                   "upload_part_freshness_limit", "60");
}

/* ============================================================================
 * Upload Chunk Size Tests
 * ============================================================================ */

/* Test: upload_chunk_size configuration */
void flb_test_upload_chunk_size_config(void)
{
    S3_TEST_DECLARE_VARS();
    S3_TEST_SIMPLE("test.blob", "upload_chunk_size_config",
                   "upload_chunk_size", "10M");
}

/* ============================================================================
 * Test List
 * ============================================================================ */

TEST_LIST = {
    {"blob_database_file_config",        flb_test_blob_database_file_config},
    {"blob_database_custom_path",        flb_test_blob_database_custom_path},
    {"file_delivery_attempt_limit",      flb_test_file_delivery_attempt_limit},
    {"part_delivery_attempt_limit",      flb_test_part_delivery_attempt_limit},
    {"unlimited_delivery_attempts",      flb_test_unlimited_delivery_attempts},
    {"upload_part_freshness_limit",      flb_test_upload_part_freshness_limit},
    {"short_freshness_limit",            flb_test_short_freshness_limit},
    {"upload_chunk_size_config",         flb_test_upload_chunk_size_config},
    {NULL, NULL}
};
