/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit.h>
#include <fluent-bit/flb_compat.h>
#include <fluent-bit/flb_sds.h>
#include "flb_tests_runtime.h"
#include "../include/aws_client_mock.h"

#include "../include/s3_test_helpers.h"
#include "../../plugins/out_s3/s3.h"

/* Test data */
#include "data/td/json_td.h" /* JSON_TD */

/* ============================================================================
 * Test: Empty data upload - verify no crash on empty flush
 * ============================================================================ */
void flb_test_empty_data_upload(void)
{
    S3_TEST_DECLARE_VARS();

    S3_TEST_RUN_AND_CLEANUP("test", "empty_data_upload");

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Do not push any data - test empty flush */
    /* Note: Empty flush may not consume mock chain, just wait briefly */
    S3_TEST_SLEEP_MS(2000);

    /* Verify no crash occurred - reaching here is the test */
    TEST_CHECK(ret == 0);

    s3_test_cleanup(ctx, db_path, store_dir);
}

/* ============================================================================
 * Test: Large file chunking - data accumulation triggers upload
 * Tests that accumulated data is properly chunked and uploaded.
 * ============================================================================ */
void flb_test_large_file_chunking(void)
{
    S3_TEST_DECLARE_VARS();

    S3_TEST_RUN_AND_CLEANUP("test", "large_file_chunking");

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Push data - upload will be triggered by timeout */
    ret = flb_lib_push(ctx, in_ffd, (char *)JSON_TD, (int)sizeof(JSON_TD) - 1);
    TEST_CHECK(ret >= 0);
    ret = flb_lib_push(ctx, in_ffd, (char *)JSON_TD, (int)sizeof(JSON_TD) - 1);
    TEST_CHECK(ret >= 0);
    S3_TEST_WAIT_MOCK_EXHAUSTED(4, "large_file_chunking");
    s3_test_cleanup(ctx, db_path, store_dir);
}

/* ============================================================================
 * Test: Maximum concurrent uploads with multiple workers
 * ============================================================================ */
void flb_test_max_concurrent_uploads(void)
{
    S3_TEST_DECLARE_VARS();
    S3_TEST_SIMPLE("test", "max_concurrent_uploads", "workers", "10");
}

/* ============================================================================
 * Test: Minimal timeout settings - 1 second timeout
 * ============================================================================ */
void flb_test_minimal_timeout(void)
{
    S3_TEST_DECLARE_VARS();
    S3_TEST_SIMPLE("test", "minimal_timeout");
}

/* ============================================================================
 * Test: Timeout trigger priority over file size
 * With large total_file_size but short timeout, timeout should trigger first
 * ============================================================================ */
void flb_test_timeout_trigger_priority(void)
{
    S3_TEST_DECLARE_VARS();

    S3_TEST_SETUP_STANDARD_MOCK();
    S3_TEST_CREATE_PATHS("timeout_priority");
    S3_TEST_INIT_CONTEXT();
    S3_TEST_SETUP_INPUT("test");
    S3_TEST_SETUP_OUTPUT_MINIMAL();
    ret = flb_output_set(ctx, out_ffd,
                   "bucket", S3_TEST_DEFAULT_BUCKET,
                   "total_file_size", "100M", NULL);
    TEST_CHECK(ret == 0);
    S3_TEST_FINISH("timeout_trigger_priority");
}

/* ============================================================================
 * Test: S3 key format with special characters and tag segments
 * ============================================================================ */
void flb_test_s3_key_format_special_chars(void)
{
    S3_TEST_DECLARE_VARS();
    S3_TEST_SIMPLE("test/special", "s3_key_format_special_chars",
                   "s3_key_format", "/logs/$TAG[0]/$TAG[1]/%Y/%m/%d/data.log");
}

/* ============================================================================
 * Test: Tag delimiter configuration for S3 key format
 * ============================================================================ */
void flb_test_tag_delimiter_config(void)
{
    S3_TEST_DECLARE_VARS();

    S3_TEST_RUN_AND_CLEANUP("app.service.logs", "tag_delimiter_config");
    ret = flb_output_set(ctx, out_ffd,
                   "s3_key_format", "/$TAG[0]/$TAG[1]/$TAG[2]/%Y%m%d.log",
                   "s3_key_format_tag_delimiters", ".", NULL);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Push same data multiple times */
    ret = flb_lib_push(ctx, in_ffd, (char *)JSON_TD, (int)sizeof(JSON_TD) - 1);
    TEST_CHECK(ret >= 0);
    ret = flb_lib_push(ctx, in_ffd, (char *)JSON_TD, (int)sizeof(JSON_TD) - 1);
    TEST_CHECK(ret >= 0);
    S3_TEST_WAIT_MOCK_EXHAUSTED(4, "tag_delimiter_config");
    s3_test_cleanup(ctx, db_path, store_dir);
}

/* ============================================================================
 * Test: Custom store_dir configuration
 * ============================================================================ */
void flb_test_custom_store_dir(void)
{
    S3_TEST_DECLARE_VARS();
    S3_TEST_SIMPLE("test", "custom_store_dir");
}

/* ============================================================================
 * Test: Configuration boundary values - minimum settings
 * ============================================================================ */
void flb_test_config_boundary_minimum(void)
{
    S3_TEST_DECLARE_VARS();

    S3_TEST_SETUP_STANDARD_MOCK();
    S3_TEST_CREATE_PATHS("boundary_min");
    S3_TEST_INIT_CONTEXT();
    S3_TEST_SETUP_INPUT("test");
    S3_TEST_SETUP_OUTPUT_MINIMAL();
    ret = flb_output_set(ctx, out_ffd,
                   "bucket", S3_TEST_DEFAULT_BUCKET,
                   "total_file_size", "1M",
                   "workers", "1",
                   "retry_limit", "1", NULL);
    TEST_CHECK(ret == 0);
    S3_TEST_FINISH("config_boundary_minimum");
}

/* ============================================================================
 * Test: Configuration boundary values - maximum settings
 * ============================================================================ */
void flb_test_config_boundary_maximum(void)
{
    S3_TEST_DECLARE_VARS();

    S3_TEST_SETUP_STANDARD_MOCK();
    S3_TEST_CREATE_PATHS("boundary_max");
    S3_TEST_INIT_CONTEXT();
    S3_TEST_SETUP_INPUT("test");
    S3_TEST_SETUP_OUTPUT_MINIMAL();
    ret = flb_output_set(ctx, out_ffd,
                   "bucket", S3_TEST_DEFAULT_BUCKET,
                   "total_file_size", "100M",
                   "upload_chunk_size", "50M",
                   "workers", "100",
                   "retry_limit", "10", NULL);
    TEST_CHECK(ret == 0);
    S3_TEST_FINISH("config_boundary_maximum");
}

/* ============================================================================
 * Test: Compression with very small data
 * ============================================================================ */
void flb_test_compression_small_data(void)
{
    S3_TEST_DECLARE_VARS();

    S3_TEST_SETUP_STANDARD_MOCK();
    S3_TEST_CREATE_PATHS("compression_small");
    S3_TEST_INIT_CONTEXT();
    S3_TEST_SETUP_INPUT("test");
    S3_TEST_SETUP_OUTPUT_MINIMAL();
    ret = flb_output_set(ctx, out_ffd,
                   "bucket", S3_TEST_DEFAULT_BUCKET,
                   "total_file_size", "1K",
                   "compression", "gzip", NULL);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Push very small data to test compression edge case */
    ret = flb_lib_push(ctx, in_ffd, (char *)"[1448403340,{\"msg\":\"x\"}]", 
                      sizeof("[1448403340,{\"msg\":\"x\"}]") - 1);
    TEST_CHECK(ret >= 0);
    S3_TEST_WAIT_MOCK_EXHAUSTED(4, "compression_small_data");
    s3_test_cleanup(ctx, db_path, store_dir);
}

/* ============================================================================
 * Test: Rapid start/stop cycles
 * ============================================================================ */
void flb_test_rapid_start_stop(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    struct flb_out_s3_init_options init_options = {0};
    struct flb_aws_client_mock_request_chain *chain;
    char *db_path;
    char *store_dir;


    /* First configuration */
    chain = FLB_AWS_CLIENT_MOCK(
        response(
            set(STATUS, 200),
            set(PAYLOAD, S3_TEST_MOCK_CREATE_RESP),
            set(PAYLOAD_SIZE, sizeof(S3_TEST_MOCK_CREATE_RESP) - 1)
        ),
        response(
            set(STATUS, 200),
            set(DATA, S3_TEST_MOCK_UPLOAD_PART_RESP),
            set(DATA_SIZE, sizeof(S3_TEST_MOCK_UPLOAD_PART_RESP) - 1)
        ),
        response(
            set(STATUS, 200),
            set(PAYLOAD, S3_TEST_MOCK_COMPLETE_RESP),
            set(PAYLOAD_SIZE, sizeof(S3_TEST_MOCK_COMPLETE_RESP) - 1)
        )
    );

    flb_aws_client_mock_configure_generator(chain);
    init_options.client_generator = flb_aws_client_get_mock_generator();

    db_path = s3_test_create_temp_db_path("rapid1");
    store_dir = s3_test_create_temp_store_dir("rapid1");

    if (db_path == NULL || store_dir == NULL) {
        TEST_MSG("Failed to create temp paths");
        if (db_path != NULL) {
            s3_test_cleanup_temp_db(db_path);
            flb_free(db_path);
        }
        if (store_dir != NULL) {
            s3_test_cleanup_temp_store_dir(store_dir);
            flb_free(store_dir);
        }
        flb_aws_client_mock_destroy_generator();
        TEST_CHECK(false);
        return;
    }

    s3_test_set_env_vars();
    ctx = flb_create();
    S3_TEST_CHECK_CONTEXT(ctx, db_path, store_dir);
    flb_service_set(ctx, "flush", "1", "grace", "1", NULL);

    in_ffd = flb_input(ctx, (char *)"lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *)"s3", (struct flb_lib_out_cb *)&init_options);
    TEST_CHECK(out_ffd >= 0);
    ret = flb_output_set(ctx, out_ffd,
                   "match", "*",
                   "region", S3_TEST_DEFAULT_REGION,
                   "bucket", "test-bucket-1",
                   "blob_database_file", db_path,
                   "store_dir", store_dir,
                   "total_file_size", "10M",
                   "upload_chunk_size", "5M",
                   "upload_timeout", "1s",
                   NULL);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    ret = flb_lib_push(ctx, in_ffd, (char *)JSON_TD, (int)sizeof(JSON_TD) - 1);
    TEST_CHECK(ret >= 0);
    S3_TEST_WAIT_MOCK_EXHAUSTED(3, "rapid_start_stop_1");
    s3_test_cleanup(ctx, db_path, store_dir);

    /* Second configuration - different bucket */

    chain = FLB_AWS_CLIENT_MOCK(
        response(
            set(STATUS, 200),
            set(PAYLOAD, S3_TEST_MOCK_CREATE_RESP),
            set(PAYLOAD_SIZE, sizeof(S3_TEST_MOCK_CREATE_RESP) - 1)
        ),
        response(
            set(STATUS, 200),
            set(DATA, S3_TEST_MOCK_UPLOAD_PART_RESP),
            set(DATA_SIZE, sizeof(S3_TEST_MOCK_UPLOAD_PART_RESP) - 1)
        ),
        response(
            set(STATUS, 200),
            set(PAYLOAD, S3_TEST_MOCK_COMPLETE_RESP),
            set(PAYLOAD_SIZE, sizeof(S3_TEST_MOCK_COMPLETE_RESP) - 1)
        )
    );

    flb_aws_client_mock_configure_generator(chain);
    init_options.client_generator = flb_aws_client_get_mock_generator();

    db_path = s3_test_create_temp_db_path("rapid2");
    store_dir = s3_test_create_temp_store_dir("rapid2");

    if (db_path == NULL || store_dir == NULL) {
        TEST_MSG("Failed to create temp paths");
        if (db_path != NULL) {
            s3_test_cleanup_temp_db(db_path);
            flb_free(db_path);
        }
        if (store_dir != NULL) {
            s3_test_cleanup_temp_store_dir(store_dir);
            flb_free(store_dir);
        }
        flb_aws_client_mock_destroy_generator();
        TEST_CHECK(false);
        return;
    }

    s3_test_set_env_vars();
    ctx = flb_create();
    S3_TEST_CHECK_CONTEXT(ctx, db_path, store_dir);
    flb_service_set(ctx, "flush", "1", "grace", "1", NULL);

    in_ffd = flb_input(ctx, (char *)"lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *)"s3", (struct flb_lib_out_cb *)&init_options);
    TEST_CHECK(out_ffd >= 0);
    ret = flb_output_set(ctx, out_ffd,
                   "match", "*",
                   "region", S3_TEST_DEFAULT_REGION,
                   "bucket", "test-bucket-2",
                   "blob_database_file", db_path,
                   "store_dir", store_dir,
                   "total_file_size", "10M",
                   "upload_chunk_size", "5M",
                   "upload_timeout", "1s",
                   NULL);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    ret = flb_lib_push(ctx, in_ffd, (char *)JSON_TD, (int)sizeof(JSON_TD) - 1);
    TEST_CHECK(ret >= 0);
    S3_TEST_WAIT_MOCK_EXHAUSTED(3, "rapid_start_stop_2");

    /* Verify second configuration worked - flb_lib_push succeeded */
    TEST_CHECK(ret >= 0);

    s3_test_cleanup(ctx, db_path, store_dir);
}

/* Test list */
TEST_LIST = {
    {"empty_data_upload", flb_test_empty_data_upload},
    {"large_file_chunking", flb_test_large_file_chunking},
    {"max_concurrent_uploads", flb_test_max_concurrent_uploads},
    {"minimal_timeout", flb_test_minimal_timeout},
    {"timeout_trigger_priority", flb_test_timeout_trigger_priority},
    {"s3_key_format_special_chars", flb_test_s3_key_format_special_chars},
    {"tag_delimiter_config", flb_test_tag_delimiter_config},
    {"custom_store_dir", flb_test_custom_store_dir},
    {"config_boundary_minimum", flb_test_config_boundary_minimum},
    {"config_boundary_maximum", flb_test_config_boundary_maximum},
    {"compression_small_data", flb_test_compression_small_data},
    {"rapid_start_stop", flb_test_rapid_start_stop},
    {NULL, NULL}
};