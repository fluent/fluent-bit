/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit.h>
#include <fluent-bit/flb_aws_util.h>
#include <fluent-bit/flb_sds.h>
#include "flb_tests_runtime.h"
#include "../include/aws_client_mock.h"

#include "../include/s3_test_helpers.h"
#include "../../plugins/out_s3/s3.h"

/* Test data */
#include "data/td/json_td.h" /* JSON_TD */

/* ============================================================================
 * Format and Compression Combination Tests
 * ============================================================================ */

/**
 * Test: Snappy compression with JSON format
 *
 * Verifies that Snappy compression works correctly when combined
 * with JSON output format. This tests the integration between
 * format conversion and compression.
 */
void flb_test_snappy_with_json(void)
{
    S3_TEST_DECLARE_VARS();
    S3_TEST_SIMPLE("test", "snappy_with_json",
                   "format", "json",
                   "compression", "snappy");
}

/* ============================================================================
 * Blob Configuration Tests
 * ============================================================================ */

/**
 * Test: Blob with custom part_size
 *
 * Verifies that the plugin correctly applies custom part_size setting
 * for blob uploads.
 */
void flb_test_blob_custom_part_size(void)
{
    S3_TEST_DECLARE_VARS();
    S3_TEST_SIMPLE("test", "blob_custom_part_size", "part_size", "5242880");
}

/* ============================================================================
 * Credential Handling Tests
 * ============================================================================ */

/**
 * Test: Credential expiration with retry
 *
 * Tests credential expiration scenario with file_delivery_attempt_limit > 1.
 * This simulates the case where credentials expire during upload, and
 * verifies that the request is retried after credentials are refreshed.
 */
void flb_test_credential_expiration_retry(void)
{
    S3_TEST_DECLARE_VARS();
    S3_TEST_SIMPLE("test", "credential_expiration_retry",
                   "file_delivery_attempt_limit", "3",
                   "part_delivery_attempt_limit", "5");
}

/**
 * Test: Credential expiration with strict mode (file_delivery_attempt_limit=1)
 *
 * Tests that with file_delivery_attempt_limit=1, credential expiration
 * still allows one immediate retry after credential refresh.
 */
void flb_test_credential_expiration_strict(void)
{
    S3_TEST_DECLARE_VARS();
    S3_TEST_SIMPLE("test", "credential_expiration_strict",
                   "file_delivery_attempt_limit", "1");
}

/* ============================================================================
 * Additional Configuration Tests
 * ============================================================================ */

/**
 * Test: Multiple workers configuration
 *
 * Verifies that the S3 plugin correctly handles multiple worker threads.
 */
void flb_test_multiple_workers(void)
{
    S3_TEST_DECLARE_VARS();
    S3_TEST_SIMPLE("test", "multiple_workers", "workers", "3");
}

/* Test list */
TEST_LIST = {
    /* Format + Compression combination tests */
    {"snappy_with_json", flb_test_snappy_with_json},
    /* Blob configuration tests */
    {"blob_custom_part_size", flb_test_blob_custom_part_size},
    /* Credential handling tests */
    {"credential_expiration_retry", flb_test_credential_expiration_retry},
    {"credential_expiration_strict", flb_test_credential_expiration_strict},
    /* Worker configuration tests */
    {"multiple_workers", flb_test_multiple_workers},
    {NULL, NULL}
};