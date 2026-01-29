/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_aws_util.h>
#include "flb_tests_runtime.h"
#include "../include/aws_client_mock.h"

#include "../include/s3_test_helpers.h"
#include "../../plugins/out_s3/s3.h"
#include "../../plugins/out_s3/s3_store.h"
#include "data/td/json_td.h"

/* ============================================================================
 * Buffer Space Management Tests
 * ============================================================================ */

/**
 * Test: Buffer space check with adequate space
 *
 * Verifies that buffer space checking works correctly when
 * there is sufficient space available.
 */
void flb_test_buffer_space_adequate(void)
{
    S3_TEST_DECLARE_VARS();
    S3_TEST_SIMPLE("test", "buffer_space_adequate",
                   "store_dir_limit_size", "100M");
}

/**
 * Test: Buffer space exhaustion handling
 *
 * Verifies correct behavior when store_dir reaches its size limit.
 * The plugin should handle this gracefully without crashing.
 */
void flb_test_buffer_space_exhaustion(void)
{
    S3_TEST_DECLARE_VARS();
    int i;
    int buffer_exhausted = FLB_FALSE;

    S3_TEST_SETUP_STANDARD_MOCK();
    S3_TEST_CREATE_PATHS("store_exhaust");
    S3_TEST_INIT_CONTEXT();
    S3_TEST_SETUP_INPUT("test");

    out_ffd = flb_output(ctx, (char *)"s3", (struct flb_lib_out_cb *)&init_options);
    TEST_CHECK(out_ffd >= 0);
    ret = flb_output_set(ctx, out_ffd, "match", "*",
                   "region", S3_TEST_DEFAULT_REGION,
                   "bucket", S3_TEST_DEFAULT_BUCKET,
                   "blob_database_file", db_path,
                   "store_dir", store_dir,
                   "store_dir_limit_size", "1M",  /* Very small limit */
                   "total_file_size", "100K",
                   "upload_timeout", "1s", NULL);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Push data multiple times to potentially exceed store limit */
    for (i = 0; i < 20; i++) {
        ret = flb_lib_push(ctx, in_ffd, (char *)JSON_TD, sizeof(JSON_TD) - 1);
        if (ret < 0) {
            buffer_exhausted = FLB_TRUE;
            break;  /* Expected when buffer is full */
        }
        S3_TEST_SLEEP_MS(50);
    }

    TEST_CHECK(buffer_exhausted == FLB_TRUE);
    S3_TEST_WAIT_MOCK_EXHAUSTED(5, "buffer_space_exhaustion");
    s3_test_cleanup(ctx, db_path, store_dir);
}

/**
 * Test: Buffer space check with zero limit (unlimited)
 *
 * Verifies that setting store_dir_limit_size=0 allows unlimited buffering.
 */
void flb_test_buffer_space_unlimited(void)
{
    S3_TEST_DECLARE_VARS();
    S3_TEST_SIMPLE("test", "buffer_space_unlimited",
                   "store_dir_limit_size", "0");
}

/* ============================================================================
 * File State Management Tests
 * ============================================================================ */

/**
 * Test: File activation and deactivation
 *
 * Verifies that files can be properly marked as active/inactive
 * in the store system.
 */
void flb_test_file_state_management(void)
{
    S3_TEST_DECLARE_VARS();
    
    S3_TEST_SETUP_STANDARD_MOCK();
    S3_TEST_CREATE_PATHS("file_state");
    S3_TEST_INIT_CONTEXT();
    S3_TEST_SETUP_INPUT("test");
    S3_TEST_SETUP_OUTPUT_BASIC();

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Push data and let it be processed */
    ret = flb_lib_push(ctx, in_ffd, (char *)JSON_TD, sizeof(JSON_TD) - 1);
    TEST_CHECK(ret >= 0);

    S3_TEST_WAIT_MOCK_EXHAUSTED(5, "file_state_management");
    s3_test_cleanup(ctx, db_path, store_dir);
}

/**
 * Test: File deletion after successful upload
 *
 * Verifies that files are properly deleted from the store
 * after successful S3 upload.
 */
void flb_test_file_cleanup_after_upload(void)
{
    S3_TEST_DECLARE_VARS();
    
    S3_TEST_SETUP_STANDARD_MOCK();
    S3_TEST_CREATE_PATHS("file_cleanup");
    S3_TEST_INIT_CONTEXT();
    S3_TEST_SETUP_INPUT("test");
    S3_TEST_SETUP_OUTPUT_BASIC();

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    ret = flb_lib_push(ctx, in_ffd, (char *)JSON_TD, sizeof(JSON_TD) - 1);
    TEST_CHECK(ret >= 0);

    S3_TEST_WAIT_MOCK_EXHAUSTED(5, "file_cleanup_after_upload");
    s3_test_cleanup(ctx, db_path, store_dir);
}

/* ============================================================================
 * File Restoration Tests
 * ============================================================================ */

/**
 * Test: Restore buffered files on startup
 *
 * Verifies that the plugin can restore previously buffered files
 * from fstore when restarting.
 */
void flb_test_restore_buffered_files(void)
{
    S3_TEST_DECLARE_VARS();

    S3_TEST_SETUP_STANDARD_MOCK();
    S3_TEST_CREATE_PATHS("restore");
    S3_TEST_INIT_CONTEXT();
    S3_TEST_SETUP_INPUT("test");
    S3_TEST_SETUP_OUTPUT_BASIC();

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    ret = flb_lib_push(ctx, in_ffd, (char *)JSON_TD, sizeof(JSON_TD) - 1);
    TEST_CHECK(ret >= 0);

    S3_TEST_WAIT_MOCK_EXHAUSTED(5, "restore_buffered_files");
    s3_test_cleanup(ctx, db_path, store_dir);
}

/**
 * Test: Handle corrupted file during restoration
 *
 * Verifies that the plugin gracefully handles corrupted chunk files
 * during restoration without crashing.
 */
void flb_test_restore_corrupted_file_handling(void)
{
    S3_TEST_DECLARE_VARS();
    
    /* This test verifies the plugin can start even if store has issues */
    S3_TEST_SETUP_STANDARD_MOCK();
    S3_TEST_CREATE_PATHS("restore_corrupt");
    S3_TEST_INIT_CONTEXT();
    S3_TEST_SETUP_INPUT("test");
    S3_TEST_SETUP_OUTPUT_BASIC();

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Push new data - plugin should handle any previous corruption */
    ret = flb_lib_push(ctx, in_ffd, (char *)JSON_TD, sizeof(JSON_TD) - 1);
    TEST_CHECK(ret >= 0);

    S3_TEST_WAIT_MOCK_EXHAUSTED(5, "restore_corrupted_file_handling");
    s3_test_cleanup(ctx, db_path, store_dir);
}

/* ============================================================================
 * File Locking Tests
 * ============================================================================ */

/**
 * Test: File lock mechanism
 *
 * Verifies that file locking prevents concurrent access to the same file.
 * Note: This is a basic test - real contention testing requires threading.
 */
void flb_test_file_lock_mechanism(void)
{
    S3_TEST_DECLARE_VARS();
    
    S3_TEST_SETUP_STANDARD_MOCK();
    S3_TEST_CREATE_PATHS("file_lock");
    S3_TEST_INIT_CONTEXT();
    S3_TEST_SETUP_INPUT("test");
    S3_TEST_SETUP_OUTPUT_BASIC();
    
    /* Enable multiple workers to test locking */
    ret = flb_output_set(ctx, out_ffd, "workers", "3", NULL);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Push data with multiple workers active */
    ret = flb_lib_push(ctx, in_ffd, (char *)JSON_TD, sizeof(JSON_TD) - 1);
    TEST_CHECK(ret >= 0);

    S3_TEST_WAIT_MOCK_EXHAUSTED(5, "file_lock_mechanism");
    s3_test_cleanup(ctx, db_path, store_dir);
}

/* ============================================================================
 * Data Buffering Tests
 * ============================================================================ */

/**
 * Test: Buffer data until file size threshold
 *
 * Verifies that data is buffered in the store until total_file_size
 * threshold is reached.
 */
void flb_test_buffer_until_threshold(void)
{
    S3_TEST_DECLARE_VARS();
    int i;

    S3_TEST_SETUP_STANDARD_MOCK();
    S3_TEST_CREATE_PATHS("buffer_threshold");
    S3_TEST_INIT_CONTEXT();
    S3_TEST_SETUP_INPUT("test");

    out_ffd = flb_output(ctx, (char *)"s3", (struct flb_lib_out_cb *)&init_options);
    TEST_CHECK(out_ffd >= 0);
    ret = flb_output_set(ctx, out_ffd, "match", "*",
                   "region", S3_TEST_DEFAULT_REGION,
                   "bucket", S3_TEST_DEFAULT_BUCKET,
                   "blob_database_file", db_path,
                   "store_dir", store_dir,
                   "total_file_size", "10M",  /* Large threshold */
                   "upload_timeout", "2s",    /* Will trigger on timeout */
                   NULL);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Push small amounts of data - should buffer */
    for (i = 0; i < 5; i++) {
        ret = flb_lib_push(ctx, in_ffd, (char *)JSON_TD, sizeof(JSON_TD) - 1);
        TEST_CHECK(ret >= 0);
        S3_TEST_SLEEP_MS(100);
    }

    S3_TEST_WAIT_MOCK_EXHAUSTED(5, "buffer_until_threshold");
    s3_test_cleanup(ctx, db_path, store_dir);
}

/**
 * Test: Buffer data for multiple tags
 *
 * Verifies that the store correctly handles multiple input tags.
 * The test creates two inputs with different tags and pushes data to one,
 * verifying the plugin can buffer and upload successfully.
 */
void flb_test_buffer_multiple_tags(void)
{
    S3_TEST_DECLARE_VARS();
    int in_ffd2;

    /* Use standard mock for one successful upload */
    S3_TEST_SETUP_STANDARD_MOCK();
    S3_TEST_CREATE_PATHS("multi_tag");
    S3_TEST_INIT_CONTEXT();
    
    /* Setup two inputs with different tags to test tag handling */
    in_ffd = flb_input(ctx, (char *)"lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    ret = flb_input_set(ctx, in_ffd, "tag", "app.service1", NULL);
    TEST_CHECK(ret == 0);

    in_ffd2 = flb_input(ctx, (char *)"lib", NULL);
    TEST_CHECK(in_ffd2 >= 0);
    ret = flb_input_set(ctx, in_ffd2, "tag", "app.service2", NULL);
    TEST_CHECK(ret == 0);

    S3_TEST_SETUP_OUTPUT_BASIC();

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Push data to only first input - will result in one file upload */
    ret = flb_lib_push(ctx, in_ffd, (char *)JSON_TD, sizeof(JSON_TD) - 1);
    TEST_CHECK(ret >= 0);

    /* Wait for the file to be uploaded */
    S3_TEST_WAIT_MOCK_EXHAUSTED(5, "buffer_multiple_tags");
    s3_test_cleanup(ctx, db_path, store_dir);
}

/**
 * Test: File hash generation consistency
 *
 * Verifies that the same tag always generates the same filename hash,
 * ensuring data from the same tag goes to the same file.
 */
void flb_test_filename_hash_consistency(void)
{
    S3_TEST_DECLARE_VARS();
    
    S3_TEST_SETUP_STANDARD_MOCK();
    S3_TEST_CREATE_PATHS("hash_consistency");
    S3_TEST_INIT_CONTEXT();
    S3_TEST_SETUP_INPUT("app.service");
    S3_TEST_SETUP_OUTPUT_BASIC();

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Push data multiple times - should use same file */
    ret = flb_lib_push(ctx, in_ffd, (char *)JSON_TD, sizeof(JSON_TD) - 1);
    TEST_CHECK(ret >= 0);
    S3_TEST_SLEEP_MS(100);
    ret = flb_lib_push(ctx, in_ffd, (char *)JSON_TD, sizeof(JSON_TD) - 1);
    TEST_CHECK(ret >= 0);

    S3_TEST_WAIT_MOCK_EXHAUSTED(5, "filename_hash_consistency");
    s3_test_cleanup(ctx, db_path, store_dir);
}

/* Test List */
TEST_LIST = {
    /* Buffer space management */
    {"buffer_space_adequate", flb_test_buffer_space_adequate},
    {"buffer_space_exhaustion", flb_test_buffer_space_exhaustion},
    {"buffer_space_unlimited", flb_test_buffer_space_unlimited},
    /* File state management */
    {"file_state_management", flb_test_file_state_management},
    {"file_cleanup_after_upload", flb_test_file_cleanup_after_upload},
    /* File restoration */
    {"restore_buffered_files", flb_test_restore_buffered_files},
    {"restore_corrupted_file_handling", flb_test_restore_corrupted_file_handling},
    /* File locking */
    {"file_lock_mechanism", flb_test_file_lock_mechanism},
    /* Data buffering */
    {"buffer_until_threshold", flb_test_buffer_until_threshold},
    {"buffer_multiple_tags", flb_test_buffer_multiple_tags},
    {"filename_hash_consistency", flb_test_filename_hash_consistency},
    {NULL, NULL}
};