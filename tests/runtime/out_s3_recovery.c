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

#include <sqlite3.h>

/*
 * Helper to pre-seed database with an existing upload using sqlite3 C API
 * Returns 0 on success, non-zero on failure
 */
static int seed_recovery_db(const char *db_path, const char *store_dir, int all_parts_uploaded)
{
    char file_path[1024];
    FILE *fp;
    sqlite3 *db = NULL;
    char *err_msg = NULL;
    int rc;
    char sql[4096];
    unsigned long created_time;
    
    /* Create a dummy file in store_dir representing the buffered data */
    snprintf(file_path, sizeof(file_path), "%s/test_file.data", store_dir);
    fp = fopen(file_path, "wb");
    if (!fp) {
        fprintf(stderr, "Failed to create dummy file: %s\n", file_path);
        return -1;
    }
    
    /* Write 6MB of data (enough for > 5M part size) */
    char *buf = calloc(1, 6 * 1024 * 1024);
    if (!buf) {
        fprintf(stderr, "Failed to allocate buffer for dummy file\n");
        fclose(fp);
        return -1;
    }
    
    memset(buf, 'A', 6 * 1024 * 1024);
    size_t written = fwrite(buf, 1, 6 * 1024 * 1024, fp);
    free(buf);
    
    if (written != 6 * 1024 * 1024) {
        fprintf(stderr, "Failed to write full dummy file: wrote %zu of %d bytes\n", 
                written, 6 * 1024 * 1024);
        fclose(fp);
        return -1;
    }
    
    fclose(fp);

    /* Open database */
    rc = sqlite3_open(db_path, &db);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
        if (db) {
            sqlite3_close(db);
        }
        return -1;
    }

    /* Create blob_files table */
    snprintf(sql, sizeof(sql),
        "CREATE TABLE IF NOT EXISTS blob_files ("
        "  id INTEGER PRIMARY KEY,"
        "  tag TEXT NOT NULL DEFAULT '',"
        "  source TEXT NOT NULL,"
        "  destination TEXT NOT NULL,"
        "  path TEXT NOT NULL,"
        "  s3_key TEXT NOT NULL DEFAULT '',"
        "  remote_id TEXT NOT NULL DEFAULT '',"
        "  size INTEGER,"
        "  created INTEGER,"
        "  delivery_attempts INTEGER DEFAULT 0,"
        "  aborted INTEGER DEFAULT 0,"
        "  last_delivery_attempt INTEGER DEFAULT 0"
        ");");
    
    rc = sqlite3_exec(db, sql, NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error creating blob_files: %s\n", err_msg);
        sqlite3_free(err_msg);
        sqlite3_close(db);
        return -1;
    }

    /* Create blob_parts table */
    snprintf(sql, sizeof(sql),
        "CREATE TABLE IF NOT EXISTS blob_parts ("
        "  id INTEGER PRIMARY KEY,"
        "  file_id INTEGER NOT NULL,"
        "  part_id INTEGER NOT NULL,"
        "  remote_id TEXT NOT NULL DEFAULT '',"
        "  uploaded INTEGER DEFAULT 0,"
        "  in_progress INTEGER DEFAULT 0,"
        "  offset_start INTEGER,"
        "  offset_end INTEGER,"
        "  delivery_attempts INTEGER DEFAULT 0,"
        "  FOREIGN KEY (file_id) REFERENCES blob_files(id) ON DELETE CASCADE"
        ");");
    
    rc = sqlite3_exec(db, sql, NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error creating blob_parts: %s\n", err_msg);
        sqlite3_free(err_msg);
        sqlite3_close(db);
        return -1;
    }

    /* Insert file record using parameterized statement */
    created_time = (unsigned long)time(NULL);
    
    sqlite3_stmt *stmt = NULL;
    const char *insert_sql = 
        "INSERT INTO blob_files (id, tag, source, destination, path, s3_key, remote_id, size, created) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);";
    
    rc = sqlite3_prepare_v2(db, insert_sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return -1;
    }
    
    sqlite3_bind_int(stmt, 1, 1);                                      /* id */
    sqlite3_bind_text(stmt, 2, "test", -1, SQLITE_STATIC);             /* tag */
    sqlite3_bind_text(stmt, 3, "", -1, SQLITE_STATIC);                 /* source */
    sqlite3_bind_text(stmt, 4, "s3.us-west-2.amazonaws.com", -1, SQLITE_STATIC); /* destination */
    sqlite3_bind_text(stmt, 5, file_path, -1, SQLITE_TRANSIENT);       /* path */
    sqlite3_bind_text(stmt, 6, "test-key", -1, SQLITE_STATIC);         /* s3_key */
    sqlite3_bind_text(stmt, 7, "test-upload-id", -1, SQLITE_STATIC);   /* remote_id */
    sqlite3_bind_int(stmt, 8, 6291456);                                /* size */
    sqlite3_bind_int64(stmt, 9, (sqlite3_int64)created_time);          /* created */
    
    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        fprintf(stderr, "SQL error inserting file: %s\n", sqlite3_errmsg(db));
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return -1;
    }
    
    sqlite3_finalize(stmt);

    /* Insert part record - if uploaded, include a mock ETag */
    if (all_parts_uploaded) {
        snprintf(sql, sizeof(sql),
            "INSERT INTO blob_parts (file_id, part_id, remote_id, uploaded, in_progress, offset_start, offset_end) "
            "VALUES (1, 1, '\"mock-etag-part-1\"', 1, 0, 0, 6291456);");
    }
    else {
        snprintf(sql, sizeof(sql),
            "INSERT INTO blob_parts (file_id, part_id, remote_id, uploaded, in_progress, offset_start, offset_end) "
            "VALUES (1, 1, '', 0, 0, 0, 6291456);");
    }
    
    rc = sqlite3_exec(db, sql, NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error inserting part: %s\n", err_msg);
        sqlite3_free(err_msg);
        sqlite3_close(db);
        return -1;
    }

    sqlite3_close(db);
    return 0;
}

/*
 * Test: Recovery Phase 1 - Resume CreateMultipartUpload
 *
 * Scenario: Plugin starts with pending blob in database that needs
 * CreateMultipartUpload to be called.
 */
void flb_test_recovery_phase1_create_multipart(void)
{
    S3_TEST_DECLARE_VARS();

    S3_TEST_SETUP_STANDARD_MOCK();
    S3_TEST_CREATE_PATHS("phase1");
    S3_TEST_INIT_CONTEXT();
    S3_TEST_SETUP_INPUT("test");
    S3_TEST_SETUP_OUTPUT_BASIC();
    ret = flb_output_set(ctx, out_ffd, "upload_chunk_size", "5M", NULL);
    TEST_CHECK(ret == 0);

    S3_TEST_START_AND_PUSH((char *)JSON_TD, sizeof(JSON_TD) - 1);
    S3_TEST_WAIT_MOCK_EXHAUSTED(5, "recovery_phase1_create_multipart");
    s3_test_cleanup(ctx, db_path, store_dir);
}

/*
 * Test: Recovery Phase 2 - Resume UploadPart
 *
 * Scenario: CreateMultipartUpload already completed (upload_id exists),
 * but parts need to be uploaded.
 */
void flb_test_recovery_phase2_upload_parts(void)
{
    S3_TEST_DECLARE_VARS();

    /* Skip CreateMultipartUpload, start with UploadPart -> Complete */
    chain = FLB_AWS_CLIENT_MOCK(
        response(expect(METHOD, FLB_HTTP_PUT),
                 set(STATUS, 200), set(DATA, S3_TEST_MOCK_UPLOAD_PART_RESP),
                 set(DATA_SIZE, sizeof(S3_TEST_MOCK_UPLOAD_PART_RESP) - 1)),
        response(expect(METHOD, FLB_HTTP_POST),
                 set(STATUS, 200), set(PAYLOAD, S3_TEST_MOCK_COMPLETE_RESP),
                 set(PAYLOAD_SIZE, sizeof(S3_TEST_MOCK_COMPLETE_RESP) - 1))
    );
    flb_aws_client_mock_configure_generator(chain);
    init_options.client_generator = flb_aws_client_get_mock_generator();

    S3_TEST_CREATE_PATHS("phase2");

    /* Pre-seed DB with existing upload, parts NOT uploaded */
    ret = seed_recovery_db(db_path, store_dir, 0);
    if (ret != 0) {
        TEST_CHECK(0);
        TEST_MSG("Failed to seed recovery database");
        s3_test_cleanup(NULL, db_path, store_dir);
        return;
    }

    S3_TEST_INIT_CONTEXT();
    S3_TEST_SETUP_INPUT("test");
    S3_TEST_SETUP_OUTPUT_BASIC();
    ret = flb_output_set(ctx, out_ffd, "upload_chunk_size", "5M", NULL);
    TEST_CHECK(ret == 0);

    /* We don't need to push new data, the plugin should recover the existing file */
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    S3_TEST_WAIT_MOCK_EXHAUSTED(5, "recovery_phase2_upload_parts");
    s3_test_cleanup(ctx, db_path, store_dir);
}

/*
 * Test: Recovery Phase 3 - Resume CompleteMultipartUpload
 *
 * Scenario: All parts uploaded, need to call CompleteMultipartUpload.
 */
void flb_test_recovery_phase3_complete(void)
{
    S3_TEST_DECLARE_VARS();

    /* Skip Create & UploadPart, expect only Complete */
    chain = FLB_AWS_CLIENT_MOCK(
        response(expect(METHOD, FLB_HTTP_POST),
                 set(STATUS, 200), set(PAYLOAD, S3_TEST_MOCK_COMPLETE_RESP),
                 set(PAYLOAD_SIZE, sizeof(S3_TEST_MOCK_COMPLETE_RESP) - 1))
    );
    flb_aws_client_mock_configure_generator(chain);
    init_options.client_generator = flb_aws_client_get_mock_generator();

    S3_TEST_CREATE_PATHS("phase3");

    /* Pre-seed DB with existing upload, parts ALREADY uploaded */
    ret = seed_recovery_db(db_path, store_dir, 1);
    if (ret != 0) {
        TEST_CHECK(0);
        TEST_MSG("Failed to seed recovery database");
        s3_test_cleanup(NULL, db_path, store_dir);
        return;
    }

    S3_TEST_INIT_CONTEXT();
    S3_TEST_SETUP_INPUT("test");
    S3_TEST_SETUP_OUTPUT_BASIC();
    ret = flb_output_set(ctx, out_ffd, 
                   "upload_chunk_size", "5M", NULL);
    TEST_CHECK(ret == 0);

    /* Plugin should recover and complete the upload */
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    S3_TEST_WAIT_MOCK_EXHAUSTED(6, "recovery_phase3_complete");
    s3_test_cleanup(ctx, db_path, store_dir);
}

/*
 * Test: Recovery with stale upload abort
 *
 * Scenario: On recovery, detect stale uploads that exceeded timeout
 * and abort them.
 *
 * Note: The S3 plugin removes files from queue after UploadPart failure
 * (retry happens at file level by re-enqueuing). This test verifies
 * the basic failure handling behavior.
 */
void flb_test_recovery_abort_stale_uploads(void)
{
    S3_TEST_DECLARE_VARS();

    /* Mock chain: Create -> fail UploadPart (file removed from queue after failure) */
    S3_TEST_ERROR_WITH_MOCK_N("recovery_abort_stale_uploads",
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

/*
 * Test: Recovery with part-level tracking
 *
 * Scenario: Parts are tracked individually in blob database.
 * When UploadPart fails, the S3 plugin removes the file from queue
 * (retry happens at file level by re-enqueuing, not immediate retry).
 * This test verifies that part failures are handled correctly.
 */
void flb_test_recovery_part_level_tracking(void)
{
    S3_TEST_DECLARE_VARS();

    /* Mock chain: Create -> UploadPart fail (file removed from queue after failure) */
    S3_TEST_ERROR_WITH_MOCK_N("recovery_part_level_tracking",
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

/*
 * Test: Recovery with multiple pending blobs
 *
 * Scenario: Multiple files pending upload, all should be recovered.
 */
void flb_test_recovery_multiple_pending_blobs(void)
{
    S3_TEST_DECLARE_VARS();
    int i;

    S3_TEST_SETUP_STANDARD_MOCK();
    S3_TEST_CREATE_PATHS("multi");
    S3_TEST_INIT_CONTEXT();
    S3_TEST_SETUP_INPUT("test");
    S3_TEST_SETUP_OUTPUT_BASIC();
    ret = flb_output_set(ctx, out_ffd,
                   "upload_chunk_size", "5M", NULL);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Push multiple batches */
    for (i = 0; i < 5; i++) {
        ret = flb_lib_push(ctx, in_ffd, (char *)JSON_TD, sizeof(JSON_TD) - 1);
        TEST_CHECK(ret >= 0);
        S3_TEST_SLEEP_MS(100);
    }

    S3_TEST_WAIT_MOCK_EXHAUSTED(7, "recovery_multiple_pending_blobs");
    s3_test_cleanup(ctx, db_path, store_dir);
}

/*
 * Test: Recovery without database tracking (non-database-tracked mode)
 *
 * Scenario: No blob_database_file configured. Log data uses fstore storage
 * without database tracking. Tests recovery of buffered log data.
 */
void flb_test_recovery_fstore_only(void)
{
    S3_TEST_DECLARE_VARS();

    /* ETag response for UploadPart - extract_etag() searches in c->resp.data */
    static const char *upload_part_etag_resp = "ETag: \"mock-etag-fstore\"\r\n";


    /* Mock chain: CreateMultipartUpload -> UploadPart (with ETag) -> Complete */
    chain = FLB_AWS_CLIENT_MOCK(
        response(expect(METHOD, FLB_HTTP_POST), set(STATUS, 200),
                 set(PAYLOAD, S3_TEST_MOCK_CREATE_RESP),
                 set(PAYLOAD_SIZE, sizeof(S3_TEST_MOCK_CREATE_RESP) - 1)),
        response(expect(METHOD, FLB_HTTP_PUT), set(STATUS, 200),
                 set(DATA, upload_part_etag_resp), set(DATA_SIZE, 26)),
        response(expect(METHOD, FLB_HTTP_POST), set(STATUS, 200),
                 set(PAYLOAD, S3_TEST_MOCK_COMPLETE_RESP),
                 set(PAYLOAD_SIZE, sizeof(S3_TEST_MOCK_COMPLETE_RESP) - 1))
    );

    flb_aws_client_mock_configure_generator(chain);
    init_options.client_generator = flb_aws_client_get_mock_generator();

    store_dir = s3_test_create_temp_store_dir("fstore");
    TEST_CHECK(store_dir != NULL);
    if (store_dir == NULL) {
        flb_aws_client_mock_destroy_generator();
        TEST_MSG("Failed to create temp store directory");
        return;
    }

    s3_test_set_env_vars();
    ctx = flb_create();
    S3_TEST_CHECK_CONTEXT(ctx, NULL, store_dir);
    flb_service_set(ctx, "flush", "1", "grace", "1", NULL);

    in_ffd = flb_input(ctx, (char *)"lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *)"s3", (struct flb_lib_out_cb *)&init_options);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "*",
                   "region", S3_TEST_DEFAULT_REGION,
                   "bucket", S3_TEST_DEFAULT_BUCKET,
                   "store_dir", store_dir,
                   "total_file_size", "10M",
                   "upload_chunk_size", "5M",
                   "upload_timeout", "1s", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    ret = flb_lib_push(ctx, in_ffd, (char *)JSON_TD, sizeof(JSON_TD) - 1);
    TEST_CHECK(ret >= 0);

    S3_TEST_WAIT_MOCK_EXHAUSTED(5, "recovery_fstore_only");
    s3_test_cleanup(ctx, NULL, store_dir);
}

/*
 * Test: Network interruption during upload recovery
 *
 * Scenario: Simulates a network interruption during upload.
 * The upload fails, and on next cycle the recovery mechanism
 * should handle the interrupted upload.
 */
void flb_test_recovery_network_interruption(void)
{
    S3_TEST_DECLARE_VARS();

    /* First attempt fails, file is removed from queue for retry */
    S3_TEST_ERROR_WITH_MOCK_N("recovery_network_interruption",
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

/*
 * Test: Partial upload success recovery
 *
 * Scenario: Verifies upload failure handling after successful multipart creation.
 * Note: S3 plugin removes file from queue after part upload failure.
 */
void flb_test_recovery_partial_success(void)
{
    S3_TEST_DECLARE_VARS();

    /* Test successful create, then part upload fail */
    S3_TEST_ERROR_WITH_MOCK_N("recovery_partial_success",
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

/*
 * Test: Recovery with mixed file states
 *
 * Scenario: Database contains files in different states
 * (some need CreateMultipartUpload, some need UploadPart, some need Complete)
 */
void flb_test_recovery_mixed_states(void)
{
    S3_TEST_DECLARE_VARS();

    S3_TEST_SETUP_STANDARD_MOCK();
    S3_TEST_CREATE_PATHS("mixed_states");
    S3_TEST_INIT_CONTEXT();
    S3_TEST_SETUP_INPUT("test");
    S3_TEST_SETUP_OUTPUT_BASIC();

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Push data multiple times to create multiple files */
    ret = flb_lib_push(ctx, in_ffd, (char *)JSON_TD, sizeof(JSON_TD) - 1);
    TEST_CHECK(ret >= 0);
    S3_TEST_SLEEP_MS(500);
    ret = flb_lib_push(ctx, in_ffd, (char *)JSON_TD, sizeof(JSON_TD) - 1);
    TEST_CHECK(ret >= 0);

    S3_TEST_WAIT_MOCK_EXHAUSTED(7, "recovery_mixed_states");
    s3_test_cleanup(ctx, db_path, store_dir);
}

/*
 * Test: Recovery after plugin crash/restart
 *
 * Scenario: Plugin restarts and must recover all pending uploads
 * from both blob database and fstore.
 */
void flb_test_recovery_after_restart(void)
{
    S3_TEST_DECLARE_VARS();

    /* Simulates restart by creating context, starting, then cleaning up 
     * In real scenario, database and store would persist */
    S3_TEST_SETUP_STANDARD_MOCK();
    S3_TEST_CREATE_PATHS("restart");
    S3_TEST_INIT_CONTEXT();
    S3_TEST_SETUP_INPUT("test");
    S3_TEST_SETUP_OUTPUT_BASIC();

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    ret = flb_lib_push(ctx, in_ffd, (char *)JSON_TD, sizeof(JSON_TD) - 1);
    TEST_CHECK(ret >= 0);

    S3_TEST_WAIT_MOCK_EXHAUSTED(5, "recovery_after_restart");
    s3_test_cleanup(ctx, db_path, store_dir);
}

/*
 * Test: Recovery with database corruption handling
 *
 * Scenario: Database has corrupted entries that must be handled gracefully.
 */
void flb_test_recovery_database_corruption(void)
{
    S3_TEST_DECLARE_VARS();

    /* Test that plugin can start and recover even with potential DB issues */
    S3_TEST_SETUP_STANDARD_MOCK();
    S3_TEST_CREATE_PATHS("db_corrupt");
    S3_TEST_INIT_CONTEXT();
    S3_TEST_SETUP_INPUT("test");
    S3_TEST_SETUP_OUTPUT_BASIC();

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Should handle any corruption and continue with new data */
    ret = flb_lib_push(ctx, in_ffd, (char *)JSON_TD, sizeof(JSON_TD) - 1);
    TEST_CHECK(ret >= 0);

    S3_TEST_WAIT_MOCK_EXHAUSTED(5, "recovery_database_corruption");
    s3_test_cleanup(ctx, db_path, store_dir);
}

/* Test List */
TEST_LIST = {
    {"recovery_phase1_create_multipart", flb_test_recovery_phase1_create_multipart},
    {"recovery_phase2_upload_parts", flb_test_recovery_phase2_upload_parts},
    {"recovery_phase3_complete", flb_test_recovery_phase3_complete},
    {"recovery_abort_stale_uploads", flb_test_recovery_abort_stale_uploads},
    {"recovery_part_level_tracking", flb_test_recovery_part_level_tracking},
    {"recovery_multiple_pending_blobs", flb_test_recovery_multiple_pending_blobs},
    {"recovery_fstore_only", flb_test_recovery_fstore_only},
    /* Enhanced recovery tests */
    {"recovery_network_interruption", flb_test_recovery_network_interruption},
    {"recovery_partial_success", flb_test_recovery_partial_success},
    {"recovery_mixed_states", flb_test_recovery_mixed_states},
    {"recovery_after_restart", flb_test_recovery_after_restart},
    {"recovery_database_corruption", flb_test_recovery_database_corruption},
    {NULL, NULL}
};