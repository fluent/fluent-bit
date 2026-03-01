/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit.h>
#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_mem.h>
#include "flb_tests_runtime.h"
#include "../include/aws_client_mock.h"

#include "../include/s3_test_helpers.h"
#include "../../plugins/out_s3/s3.h"

/* Test data */
#include "data/td/json_td.h" /* JSON_TD */

/* Test: Basic JSON format conversion */
void flb_test_json_format_basic(void)
{
    S3_TEST_DECLARE_VARS();
    S3_TEST_SIMPLE("test", "json_format_basic", "format", "json");
}

/* Test: JSON with date key formatting */
void flb_test_json_with_date_key(void)
{
    S3_TEST_DECLARE_VARS();
    S3_TEST_SIMPLE("test", "json_with_date_key",
                   "format", "json",
                   "json_date_format", "iso8601",
                   "json_date_key", "timestamp");
}

/* Test: JSON streaming conversion - multiple data pushes aggregated into single upload */
void flb_test_json_streaming_conversion(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    int i;
    char *db_path = NULL;
    char *store_dir = NULL;
    struct flb_out_s3_init_options init_options = {0};
    struct flb_aws_client_mock_request_chain *chain;


    /*
     * Note: Multiple data pushes are aggregated into a single chunk file,
     * resulting in a standard multipart upload (Create -> UploadPart -> Complete).
     * The S3 plugin aggregates data until total_file_size or upload_timeout is reached.
     */
    chain = FLB_AWS_CLIENT_MOCK(
        response(
            expect(METHOD, FLB_HTTP_POST),
            set(STATUS, 200),
            set(PAYLOAD, S3_TEST_MOCK_CREATE_RESP),
            set(PAYLOAD_SIZE, sizeof(S3_TEST_MOCK_CREATE_RESP) - 1)
        ),
        response(
            expect(METHOD, FLB_HTTP_PUT),
            set(STATUS, 200),
            set(DATA, S3_TEST_MOCK_UPLOAD_PART_RESP),
            set(DATA_SIZE, sizeof(S3_TEST_MOCK_UPLOAD_PART_RESP) - 1)
        ),
        response(
            expect(METHOD, FLB_HTTP_POST),
            set(STATUS, 200),
            set(PAYLOAD, S3_TEST_MOCK_COMPLETE_RESP),
            set(PAYLOAD_SIZE, sizeof(S3_TEST_MOCK_COMPLETE_RESP) - 1)
        )
    );

    flb_aws_client_mock_configure_generator(chain);
    init_options.client_generator = flb_aws_client_get_mock_generator();

    db_path = s3_test_create_temp_db_path("json_streaming");
    store_dir = s3_test_create_temp_store_dir("json_streaming");
    TEST_CHECK(db_path != NULL);
    TEST_CHECK(store_dir != NULL);

    s3_test_set_env_vars();
    ctx = flb_create();
    S3_TEST_CHECK_CONTEXT(ctx, db_path, store_dir);
    flb_service_set(ctx, "flush", "1", "grace", "1", NULL);

    in_ffd = flb_input(ctx, (char *)"lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *)"s3", (struct flb_lib_out_cb *)&init_options);
    TEST_CHECK(out_ffd >= 0);
    ret = flb_output_set(ctx, out_ffd, "match", "*",
                   "region", S3_TEST_DEFAULT_REGION,
                   "bucket", S3_TEST_DEFAULT_BUCKET,
                   "format", "json",
                   "blob_database_file", db_path,
                   "store_dir", store_dir,
                   "total_file_size", "10M",
                   "upload_chunk_size", "5M",
                   "upload_timeout", "2s", NULL);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Push data multiple times - all aggregated into single chunk */
    for (i = 0; i < 5; i++) {
        ret = flb_lib_push(ctx, in_ffd, (char *)JSON_TD, (int)sizeof(JSON_TD) - 1);
        TEST_CHECK(ret >= 0);
    }
    S3_TEST_WAIT_MOCK_EXHAUSTED(5, "json_streaming_conversion");

    s3_test_cleanup(ctx, db_path, store_dir);
}

/* Test: GZIP compression integration */
void flb_test_compression_gzip_integration(void)
{
    S3_TEST_DECLARE_VARS();
    S3_TEST_SIMPLE("test", "compression_gzip_integration",
                   "format", "json",
                   "compression", "gzip");
}

/* Test: ZSTD compression integration */
void flb_test_compression_zstd_integration(void)
{
    S3_TEST_DECLARE_VARS();
    S3_TEST_SIMPLE("test", "compression_zstd_integration",
                   "format", "json",
                   "compression", "zstd");
}

/* Test: Snappy compression */
void flb_test_compression_snappy(void)
{
    S3_TEST_DECLARE_VARS();
    S3_TEST_SIMPLE("test", "compression_snappy", "compression", "snappy");
}

/* Test: log_key extraction - extract specific field from records */
void flb_test_log_key_extraction(void)
{
    S3_TEST_DECLARE_VARS();
    S3_TEST_SIMPLE("test", "log_key_extraction", "log_key", "key_0");
}

/* Test: log_key with compression - extract field and compress */
void flb_test_log_key_with_compression(void)
{
    S3_TEST_DECLARE_VARS();
    S3_TEST_SIMPLE("test", "log_key_with_compression",
                   "log_key", "key_0",
                   "compression", "gzip");
}

/* Test: JSON format with gzip compression */
void flb_test_json_with_gzip(void)
{
    S3_TEST_DECLARE_VARS();
    S3_TEST_SIMPLE("test", "json_with_gzip",
                   "format", "json",
                   "compression", "gzip");
}

/* Test: JSON format with zstd compression */
void flb_test_json_with_zstd(void)
{
    S3_TEST_DECLARE_VARS();
    S3_TEST_SIMPLE("test", "json_with_zstd",
                   "format", "json",
                   "compression", "zstd");
}

/* Test: Parquet format (if enabled)
 *
 * Verifies parquet format configuration works when Parquet support is compiled in.
 */
void flb_test_parquet_format(void)
{
#ifdef FLB_HAVE_PARQUET_ENCODER
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    char *db_path = NULL;
    char *store_dir = NULL;
    struct flb_out_s3_init_options init_options = {0};
    struct flb_aws_client_mock_request_chain *chain;

    chain = FLB_AWS_CLIENT_MOCK(
        response(
            expect(METHOD, FLB_HTTP_POST),
            set(STATUS, 200),
            set(PAYLOAD, S3_TEST_MOCK_CREATE_RESP),
            set(PAYLOAD_SIZE, sizeof(S3_TEST_MOCK_CREATE_RESP) - 1)
        ),
        response(
            expect(METHOD, FLB_HTTP_PUT),
            set(STATUS, 200),
            set(DATA, S3_TEST_MOCK_UPLOAD_PART_RESP),
            set(DATA_SIZE, sizeof(S3_TEST_MOCK_UPLOAD_PART_RESP) - 1)
        ),
        response(
            expect(METHOD, FLB_HTTP_POST),
            set(STATUS, 200),
            set(PAYLOAD, S3_TEST_MOCK_COMPLETE_RESP),
            set(PAYLOAD_SIZE, sizeof(S3_TEST_MOCK_COMPLETE_RESP) - 1)
        )
    );

    flb_aws_client_mock_configure_generator(chain);
    init_options.client_generator = flb_aws_client_get_mock_generator();

    db_path = s3_test_create_temp_db_path("parquet");
    store_dir = s3_test_create_temp_store_dir("parquet");
    TEST_CHECK(db_path != NULL);
    TEST_CHECK(store_dir != NULL);

    s3_test_set_env_vars();
    ctx = flb_create();
    S3_TEST_CHECK_CONTEXT(ctx, db_path, store_dir);
    flb_service_set(ctx, "flush", "1", "grace", "1", NULL);

    in_ffd = flb_input(ctx, (char *)"lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *)"s3", (struct flb_lib_out_cb *)&init_options);
    TEST_CHECK(out_ffd >= 0);
    ret = flb_output_set(ctx, out_ffd, "match", "*",
                   "region", S3_TEST_DEFAULT_REGION,
                   "bucket", S3_TEST_DEFAULT_BUCKET,
                   "blob_database_file", db_path,
                   "store_dir", store_dir,
                   "format", "parquet",
                   "schema_str", "{\"fields\":[{\"name\":\"log\",\"type\":{\"name\":\"utf8\"}}]}",
                   "total_file_size", "10M",
                   "upload_chunk_size", "5M",
                   "upload_timeout", "1s", NULL);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    ret = flb_lib_push(ctx, in_ffd, (char *)JSON_TD, (int)sizeof(JSON_TD) - 1);
    TEST_CHECK(ret >= 0);
    S3_TEST_WAIT_MOCK_EXHAUSTED(4, "parquet_format");

    s3_test_cleanup(ctx, db_path, store_dir);
#else
    TEST_MSG("Skipping flb_test_parquet_format: Parquet encoder not enabled");
#endif
}

/* Test: Invalid compression type should fail */
void flb_test_invalid_compression_type(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    char *db_path = NULL;
    char *store_dir = NULL;
    struct flb_out_s3_init_options init_options = {0};

    db_path = s3_test_create_temp_db_path("invalid_comp");
    store_dir = s3_test_create_temp_store_dir("invalid_comp");
    TEST_CHECK(db_path != NULL);
    TEST_CHECK(store_dir != NULL);

    s3_test_set_env_vars();
    ctx = flb_create();
    S3_TEST_CHECK_CONTEXT(ctx, db_path, store_dir);
    flb_service_set(ctx, "flush", "1", "grace", "1", NULL);

    in_ffd = flb_input(ctx, (char *)"lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *)"s3", (struct flb_lib_out_cb *)&init_options);
    TEST_CHECK(out_ffd >= 0);
    ret = flb_output_set(ctx, out_ffd, "match", "*",
                   "region", S3_TEST_DEFAULT_REGION,
                   "bucket", S3_TEST_DEFAULT_BUCKET,
                   "compression", "invalid_compression",
                   "blob_database_file", db_path,
                   "store_dir", store_dir,
                   "total_file_size", "10M",
                   "upload_chunk_size", "5M", NULL);
    TEST_CHECK(ret == 0);

    /* Should fail due to invalid compression type */
    ret = flb_start(ctx);
    TEST_CHECK(ret == -1);

    /* When flb_start fails, we should NOT call flb_stop, only flb_destroy */
    if (ctx) {
        flb_destroy(ctx);
    }
    if (db_path) {
        s3_test_cleanup_temp_db(db_path);
        flb_free(db_path);
    }
    if (store_dir) {
        s3_test_cleanup_temp_store_dir(store_dir);
        flb_free(store_dir);
    }
}

/* Test list */
TEST_LIST = {
    {"json_format_basic", flb_test_json_format_basic},
    {"json_with_date_key", flb_test_json_with_date_key},
    {"json_streaming_conversion", flb_test_json_streaming_conversion},
    {"compression_gzip_integration", flb_test_compression_gzip_integration},
    {"compression_zstd_integration", flb_test_compression_zstd_integration},
    {"compression_snappy", flb_test_compression_snappy},
    {"log_key_extraction", flb_test_log_key_extraction},
    {"log_key_with_compression", flb_test_log_key_with_compression},
    {"json_with_gzip", flb_test_json_with_gzip},
    {"json_with_zstd", flb_test_json_with_zstd},
    {"parquet_format", flb_test_parquet_format},
    {"invalid_compression_type", flb_test_invalid_compression_type},
    {NULL, NULL}
};