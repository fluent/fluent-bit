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
 * s3_key_format Tests
 * ============================================================================ */

/* Test: s3_key_format with $TAG expansion */
void flb_test_s3_key_format_tag_expansion(void)
{
    S3_TEST_DECLARE_VARS();
    S3_TEST_SIMPLE("app.production.service1", "s3_key_format_tag_expansion",
                   "s3_key_format", "/logs/$TAG/%Y/%m/%d");
}

/* Test: s3_key_format with $TAG[n] parts */
void flb_test_s3_key_format_tag_parts(void)
{
    S3_TEST_DECLARE_VARS();
    S3_TEST_SIMPLE("app.production.service1", "s3_key_format_tag_parts",
                   "s3_key_format", "/logs/$TAG[0]/$TAG[1]/%H%M%S",
                   "s3_key_format_tag_delimiters", ".");
}

/* Test: s3_key_format with $INDEX sequence */
void flb_test_s3_key_format_index_sequence(void)
{
    S3_TEST_DECLARE_VARS();

    /* Multiple uploads for index sequence test */
    chain = FLB_AWS_CLIENT_MOCK(
        response(expect(METHOD, FLB_HTTP_POST),
                 set(STATUS, 200), set(PAYLOAD, S3_TEST_MOCK_CREATE_RESP),
                 set(PAYLOAD_SIZE, sizeof(S3_TEST_MOCK_CREATE_RESP) - 1)),
        response(expect(METHOD, FLB_HTTP_PUT),
                 set(STATUS, 200), set(DATA, S3_TEST_MOCK_UPLOAD_PART_RESP),
                 set(DATA_SIZE, sizeof(S3_TEST_MOCK_UPLOAD_PART_RESP) - 1)),
        response(expect(METHOD, FLB_HTTP_POST),
                 set(STATUS, 200), set(PAYLOAD, S3_TEST_MOCK_COMPLETE_RESP),
                 set(PAYLOAD_SIZE, sizeof(S3_TEST_MOCK_COMPLETE_RESP) - 1)),
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

    S3_TEST_CREATE_PATHS("cfg");
    S3_TEST_INIT_CONTEXT();
    S3_TEST_SETUP_INPUT("test");
    S3_TEST_SETUP_OUTPUT_BASIC();
    ret = flb_output_set(ctx, out_ffd, "s3_key_format", "/logs/$TAG-$INDEX", NULL);
    TEST_CHECK(ret >= 0);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Push data multiple times to trigger index increment */
    ret = flb_lib_push(ctx, in_ffd, (char *)JSON_TD, sizeof(JSON_TD) - 1);
    TEST_CHECK(ret >= 0);
    S3_TEST_SLEEP_MS(2000);
    ret = flb_lib_push(ctx, in_ffd, (char *)JSON_TD, sizeof(JSON_TD) - 1);
    TEST_CHECK(ret >= 0);

    S3_TEST_WAIT_MOCK_EXHAUSTED(5, "s3_key_format_index_sequence");
    s3_test_cleanup(ctx, db_path, store_dir);
}

/* Test: s3_key_format with $UUID generation */
void flb_test_s3_key_format_uuid_generation(void)
{
    S3_TEST_DECLARE_VARS();
    S3_TEST_SIMPLE("test", "s3_key_format_uuid_generation",
                   "s3_key_format", "/logs/$TAG-$UUID");
}

/* Test: s3_key_format with time formatters */
void flb_test_s3_key_format_time_formatters(void)
{
    S3_TEST_DECLARE_VARS();
    S3_TEST_SIMPLE("test", "s3_key_format_time_formatters",
                   "s3_key_format", "/logs/%Y/%m/%d/%H/%M/%S");
}

/* Test: s3_key_format with mixed variables */
void flb_test_s3_key_format_mixed_variables(void)
{
    S3_TEST_DECLARE_VARS();
    S3_TEST_SIMPLE("app.production.service1", "s3_key_format_mixed_variables",
                   "s3_key_format", "/$TAG[0]/%Y%m%d-$INDEX-$UUID",
                   "s3_key_format_tag_delimiters", ".");
}

/* ============================================================================
 * Endpoint Configuration Tests
 * ============================================================================ */

/* Test: endpoint HTTP vs HTTPS */
void flb_test_endpoint_http_vs_https(void)
{
    S3_TEST_DECLARE_VARS();

    /* Test HTTP endpoint */
    S3_TEST_SIMPLE("test", "endpoint_http_vs_https_http",
                   "endpoint", "http://s3.example.com");

    /* Test HTTPS endpoint */
    S3_TEST_SIMPLE("test", "endpoint_http_vs_https_https",
                   "endpoint", "https://s3.example.com");
}

/* Test: endpoint with custom port */
void flb_test_endpoint_custom_port(void)
{
    S3_TEST_DECLARE_VARS();

    /* Test with port 9000 (MinIO default) */
    S3_TEST_SIMPLE("test", "endpoint_custom_port_http",
                   "endpoint", "http://localhost:9000");

    /* Test with custom HTTPS port */
    S3_TEST_SIMPLE("test", "endpoint_custom_port_https",
                   "endpoint", "https://s3.example.com:8443");
}

/* ============================================================================
 * Storage Class and ACL Tests
 * ============================================================================ */

/* Test: storage_class variations */
void flb_test_storage_class_variations(void)
{
    S3_TEST_DECLARE_VARS();

    S3_TEST_SIMPLE("test", "storage_class_STANDARD",
                   "storage_class", "STANDARD");
    S3_TEST_SIMPLE("test", "storage_class_STANDARD_IA",
                   "storage_class", "STANDARD_IA");
    S3_TEST_SIMPLE("test", "storage_class_GLACIER",
                   "storage_class", "GLACIER");
    S3_TEST_SIMPLE("test", "storage_class_INTELLIGENT_TIERING",
                   "storage_class", "INTELLIGENT_TIERING");
}

/* Test: canned_acl options */
void flb_test_canned_acl_options(void)
{
    S3_TEST_DECLARE_VARS();
    const char *acls[] = {"private", "public-read", "bucket-owner-full-control"};
    int i;

    for (i = 0; i < 3; i++) {
        chain = FLB_AWS_CLIENT_MOCK(
            response(expect(METHOD, FLB_HTTP_POST),
                     expect(HEADER, "x-amz-acl", acls[i]),
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

        S3_TEST_CREATE_PATHS("cfg");
        S3_TEST_INIT_CONTEXT();
        S3_TEST_SETUP_INPUT("test");
        S3_TEST_SETUP_OUTPUT_BASIC();
        ret = flb_output_set(ctx, out_ffd, "canned_acl", acls[i], NULL);
        TEST_CHECK(ret >= 0);
        S3_TEST_START_AND_PUSH((char *)JSON_TD, sizeof(JSON_TD) - 1);

        S3_TEST_WAIT_MOCK_EXHAUSTED(5, "canned_acl_options");
        s3_test_cleanup(ctx, db_path, store_dir);
    }
}

/* ============================================================================
 * Content Type and MD5 Tests
 * ============================================================================ */

/* Test: content_type setting */
void flb_test_content_type_setting(void)
{
    S3_TEST_DECLARE_VARS();

    S3_TEST_SIMPLE("test", "content_type_json",
                   "content_type", "application/json");
    S3_TEST_SIMPLE("test", "content_type_text",
                   "content_type", "text/plain");
}

/* Test: send_content_md5 flag */
void flb_test_send_content_md5_flag(void)
{
    S3_TEST_DECLARE_VARS();

    S3_TEST_SIMPLE("test", "send_content_md5_true",
                   "send_content_md5", "true");
    S3_TEST_SIMPLE("test", "send_content_md5_false",
                   "send_content_md5", "false");
}

/* ============================================================================
 * Size Limits and Auto-adjustment Tests
 * ============================================================================ */

/* Test: store_dir_limit_size enforcement */
void flb_test_store_dir_limit_enforcement(void)
{
    S3_TEST_DECLARE_VARS();
    S3_TEST_SIMPLE("test", "store_dir_limit_enforcement",
                   "store_dir_limit_size", "10M");
}

/* Test: chunk_size auto adjustment */
void flb_test_chunk_size_auto_adjustment(void)
{
    S3_TEST_DECLARE_VARS();

    /* Test: upload_chunk_size > total_file_size should auto-adjust */
    S3_TEST_SETUP_STANDARD_MOCK();
    S3_TEST_CREATE_PATHS("cfg");
    S3_TEST_INIT_CONTEXT();
    S3_TEST_SETUP_INPUT("test");

    out_ffd = flb_output(ctx, (char *)"s3", (struct flb_lib_out_cb *)&init_options);
    TEST_CHECK(out_ffd >= 0);
    ret = flb_output_set(ctx, out_ffd, "match", "*",
                   "region", S3_TEST_DEFAULT_REGION,
                   "bucket", S3_TEST_DEFAULT_BUCKET,
                   "blob_database_file", db_path,
                   "store_dir", store_dir,
                   "total_file_size", "5M",
                   "upload_chunk_size", "10M",
                   "upload_timeout", "1s", NULL);
    TEST_CHECK(ret >= 0);

    S3_TEST_START_AND_PUSH((char *)JSON_TD, sizeof(JSON_TD) - 1);

    S3_TEST_WAIT_MOCK_EXHAUSTED(5, "chunk_size_auto_adjustment_1");
    s3_test_cleanup(ctx, db_path, store_dir);

    /* Test: very large total_file_size requiring chunk adjustment */
    S3_TEST_SETUP_STANDARD_MOCK();
    S3_TEST_CREATE_PATHS("cfg");
    S3_TEST_INIT_CONTEXT();
    S3_TEST_SETUP_INPUT("test");

    out_ffd = flb_output(ctx, (char *)"s3", (struct flb_lib_out_cb *)&init_options);
    TEST_CHECK(out_ffd >= 0);
    ret = flb_output_set(ctx, out_ffd, "match", "*",
                   "region", S3_TEST_DEFAULT_REGION,
                   "bucket", S3_TEST_DEFAULT_BUCKET,
                   "blob_database_file", db_path,
                   "store_dir", store_dir,
                   "total_file_size", "1000G",
                   "upload_chunk_size", "5M",
                   "upload_timeout", "1s", NULL);
    TEST_CHECK(ret >= 0);

    S3_TEST_START_AND_PUSH((char *)JSON_TD, sizeof(JSON_TD) - 1);

    S3_TEST_WAIT_MOCK_EXHAUSTED(5, "chunk_size_auto_adjustment_2");
    s3_test_cleanup(ctx, db_path, store_dir);
}

/* ============================================================================
 * Invalid Parameter Validation Tests
 * ============================================================================ */

/* Test: invalid parameter - total_file_size exceeds AWS maximum */
void flb_test_invalid_parameter_combinations(void)
{
    S3_TEST_DECLARE_VARS();

    /* Test: total_file_size > 5TB (AWS max) */
    chain = FLB_AWS_CLIENT_MOCK(
        response(set(STATUS, 200), set(PAYLOAD, S3_TEST_MOCK_CREATE_RESP),
                 set(PAYLOAD_SIZE, sizeof(S3_TEST_MOCK_CREATE_RESP) - 1))
    );

    flb_aws_client_mock_configure_generator(chain);
    init_options.client_generator = flb_aws_client_get_mock_generator();

    S3_TEST_CREATE_PATHS("cfg");
    S3_TEST_INIT_CONTEXT();
    S3_TEST_SETUP_INPUT("test");

    out_ffd = flb_output(ctx, (char *)"s3", (struct flb_lib_out_cb *)&init_options);
    TEST_CHECK(out_ffd >= 0);
    ret = flb_output_set(ctx, out_ffd, "match", "*",
                   "region", S3_TEST_DEFAULT_REGION,
                   "bucket", S3_TEST_DEFAULT_BUCKET,
                   "blob_database_file", db_path,
                   "store_dir", store_dir,
                   "total_file_size", "6TB", NULL);
    TEST_CHECK(ret >= 0);

    ret = flb_start(ctx);
    TEST_CHECK(ret == -1);

    /* When flb_start fails, manual cleanup without flb_stop */
    if (ctx) {
        flb_destroy(ctx);
    }
    flb_aws_client_mock_clear_generator_instance();
    if (db_path) {
        s3_test_cleanup_temp_db(db_path);
        flb_free(db_path);
    }
    if (store_dir) {
        s3_test_cleanup_temp_store_dir(store_dir);
        flb_free(store_dir);
    }
}

/* Test List */
TEST_LIST = {
    {"s3_key_format_tag_expansion", flb_test_s3_key_format_tag_expansion},
    {"s3_key_format_tag_parts", flb_test_s3_key_format_tag_parts},
    {"s3_key_format_index_sequence", flb_test_s3_key_format_index_sequence},
    {"s3_key_format_uuid_generation", flb_test_s3_key_format_uuid_generation},
    {"s3_key_format_time_formatters", flb_test_s3_key_format_time_formatters},
    {"s3_key_format_mixed_variables", flb_test_s3_key_format_mixed_variables},
    {"endpoint_http_vs_https", flb_test_endpoint_http_vs_https},
    {"endpoint_custom_port", flb_test_endpoint_custom_port},
    {"storage_class_variations", flb_test_storage_class_variations},
    {"canned_acl_options", flb_test_canned_acl_options},
    {"content_type_setting", flb_test_content_type_setting},
    {"send_content_md5_flag", flb_test_send_content_md5_flag},
    {"store_dir_limit_enforcement", flb_test_store_dir_limit_enforcement},
    {"chunk_size_auto_adjustment", flb_test_chunk_size_auto_adjustment},
    {"invalid_parameter_combinations", flb_test_invalid_parameter_combinations},
    {NULL, NULL}
};