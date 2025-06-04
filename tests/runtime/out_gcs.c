/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2024 The Fluent Bit Authors
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#include <fluent-bit.h>
#include "flb_tests_runtime.h"
#include "data/gcs/gcs_test_data.h"

#define TEST_GCS_BUCKET         "test-bucket"
#define TEST_SERVICE_ACCOUNT    "test@project.iam.gserviceaccount.com"
#define TEST_PROJECT_ID         "test-project-123"
#define TEST_STORE_DIR          "/tmp/flb-test-gcs"

/* Test credentials JSON content */
static const char *test_credentials_json = 
"{"
"\"type\": \"service_account\","
"\"project_id\": \"test-project-123\","
"\"private_key_id\": \"test-key-id\","
"\"private_key\": \"-----BEGIN PRIVATE KEY-----\\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7vL7q...\\n-----END PRIVATE KEY-----\\n\","
"\"client_email\": \"test@project.iam.gserviceaccount.com\","
"\"client_id\": \"123456789012345678901\","
"\"auth_uri\": \"https://accounts.google.com/o/oauth2/auth\","
"\"token_uri\": \"https://oauth2.googleapis.com/token\""
"}";

static const char *test_log_data = 
"[1234567890, {\"message\":\"test log entry\", \"level\":\"info\", \"host\":\"test-host\"}]";

/* Helper function to create temporary credentials file */
static int create_test_credentials_file(char *filepath, size_t filepath_size) 
{
    FILE *fp;
    int ret;
    
    snprintf(filepath, filepath_size, "/tmp/flb-test-gcs-creds-%d.json", getpid());
    
    fp = fopen(filepath, "w");
    if (!fp) {
        return -1;
    }
    
    ret = fwrite(test_credentials_json, 1, strlen(test_credentials_json), fp);
    fclose(fp);
    
    return (ret == strlen(test_credentials_json)) ? 0 : -1;
}

/* Helper function to setup mock environment for testing */
static void setup_gcs_test_env(void)
{
    /* Enable test mode */
    setenv("FLB_GCS_PLUGIN_UNDER_TEST", "true", 1);
    
    /* Mock OAuth2 success response */
    setenv("FLB_GCS_MOCK_TOKEN_RESPONSE", 
           "{\"access_token\":\"test-token-123\",\"token_type\":\"Bearer\",\"expires_in\":3600}", 1);
    
    /* Mock successful upload response */
    setenv("FLB_GCS_MOCK_UPLOAD_RESPONSE", 
           "{\"name\":\"test-object\",\"bucket\":\"test-bucket\",\"size\":\"1024\"}", 1);
}

static void cleanup_gcs_test_env(void)
{
    unsetenv("FLB_GCS_PLUGIN_UNDER_TEST");
    unsetenv("FLB_GCS_MOCK_TOKEN_RESPONSE");
    unsetenv("FLB_GCS_MOCK_UPLOAD_RESPONSE");
    unsetenv("FLB_GCS_MOCK_ERROR_CODE");
    unsetenv("FLB_GCS_MOCK_ERROR_RESPONSE");
}

/* Test basic GCS plugin functionality */
void flb_test_gcs_basic_upload(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    char credentials_file[256];

    setup_gcs_test_env();
    
    /* Create test credentials file */
    ret = create_test_credentials_file(credentials_file, sizeof(credentials_file));
    TEST_CHECK(ret == 0);

    /* Create context and configure input */
    ctx = flb_create();
    TEST_CHECK(ctx != NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test.gcs", NULL);

    /* Configure GCS output */
    out_ffd = flb_output(ctx, (char *) "gcs", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "*", NULL);
    flb_output_set(ctx, out_ffd, "bucket", TEST_GCS_BUCKET, NULL);
    flb_output_set(ctx, out_ffd, "credentials_file", credentials_file, NULL);
    flb_output_set(ctx, out_ffd, "gcs_key_format", "test-logs/%Y/%m/%d/${tag}.json", NULL);
    flb_output_set(ctx, out_ffd, "format", "json", NULL);
    flb_output_set(ctx, out_ffd, "store_dir", TEST_STORE_DIR, NULL);
    flb_output_set(ctx, out_ffd, "Retry_Limit", "1", NULL);

    /* Start engine */
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Push test data */
    flb_lib_push(ctx, in_ffd, (char *) test_log_data, strlen(test_log_data));

    /* Wait for processing */
    sleep(2);

    /* Cleanup */
    flb_stop(ctx);
    flb_destroy(ctx);
    unlink(credentials_file);
    cleanup_gcs_test_env();
}

/* Test GCS plugin with different formats */
void flb_test_gcs_different_formats(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    char credentials_file[256];
    const char *formats[] = {"text", "json", NULL};
    int i;

    setup_gcs_test_env();
    
    ret = create_test_credentials_file(credentials_file, sizeof(credentials_file));
    TEST_CHECK(ret == 0);

    for (i = 0; formats[i] != NULL; i++) {
        ctx = flb_create();
        TEST_CHECK(ctx != NULL);

        in_ffd = flb_input(ctx, (char *) "lib", NULL);
        TEST_CHECK(in_ffd >= 0);
        flb_input_set(ctx, in_ffd, "tag", "test.format", NULL);

        out_ffd = flb_output(ctx, (char *) "gcs", NULL);
        TEST_CHECK(out_ffd >= 0);
        flb_output_set(ctx, out_ffd, "match", "*", NULL);
        flb_output_set(ctx, out_ffd, "bucket", TEST_GCS_BUCKET, NULL);
        flb_output_set(ctx, out_ffd, "credentials_file", credentials_file, NULL);
        flb_output_set(ctx, out_ffd, "format", formats[i], NULL);
        flb_output_set(ctx, out_ffd, "store_dir", TEST_STORE_DIR, NULL);
        flb_output_set(ctx, out_ffd, "Retry_Limit", "1", NULL);

        ret = flb_start(ctx);
        TEST_CHECK(ret == 0);

        flb_lib_push(ctx, in_ffd, (char *) test_log_data, strlen(test_log_data));
        sleep(1);

        flb_stop(ctx);
        flb_destroy(ctx);
    }

    unlink(credentials_file);
    cleanup_gcs_test_env();
}

/* Test GCS plugin with compression */
void flb_test_gcs_compression(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    char credentials_file[256];

    setup_gcs_test_env();
    
    ret = create_test_credentials_file(credentials_file, sizeof(credentials_file));
    TEST_CHECK(ret == 0);

    ctx = flb_create();
    TEST_CHECK(ctx != NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test.compression", NULL);

    out_ffd = flb_output(ctx, (char *) "gcs", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "*", NULL);
    flb_output_set(ctx, out_ffd, "bucket", TEST_GCS_BUCKET, NULL);
    flb_output_set(ctx, out_ffd, "credentials_file", credentials_file, NULL);
    flb_output_set(ctx, out_ffd, "compression", "gzip", NULL);
    flb_output_set(ctx, out_ffd, "format", "json", NULL);
    flb_output_set(ctx, out_ffd, "store_dir", TEST_STORE_DIR, NULL);
    flb_output_set(ctx, out_ffd, "Retry_Limit", "1", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    flb_lib_push(ctx, in_ffd, (char *) test_log_data, strlen(test_log_data));
    sleep(2);

    flb_stop(ctx);
    flb_destroy(ctx);
    unlink(credentials_file);
    cleanup_gcs_test_env();
}

/* Test authentication failure scenarios */
void flb_test_gcs_auth_failure(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    /* Setup error response for authentication */
    setenv("FLB_GCS_PLUGIN_UNDER_TEST", "true", 1);
    setenv("FLB_GCS_MOCK_ERROR_CODE", "401", 1);
    setenv("FLB_GCS_MOCK_ERROR_RESPONSE", 
           "{\"error\":\"invalid_grant\",\"error_description\":\"Invalid JWT\"}", 1);

    ctx = flb_create();
    TEST_CHECK(ctx != NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test.auth_fail", NULL);

    out_ffd = flb_output(ctx, (char *) "gcs", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "*", NULL);
    flb_output_set(ctx, out_ffd, "bucket", TEST_GCS_BUCKET, NULL);
    flb_output_set(ctx, out_ffd, "credentials_file", "/nonexistent/credentials.json", NULL);
    flb_output_set(ctx, out_ffd, "store_dir", TEST_STORE_DIR, NULL);
    flb_output_set(ctx, out_ffd, "Retry_Limit", "1", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    flb_lib_push(ctx, in_ffd, (char *) test_log_data, strlen(test_log_data));
    sleep(2);

    flb_stop(ctx);
    flb_destroy(ctx);
    cleanup_gcs_test_env();
}

/* Test upload failure and retry */
void flb_test_gcs_upload_failure(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    char credentials_file[256];

    /* Setup OAuth success but upload failure */
    setenv("FLB_GCS_PLUGIN_UNDER_TEST", "true", 1);
    setenv("FLB_GCS_MOCK_TOKEN_RESPONSE", 
           "{\"access_token\":\"test-token-123\",\"token_type\":\"Bearer\",\"expires_in\":3600}", 1);
    setenv("FLB_GCS_MOCK_ERROR_CODE", "500", 1);
    setenv("FLB_GCS_MOCK_ERROR_RESPONSE", 
           "{\"error\":{\"code\":500,\"message\":\"Internal Server Error\"}}", 1);
    
    ret = create_test_credentials_file(credentials_file, sizeof(credentials_file));
    TEST_CHECK(ret == 0);

    ctx = flb_create();
    TEST_CHECK(ctx != NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test.upload_fail", NULL);

    out_ffd = flb_output(ctx, (char *) "gcs", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "*", NULL);
    flb_output_set(ctx, out_ffd, "bucket", TEST_GCS_BUCKET, NULL);
    flb_output_set(ctx, out_ffd, "credentials_file", credentials_file, NULL);
    flb_output_set(ctx, out_ffd, "store_dir", TEST_STORE_DIR, NULL);
    flb_output_set(ctx, out_ffd, "retry_limit", "2", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    flb_lib_push(ctx, in_ffd, (char *) test_log_data, strlen(test_log_data));
    sleep(3); /* Allow time for retries */

    flb_stop(ctx);
    flb_destroy(ctx);
    unlink(credentials_file);
    cleanup_gcs_test_env();
}

/* Test invalid configuration scenarios */
void flb_test_gcs_invalid_config(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    /* Test missing bucket */
    ctx = flb_create();
    TEST_CHECK(ctx != NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);

    out_ffd = flb_output(ctx, (char *) "gcs", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "*", NULL);
    /* Intentionally omit bucket parameter */

    ret = flb_start(ctx);
    TEST_CHECK(ret != 0); /* Should fail due to missing bucket */

    flb_destroy(ctx);

    /* Test invalid format */
    ctx = flb_create();
    TEST_CHECK(ctx != NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);

    out_ffd = flb_output(ctx, (char *) "gcs", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "*", NULL);
    flb_output_set(ctx, out_ffd, "bucket", TEST_GCS_BUCKET, NULL);
    flb_output_set(ctx, out_ffd, "format", "invalid_format", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret != 0); /* Should fail due to invalid format */

    flb_destroy(ctx);
}

/* Test metadata server authentication (ADC) */
void flb_test_gcs_metadata_server_auth(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    /* Setup metadata server mock response */
    setenv("FLB_GCS_PLUGIN_UNDER_TEST", "true", 1);
    setenv("FLB_GCS_MOCK_METADATA_RESPONSE", 
           "{\"access_token\":\"metadata-token-123\",\"expires_in\":3600,\"token_type\":\"Bearer\"}", 1);
    setenv("FLB_GCS_MOCK_UPLOAD_RESPONSE", 
           "{\"name\":\"test-object\",\"bucket\":\"test-bucket\",\"size\":\"1024\"}", 1);

    ctx = flb_create();
    TEST_CHECK(ctx != NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test.metadata", NULL);

    out_ffd = flb_output(ctx, (char *) "gcs", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "*", NULL);
    flb_output_set(ctx, out_ffd, "bucket", TEST_GCS_BUCKET, NULL);
    /* No credentials_file - should use metadata server */
    flb_output_set(ctx, out_ffd, "store_dir", TEST_STORE_DIR, NULL);
    flb_output_set(ctx, out_ffd, "Retry_Limit", "1", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    flb_lib_push(ctx, in_ffd, (char *) test_log_data, strlen(test_log_data));
    sleep(2);

    flb_stop(ctx);
    flb_destroy(ctx);
    cleanup_gcs_test_env();
}

/* Test object key formatting */
void flb_test_gcs_key_formatting(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    char credentials_file[256];

    setup_gcs_test_env();
    
    ret = create_test_credentials_file(credentials_file, sizeof(credentials_file));
    TEST_CHECK(ret == 0);

    ctx = flb_create();
    TEST_CHECK(ctx != NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "app.frontend", NULL);

    out_ffd = flb_output(ctx, (char *) "gcs", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "*", NULL);
    flb_output_set(ctx, out_ffd, "bucket", TEST_GCS_BUCKET, NULL);
    flb_output_set(ctx, out_ffd, "credentials_file", credentials_file, NULL);
    flb_output_set(ctx, out_ffd, "gcs_key_format", 
                   "logs/%Y/%m/%d/${tag}/%H%M%S.json.gz", NULL);
    flb_output_set(ctx, out_ffd, "compression", "gzip", NULL);
    flb_output_set(ctx, out_ffd, "store_dir", TEST_STORE_DIR, NULL);
    flb_output_set(ctx, out_ffd, "Retry_Limit", "1", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    flb_lib_push(ctx, in_ffd, (char *) test_log_data, strlen(test_log_data));
    sleep(2);

    flb_stop(ctx);
    flb_destroy(ctx);
    unlink(credentials_file);
    cleanup_gcs_test_env();
}

/* Test large file upload (multipart) */
void flb_test_gcs_large_file_upload(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    char credentials_file[256];
    char large_data[8192];
    int i;

    /* Create large test data */
    for (i = 0; i < sizeof(large_data) - 1; i++) {
        large_data[i] = 'A' + (i % 26);
    }
    large_data[sizeof(large_data) - 1] = '\0';

    setup_gcs_test_env();
    
    ret = create_test_credentials_file(credentials_file, sizeof(credentials_file));
    TEST_CHECK(ret == 0);

    ctx = flb_create();
    TEST_CHECK(ctx != NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test.large", NULL);

    out_ffd = flb_output(ctx, (char *) "gcs", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "*", NULL);
    flb_output_set(ctx, out_ffd, "bucket", TEST_GCS_BUCKET, NULL);
    flb_output_set(ctx, out_ffd, "credentials_file", credentials_file, NULL);
    flb_output_set(ctx, out_ffd, "total_file_size", "4096", NULL); /* Small size to force upload */
    flb_output_set(ctx, out_ffd, "upload_chunk_size", "2048", NULL);
    flb_output_set(ctx, out_ffd, "store_dir", TEST_STORE_DIR, NULL);
    flb_output_set(ctx, out_ffd, "Retry_Limit", "1", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Push large data multiple times */
    for (i = 0; i < 3; i++) {
        flb_lib_push(ctx, in_ffd, large_data, strlen(large_data));
    }
    
    sleep(3);

    flb_stop(ctx);
    flb_destroy(ctx);
    unlink(credentials_file);
    cleanup_gcs_test_env();
}

/* Define test list */
TEST_LIST = {
    {"basic_upload",           flb_test_gcs_basic_upload},
    {"different_formats",      flb_test_gcs_different_formats},
    {"compression",            flb_test_gcs_compression},
    {"auth_failure",           flb_test_gcs_auth_failure},
    {"upload_failure",         flb_test_gcs_upload_failure},
    {"invalid_config",         flb_test_gcs_invalid_config},
    {"metadata_server_auth",   flb_test_gcs_metadata_server_auth},
    {"key_formatting",         flb_test_gcs_key_formatting},
    {"large_file_upload",      flb_test_gcs_large_file_upload},
    {NULL, NULL}
};