/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
#include <dirent.h>
#include <limits.h>
#include <sys/stat.h>
#include <ctype.h>
#include <time.h>
#include <fluent-bit.h>
#include <fluent-bit/flb_time.h>
#include "flb_tests_runtime.h"
#include "../include/flb_tests_tmpdir.h"

#include "data/td/json_td.h"
#include "../../plugins/out_gcs/gcs.h"
#include "../../plugins/out_gcs/gcs_store.h"

/* Local 'test' credentials file */
#define SERVICE_CREDENTIALS \
    FLB_TESTS_DATA_PATH "/data/stackdriver/stackdriver-credentials.json"
#define SERVICE_CREDENTIALS_EXTRA_FIELDS \
    FLB_TESTS_DATA_PATH "/data/gcs/gcs-credentials-extra-fields.json"
#define TEST_PRIVATE_KEY FLB_TESTS_DATA_PATH "/data/tls/private_key.pem"

static char *create_test_store_directory(const char *postfix)
{
    char *store_dir;

    store_dir = flb_test_tmpdir_cat(postfix);
    if (!store_dir) {
        return NULL;
    }

    if (!mkdtemp(store_dir)) {
        flb_free(store_dir);
        return NULL;
    }

    return store_dir;
}

void flb_test_gcs_jwt_signing(void)
{
    int ret;
    char *private_key;
    char *jwt;
    char *first_separator;
    char *second_separator;
    size_t jwt_size;

    private_key = mk_file_to_buffer(TEST_PRIVATE_KEY);
    TEST_CHECK(private_key != NULL);
    if (!private_key) {
        return;
    }

    ret = gcs_jwt_encode(NULL, "{\"sub\":\"fluent-bit\"}", private_key,
                         &jwt, &jwt_size);
    TEST_CHECK(ret == 0);
    if (ret == 0) {
        TEST_CHECK(jwt_size == flb_sds_len(jwt));
        first_separator = strchr(jwt, '.');
        TEST_CHECK(first_separator != NULL);
        second_separator = first_separator ? strchr(first_separator + 1, '.') : NULL;
        TEST_CHECK(second_separator != NULL);
        TEST_CHECK(second_separator && second_separator[1] != '\0');
        flb_sds_destroy(jwt);
    }

    flb_free(private_key);
}

void flb_test_gcs_uri_encode_object_name(void)
{
    flb_sds_t encoded;
    const char *object_name = "logs/a+b&c=d?#%/space key";
    const char *expected = "logs%2Fa%2Bb%26c%3Dd%3F%23%25%2Fspace%20key";

    encoded = gcs_uri_encode_object_name(object_name, strlen(object_name));
    TEST_CHECK(encoded != NULL);
    if (encoded) {
        TEST_CHECK(strcmp(encoded, expected) == 0);
        flb_sds_destroy(encoded);
    }
}

void flb_test_gcs_upload_success(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    char *call_count_str;
    int call_count;
    char *store_dir;

    store_dir = create_test_store_directory("/flb-gcs-test-success-XXXXXX");
    TEST_CHECK(store_dir != NULL);
    if (!store_dir) {
        return;
    }

    setenv("FLB_GCS_PLUGIN_UNDER_TEST", "true", 1);

    ctx = flb_create();

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test+a&b=c#d", NULL);

    out_ffd = flb_output(ctx, (char *) "gcs", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "*", NULL);
    flb_output_set(ctx, out_ffd, "bucket", "fluent", NULL);
    flb_output_set(ctx, out_ffd, "google_service_credentials", SERVICE_CREDENTIALS, NULL);
    flb_output_set(ctx, out_ffd, "upload_timeout", "3s", NULL);
    flb_output_set(ctx, out_ffd, "store_dir", store_dir, NULL);
    flb_output_set(ctx, out_ffd, "gcs_key_format", "logs/$TAG", NULL);
    flb_output_set(ctx, out_ffd, "static_file_path", "true", NULL);
    flb_output_set(ctx, out_ffd, "compression", "GZIP", NULL);
    flb_output_set(ctx, out_ffd, "canned_acl", "public-read", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    flb_lib_push(ctx, in_ffd, (char *) JSON_TD, (int) sizeof(JSON_TD) - 1);
    sleep(5);

    call_count_str = getenv("TEST_GCS_UploadObject_CALL_COUNT");
    call_count = call_count_str ? atoi(call_count_str) : 0;
    TEST_CHECK_(call_count == 1,
                "Expected 1 UploadObject call, got %d", call_count);
    TEST_CHECK_(getenv("TEST_GCS_LAST_URI") != NULL,
                "Expected the mock upload URI to be captured");
    if (getenv("TEST_GCS_LAST_URI")) {
        TEST_CHECK(strcmp(getenv("TEST_GCS_LAST_URI"),
                          "/upload/storage/v1/b/fluent/o?uploadType=media&"
                          "name=logs%2Ftest%2Ba%26b%3Dc%23d&contentEncoding=gzip&"
                          "predefinedAcl=publicRead") == 0);
    }
    TEST_CHECK_(getenv("TEST_GCS_LAST_BODY_GZIP") != NULL,
                "Expected the mock upload body encoding to be captured");
    if (getenv("TEST_GCS_LAST_BODY_GZIP")) {
        TEST_CHECK(strcmp(getenv("TEST_GCS_LAST_BODY_GZIP"), "true") == 0);
    }

    flb_stop(ctx);
    flb_destroy(ctx);

    unsetenv("FLB_GCS_PLUGIN_UNDER_TEST");
    unsetenv("TEST_GCS_UploadObject_CALL_COUNT");
    unsetenv("TEST_GCS_LAST_URI");
    unsetenv("TEST_GCS_LAST_BODY_GZIP");
    unsetenv("TEST_GCS_LAST_BODY_PARQUET");
    unsetenv("TEST_GCS_LAST_CONTENT_TYPE");
    flb_free(store_dir);
}

#ifdef FLB_HAVE_ARROW_PARQUET
static void test_gcs_upload_parquet(const char *compression,
                                    const char *store_directory_postfix)
{
    int ret;
    int call_count;
    int in_ffd;
    int out_ffd;
    char *call_count_str;
    char *store_dir;
    flb_ctx_t *ctx;

    store_dir = create_test_store_directory(store_directory_postfix);
    TEST_CHECK(store_dir != NULL);
    if (!store_dir) {
        return;
    }

    setenv("FLB_GCS_PLUGIN_UNDER_TEST", "true", 1);
    unsetenv("TEST_GCS_UploadObject_CALL_COUNT");

    ctx = flb_create();
    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "gcs", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "*", NULL);
    flb_output_set(ctx, out_ffd, "bucket", "fluent", NULL);
    flb_output_set(ctx, out_ffd, "google_service_credentials", SERVICE_CREDENTIALS, NULL);
    flb_output_set(ctx, out_ffd, "upload_timeout", "3s", NULL);
    flb_output_set(ctx, out_ffd, "store_dir", store_dir, NULL);
    flb_output_set(ctx, out_ffd, "gcs_key_format", "logs/$TAG", NULL);
    flb_output_set(ctx, out_ffd, "static_file_path", "true", NULL);
    flb_output_set(ctx, out_ffd, "format", "parquet", NULL);
    flb_output_set(ctx, out_ffd, "compression", compression, NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    flb_lib_push(ctx, in_ffd, (char *) JSON_TD, (int) sizeof(JSON_TD) - 1);
    sleep(5);

    call_count_str = getenv("TEST_GCS_UploadObject_CALL_COUNT");
    call_count = call_count_str ? atoi(call_count_str) : 0;
    TEST_CHECK_(call_count == 1,
                "Expected 1 UploadObject call, got %d", call_count);
    TEST_CHECK_(getenv("TEST_GCS_LAST_URI") != NULL,
                "Expected the mock upload URI to be captured");
    if (getenv("TEST_GCS_LAST_URI")) {
        TEST_CHECK(strcmp(getenv("TEST_GCS_LAST_URI"),
                          "/upload/storage/v1/b/fluent/o?uploadType=media&"
                          "name=logs%2Ftest") == 0);
    }
    TEST_CHECK_(getenv("TEST_GCS_LAST_BODY_PARQUET") != NULL,
                "Expected the mock upload body format to be captured");
    if (getenv("TEST_GCS_LAST_BODY_PARQUET")) {
        TEST_CHECK(strcmp(getenv("TEST_GCS_LAST_BODY_PARQUET"), "true") == 0);
    }
    TEST_CHECK_(getenv("TEST_GCS_LAST_BODY_GZIP") != NULL,
                "Expected the mock upload body encoding to be captured");
    if (getenv("TEST_GCS_LAST_BODY_GZIP")) {
        TEST_CHECK(strcmp(getenv("TEST_GCS_LAST_BODY_GZIP"), "false") == 0);
    }
    TEST_CHECK_(getenv("TEST_GCS_LAST_CONTENT_TYPE") != NULL,
                "Expected the mock upload content type to be captured");
    if (getenv("TEST_GCS_LAST_CONTENT_TYPE")) {
        TEST_CHECK(strcmp(getenv("TEST_GCS_LAST_CONTENT_TYPE"),
                          "application/vnd.apache.parquet") == 0);
    }

    flb_stop(ctx);
    flb_destroy(ctx);

    unsetenv("FLB_GCS_PLUGIN_UNDER_TEST");
    unsetenv("TEST_GCS_UploadObject_CALL_COUNT");
    unsetenv("TEST_GCS_LAST_URI");
    unsetenv("TEST_GCS_LAST_BODY_GZIP");
    unsetenv("TEST_GCS_LAST_BODY_PARQUET");
    unsetenv("TEST_GCS_LAST_CONTENT_TYPE");
    flb_free(store_dir);
}

void flb_test_gcs_upload_parquet_zstd(void)
{
    test_gcs_upload_parquet("ZSTD", "/flb-gcs-test-parquet-zstd-XXXXXX");
}

void flb_test_gcs_upload_parquet_snappy(void)
{
    test_gcs_upload_parquet("SNAPPY", "/flb-gcs-test-parquet-snappy-XXXXXX");
}
#endif

#ifndef FLB_HAVE_ARROW_PARQUET
void flb_test_gcs_rejects_parquet_without_support(void)
{
    int ret;
    int in_ffd;
    int out_ffd;
    char *store_dir;
    flb_ctx_t *ctx;

    store_dir = create_test_store_directory("/flb-gcs-test-no-parquet-XXXXXX");
    TEST_CHECK(store_dir != NULL);
    if (!store_dir) {
        return;
    }

    ctx = flb_create();
    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "gcs", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "*", NULL);
    flb_output_set(ctx, out_ffd, "bucket", "fluent", NULL);
    flb_output_set(ctx, out_ffd, "google_service_credentials", SERVICE_CREDENTIALS, NULL);
    flb_output_set(ctx, out_ffd, "store_dir", store_dir, NULL);
    flb_output_set(ctx, out_ffd, "format", "parquet", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret != 0);

    flb_destroy(ctx);
    flb_free(store_dir);
}
#endif

void flb_test_gcs_identity_federation_upload(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    char *call_count_str;
    int call_count;
    char *store_dir;

    store_dir = create_test_store_directory("/flb-gcs-test-wif-XXXXXX");
    TEST_CHECK(store_dir != NULL);
    if (!store_dir) {
        return;
    }

    setenv("FLB_GCS_PLUGIN_UNDER_TEST", "true", 1);

    ctx = flb_create();

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "gcs", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "*", NULL);
    flb_output_set(ctx, out_ffd, "bucket", "fluent", NULL);
    flb_output_set(ctx, out_ffd, "enable_identity_federation", "true", NULL);
    flb_output_set(ctx, out_ffd, "project_number", "123456789", NULL);
    flb_output_set(ctx, out_ffd, "pool_id", "my-pool", NULL);
    flb_output_set(ctx, out_ffd, "provider_id", "my-provider", NULL);
    flb_output_set(ctx, out_ffd, "identity_token_file", TEST_PRIVATE_KEY, NULL);
    flb_output_set(ctx, out_ffd, "google_service_account",
                   "logger@my-proj.iam.gserviceaccount.com", NULL);
    flb_output_set(ctx, out_ffd, "upload_timeout", "3s", NULL);
    flb_output_set(ctx, out_ffd, "store_dir", store_dir, NULL);
    flb_output_set(ctx, out_ffd, "gcs_key_format", "logs/$TAG", NULL);
    flb_output_set(ctx, out_ffd, "static_file_path", "true", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    flb_lib_push(ctx, in_ffd, (char *) JSON_TD, (int) sizeof(JSON_TD) - 1);
    sleep(5);

    call_count_str = getenv("TEST_GCS_UploadObject_CALL_COUNT");
    call_count = call_count_str ? atoi(call_count_str) : 0;
    TEST_CHECK_(call_count == 1,
                "Expected 1 UploadObject call, got %d", call_count);

    flb_stop(ctx);
    flb_destroy(ctx);

    unsetenv("FLB_GCS_PLUGIN_UNDER_TEST");
    unsetenv("TEST_GCS_UploadObject_CALL_COUNT");
    unsetenv("TEST_GCS_LAST_URI");
    unsetenv("TEST_GCS_LAST_BODY_GZIP");
    flb_free(store_dir);
}

void flb_test_gcs_rejects_incomplete_federation(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    char *store_dir;

    store_dir = create_test_store_directory("/flb-gcs-test-wif-incomplete-XXXXXX");
    TEST_CHECK(store_dir != NULL);
    if (!store_dir) {
        return;
    }

    ctx = flb_create();
    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "gcs", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "*", NULL);
    flb_output_set(ctx, out_ffd, "bucket", "fluent", NULL);
    flb_output_set(ctx, out_ffd, "enable_identity_federation", "true", NULL);
    flb_output_set(ctx, out_ffd, "project_number", "123456789", NULL);
    /* pool_id/provider_id/identity_token_file intentionally missing */
    flb_output_set(ctx, out_ffd, "store_dir", store_dir, NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret != 0);
    flb_destroy(ctx);
    flb_free(store_dir);
}

void flb_test_gcs_rejects_conflicting_credentials(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    char *store_dir;

    store_dir = create_test_store_directory("/flb-gcs-test-wif-conflict-XXXXXX");
    TEST_CHECK(store_dir != NULL);
    if (!store_dir) {
        return;
    }

    ctx = flb_create();
    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "gcs", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "*", NULL);
    flb_output_set(ctx, out_ffd, "bucket", "fluent", NULL);
    flb_output_set(ctx, out_ffd, "google_service_credentials", SERVICE_CREDENTIALS, NULL);
    flb_output_set(ctx, out_ffd, "enable_identity_federation", "true", NULL);
    flb_output_set(ctx, out_ffd, "project_number", "123456789", NULL);
    flb_output_set(ctx, out_ffd, "pool_id", "my-pool", NULL);
    flb_output_set(ctx, out_ffd, "provider_id", "my-provider", NULL);
    flb_output_set(ctx, out_ffd, "identity_token_file", TEST_PRIVATE_KEY, NULL);
    flb_output_set(ctx, out_ffd, "store_dir", store_dir, NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret != 0);
    flb_destroy(ctx);
    flb_free(store_dir);
}

void flb_test_gcs_rejects_invalid_configuration(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    char *store_dir;

    store_dir = create_test_store_directory("/flb-gcs-test-invalid-config-XXXXXX");
    TEST_CHECK(store_dir != NULL);
    if (!store_dir) {
        return;
    }

    ctx = flb_create();
    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "gcs", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "*", NULL);
    flb_output_set(ctx, out_ffd, "bucket", "fluent", NULL);
    flb_output_set(ctx, out_ffd, "google_service_credentials", SERVICE_CREDENTIALS, NULL);
    flb_output_set(ctx, out_ffd, "store_dir", store_dir, NULL);
    flb_output_set(ctx, out_ffd, "send_content_md5", "not-a-boolean", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret != 0);
    flb_destroy(ctx);
    flb_free(store_dir);
}

void flb_test_gcs_rejects_invalid_compression(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    char *store_dir;

    store_dir = create_test_store_directory("/flb-gcs-test-invalid-compression-XXXXXX");
    TEST_CHECK(store_dir != NULL);
    if (!store_dir) {
        return;
    }

    ctx = flb_create();
    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "gcs", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "*", NULL);
    flb_output_set(ctx, out_ffd, "bucket", "fluent", NULL);
    flb_output_set(ctx, out_ffd, "google_service_credentials", SERVICE_CREDENTIALS, NULL);
    flb_output_set(ctx, out_ffd, "store_dir", store_dir, NULL);
    flb_output_set(ctx, out_ffd, "compression", "zstd", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret != 0);
    flb_destroy(ctx);
    flb_free(store_dir);
}

void flb_test_gcs_accepts_extra_credential_fields(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    char *store_dir;

    store_dir = create_test_store_directory("/flb-gcs-test-extra-credentials-XXXXXX");
    TEST_CHECK(store_dir != NULL);
    if (!store_dir) {
        return;
    }

    ctx = flb_create();
    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "gcs", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "*", NULL);
    flb_output_set(ctx, out_ffd, "bucket", "fluent", NULL);
    flb_output_set(ctx, out_ffd, "google_service_credentials",
                   SERVICE_CREDENTIALS_EXTRA_FIELDS, NULL);
    flb_output_set(ctx, out_ffd, "store_dir", store_dir, NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);
    if (ret == 0) {
        flb_stop(ctx);
    }
    flb_destroy(ctx);
    flb_free(store_dir);
}

void flb_test_gcs_application_default_credentials_env(void)
{
    int ret;
    int in_ffd;
    int out_ffd;
    char *store_dir;
    flb_ctx_t *ctx;

    store_dir = create_test_store_directory("/flb-gcs-test-adc-env-XXXXXX");
    TEST_CHECK(store_dir != NULL);
    if (!store_dir) {
        return;
    }

    setenv("GOOGLE_APPLICATION_CREDENTIALS", SERVICE_CREDENTIALS, 1);
    setenv("GOOGLE_SERVICE_CREDENTIALS", "/does/not/exist", 1);

    ctx = flb_create();
    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "gcs", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "*", NULL);
    flb_output_set(ctx, out_ffd, "bucket", "fluent", NULL);
    flb_output_set(ctx, out_ffd, "store_dir", store_dir, NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);
    if (ret == 0) {
        flb_stop(ctx);
    }
    flb_destroy(ctx);

    unsetenv("GOOGLE_APPLICATION_CREDENTIALS");
    unsetenv("GOOGLE_SERVICE_CREDENTIALS");
    flb_free(store_dir);
}

void flb_test_gcs_metadata_server_authentication(void)
{
    int ret;
    int in_ffd;
    int out_ffd;
    int metadata_calls;
    int upload_calls;
    char *store_dir;
    char *value;
    flb_ctx_t *ctx;

    store_dir = create_test_store_directory("/flb-gcs-test-metadata-XXXXXX");
    TEST_CHECK(store_dir != NULL);
    if (!store_dir) {
        return;
    }

    unsetenv("GOOGLE_APPLICATION_CREDENTIALS");
    unsetenv("GOOGLE_SERVICE_CREDENTIALS");
    unsetenv("TEST_GCS_MetadataToken_CALL_COUNT");
    unsetenv("TEST_GCS_UploadObject_CALL_COUNT");
    setenv("FLB_GCS_PLUGIN_UNDER_TEST", "true", 1);
    setenv("TEST_GCS_METADATA_RESPONSE",
           "{\"access_token\":\"metadata-token\",\"expires_in\":3600,"
           "\"token_type\":\"Bearer\"}", 1);

    ctx = flb_create();
    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "gcs", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "*", NULL);
    flb_output_set(ctx, out_ffd, "bucket", "fluent", NULL);
    flb_output_set(ctx, out_ffd, "upload_timeout", "1s", NULL);
    flb_output_set(ctx, out_ffd, "store_dir", store_dir, NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);
    if (ret == 0) {
        flb_lib_push(ctx, in_ffd, (char *) JSON_TD, (int) sizeof(JSON_TD) - 1);
        sleep(3);
        flb_stop(ctx);
    }
    flb_destroy(ctx);

    value = getenv("TEST_GCS_MetadataToken_CALL_COUNT");
    metadata_calls = value ? atoi(value) : 0;
    TEST_CHECK_(metadata_calls == 1,
                "Expected 1 metadata token call, got %d", metadata_calls);
    value = getenv("TEST_GCS_UploadObject_CALL_COUNT");
    upload_calls = value ? atoi(value) : 0;
    TEST_CHECK_(upload_calls == 1,
                "Expected 1 UploadObject call, got %d", upload_calls);
    value = getenv("TEST_GCS_LAST_METADATA_URI");
    TEST_CHECK_(value != NULL, "Expected the metadata URI to be captured");
    if (value) {
        TEST_CHECK(strcmp(value, FLB_GCS_METADATA_TOKEN_URI) == 0);
    }

    unsetenv("FLB_GCS_PLUGIN_UNDER_TEST");
    unsetenv("TEST_GCS_METADATA_RESPONSE");
    unsetenv("TEST_GCS_MetadataToken_CALL_COUNT");
    unsetenv("TEST_GCS_UploadObject_CALL_COUNT");
    unsetenv("TEST_GCS_LAST_METADATA_URI");
    unsetenv("TEST_GCS_LAST_URI");
    unsetenv("TEST_GCS_LAST_BODY_GZIP");
    flb_free(store_dir);
}

void flb_test_gcs_rejects_invalid_metadata_response(void)
{
    int ret;
    int in_ffd;
    int out_ffd;
    int metadata_calls;
    int upload_calls;
    char *store_dir;
    char *value;
    flb_ctx_t *ctx;

    store_dir = create_test_store_directory("/flb-gcs-test-metadata-invalid-XXXXXX");
    TEST_CHECK(store_dir != NULL);
    if (!store_dir) {
        return;
    }

    unsetenv("GOOGLE_APPLICATION_CREDENTIALS");
    unsetenv("GOOGLE_SERVICE_CREDENTIALS");
    unsetenv("TEST_GCS_MetadataToken_CALL_COUNT");
    unsetenv("TEST_GCS_UploadObject_CALL_COUNT");
    setenv("FLB_GCS_PLUGIN_UNDER_TEST", "true", 1);
    setenv("TEST_GCS_METADATA_RESPONSE", "{\"invalid\":true}", 1);

    ctx = flb_create();
    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "gcs", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "*", NULL);
    flb_output_set(ctx, out_ffd, "bucket", "fluent", NULL);
    flb_output_set(ctx, out_ffd, "upload_timeout", "1s", NULL);
    flb_output_set(ctx, out_ffd, "store_dir", store_dir, NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);
    if (ret == 0) {
        flb_lib_push(ctx, in_ffd, (char *) JSON_TD, (int) sizeof(JSON_TD) - 1);
        sleep(3);
        flb_stop(ctx);
    }
    flb_destroy(ctx);

    value = getenv("TEST_GCS_MetadataToken_CALL_COUNT");
    metadata_calls = value ? atoi(value) : 0;
    TEST_CHECK_(metadata_calls >= 1,
                "Expected at least 1 metadata token call, got %d", metadata_calls);
    value = getenv("TEST_GCS_UploadObject_CALL_COUNT");
    upload_calls = value ? atoi(value) : 0;
    TEST_CHECK_(upload_calls == 0,
                "Expected no UploadObject calls, got %d", upload_calls);

    unsetenv("FLB_GCS_PLUGIN_UNDER_TEST");
    unsetenv("TEST_GCS_METADATA_RESPONSE");
    unsetenv("TEST_GCS_MetadataToken_CALL_COUNT");
    unsetenv("TEST_GCS_UploadObject_CALL_COUNT");
    unsetenv("TEST_GCS_LAST_METADATA_URI");
    unsetenv("TEST_GCS_LAST_URI");
    unsetenv("TEST_GCS_LAST_BODY_GZIP");
    flb_free(store_dir);
}

void flb_test_gcs_upload_error(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    char *call_count_str;
    int call_count;
    char *store_dir;

    store_dir = create_test_store_directory("/flb-gcs-test-error-XXXXXX");
    TEST_CHECK(store_dir != NULL);
    if (!store_dir) {
        return;
    }

    setenv("FLB_GCS_PLUGIN_UNDER_TEST", "true", 1);
    setenv("TEST_GCS_UPLOAD_ERROR", "true", 1);

    ctx = flb_create();

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "gcs", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "*", NULL);
    flb_output_set(ctx, out_ffd, "bucket", "fluent", NULL);
    flb_output_set(ctx, out_ffd, "google_service_credentials", SERVICE_CREDENTIALS, NULL);
    flb_output_set(ctx, out_ffd, "upload_timeout", "3s", NULL);
    flb_output_set(ctx, out_ffd, "store_dir", store_dir, NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    flb_lib_push(ctx, in_ffd, (char *) JSON_TD, (int) sizeof(JSON_TD) - 1);
    sleep(6);

    call_count_str = getenv("TEST_GCS_UploadObject_CALL_COUNT");
    call_count = call_count_str ? atoi(call_count_str) : 0;
    TEST_CHECK_(call_count >= 1,
                "Expected >=1 UploadObject calls, got %d", call_count);

    flb_stop(ctx);
    flb_destroy(ctx);

    unsetenv("FLB_GCS_PLUGIN_UNDER_TEST");
    unsetenv("TEST_GCS_UPLOAD_ERROR");
    unsetenv("TEST_GCS_CONSTRUCT_REQUEST_BUFFER_ERROR");
    unsetenv("TEST_GCS_UploadObject_CALL_COUNT");
    unsetenv("TEST_GCS_LAST_URI");
    unsetenv("TEST_GCS_LAST_BODY_GZIP");
    unsetenv("TEST_GCS_LAST_BODY_PARQUET");
    unsetenv("TEST_GCS_LAST_CONTENT_TYPE");
    flb_free(store_dir);
}

void flb_test_gcs_shutdown_preserves_pending_upload(void)
{
    int ret;
    int in_ffd;
    int out_ffd;
    int call_count;
    char *call_count_str;
    char *store_dir;
    char body[] = "{\"message\":\"pending\"}\n";
    flb_ctx_t *ctx;
    struct flb_gcs *gcs_ctx;
    struct gcs_file *chunk;
    struct upload_queue *entry;
    struct flb_output_instance *out_ins;

    store_dir = create_test_store_directory("/flb-gcs-test-shutdown-XXXXXX");
    TEST_CHECK(store_dir != NULL);
    if (!store_dir) {
        return;
    }

    setenv("FLB_GCS_PLUGIN_UNDER_TEST", "true", 1);
    unsetenv("TEST_GCS_UploadObject_CALL_COUNT");

    ctx = flb_create();
    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "gcs", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "*", NULL);
    flb_output_set(ctx, out_ffd, "bucket", "fluent", NULL);
    flb_output_set(ctx, out_ffd, "google_service_credentials", SERVICE_CREDENTIALS, NULL);
    flb_output_set(ctx, out_ffd, "store_dir", store_dir, NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);
    if (ret != 0) {
        flb_destroy(ctx);
        unsetenv("FLB_GCS_PLUGIN_UNDER_TEST");
        flb_free(store_dir);
        return;
    }

    out_ins = flb_output_get_instance(ctx->config, out_ffd);
    TEST_CHECK(out_ins != NULL);
    gcs_ctx = out_ins ? out_ins->context : NULL;
    TEST_CHECK(gcs_ctx != NULL);

    ret = gcs_store_buffer_put(gcs_ctx, NULL, "test", 4, body, sizeof(body) - 1);
    TEST_CHECK(ret == 0);
    chunk = gcs_store_file_get(gcs_ctx, "test", 4);
    TEST_CHECK(chunk != NULL);

    entry = flb_calloc(1, sizeof(struct upload_queue));
    TEST_CHECK(entry != NULL);
    if (entry && chunk) {
        entry->tag = flb_strdup("test");
        TEST_CHECK(entry->tag != NULL);
        if (entry->tag) {
            entry->tag_len = 4;
            entry->upload_file = chunk;
            entry->upload_time = 0;
            mk_list_add(&entry->_head, &gcs_ctx->upload_queue);
        }
        else {
            flb_free(entry);
        }
    }

    flb_stop(ctx);
    flb_destroy(ctx);

    call_count_str = getenv("TEST_GCS_UploadObject_CALL_COUNT");
    call_count = call_count_str ? atoi(call_count_str) : 0;
    TEST_CHECK_(call_count == 0,
                "Expected shutdown to preserve pending data without uploading, got %d call(s)",
                call_count);

    unsetenv("FLB_GCS_PLUGIN_UNDER_TEST");
    unsetenv("TEST_GCS_UploadObject_CALL_COUNT");
    unsetenv("TEST_GCS_LAST_URI");
    unsetenv("TEST_GCS_LAST_BODY_GZIP");
    unsetenv("TEST_GCS_LAST_BODY_PARQUET");
    unsetenv("TEST_GCS_LAST_CONTENT_TYPE");
    flb_free(store_dir);
}

void flb_test_gcs_unify_tag_buffers_multiple_tags(void)
{
    int ret;
    int i;
    flb_ctx_t *ctx;
    int in_a;
    int in_b;
    int out_ffd;
    char *store_dir;
    char *buf;
    size_t buf_size;
    flb_sds_t content;
    struct flb_output_instance *out_ins;
    struct flb_gcs *gcs_ctx;
    struct gcs_file *chunk_unify;
    int found_a = FLB_FALSE;
    int found_b = FLB_FALSE;
    const char *unify_tag = "unified-test-key";
    const char *rec_a = "[1448403340, {\"src\": \"unify-marker-a\"}]";
    const char *rec_b = "[1448403340, {\"src\": \"unify-marker-b\"}]";

    store_dir = create_test_store_directory("/flb-gcs-test-unify-tag-XXXXXX");
    TEST_CHECK(store_dir != NULL);
    if (!store_dir) {
        return;
    }

    setenv("FLB_GCS_PLUGIN_UNDER_TEST", "true", 1);

    ctx = flb_create();

    in_a = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_a >= 0);
    flb_input_set(ctx, in_a, "tag", "kube.a", NULL);

    in_b = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_b >= 0);
    flb_input_set(ctx, in_b, "tag", "kube.b", NULL);

    out_ffd = flb_output(ctx, (char *) "gcs", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "*", NULL);
    flb_output_set(ctx, out_ffd, "bucket", "fluent", NULL);
    flb_output_set(ctx, out_ffd, "google_service_credentials", SERVICE_CREDENTIALS, NULL);
    flb_output_set(ctx, out_ffd, "unify_tag", "true", NULL);
    flb_output_set(ctx, out_ffd, "unify_tag_name", "unified-test-key", NULL);
    flb_output_set(ctx, out_ffd, "store_dir", store_dir, NULL);
    /* keep chunks buffered so the merged result can be inspected */
    flb_output_set(ctx, out_ffd, "upload_timeout", "60m", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    out_ins = flb_output_get_instance(ctx->config, out_ffd);
    TEST_CHECK(out_ins != NULL);
    gcs_ctx = out_ins ? out_ins->context : NULL;
    TEST_CHECK(gcs_ctx != NULL);

    flb_lib_push(ctx, in_a, (char *) rec_a, (int) strlen(rec_a));
    flb_lib_push(ctx, in_b, (char *) rec_b, (int) strlen(rec_b));

    /*
     * Wait (bounded) until both records are present in the single unified
     * buffer chunk. Distinct markers prove both inputs were processed and
     * merged, rather than a single record satisfying the check.
     */
    for (i = 0; gcs_ctx && i < 10 && !(found_a && found_b); i++) {
        sleep(1);
        chunk_unify = gcs_store_file_get(gcs_ctx, (char *) unify_tag,
                                         strlen(unify_tag));
        if (!chunk_unify) {
            continue;
        }
        buf = NULL;
        buf_size = 0;
        if (gcs_store_file_read(gcs_ctx, chunk_unify, &buf, &buf_size) != 0 || !buf) {
            continue;
        }
        content = flb_sds_create_len(buf, buf_size);
        if (content) {
            found_a = strstr(content, "unify-marker-a") != NULL;
            found_b = strstr(content, "unify-marker-b") != NULL;
            flb_sds_destroy(content);
        }
        flb_free(buf);
    }

    if (gcs_ctx) {
        TEST_CHECK(gcs_ctx->unify_tag == FLB_TRUE);

        TEST_CHECK_(gcs_store_file_get(gcs_ctx, "kube.a", 6) == NULL,
                    "expected no per-tag chunk for kube.a");
        TEST_CHECK_(gcs_store_file_get(gcs_ctx, "kube.b", 6) == NULL,
                    "expected no per-tag chunk for kube.b");
        TEST_CHECK_(found_a, "record from kube.a missing from unified buffer");
        TEST_CHECK_(found_b, "record from kube.b missing from unified buffer");
    }

    flb_stop(ctx);
    flb_destroy(ctx);

    unsetenv("FLB_GCS_PLUGIN_UNDER_TEST");
    unsetenv("TEST_GCS_UploadObject_CALL_COUNT");
    unsetenv("TEST_GCS_LAST_URI");
    unsetenv("TEST_GCS_LAST_BODY_GZIP");
    flb_free(store_dir);
}

void flb_test_gcs_unify_tag_disabled_by_default(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    char *store_dir;
    struct flb_output_instance *out_ins;
    struct flb_gcs *gcs_ctx;

    store_dir = create_test_store_directory("/flb-gcs-test-no-unify-tag-XXXXXX");
    TEST_CHECK(store_dir != NULL);
    if (!store_dir) {
        return;
    }

    setenv("FLB_GCS_PLUGIN_UNDER_TEST", "true", 1);

    ctx = flb_create();

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "gcs", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "*", NULL);
    flb_output_set(ctx, out_ffd, "bucket", "fluent", NULL);
    flb_output_set(ctx, out_ffd, "google_service_credentials", SERVICE_CREDENTIALS, NULL);
    flb_output_set(ctx, out_ffd, "store_dir", store_dir, NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    out_ins = flb_output_get_instance(ctx->config, out_ffd);
    TEST_CHECK(out_ins != NULL);
    gcs_ctx = out_ins ? out_ins->context : NULL;
    TEST_CHECK(gcs_ctx != NULL);

    if (gcs_ctx) {
        TEST_CHECK(gcs_ctx->unify_tag == FLB_FALSE);
    }

    flb_stop(ctx);
    flb_destroy(ctx);

    unsetenv("FLB_GCS_PLUGIN_UNDER_TEST");
    unsetenv("TEST_GCS_UploadObject_CALL_COUNT");
    unsetenv("TEST_GCS_LAST_URI");
    unsetenv("TEST_GCS_LAST_BODY_GZIP");
    flb_free(store_dir);
}

void flb_test_gcs_net_settings_applied_to_upstream(void)
{
    int ret;
    int in_ffd;
    int out_ffd;
    char *store_dir;
    flb_ctx_t *ctx;
    struct flb_gcs *gcs_ctx;
    struct flb_output_instance *out_ins;

    store_dir = create_test_store_directory("/flb-gcs-test-net-XXXXXX");
    TEST_CHECK(store_dir != NULL);
    if (!store_dir) {
        return;
    }

    ctx = flb_create();
    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "gcs", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "*", NULL);
    flb_output_set(ctx, out_ffd, "bucket", "fluent", NULL);
    flb_output_set(ctx, out_ffd, "google_service_credentials", SERVICE_CREDENTIALS, NULL);
    flb_output_set(ctx, out_ffd, "store_dir", store_dir, NULL);
    flb_output_set(ctx, out_ffd, "net.connect_timeout", "7", NULL);
    flb_output_set(ctx, out_ffd, "net.keepalive_idle_timeout", "17", NULL);
    flb_output_set(ctx, out_ffd, "net.keepalive_max_recycle", "5", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);
    if (ret != 0) {
        flb_destroy(ctx);
        flb_free(store_dir);
        return;
    }

    out_ins = flb_output_get_instance(ctx->config, out_ffd);
    TEST_CHECK(out_ins != NULL);
    gcs_ctx = out_ins ? out_ins->context : NULL;
    TEST_CHECK(gcs_ctx != NULL);

    if (gcs_ctx && gcs_ctx->u) {
        TEST_CHECK_(gcs_ctx->u->base.net.connect_timeout == 7,
                    "Expected net.connect_timeout=7 on upstream, got %d",
                    gcs_ctx->u->base.net.connect_timeout);
        TEST_CHECK_(gcs_ctx->u->base.net.keepalive_idle_timeout == 17,
                    "Expected net.keepalive_idle_timeout=17 on upstream, got %d",
                    gcs_ctx->u->base.net.keepalive_idle_timeout);
        TEST_CHECK_(gcs_ctx->u->base.net.keepalive_max_recycle == 5,
                    "Expected net.keepalive_max_recycle=5 on upstream, got %d",
                    gcs_ctx->u->base.net.keepalive_max_recycle);
    }

    flb_stop(ctx);
    flb_destroy(ctx);
    flb_free(store_dir);
}

/*
 * The upload timer callback runs outside of any coroutine. If the upstream
 * were left in async mode, the first network write from the timer would
 * try to yield a NULL coroutine and crash. The plugin must therefore keep
 * the upstream in sync mode and still deliver timer-driven uploads when
 * preserve_data_ordering is disabled.
 */
void flb_test_gcs_timer_upload_without_ordering_uses_sync_upstream(void)
{
    int ret;
    int in_ffd;
    int out_ffd;
    int call_count;
    char *call_count_str;
    char *store_dir;
    flb_ctx_t *ctx;
    struct flb_gcs *gcs_ctx;
    struct flb_output_instance *out_ins;

    store_dir = create_test_store_directory("/flb-gcs-test-unordered-XXXXXX");
    TEST_CHECK(store_dir != NULL);
    if (!store_dir) {
        return;
    }

    setenv("FLB_GCS_PLUGIN_UNDER_TEST", "true", 1);
    unsetenv("TEST_GCS_UploadObject_CALL_COUNT");

    ctx = flb_create();
    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "gcs", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "*", NULL);
    flb_output_set(ctx, out_ffd, "bucket", "fluent", NULL);
    flb_output_set(ctx, out_ffd, "google_service_credentials", SERVICE_CREDENTIALS, NULL);
    flb_output_set(ctx, out_ffd, "store_dir", store_dir, NULL);
    flb_output_set(ctx, out_ffd, "upload_timeout", "3s", NULL);
    flb_output_set(ctx, out_ffd, "preserve_data_ordering", "false", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);
    if (ret != 0) {
        flb_destroy(ctx);
        unsetenv("FLB_GCS_PLUGIN_UNDER_TEST");
        flb_free(store_dir);
        return;
    }

    out_ins = flb_output_get_instance(ctx->config, out_ffd);
    TEST_CHECK(out_ins != NULL);
    gcs_ctx = out_ins ? out_ins->context : NULL;
    TEST_CHECK(gcs_ctx != NULL);
    if (gcs_ctx && gcs_ctx->u) {
        TEST_CHECK_(flb_stream_is_async(&gcs_ctx->u->base) == FLB_FALSE,
                    "Expected the GCS upstream to run in sync mode");
    }

    flb_lib_push(ctx, in_ffd, (char *) JSON_TD, (int) sizeof(JSON_TD) - 1);
    sleep(6);

    call_count_str = getenv("TEST_GCS_UploadObject_CALL_COUNT");
    call_count = call_count_str ? atoi(call_count_str) : 0;
    TEST_CHECK_(call_count == 1,
                "Expected 1 timer-driven UploadObject call, got %d", call_count);

    flb_stop(ctx);
    flb_destroy(ctx);

    unsetenv("FLB_GCS_PLUGIN_UNDER_TEST");
    unsetenv("TEST_GCS_UploadObject_CALL_COUNT");
    unsetenv("TEST_GCS_LAST_URI");
    unsetenv("TEST_GCS_LAST_BODY_GZIP");
    flb_free(store_dir);
}

/* Build a single ~size-byte JSON record for in_lib */
static char *build_large_record(size_t size, size_t *out_len)
{
    char *buf;
    size_t prefix_len;
    const char *prefix = "[0, {\"message\": \"";
    const char *suffix = "\"}]";

    prefix_len = strlen(prefix);
    buf = flb_malloc(size + prefix_len + strlen(suffix) + 1);
    if (!buf) {
        return NULL;
    }
    memcpy(buf, prefix, prefix_len);
    memset(buf + prefix_len, 'a', size);
    memcpy(buf + prefix_len + size, suffix, strlen(suffix) + 1);
    *out_len = prefix_len + size + strlen(suffix);
    return buf;
}

void flb_test_gcs_total_file_size_triggers_upload(void)
{
    int ret;
    int in_ffd;
    int out_ffd;
    int call_count;
    char *call_count_str;
    char *store_dir;
    char *record;
    size_t record_len;
    flb_ctx_t *ctx;

    store_dir = create_test_store_directory("/flb-gcs-test-total-size-XXXXXX");
    TEST_CHECK(store_dir != NULL);
    if (!store_dir) {
        return;
    }

    record = build_large_record(600 * 1024, &record_len);
    TEST_CHECK(record != NULL);
    if (!record) {
        flb_free(store_dir);
        return;
    }

    setenv("FLB_GCS_PLUGIN_UNDER_TEST", "true", 1);
    unsetenv("TEST_GCS_UploadObject_CALL_COUNT");

    ctx = flb_create();
    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "gcs", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "*", NULL);
    flb_output_set(ctx, out_ffd, "bucket", "fluent", NULL);
    flb_output_set(ctx, out_ffd, "google_service_credentials", SERVICE_CREDENTIALS, NULL);
    flb_output_set(ctx, out_ffd, "store_dir", store_dir, NULL);
    /* long timeout: only total_file_size can trigger an upload in this test */
    flb_output_set(ctx, out_ffd, "upload_timeout", "10m", NULL);
    flb_output_set(ctx, out_ffd, "total_file_size", "1M", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);
    if (ret != 0) {
        flb_destroy(ctx);
        unsetenv("FLB_GCS_PLUGIN_UNDER_TEST");
        flb_free(record);
        flb_free(store_dir);
        return;
    }

    /* first record (~600KB) is buffered, no upload yet */
    flb_lib_push(ctx, in_ffd, record, (int) record_len);
    sleep(3);
    call_count_str = getenv("TEST_GCS_UploadObject_CALL_COUNT");
    call_count = call_count_str ? atoi(call_count_str) : 0;
    TEST_CHECK_(call_count == 0,
                "Expected no upload below total_file_size, got %d", call_count);

    /* second record would exceed 1M: the buffered file must be uploaded */
    flb_lib_push(ctx, in_ffd, record, (int) record_len);
    sleep(3);
    call_count_str = getenv("TEST_GCS_UploadObject_CALL_COUNT");
    call_count = call_count_str ? atoi(call_count_str) : 0;
    TEST_CHECK_(call_count == 1,
                "Expected 1 upload after reaching total_file_size, got %d",
                call_count);

    flb_stop(ctx);
    flb_destroy(ctx);

    unsetenv("FLB_GCS_PLUGIN_UNDER_TEST");
    unsetenv("TEST_GCS_UploadObject_CALL_COUNT");
    unsetenv("TEST_GCS_LAST_URI");
    unsetenv("TEST_GCS_LAST_BODY_GZIP");
    flb_free(record);
    flb_free(store_dir);
}

/* Each serialized JSON line contains the message plus its JSON wrapper. */
static void check_total_file_size_boundary(size_t file_size, int record_count)
{
    int ret;
    int i;
    int in_ffd;
    int out_ffd;
    int call_count;
    char *call_count_str;
    char *store_dir;
    char *record;
    size_t record_len;
    size_t wrapper_size;
    flb_ctx_t *ctx;

    store_dir = create_test_store_directory("/flb-gcs-test-size-boundary-XXXXXX");
    if (!TEST_CHECK(store_dir != NULL)) {
        return;
    }

    wrapper_size = sizeof("{\"message\":\"\"}\n") - 1;
    record = build_large_record(file_size / record_count - wrapper_size, &record_len);
    if (!TEST_CHECK(record != NULL)) {
        flb_free(store_dir);
        return;
    }

    setenv("FLB_GCS_PLUGIN_UNDER_TEST", "true", 1);
    unsetenv("TEST_GCS_UploadObject_CALL_COUNT");

    ctx = flb_create();
    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "gcs", NULL);
    TEST_CHECK(out_ffd >= 0);
    /*
     * Payloads are sized byte-exactly here: keep the date field out of them,
     * date output is covered by the dedicated json_date_* tests.
     */
    flb_output_set(ctx, out_ffd,
                   "match", "*",
                   "bucket", "fluent",
                   "google_service_credentials", SERVICE_CREDENTIALS,
                   "store_dir", store_dir,
                   "upload_timeout", "10m",
                   "total_file_size", "1M",
                   "json_date_key", "false", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);
    if (ret == 0) {
        for (i = 0; i < record_count; i++) {
            ret = flb_lib_push(ctx, in_ffd, record, (int) record_len);
            TEST_CHECK(ret == (int) record_len);
            /* Separate flushes exercise appending to an existing file. */
            sleep(3);
        }
        flb_stop(ctx);
    }
    flb_destroy(ctx);

    /* Read the mock result after workers stop, without racing their writes. */
    call_count_str = getenv("TEST_GCS_UploadObject_CALL_COUNT");
    call_count = call_count_str ? atoi(call_count_str) : 0;
    TEST_CHECK_(call_count == 1,
                "Expected one size-triggered upload for %zu bytes in %d records, got %d",
                file_size, record_count, call_count);

    unsetenv("FLB_GCS_PLUGIN_UNDER_TEST");
    unsetenv("TEST_GCS_UploadObject_CALL_COUNT");
    unsetenv("TEST_GCS_LAST_URI");
    unsetenv("TEST_GCS_LAST_BODY_GZIP");
    flb_free(record);
    flb_free(store_dir);
}

void flb_test_gcs_total_file_size_exact_first_payload(void)
{
    check_total_file_size_boundary(1000000, 1);
}

void flb_test_gcs_total_file_size_oversized_first_payload(void)
{
    check_total_file_size_boundary(1200000, 1);
}

void flb_test_gcs_total_file_size_exact_append(void)
{
    check_total_file_size_boundary(1000000, 2);
}

/* Check size-triggered files alongside an older buffered or failed file. */
static void check_total_file_size_queue(int preserve_ordering, int fail_upload, int fail_read)
{
    int ret;
    int i;
    int in_ffd[2];
    int out_ffd;
    int call_count;
    char *call_count_str;
    char *store_dir;
    char *record[2];
    size_t record_len[2];
    size_t wrapper_size;
    struct flb_output_instance *out_ins;
    struct flb_gcs *gcs_ctx;
    struct upload_queue *entry;
    struct mk_list *head;
    flb_ctx_t *ctx;

    store_dir = create_test_store_directory("/flb-gcs-test-size-queue-XXXXXX");
    if (!TEST_CHECK(store_dir != NULL)) {
        return;
    }
    wrapper_size = sizeof("{\"message\":\"\"}\n") - 1;
    record[0] = build_large_record((fail_upload ? 1000000 : 500000) - wrapper_size,
                                   &record_len[0]);
    record[1] = build_large_record((fail_upload ? 500000 : 1000000) - wrapper_size,
                                   &record_len[1]);
    if (!TEST_CHECK(record[0] != NULL && record[1] != NULL)) {
        flb_free(record[0]);
        flb_free(record[1]);
        flb_free(store_dir);
        return;
    }
    setenv("FLB_GCS_PLUGIN_UNDER_TEST", "true", 1);
    unsetenv("TEST_GCS_UploadObject_CALL_COUNT");
    if (fail_upload) {
        setenv("TEST_GCS_UPLOAD_ERROR", "true", 1);
    }

    ctx = flb_create();
    for (i = 0; i < 2; i++) {
        in_ffd[i] = flb_input(ctx, (char *) "lib", NULL);
        TEST_CHECK(in_ffd[i] >= 0);
        flb_input_set(ctx, in_ffd[i], "tag", fail_upload || i == 0 ? "first" : "second", NULL);
    }
    out_ffd = flb_output(ctx, (char *) "gcs", NULL);
    /*
     * Payloads are sized byte-exactly here: keep the date field out of them,
     * date output is covered by the dedicated json_date_* tests.
     */
    flb_output_set(ctx, out_ffd,
                   "match", "*",
                   "bucket", "fluent",
                   "google_service_credentials", SERVICE_CREDENTIALS,
                   "store_dir", store_dir,
                   "upload_timeout", "10m",
                   "total_file_size", "1M",
                   "json_date_key", "false",
                   "preserve_data_ordering", preserve_ordering ? "true" : "false", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);
    if (ret == 0) {
        for (i = 0; i < 2; i++) {
            ret = flb_lib_push(ctx, in_ffd[i], record[i], (int) record_len[i]);
            TEST_CHECK(ret == (int) record_len[i]);
            sleep(3);
            if (fail_read && i == 0) {
                out_ins = flb_output_get_instance(ctx->config, out_ffd);
                gcs_ctx = out_ins->context;
                pthread_mutex_lock(&gcs_ctx->upload_lock);
                if (TEST_CHECK(mk_list_size(&gcs_ctx->upload_queue) == 1)) {
                    entry = mk_list_entry(gcs_ctx->upload_queue.next, struct upload_queue, _head);
                    setenv("TEST_GCS_CONSTRUCT_REQUEST_BUFFER_ERROR", "true", 1);
                    entry->upload_time = 0;
                    gcs_store_file_seal(entry->upload_file);
                }
                pthread_mutex_unlock(&gcs_ctx->upload_lock);
            }
        }

        out_ins = flb_output_get_instance(ctx->config, out_ffd);
        gcs_ctx = out_ins->context;
        pthread_mutex_lock(&gcs_ctx->upload_lock);
        if (fail_upload) {
            TEST_CHECK(mk_list_size(&gcs_ctx->upload_queue) == 2);
            mk_list_foreach(head, &gcs_ctx->upload_queue) {
                entry = mk_list_entry(head, struct upload_queue, _head);
                if (head == gcs_ctx->upload_queue.next) {
                    TEST_CHECK(entry->upload_file->sealed == FLB_TRUE);
                    TEST_CHECK(entry->upload_file->size == 1000000);
                    TEST_CHECK(entry->retry_counter > 0);
                }
                else {
                    TEST_CHECK(entry->upload_file->sealed == FLB_FALSE);
                    TEST_CHECK(entry->upload_file->size == 500000);
                }
            }
        }
        else {
            TEST_CHECK(mk_list_size(&gcs_ctx->upload_queue) == (preserve_ordering ? 2 : 1));
        }
        if (fail_read) {
            mk_list_foreach(head, &gcs_ctx->upload_queue) {
                entry = mk_list_entry(head, struct upload_queue, _head);
                if (head == gcs_ctx->upload_queue.next) {
                    TEST_CHECK(entry->retry_counter > 0);
                }
                else {
                    TEST_CHECK(entry->retry_counter == 0);
                }
            }
        }
        pthread_mutex_unlock(&gcs_ctx->upload_lock);
        flb_stop(ctx);
    }
    flb_destroy(ctx);

    call_count_str = getenv("TEST_GCS_UploadObject_CALL_COUNT");
    call_count = call_count_str ? atoi(call_count_str) : 0;
    if (fail_upload) {
        TEST_CHECK(call_count > 0);
    }
    else {
        TEST_CHECK(call_count == (preserve_ordering ? 0 : 1));
    }

    unsetenv("FLB_GCS_PLUGIN_UNDER_TEST");
    unsetenv("TEST_GCS_UPLOAD_ERROR");
    unsetenv("TEST_GCS_CONSTRUCT_REQUEST_BUFFER_ERROR");
    unsetenv("TEST_GCS_UploadObject_CALL_COUNT");
    unsetenv("TEST_GCS_LAST_URI");
    unsetenv("TEST_GCS_LAST_BODY_GZIP");
    flb_free(record[0]);
    flb_free(record[1]);
    flb_free(store_dir);
}

void flb_test_gcs_total_file_size_preserves_ordering(void)
{
    check_total_file_size_queue(FLB_TRUE, FLB_FALSE, FLB_FALSE);
}

void flb_test_gcs_total_file_size_without_ordering(void)
{
    check_total_file_size_queue(FLB_FALSE, FLB_FALSE, FLB_FALSE);
}

void flb_test_gcs_total_file_size_failed_upload_stays_sealed(void)
{
    check_total_file_size_queue(FLB_TRUE, FLB_TRUE, FLB_FALSE);
}

void flb_test_gcs_total_file_size_ordered_read_failure(void)
{
    check_total_file_size_queue(FLB_TRUE, FLB_FALSE, FLB_TRUE);
}

void flb_test_gcs_rejects_total_file_size_below_minimum(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    char *store_dir;

    store_dir = create_test_store_directory("/flb-gcs-test-small-total-size-XXXXXX");
    TEST_CHECK(store_dir != NULL);
    if (!store_dir) {
        return;
    }

    ctx = flb_create();
    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "gcs", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "*", NULL);
    flb_output_set(ctx, out_ffd, "bucket", "fluent", NULL);
    flb_output_set(ctx, out_ffd, "google_service_credentials", SERVICE_CREDENTIALS, NULL);
    flb_output_set(ctx, out_ffd, "store_dir", store_dir, NULL);
    flb_output_set(ctx, out_ffd, "total_file_size", "512K", NULL);

    ret = flb_start(ctx);
    TEST_CHECK_(ret != 0, "Expected total_file_size below 1M to be rejected");
    if (ret == 0) {
        flb_stop(ctx);
    }
    flb_destroy(ctx);
    flb_free(store_dir);
}

/*
 * Multiple output workers flush concurrently and share the upload queue,
 * the local file store and the sequence index. Every tag must still be
 * uploaded exactly once and the process must not crash or corrupt state.
 */
void flb_test_gcs_workers_upload_all_tags(void)
{
    int i;
    int ret;
    int in_ffd[4];
    int out_ffd;
    int call_count;
    char tag[16];
    char *call_count_str;
    char *store_dir;
    flb_ctx_t *ctx;

    store_dir = create_test_store_directory("/flb-gcs-test-workers-XXXXXX");
    TEST_CHECK(store_dir != NULL);
    if (!store_dir) {
        return;
    }

    setenv("FLB_GCS_PLUGIN_UNDER_TEST", "true", 1);
    unsetenv("TEST_GCS_UploadObject_CALL_COUNT");

    ctx = flb_create();
    for (i = 0; i < 4; i++) {
        snprintf(tag, sizeof(tag), "test.%d", i);
        in_ffd[i] = flb_input(ctx, (char *) "lib", NULL);
        TEST_CHECK(in_ffd[i] >= 0);
        flb_input_set(ctx, in_ffd[i], "tag", tag, NULL);
    }

    out_ffd = flb_output(ctx, (char *) "gcs", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "*", NULL);
    flb_output_set(ctx, out_ffd, "bucket", "fluent", NULL);
    flb_output_set(ctx, out_ffd, "google_service_credentials", SERVICE_CREDENTIALS, NULL);
    flb_output_set(ctx, out_ffd, "store_dir", store_dir, NULL);
    flb_output_set(ctx, out_ffd, "upload_timeout", "3s", NULL);
    flb_output_set(ctx, out_ffd, "preserve_data_ordering", "true", NULL);
    flb_output_set(ctx, out_ffd, "gcs_key_format", "logs/$TAG/$INDEX", NULL);
    flb_output_set(ctx, out_ffd, "workers", "4", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);
    if (ret != 0) {
        flb_destroy(ctx);
        unsetenv("FLB_GCS_PLUGIN_UNDER_TEST");
        flb_free(store_dir);
        return;
    }

    for (i = 0; i < 4; i++) {
        flb_lib_push(ctx, in_ffd[i], (char *) JSON_TD, (int) sizeof(JSON_TD) - 1);
    }
    sleep(6);

    call_count_str = getenv("TEST_GCS_UploadObject_CALL_COUNT");
    call_count = call_count_str ? atoi(call_count_str) : 0;
    TEST_CHECK_(call_count == 4,
                "Expected 4 UploadObject calls (one per tag), got %d", call_count);

    flb_stop(ctx);
    flb_destroy(ctx);

    unsetenv("FLB_GCS_PLUGIN_UNDER_TEST");
    unsetenv("TEST_GCS_UploadObject_CALL_COUNT");
    unsetenv("TEST_GCS_LAST_URI");
    unsetenv("TEST_GCS_LAST_BODY_GZIP");
    flb_free(store_dir);
}

/*
 * Data left in store_dir by a previous run must be recovered and uploaded
 * shortly after startup (the recovery path runs from init and from the
 * upload timer, both outside of any flush coroutine).
 */
static void check_backlog_recovery(int fail_upload)
{
    int ret;
    int in_ffd;
    int out_ffd;
    int call_count;
    char *call_count_str;
    char *store_dir;
    flb_ctx_t *ctx;
    struct flb_output_instance *out_ins;
    struct flb_gcs *gcs_ctx;
    struct upload_queue *entry;

    store_dir = create_test_store_directory("/flb-gcs-test-backlog-XXXXXX");
    TEST_CHECK(store_dir != NULL);
    if (!store_dir) {
        return;
    }

    setenv("FLB_GCS_PLUGIN_UNDER_TEST", "true", 1);
    unsetenv("TEST_GCS_UploadObject_CALL_COUNT");

    /* first instance: buffer data but never reach upload_timeout */
    ctx = flb_create();
    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "gcs", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "*", NULL);
    flb_output_set(ctx, out_ffd, "bucket", "fluent", NULL);
    flb_output_set(ctx, out_ffd, "google_service_credentials", SERVICE_CREDENTIALS, NULL);
    flb_output_set(ctx, out_ffd, "store_dir", store_dir, NULL);
    flb_output_set(ctx, out_ffd, "upload_timeout", "10m", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);
    if (ret != 0) {
        flb_destroy(ctx);
        unsetenv("FLB_GCS_PLUGIN_UNDER_TEST");
        flb_free(store_dir);
        return;
    }

    flb_lib_push(ctx, in_ffd, (char *) JSON_TD, (int) sizeof(JSON_TD) - 1);
    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);

    call_count_str = getenv("TEST_GCS_UploadObject_CALL_COUNT");
    call_count = call_count_str ? atoi(call_count_str) : 0;
    TEST_CHECK_(call_count == 0,
                "Expected no upload before shutdown, got %d", call_count);

    /* second instance on the same store_dir: backlog must be uploaded */
    if (fail_upload) {
        setenv("TEST_GCS_UPLOAD_ERROR", "true", 1);
    }
    ctx = flb_create();
    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "gcs", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "*", NULL);
    flb_output_set(ctx, out_ffd, "bucket", "fluent", NULL);
    flb_output_set(ctx, out_ffd, "google_service_credentials", SERVICE_CREDENTIALS, NULL);
    flb_output_set(ctx, out_ffd, "store_dir", store_dir, NULL);
    flb_output_set(ctx, out_ffd, "upload_timeout", "10m", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);
    if (ret == 0) {
        sleep(3);
        call_count_str = getenv("TEST_GCS_UploadObject_CALL_COUNT");
        call_count = call_count_str ? atoi(call_count_str) : 0;
        TEST_CHECK_(call_count == 1,
                    "Expected recovered backlog to be uploaded once, got %d",
                    call_count);
        if (fail_upload) {
            out_ins = flb_output_get_instance(ctx->config, out_ffd);
            gcs_ctx = out_ins->context;
            pthread_mutex_lock(&gcs_ctx->upload_lock);
            if (TEST_CHECK(mk_list_size(&gcs_ctx->upload_queue) == 1)) {
                entry = mk_list_entry(gcs_ctx->upload_queue.next, struct upload_queue, _head);
                TEST_CHECK(entry->upload_file->sealed == FLB_TRUE);
                TEST_CHECK(gcs_store_file_get(gcs_ctx, "test", 4) == NULL);
            }
            pthread_mutex_unlock(&gcs_ctx->upload_lock);
        }
        flb_stop(ctx);
    }
    flb_destroy(ctx);

    unsetenv("FLB_GCS_PLUGIN_UNDER_TEST");
    unsetenv("TEST_GCS_UPLOAD_ERROR");
    unsetenv("TEST_GCS_UploadObject_CALL_COUNT");
    unsetenv("TEST_GCS_LAST_URI");
    unsetenv("TEST_GCS_LAST_BODY_GZIP");
    flb_free(store_dir);
}

void flb_test_gcs_recovers_backlog_on_restart(void)
{
    check_backlog_recovery(FLB_FALSE);
}

void flb_test_gcs_recovered_upload_failure_stays_sealed(void)
{
    check_backlog_recovery(FLB_TRUE);
}

/* total_file_size must also apply to the shared file used by unify_tag */
void flb_test_gcs_total_file_size_with_unify_tag(void)
{
    int i;
    int ret;
    int in_ffd[2];
    int out_ffd;
    int call_count;
    char tag[16];
    char *call_count_str;
    char *store_dir;
    char *record;
    size_t record_len;
    flb_ctx_t *ctx;

    store_dir = create_test_store_directory("/flb-gcs-test-unify-size-XXXXXX");
    TEST_CHECK(store_dir != NULL);
    if (!store_dir) {
        return;
    }

    record = build_large_record(600 * 1024, &record_len);
    TEST_CHECK(record != NULL);
    if (!record) {
        flb_free(store_dir);
        return;
    }

    setenv("FLB_GCS_PLUGIN_UNDER_TEST", "true", 1);
    unsetenv("TEST_GCS_UploadObject_CALL_COUNT");

    ctx = flb_create();
    for (i = 0; i < 2; i++) {
        snprintf(tag, sizeof(tag), "test.%d", i);
        in_ffd[i] = flb_input(ctx, (char *) "lib", NULL);
        TEST_CHECK(in_ffd[i] >= 0);
        flb_input_set(ctx, in_ffd[i], "tag", tag, NULL);
    }

    out_ffd = flb_output(ctx, (char *) "gcs", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "*", NULL);
    flb_output_set(ctx, out_ffd, "bucket", "fluent", NULL);
    flb_output_set(ctx, out_ffd, "google_service_credentials", SERVICE_CREDENTIALS, NULL);
    flb_output_set(ctx, out_ffd, "store_dir", store_dir, NULL);
    flb_output_set(ctx, out_ffd, "upload_timeout", "10m", NULL);
    flb_output_set(ctx, out_ffd, "total_file_size", "1M", NULL);
    flb_output_set(ctx, out_ffd, "unify_tag", "true", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);
    if (ret != 0) {
        flb_destroy(ctx);
        unsetenv("FLB_GCS_PLUGIN_UNDER_TEST");
        flb_free(record);
        flb_free(store_dir);
        return;
    }

    /* records from different tags land in the same unified buffer file */
    flb_lib_push(ctx, in_ffd[0], record, (int) record_len);
    sleep(2);
    flb_lib_push(ctx, in_ffd[1], record, (int) record_len);
    sleep(3);

    call_count_str = getenv("TEST_GCS_UploadObject_CALL_COUNT");
    call_count = call_count_str ? atoi(call_count_str) : 0;
    TEST_CHECK_(call_count == 1,
                "Expected 1 upload after the unified file reached "
                "total_file_size, got %d", call_count);

    flb_stop(ctx);
    flb_destroy(ctx);

    unsetenv("FLB_GCS_PLUGIN_UNDER_TEST");
    unsetenv("TEST_GCS_UploadObject_CALL_COUNT");
    unsetenv("TEST_GCS_LAST_URI");
    unsetenv("TEST_GCS_LAST_BODY_GZIP");
    flb_free(record);
    flb_free(store_dir);
}

/* total_file_size 0 disables the size trigger: only upload_timeout applies */
void flb_test_gcs_total_file_size_zero_disables_size_trigger(void)
{
    int ret;
    int in_ffd;
    int out_ffd;
    int call_count;
    char *call_count_str;
    char *store_dir;
    char *record;
    size_t record_len;
    flb_ctx_t *ctx;

    store_dir = create_test_store_directory("/flb-gcs-test-size-off-XXXXXX");
    TEST_CHECK(store_dir != NULL);
    if (!store_dir) {
        return;
    }

    record = build_large_record(600 * 1024, &record_len);
    TEST_CHECK(record != NULL);
    if (!record) {
        flb_free(store_dir);
        return;
    }

    setenv("FLB_GCS_PLUGIN_UNDER_TEST", "true", 1);
    unsetenv("TEST_GCS_UploadObject_CALL_COUNT");

    ctx = flb_create();
    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "gcs", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "*", NULL);
    flb_output_set(ctx, out_ffd, "bucket", "fluent", NULL);
    flb_output_set(ctx, out_ffd, "google_service_credentials", SERVICE_CREDENTIALS, NULL);
    flb_output_set(ctx, out_ffd, "store_dir", store_dir, NULL);
    flb_output_set(ctx, out_ffd, "upload_timeout", "10m", NULL);
    flb_output_set(ctx, out_ffd, "total_file_size", "0", NULL);

    ret = flb_start(ctx);
    TEST_CHECK_(ret == 0, "Expected total_file_size=0 to be accepted");
    if (ret != 0) {
        flb_destroy(ctx);
        unsetenv("FLB_GCS_PLUGIN_UNDER_TEST");
        flb_free(record);
        flb_free(store_dir);
        return;
    }

    /* more than 1M of buffered data must NOT trigger an upload */
    flb_lib_push(ctx, in_ffd, record, (int) record_len);
    sleep(2);
    flb_lib_push(ctx, in_ffd, record, (int) record_len);
    sleep(3);

    call_count_str = getenv("TEST_GCS_UploadObject_CALL_COUNT");
    call_count = call_count_str ? atoi(call_count_str) : 0;
    TEST_CHECK_(call_count == 0,
                "Expected no size-triggered upload with total_file_size=0, "
                "got %d", call_count);

    flb_stop(ctx);
    flb_destroy(ctx);

    unsetenv("FLB_GCS_PLUGIN_UNDER_TEST");
    unsetenv("TEST_GCS_UploadObject_CALL_COUNT");
    unsetenv("TEST_GCS_LAST_URI");
    unsetenv("TEST_GCS_LAST_BODY_GZIP");
    flb_free(record);
    flb_free(store_dir);
}

/*
 * Recursively append the content of every regular file under 'path' to
 * '*buf'. Used to inspect what the plugin buffered in store_dir.
 */
static void read_store_dir_files(const char *path, char **buf, size_t *len)
{
    DIR *dir;
    struct dirent *entry;
    struct stat st;
    char child[PATH_MAX];
    FILE *fp;
    char *tmp;
    size_t n;

    dir = opendir(path);
    if (!dir) {
        return;
    }

    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        snprintf(child, sizeof(child), "%s/%s", path, entry->d_name);
        if (stat(child, &st) != 0) {
            continue;
        }

        if (S_ISDIR(st.st_mode)) {
            read_store_dir_files(child, buf, len);
            continue;
        }
        if (!S_ISREG(st.st_mode)) {
            continue;
        }

        fp = fopen(child, "rb");
        if (!fp) {
            continue;
        }

        tmp = flb_realloc(*buf, *len + (size_t) st.st_size + 1);
        if (!tmp) {
            fclose(fp);
            break;
        }
        *buf = tmp;
        n = fread(*buf + *len, 1, (size_t) st.st_size, fp);
        *len += n;
        (*buf)[*len] = '\0';
        fclose(fp);
    }

    closedir(dir);
}

/* Byte search: buffered files carry a binary header before the JSON lines */
static int buffer_contains(const char *buf, size_t len, const char *needle)
{
    size_t i;
    size_t needle_len;

    needle_len = strlen(needle);
    if (!buf || needle_len == 0 || needle_len > len) {
        return FLB_FALSE;
    }

    for (i = 0; i + needle_len <= len; i++) {
        if (memcmp(buf + i, needle, needle_len) == 0) {
            return FLB_TRUE;
        }
    }

    return FLB_FALSE;
}

#define DATE_TEST_WAIT_STEP_MS   100
#define DATE_TEST_WAIT_STEPS     100
#define DATE_TEST_PREVIEW_SIZE   512

struct gcs_date_test {
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    int started;
    char *store_dir;
    char *data;
    size_t data_len;
};

/*
 * Read the files under store_dir until 'needle' shows up or ~10 seconds
 * pass. The last content read is kept in t->data either way, so the caller
 * can run more assertions (or print it) on the same buffer.
 */
static int date_test_wait_for(struct gcs_date_test *t, const char *needle)
{
    int i;

    for (i = 0; i < DATE_TEST_WAIT_STEPS; i++) {
        if (t->data) {
            flb_free(t->data);
            t->data = NULL;
        }
        t->data_len = 0;

        read_store_dir_files(t->store_dir, &t->data, &t->data_len);
        if (buffer_contains(t->data, t->data_len, needle)) {
            return FLB_TRUE;
        }

        flb_time_msleep(DATE_TEST_WAIT_STEP_MS);
    }

    return FLB_FALSE;
}

/* Printable copy of the buffered content for failure messages */
static void date_test_preview(struct gcs_date_test *t, char *out, size_t size)
{
    size_t i;
    size_t len;

    len = t->data_len < size - 1 ? t->data_len : size - 1;
    for (i = 0; i < len; i++) {
        out[i] = isprint((unsigned char) t->data[i]) ? t->data[i] : '.';
    }
    out[len] = '\0';
}

static void date_test_expect(struct gcs_date_test *t, const char *needle, int present)
{
    char preview[DATE_TEST_PREVIEW_SIZE];
    int found;

    found = buffer_contains(t->data, t->data_len, needle);
    date_test_preview(t, preview, sizeof(preview));

    if (present) {
        TEST_CHECK_(found == FLB_TRUE,
                    "expected '%s' in the buffered object, got: %s", needle, preview);
    }
    else {
        TEST_CHECK_(found == FLB_FALSE,
                    "expected no '%s' in the buffered object, got: %s", needle, preview);
    }
}

/*
 * Create a lib -> gcs pipeline that only buffers into its own store_dir
 * (long upload_timeout, large total_file_size). 'key'/'value' is an optional
 * extra output property. The pipeline is not started.
 */
static int date_test_create(struct gcs_date_test *t, const char *key, const char *value)
{
    memset(t, 0, sizeof(struct gcs_date_test));

    t->store_dir = create_test_store_directory("/flb-gcs-test-date-XXXXXX");
    TEST_CHECK(t->store_dir != NULL);
    if (!t->store_dir) {
        return -1;
    }

    setenv("FLB_GCS_PLUGIN_UNDER_TEST", "true", 1);

    t->ctx = flb_create();

    t->in_ffd = flb_input(t->ctx, (char *) "lib", NULL);
    TEST_CHECK(t->in_ffd >= 0);
    flb_input_set(t->ctx, t->in_ffd, "tag", "test", NULL);

    t->out_ffd = flb_output(t->ctx, (char *) "gcs", NULL);
    TEST_CHECK(t->out_ffd >= 0);
    flb_output_set(t->ctx, t->out_ffd, "match", "*", NULL);
    flb_output_set(t->ctx, t->out_ffd, "bucket", "fluent", NULL);
    flb_output_set(t->ctx, t->out_ffd, "google_service_credentials", SERVICE_CREDENTIALS, NULL);
    flb_output_set(t->ctx, t->out_ffd, "upload_timeout", "1h", NULL);
    flb_output_set(t->ctx, t->out_ffd, "total_file_size", "100M", NULL);
    flb_output_set(t->ctx, t->out_ffd, "store_dir", t->store_dir, NULL);
    flb_output_set(t->ctx, t->out_ffd, "compression", "none", NULL);
    if (key) {
        flb_output_set(t->ctx, t->out_ffd, key, value, NULL);
    }

    return 0;
}

static void date_test_destroy(struct gcs_date_test *t)
{
    if (t->data) {
        flb_free(t->data);
    }

    if (t->ctx) {
        if (t->started) {
            flb_stop(t->ctx);
        }
        flb_destroy(t->ctx);
    }

    unsetenv("FLB_GCS_PLUGIN_UNDER_TEST");
    unsetenv("TEST_GCS_UploadObject_CALL_COUNT");
    unsetenv("TEST_GCS_LAST_URI");
    unsetenv("TEST_GCS_LAST_BODY_GZIP");
    unsetenv("TEST_GCS_LAST_BODY_PARQUET");
    unsetenv("TEST_GCS_LAST_CONTENT_TYPE");

    if (t->store_dir) {
        flb_free(t->store_dir);
    }
}

/*
 * Start a pipeline with the optional 'key'/'value' property, push 'record'
 * (and 'record2' when set) and wait until 'wait_needle' is buffered. Returns
 * 0 with the buffered content in t->data; on failure everything is released.
 */
static int date_test_run(struct gcs_date_test *t, const char *key, const char *value,
                         const char *record, const char *record2, const char *wait_needle)
{
    int ret;
    char preview[DATE_TEST_PREVIEW_SIZE];

    ret = date_test_create(t, key, value);
    if (ret != 0) {
        return -1;
    }

    ret = flb_start(t->ctx);
    TEST_CHECK_(ret == 0, "expected flb_start to succeed with %s=%s, got %d",
                key ? key : "(defaults)", value ? value : "", ret);
    if (ret != 0) {
        date_test_destroy(t);
        return -1;
    }
    t->started = FLB_TRUE;

    flb_lib_push(t->ctx, t->in_ffd, (char *) record, (int) strlen(record));
    if (record2) {
        flb_lib_push(t->ctx, t->in_ffd, (char *) record2, (int) strlen(record2));
    }

    /* Inspect the buffered object before shutdown uploads or removes it */
    ret = date_test_wait_for(t, wait_needle);
    date_test_preview(t, preview, sizeof(preview));
    TEST_CHECK_(ret == FLB_TRUE,
                "expected '%s' in the buffered object within 10 seconds, got: %s",
                wait_needle, preview);
    if (ret != FLB_TRUE) {
        date_test_destroy(t);
        return -1;
    }

    return 0;
}

#define DATE_TEST_RECORD        "[1700000000.5, {\"message\":\"hello\"}]"
#define DATE_TEST_RECORD_NEXT   "[1700000001.25, {\"message\":\"world\"}]"
/* Wait needles end with '}' so the poll returns only once the whole object is buffered */
#define DATE_TEST_BODY          "\"message\":\"hello\"}"
#define DATE_TEST_ISO8601       "2023-11-14T22:13:20.500000Z"

void flb_test_gcs_record_includes_event_timestamp(void)
{
    int ret;
    struct gcs_date_test t;

    ret = date_test_run(&t, NULL, NULL, DATE_TEST_RECORD, DATE_TEST_RECORD_NEXT,
                        "\"message\":\"world\"}");
    if (ret != 0) {
        return;
    }

    /* Each record carries its own event time, with the date key first */
    date_test_expect(&t, "{\"date\":\"" DATE_TEST_ISO8601 "\",\"message\":\"hello\"}",
                     FLB_TRUE);
    date_test_expect(&t, "{\"date\":\"2023-11-14T22:13:21.250000Z\",\"message\":\"world\"}",
                     FLB_TRUE);

    date_test_destroy(&t);
}

void flb_test_gcs_json_date_key_custom(void)
{
    int ret;
    struct gcs_date_test t;

    ret = date_test_run(&t, "json_date_key", "timestamp", DATE_TEST_RECORD, NULL,
                        DATE_TEST_BODY);
    if (ret != 0) {
        return;
    }

    date_test_expect(&t, "{\"timestamp\":\"" DATE_TEST_ISO8601 "\",\"message\":\"hello\"}",
                     FLB_TRUE);
    date_test_expect(&t, "\"date\"", FLB_FALSE);

    date_test_destroy(&t);
}

void flb_test_gcs_json_date_key_disabled(void)
{
    int ret;
    size_t i;
    struct gcs_date_test t;
    const char *values[] = {"false", "off", "no"};

    for (i = 0; i < sizeof(values) / sizeof(values[0]); i++) {
        TEST_CASE(values[i]);

        ret = date_test_run(&t, "json_date_key", values[i], DATE_TEST_RECORD, NULL,
                            DATE_TEST_BODY);
        if (ret != 0) {
            continue;
        }

        date_test_expect(&t, "{\"message\":\"hello\"}", FLB_TRUE);
        date_test_expect(&t, "\"date\"", FLB_FALSE);
        date_test_expect(&t, "2023-11-14", FLB_FALSE);

        date_test_destroy(&t);
    }
}

void flb_test_gcs_json_date_format_variants(void)
{
    int ret;
    size_t i;
    struct gcs_date_test t;
    struct {
        const char *format;
        const char *expected;
    } cases[] = {
        {"iso8601",            "\"date\":\"" DATE_TEST_ISO8601 "\""},
        {"ISO8601",            "\"date\":\"" DATE_TEST_ISO8601 "\""},
        {"double",             "\"date\":1700000000.5,"},
        {"epoch",              "\"date\":1700000000,"},
        {"epoch_ms",           "\"date\":1700000000500,"},
        {"epoch_millis",       "\"date\":1700000000500,"},
        {"java_sql_timestamp", "\"date\":\"2023-11-14 22:13:20.500000\""}
    };

    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        TEST_CASE(cases[i].format);

        ret = date_test_run(&t, "json_date_format", cases[i].format, DATE_TEST_RECORD,
                            NULL, DATE_TEST_BODY);
        if (ret != 0) {
            continue;
        }

        date_test_expect(&t, cases[i].expected, FLB_TRUE);

        date_test_destroy(&t);
    }
}

void flb_test_gcs_timestamp_zero_is_emitted(void)
{
    int ret;
    time_t now;
    struct tm tm_now;
    char current_year[32];
    struct gcs_date_test t;

    ret = date_test_run(&t, NULL, NULL, "[0, {\"message\":\"hello\"}]", NULL,
                        DATE_TEST_BODY);
    if (ret != 0) {
        return;
    }

    /* A zero event time is a valid timestamp, not a request for "now" */
    now = time(NULL);
    gmtime_r(&now, &tm_now);
    snprintf(current_year, sizeof(current_year), "\"date\":\"%04d-", tm_now.tm_year + 1900);

    date_test_expect(&t, "\"date\":\"1970-01-01T00:00:00.000000Z\"", FLB_TRUE);
    date_test_expect(&t, current_year, FLB_FALSE);

    date_test_destroy(&t);
}

#define DATE_TEST_RECORD_OWN_DATE \
    "[1700000000.5, {\"date\":\"mine\",\"message\":\"hello\"}]"

void flb_test_gcs_existing_date_field_overrides_event_time(void)
{
    int ret;
    struct gcs_date_test t;

    /*
     * The record's own field wins over the event time: the JSON serializer
     * keeps the last occurrence of a duplicated key.
     */
    TEST_CASE("same key");
    ret = date_test_run(&t, NULL, NULL, DATE_TEST_RECORD_OWN_DATE, NULL, DATE_TEST_BODY);
    if (ret == 0) {
        date_test_expect(&t, "{\"date\":\"mine\",\"message\":\"hello\"}", FLB_TRUE);
        date_test_expect(&t, "2023-11-14", FLB_FALSE);

        date_test_destroy(&t);
    }

    /* Set json_date_key to another name to keep both */
    TEST_CASE("other key");
    ret = date_test_run(&t, "json_date_key", "event_time", DATE_TEST_RECORD_OWN_DATE, NULL,
                        DATE_TEST_BODY);
    if (ret == 0) {
        date_test_expect(&t,
                         "{\"event_time\":\"" DATE_TEST_ISO8601 "\",\"date\":\"mine\","
                         "\"message\":\"hello\"}",
                         FLB_TRUE);

        date_test_destroy(&t);
    }
}

void flb_test_gcs_rejects_invalid_json_date_format(void)
{
    int ret;
    struct gcs_date_test t;

    ret = date_test_create(&t, "json_date_format", "bogus");
    if (ret != 0) {
        return;
    }

    ret = flb_start(t.ctx);
    TEST_CHECK_(ret != 0, "expected flb_start to fail with json_date_format=bogus, got %d",
                ret);
    if (ret == 0) {
        t.started = FLB_TRUE;
    }

    date_test_destroy(&t);
}

void flb_test_gcs_empty_json_date_format_uses_iso8601(void)
{
    int ret;
    struct gcs_date_test t;

    ret = date_test_run(&t, "json_date_format", "", DATE_TEST_RECORD, NULL,
                        DATE_TEST_BODY);
    if (ret != 0) {
        return;
    }

    date_test_expect(&t, "\"date\":\"" DATE_TEST_ISO8601 "\"", FLB_TRUE);

    date_test_destroy(&t);
}

TEST_LIST = {
    {"jwt_signing", flb_test_gcs_jwt_signing},
    {"net_settings_applied_to_upstream", flb_test_gcs_net_settings_applied_to_upstream},
    {"timer_upload_without_ordering_uses_sync_upstream",
     flb_test_gcs_timer_upload_without_ordering_uses_sync_upstream},
    {"total_file_size_triggers_upload", flb_test_gcs_total_file_size_triggers_upload},
    {"total_file_size_exact_first_payload", flb_test_gcs_total_file_size_exact_first_payload},
    {"total_file_size_oversized_first_payload", flb_test_gcs_total_file_size_oversized_first_payload},
    {"total_file_size_exact_append", flb_test_gcs_total_file_size_exact_append},
    {"total_file_size_ordered_read_failure", flb_test_gcs_total_file_size_ordered_read_failure},
    {"total_file_size_preserves_ordering", flb_test_gcs_total_file_size_preserves_ordering},
    {"total_file_size_without_ordering", flb_test_gcs_total_file_size_without_ordering},
    {"total_file_size_failed_upload_stays_sealed",
     flb_test_gcs_total_file_size_failed_upload_stays_sealed},
    {"total_file_size_zero_disables_size_trigger",
     flb_test_gcs_total_file_size_zero_disables_size_trigger},
    {"rejects_total_file_size_below_minimum",
     flb_test_gcs_rejects_total_file_size_below_minimum},
    {"workers_upload_all_tags", flb_test_gcs_workers_upload_all_tags},
    {"recovers_backlog_on_restart", flb_test_gcs_recovers_backlog_on_restart},
    {"recovered_upload_failure_stays_sealed", flb_test_gcs_recovered_upload_failure_stays_sealed},
    {"total_file_size_with_unify_tag", flb_test_gcs_total_file_size_with_unify_tag},
    {"uri_encode_object_name", flb_test_gcs_uri_encode_object_name},
    {"upload_success", flb_test_gcs_upload_success},
#ifdef FLB_HAVE_ARROW_PARQUET
    {"upload_parquet_zstd", flb_test_gcs_upload_parquet_zstd},
    {"upload_parquet_snappy", flb_test_gcs_upload_parquet_snappy},
#else
    {"rejects_parquet_without_support", flb_test_gcs_rejects_parquet_without_support},
#endif
    {"identity_federation_upload", flb_test_gcs_identity_federation_upload},
    {"rejects_incomplete_federation", flb_test_gcs_rejects_incomplete_federation},
    {"rejects_conflicting_credentials", flb_test_gcs_rejects_conflicting_credentials},
    {"rejects_invalid_configuration", flb_test_gcs_rejects_invalid_configuration},
    {"rejects_invalid_compression", flb_test_gcs_rejects_invalid_compression},
    {"accepts_extra_credential_fields", flb_test_gcs_accepts_extra_credential_fields},
    {"application_default_credentials_env", flb_test_gcs_application_default_credentials_env},
    {"metadata_server_authentication", flb_test_gcs_metadata_server_authentication},
    {"rejects_invalid_metadata_response", flb_test_gcs_rejects_invalid_metadata_response},
    {"upload_error", flb_test_gcs_upload_error},
    {"shutdown_preserves_pending_upload", flb_test_gcs_shutdown_preserves_pending_upload},
    {"unify_tag_buffers_multiple_tags", flb_test_gcs_unify_tag_buffers_multiple_tags},
    {"unify_tag_disabled_by_default", flb_test_gcs_unify_tag_disabled_by_default},
    {"record_includes_event_timestamp", flb_test_gcs_record_includes_event_timestamp},
    {"json_date_key_custom", flb_test_gcs_json_date_key_custom},
    {"json_date_key_disabled", flb_test_gcs_json_date_key_disabled},
    {"json_date_format_variants", flb_test_gcs_json_date_format_variants},
    {"timestamp_zero_is_emitted", flb_test_gcs_timestamp_zero_is_emitted},
    {"existing_date_field_overrides_event_time",
     flb_test_gcs_existing_date_field_overrides_event_time},
    {"rejects_invalid_json_date_format", flb_test_gcs_rejects_invalid_json_date_format},
    {"empty_json_date_format_uses_iso8601",
     flb_test_gcs_empty_json_date_format_uses_iso8601},
    {NULL, NULL}
};
