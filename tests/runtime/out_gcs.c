/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
#include <fluent-bit.h>
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

TEST_LIST = {
    {"jwt_signing", flb_test_gcs_jwt_signing},
    {"uri_encode_object_name", flb_test_gcs_uri_encode_object_name},
    {"upload_success", flb_test_gcs_upload_success},
#ifdef FLB_HAVE_ARROW_PARQUET
    {"upload_parquet_zstd", flb_test_gcs_upload_parquet_zstd},
    {"upload_parquet_snappy", flb_test_gcs_upload_parquet_snappy},
#else
    {"rejects_parquet_without_support", flb_test_gcs_rejects_parquet_without_support},
#endif
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
    {NULL, NULL}
};
