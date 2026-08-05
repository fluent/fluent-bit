/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
#include <fluent-bit.h>
#include <fluent-bit/flb_time.h>
#include "flb_tests_runtime.h"
#include "../include/flb_tests_tmpdir.h"
#include <errno.h>

#ifdef FLB_SYSTEM_WINDOWS
#include <windows.h>
#else
#include <dirent.h>
#include <sys/stat.h>
#endif

/* Test data */
#include "data/td/json_td.h" /* JSON_TD */

#define S3_TEST_UPLOAD_TIMEOUT  "1s"
#define S3_TEST_WAIT_STEP_MS      10
#define S3_TEST_WAIT_TIMEOUT_MS 5000

/* not a real error code, but tests that the code can respond to any error */
#define ERROR_ACCESS_DENIED "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
                            <Error>\
                            <Code>AccessDenied</Code>\
                            <Message>Access Denied</Message>\
                            <RequestId>656c76696e6727732072657175657374</RequestId>\
                            <HostId>Uuag1LuByRx9e6j5Onimru9pO4ZVKnJ2Qz7/C1NPcfTWAtRPfTaOFg==</HostId>\
                            </Error>"

static int count_files_recursive(const char *path)
{
#ifdef FLB_SYSTEM_WINDOWS
    WIN32_FIND_DATAA data;
    HANDLE handle;
    char pattern[2048];
    char child[2048];
    int total = 0;

    snprintf(pattern, sizeof(pattern), "%s\\*", path);
    handle = FindFirstFileA(pattern, &data);
    if (handle == INVALID_HANDLE_VALUE) {
        return 0;
    }

    do {
        if (strcmp(data.cFileName, ".") == 0 || strcmp(data.cFileName, "..") == 0) {
            continue;
        }

        snprintf(child, sizeof(child), "%s\\%s", path, data.cFileName);
        if (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            total += count_files_recursive(child);
        }
        else {
            total++;
        }
    } while (FindNextFileA(handle, &data) != 0);

    FindClose(handle);
    return total;
#else
    DIR *dir;
    struct dirent *entry;
    struct stat st;
    char child[2048];
    int total = 0;

    dir = opendir(path);
    if (dir == NULL) {
        return 0;
    }

    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        snprintf(child, sizeof(child), "%s/%s", path, entry->d_name);
        if (stat(child, &st) != 0) {
            continue;
        }

        if (S_ISDIR(st.st_mode)) {
            total += count_files_recursive(child);
        }
        else if (S_ISREG(st.st_mode)) {
            total++;
        }
    }

    closedir(dir);
    return total;
#endif
}

static int get_s3_call_count(const char *api)
{
    char name[64];
    char *value;

    snprintf(name, sizeof(name), "TEST_%s_CALL_COUNT", api);
    value = getenv(name);

    return value ? atoi(value) : 0;
}

static void wait_for_s3_call_count(const char *api, int expected)
{
    uint64_t elapsed_ms;
    struct flb_time start_time;
    struct flb_time end_time;
    struct flb_time diff_time;

    elapsed_ms = 0;
    flb_time_get(&start_time);

    while (get_s3_call_count(api) < expected &&
           elapsed_ms < S3_TEST_WAIT_TIMEOUT_MS) {
        flb_time_msleep(S3_TEST_WAIT_STEP_MS);
        flb_time_get(&end_time);
        flb_time_diff(&end_time, &start_time, &diff_time);
        elapsed_ms = flb_time_to_nanosec(&diff_time) / 1000000;
    }
}

static void wait_for_file_count(const char *path, int expected)
{
    uint64_t elapsed_ms;
    struct flb_time start_time;
    struct flb_time end_time;
    struct flb_time diff_time;

    elapsed_ms = 0;
    flb_time_get(&start_time);

    while (count_files_recursive(path) < expected &&
           elapsed_ms < S3_TEST_WAIT_TIMEOUT_MS) {
        flb_time_msleep(S3_TEST_WAIT_STEP_MS);
        flb_time_get(&end_time);
        flb_time_diff(&end_time, &start_time, &diff_time);
        elapsed_ms = flb_time_to_nanosec(&diff_time) / 1000000;
    }
}

static int ensure_test_directory(const char *path)
{
#ifdef FLB_SYSTEM_WINDOWS
    WIN32_FILE_ATTRIBUTE_DATA attributes;

    if (flb_utils_mkdir(path, 0777) == 0) {
        return 0;
    }

    if (GetFileAttributesExA(path, GetFileExInfoStandard, &attributes) != 0 &&
        (attributes.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) {
        return 0;
    }

    return -1;
#else
    struct stat st;

    if (flb_utils_mkdir(path, 0777) == 0) {
        return 0;
    }

    if (errno == EEXIST && stat(path, &st) == 0 && S_ISDIR(st.st_mode)) {
        return 0;
    }

    return -1;
#endif
}

static char *create_test_store_directory(const char *postfix)
{
    char *store_dir;

    store_dir = flb_test_tmpdir_cat(postfix);
    if (store_dir == NULL) {
        return NULL;
    }

    if (mkdtemp(store_dir) == NULL) {
        flb_free(store_dir);
        return NULL;
    }

    return store_dir;
}

void flb_test_s3_multipart_success(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    char *call_count_str;
    int call_count;
    char *store_dir;

    store_dir = create_test_store_directory("/flb-s3-test-multipart-XXXXXX");
    TEST_CHECK(store_dir != NULL);
    if (store_dir == NULL) {
        return;
    }

    /* mocks calls- signals that we are in test mode */
    setenv("FLB_S3_PLUGIN_UNDER_TEST", "true", 1);

    ctx = flb_create();

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx,in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "s3", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd,"match", "*", NULL);
    flb_output_set(ctx, out_ffd,"region", "us-west-2", NULL);
    flb_output_set(ctx, out_ffd,"bucket", "fluent", NULL);
    flb_output_set(ctx, out_ffd,"upload_timeout", S3_TEST_UPLOAD_TIMEOUT, NULL);
    flb_output_set(ctx, out_ffd,"store_dir", store_dir, NULL);
    flb_output_set(ctx, out_ffd,"s3_object_tag", "key1", "value1", NULL);
    flb_output_set(ctx, out_ffd,"s3_object_tag", "key2", "value2", NULL);
    flb_output_set(ctx, out_ffd,"Retry_Limit", "1", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    flb_lib_push(ctx, in_ffd, (char *) JSON_TD , (int) sizeof(JSON_TD) - 1);

    wait_for_s3_call_count("CompleteMultipartUpload", 1);

    call_count_str = getenv("TEST_CompleteMultipartUpload_CALL_COUNT");
    call_count = call_count_str ? atoi(call_count_str) : 0;
    TEST_CHECK_(call_count == 1,
                "Expected 1 CompleteMultipartUpload call, got %d", call_count);

    flb_stop(ctx);
    flb_destroy(ctx);
    unsetenv("FLB_S3_PLUGIN_UNDER_TEST");
    unsetenv("TEST_CreateMultipartUpload_CALL_COUNT");
    unsetenv("TEST_UploadPart_CALL_COUNT");
    unsetenv("TEST_CompleteMultipartUpload_CALL_COUNT");
    unsetenv("TEST_PutObject_CALL_COUNT");
    flb_free(store_dir);
}

void flb_test_s3_putobject_success(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    char *call_count_str;
    int call_count;

    /* mocks calls- signals that we are in test mode */
    setenv("FLB_S3_PLUGIN_UNDER_TEST", "true", 1);

    ctx = flb_create();

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx,in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "s3", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd,"match", "*", NULL);
    flb_output_set(ctx, out_ffd,"region", "us-west-2", NULL);
    flb_output_set(ctx, out_ffd,"bucket", "fluent", NULL);
    flb_output_set(ctx, out_ffd,"use_put_object", "true", NULL);
    flb_output_set(ctx, out_ffd,"total_file_size", "5M", NULL);
    flb_output_set(ctx, out_ffd,"upload_timeout", S3_TEST_UPLOAD_TIMEOUT, NULL);
    flb_output_set(ctx, out_ffd,"Retry_Limit", "1", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    flb_lib_push(ctx, in_ffd, (char *) JSON_TD , (int) sizeof(JSON_TD) - 1);


    wait_for_s3_call_count("PutObject", 1);

    call_count_str = getenv("TEST_PutObject_CALL_COUNT");
    call_count = call_count_str ? atoi(call_count_str) : 0;
    TEST_CHECK_(call_count == 1,
                "Expected 1 PutObject call, got %d", call_count);

    flb_stop(ctx);
    flb_destroy(ctx);
    unsetenv("FLB_S3_PLUGIN_UNDER_TEST");
    unsetenv("TEST_PutObject_CALL_COUNT");
}

void flb_test_s3_putobject_error(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    char *call_count_str;
    int call_count;
    char *store_dir;

    store_dir = create_test_store_directory("/flb-s3-test-putobj-XXXXXX");
    TEST_CHECK(store_dir != NULL);
    if (store_dir == NULL) {
        return;
    }

    /* mocks calls- signals that we are in test mode */
    setenv("FLB_S3_PLUGIN_UNDER_TEST", "true", 1);
    setenv("TEST_PUT_OBJECT_ERROR", ERROR_ACCESS_DENIED, 1);

    ctx = flb_create();

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx,in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "s3", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd,"match", "*", NULL);
    flb_output_set(ctx, out_ffd,"region", "us-west-2", NULL);
    flb_output_set(ctx, out_ffd,"bucket", "fluent", NULL);
    flb_output_set(ctx, out_ffd,"use_put_object", "true", NULL);
    flb_output_set(ctx, out_ffd,"total_file_size", "5M", NULL);
    flb_output_set(ctx, out_ffd,"upload_timeout", S3_TEST_UPLOAD_TIMEOUT, NULL);
    flb_output_set(ctx, out_ffd,"store_dir", store_dir, NULL);
    flb_output_set(ctx, out_ffd,"Retry_Limit", "1", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    flb_lib_push(ctx, in_ffd, (char *) JSON_TD , (int) sizeof(JSON_TD) - 1);


    wait_for_s3_call_count("PutObject", 1);

    call_count_str = getenv("TEST_PutObject_CALL_COUNT");
    call_count = call_count_str ? atoi(call_count_str) : 0;
    TEST_CHECK_(call_count >= 1,
                "Expected >= 1 PutObject calls, got %d", call_count);

    flb_stop(ctx);
    flb_destroy(ctx);
    unsetenv("FLB_S3_PLUGIN_UNDER_TEST");
    unsetenv("TEST_PUT_OBJECT_ERROR");
    unsetenv("TEST_PutObject_CALL_COUNT");
    flb_free(store_dir);

}

void flb_test_s3_create_upload_error(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    char *call_count_str;
    int call_count;
    char *store_dir;

    store_dir = create_test_store_directory("/flb-s3-test-XXXXXX");
    TEST_CHECK(store_dir != NULL);
    if (store_dir == NULL) {
        return;
    }

    /* mocks calls- signals that we are in test mode */
    setenv("FLB_S3_PLUGIN_UNDER_TEST", "true", 1);
    setenv("TEST_CREATE_MULTIPART_UPLOAD_ERROR", ERROR_ACCESS_DENIED, 1);

    ctx = flb_create();

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx,in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "s3", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd,"match", "*", NULL);
    flb_output_set(ctx, out_ffd,"region", "us-west-2", NULL);
    flb_output_set(ctx, out_ffd,"bucket", "fluent", NULL);
    flb_output_set(ctx, out_ffd,"upload_timeout", S3_TEST_UPLOAD_TIMEOUT, NULL);
    flb_output_set(ctx, out_ffd,"store_dir", store_dir, NULL);
    flb_output_set(ctx, out_ffd,"Retry_Limit", "1", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    flb_lib_push(ctx, in_ffd, (char *) JSON_TD , (int) sizeof(JSON_TD) - 1);

    wait_for_s3_call_count("CreateMultipartUpload", 1);

    call_count_str = getenv("TEST_CreateMultipartUpload_CALL_COUNT");
    call_count = call_count_str ? atoi(call_count_str) : 0;
    TEST_CHECK_(call_count >= 1,
                "Expected >= 1 CreateMultipartUpload calls, got %d", call_count);

    call_count_str = getenv("TEST_UploadPart_CALL_COUNT");
    call_count = call_count_str ? atoi(call_count_str) : 0;
    TEST_CHECK_(call_count == 0,
                "Expected 0 UploadPart calls, got %d", call_count);

    flb_stop(ctx);
    flb_destroy(ctx);
    unsetenv("FLB_S3_PLUGIN_UNDER_TEST");
    unsetenv("TEST_CREATE_MULTIPART_UPLOAD_ERROR");
    unsetenv("TEST_CreateMultipartUpload_CALL_COUNT");
    unsetenv("TEST_UploadPart_CALL_COUNT");
    unsetenv("TEST_CompleteMultipartUpload_CALL_COUNT");
    unsetenv("TEST_PutObject_CALL_COUNT");
    flb_free(store_dir);
}

void flb_test_s3_upload_part_error(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    char *call_count_str;
    int call_count;
    char *store_dir;

    store_dir = create_test_store_directory("/flb-s3-test-part-err-XXXXXX");
    TEST_CHECK(store_dir != NULL);
    if (store_dir == NULL) {
        return;
    }

    /* mocks calls- signals that we are in test mode */
    setenv("FLB_S3_PLUGIN_UNDER_TEST", "true", 1);
    setenv("TEST_UPLOAD_PART_ERROR", ERROR_ACCESS_DENIED, 1);

    ctx = flb_create();

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx,in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "s3", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd,"match", "*", NULL);
    flb_output_set(ctx, out_ffd,"region", "us-west-2", NULL);
    flb_output_set(ctx, out_ffd,"bucket", "fluent", NULL);
    flb_output_set(ctx, out_ffd,"upload_timeout", S3_TEST_UPLOAD_TIMEOUT, NULL);
    flb_output_set(ctx, out_ffd,"store_dir", store_dir, NULL);
    flb_output_set(ctx, out_ffd,"Retry_Limit", "1", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    flb_lib_push(ctx, in_ffd, (char *) JSON_TD , (int) sizeof(JSON_TD) - 1);

    wait_for_s3_call_count("UploadPart", 1);

    call_count_str = getenv("TEST_UploadPart_CALL_COUNT");
    call_count = call_count_str ? atoi(call_count_str) : 0;
    TEST_CHECK_(call_count >= 1,
                "Expected >= 1 UploadPart calls, got %d", call_count);

    call_count_str = getenv("TEST_CompleteMultipartUpload_CALL_COUNT");
    call_count = call_count_str ? atoi(call_count_str) : 0;
    TEST_CHECK_(call_count == 0,
                "Expected 0 CompleteMultipartUpload calls, got %d", call_count);

    flb_stop(ctx);
    flb_destroy(ctx);
    unsetenv("FLB_S3_PLUGIN_UNDER_TEST");
    unsetenv("TEST_UPLOAD_PART_ERROR");
    unsetenv("TEST_CreateMultipartUpload_CALL_COUNT");
    unsetenv("TEST_UploadPart_CALL_COUNT");
    unsetenv("TEST_CompleteMultipartUpload_CALL_COUNT");
    unsetenv("TEST_PutObject_CALL_COUNT");
    flb_free(store_dir);
}

void flb_test_s3_complete_upload_error(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    char *call_count_str;
    int call_count;
    char *store_dir;

    store_dir = create_test_store_directory("/flb-s3-test-upload-err-XXXXXX");
    TEST_CHECK(store_dir != NULL);
    if (store_dir == NULL) {
        return;
    }

    /* mocks calls- signals that we are in test mode */
    setenv("FLB_S3_PLUGIN_UNDER_TEST", "true", 1);
    setenv("TEST_COMPLETE_MULTIPART_UPLOAD_ERROR", ERROR_ACCESS_DENIED, 1);

    ctx = flb_create();

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx,in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "s3", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd,"match", "*", NULL);
    flb_output_set(ctx, out_ffd,"region", "us-west-2", NULL);
    flb_output_set(ctx, out_ffd,"bucket", "fluent", NULL);
    flb_output_set(ctx, out_ffd,"upload_timeout", S3_TEST_UPLOAD_TIMEOUT, NULL);
    flb_output_set(ctx, out_ffd,"store_dir", store_dir, NULL);
    flb_output_set(ctx, out_ffd,"s3_object_tag", "key", "value with spaces", NULL);
    flb_output_set(ctx, out_ffd,"Retry_Limit", "1", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    flb_lib_push(ctx, in_ffd, (char *) JSON_TD , (int) sizeof(JSON_TD) - 1);

    wait_for_s3_call_count("CompleteMultipartUpload", 2);

    call_count_str = getenv("TEST_CompleteMultipartUpload_CALL_COUNT");
    call_count = call_count_str ? atoi(call_count_str) : 0;
    TEST_CHECK_(call_count >= 2,
                "Expected >= 2 CompleteMultipartUpload calls (retried), got %d",
                call_count);

    flb_stop(ctx);
    flb_destroy(ctx);
    unsetenv("FLB_S3_PLUGIN_UNDER_TEST");
    unsetenv("TEST_COMPLETE_MULTIPART_UPLOAD_ERROR");
    unsetenv("TEST_CreateMultipartUpload_CALL_COUNT");
    unsetenv("TEST_UploadPart_CALL_COUNT");
    unsetenv("TEST_CompleteMultipartUpload_CALL_COUNT");
    unsetenv("TEST_PutObject_CALL_COUNT");
    flb_free(store_dir);
}

void flb_test_s3_compression_gzip(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    char *call_count_str;
    int call_count;

    /* mocks calls- signals that we are in test mode */
    setenv("FLB_S3_PLUGIN_UNDER_TEST", "true", 1);

    ctx = flb_create();

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx,in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "s3", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd,"match", "*", NULL);
    flb_output_set(ctx, out_ffd,"region", "us-west-2", NULL);
    flb_output_set(ctx, out_ffd,"bucket", "fluent", NULL);
    flb_output_set(ctx, out_ffd,"compression", "gzip", NULL);
    flb_output_set(ctx, out_ffd,"upload_timeout", S3_TEST_UPLOAD_TIMEOUT, NULL);
    flb_output_set(ctx, out_ffd,"Retry_Limit", "1", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    flb_lib_push(ctx, in_ffd, (char *) JSON_TD , (int) sizeof(JSON_TD) - 1);

    wait_for_s3_call_count("CompleteMultipartUpload", 1);

    call_count_str = getenv("TEST_CompleteMultipartUpload_CALL_COUNT");
    call_count = call_count_str ? atoi(call_count_str) : 0;
    TEST_CHECK_(call_count == 1,
                "Expected 1 CompleteMultipartUpload call, got %d", call_count);

    flb_stop(ctx);
    flb_destroy(ctx);
    unsetenv("FLB_S3_PLUGIN_UNDER_TEST");
    unsetenv("TEST_CreateMultipartUpload_CALL_COUNT");
    unsetenv("TEST_UploadPart_CALL_COUNT");
    unsetenv("TEST_CompleteMultipartUpload_CALL_COUNT");
    unsetenv("TEST_PutObject_CALL_COUNT");
}

void flb_test_s3_compression_gzip_putobject(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    char *call_count_str;
    int call_count;

    /* mocks calls- signals that we are in test mode */
    setenv("FLB_S3_PLUGIN_UNDER_TEST", "true", 1);

    ctx = flb_create();

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx,in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "s3", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd,"match", "*", NULL);
    flb_output_set(ctx, out_ffd,"region", "us-west-2", NULL);
    flb_output_set(ctx, out_ffd,"bucket", "fluent", NULL);
    flb_output_set(ctx, out_ffd,"compression", "gzip", NULL);
    flb_output_set(ctx, out_ffd,"use_put_object", "true", NULL);
    flb_output_set(ctx, out_ffd,"total_file_size", "5M", NULL);
    flb_output_set(ctx, out_ffd,"upload_timeout", S3_TEST_UPLOAD_TIMEOUT, NULL);
    flb_output_set(ctx, out_ffd,"Retry_Limit", "1", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    flb_lib_push(ctx, in_ffd, (char *) JSON_TD , (int) sizeof(JSON_TD) - 1);

    wait_for_s3_call_count("PutObject", 1);

    call_count_str = getenv("TEST_PutObject_CALL_COUNT");
    call_count = call_count_str ? atoi(call_count_str) : 0;
    TEST_CHECK_(call_count == 1,
                "Expected 1 PutObject call, got %d", call_count);

    flb_stop(ctx);
    flb_destroy(ctx);
    unsetenv("FLB_S3_PLUGIN_UNDER_TEST");
    unsetenv("TEST_PutObject_CALL_COUNT");
}

void flb_test_s3_compression_zstd(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    char *call_count_str;
    int call_count;

    /* mocks calls- signals that we are in test mode */
    setenv("FLB_S3_PLUGIN_UNDER_TEST", "true", 1);

    ctx = flb_create();

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx,in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "s3", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd,"match", "*", NULL);
    flb_output_set(ctx, out_ffd,"region", "us-west-2", NULL);
    flb_output_set(ctx, out_ffd,"bucket", "fluent", NULL);
    flb_output_set(ctx, out_ffd,"compression", "zstd", NULL);
    flb_output_set(ctx, out_ffd,"upload_timeout", S3_TEST_UPLOAD_TIMEOUT, NULL);
    flb_output_set(ctx, out_ffd,"Retry_Limit", "1", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    flb_lib_push(ctx, in_ffd, (char *) JSON_TD , (int) sizeof(JSON_TD) - 1);

    wait_for_s3_call_count("CompleteMultipartUpload", 1);

    call_count_str = getenv("TEST_CompleteMultipartUpload_CALL_COUNT");
    call_count = call_count_str ? atoi(call_count_str) : 0;
    TEST_CHECK_(call_count == 1,
                "Expected 1 CompleteMultipartUpload call, got %d", call_count);

    flb_stop(ctx);
    flb_destroy(ctx);
    unsetenv("FLB_S3_PLUGIN_UNDER_TEST");
    unsetenv("TEST_CreateMultipartUpload_CALL_COUNT");
    unsetenv("TEST_UploadPart_CALL_COUNT");
    unsetenv("TEST_CompleteMultipartUpload_CALL_COUNT");
    unsetenv("TEST_PutObject_CALL_COUNT");
}

void flb_test_s3_compression_zstd_putobject(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    char *call_count_str;
    int call_count;

    /* mocks calls- signals that we are in test mode */
    setenv("FLB_S3_PLUGIN_UNDER_TEST", "true", 1);

    ctx = flb_create();

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx,in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "s3", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd,"match", "*", NULL);
    flb_output_set(ctx, out_ffd,"region", "us-west-2", NULL);
    flb_output_set(ctx, out_ffd,"bucket", "fluent", NULL);
    flb_output_set(ctx, out_ffd,"compression", "zstd", NULL);
    flb_output_set(ctx, out_ffd,"use_put_object", "true", NULL);
    flb_output_set(ctx, out_ffd,"total_file_size", "5M", NULL);
    flb_output_set(ctx, out_ffd,"upload_timeout", S3_TEST_UPLOAD_TIMEOUT, NULL);
    flb_output_set(ctx, out_ffd,"Retry_Limit", "1", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    flb_lib_push(ctx, in_ffd, (char *) JSON_TD , (int) sizeof(JSON_TD) - 1);

    wait_for_s3_call_count("PutObject", 1);

    call_count_str = getenv("TEST_PutObject_CALL_COUNT");
    call_count = call_count_str ? atoi(call_count_str) : 0;
    TEST_CHECK_(call_count == 1,
                "Expected 1 PutObject call, got %d", call_count);

    flb_stop(ctx);
    flb_destroy(ctx);
    unsetenv("FLB_S3_PLUGIN_UNDER_TEST");
    unsetenv("TEST_PutObject_CALL_COUNT");
}

void flb_test_s3_compression_snappy(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    char *call_count_str;
    int call_count;

    /* mocks calls- signals that we are in test mode */
    setenv("FLB_S3_PLUGIN_UNDER_TEST", "true", 1);

    ctx = flb_create();

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx,in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "s3", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd,"match", "*", NULL);
    flb_output_set(ctx, out_ffd,"region", "us-west-2", NULL);
    flb_output_set(ctx, out_ffd,"bucket", "fluent", NULL);
    flb_output_set(ctx, out_ffd,"compression", "snappy", NULL);
    flb_output_set(ctx, out_ffd,"upload_timeout", S3_TEST_UPLOAD_TIMEOUT, NULL);
    flb_output_set(ctx, out_ffd,"Retry_Limit", "1", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    flb_lib_push(ctx, in_ffd, (char *) JSON_TD , (int) sizeof(JSON_TD) - 1);

    wait_for_s3_call_count("CompleteMultipartUpload", 1);

    call_count_str = getenv("TEST_CompleteMultipartUpload_CALL_COUNT");
    call_count = call_count_str ? atoi(call_count_str) : 0;
    TEST_CHECK_(call_count == 1,
                "Expected 1 CompleteMultipartUpload call, got %d", call_count);

    flb_stop(ctx);
    flb_destroy(ctx);
    unsetenv("FLB_S3_PLUGIN_UNDER_TEST");
    unsetenv("TEST_CreateMultipartUpload_CALL_COUNT");
    unsetenv("TEST_UploadPart_CALL_COUNT");
    unsetenv("TEST_CompleteMultipartUpload_CALL_COUNT");
    unsetenv("TEST_PutObject_CALL_COUNT");
}

void flb_test_s3_compression_snappy_putobject(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    char *call_count_str;
    int call_count;

    /* mocks calls- signals that we are in test mode */
    setenv("FLB_S3_PLUGIN_UNDER_TEST", "true", 1);

    ctx = flb_create();

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx,in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "s3", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd,"match", "*", NULL);
    flb_output_set(ctx, out_ffd,"region", "us-west-2", NULL);
    flb_output_set(ctx, out_ffd,"bucket", "fluent", NULL);
    flb_output_set(ctx, out_ffd,"compression", "snappy", NULL);
    flb_output_set(ctx, out_ffd,"use_put_object", "true", NULL);
    flb_output_set(ctx, out_ffd,"total_file_size", "5M", NULL);
    flb_output_set(ctx, out_ffd,"upload_timeout", S3_TEST_UPLOAD_TIMEOUT, NULL);
    flb_output_set(ctx, out_ffd,"Retry_Limit", "1", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    flb_lib_push(ctx, in_ffd, (char *) JSON_TD , (int) sizeof(JSON_TD) - 1);

    wait_for_s3_call_count("PutObject", 1);

    call_count_str = getenv("TEST_PutObject_CALL_COUNT");
    call_count = call_count_str ? atoi(call_count_str) : 0;
    TEST_CHECK_(call_count == 1,
                "Expected 1 PutObject call, got %d", call_count);

    flb_stop(ctx);
    flb_destroy(ctx);
    unsetenv("FLB_S3_PLUGIN_UNDER_TEST");
    unsetenv("TEST_PutObject_CALL_COUNT");
}

void flb_test_s3_preserve_data_ordering(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    char *call_count_str;
    int call_count;
    char *store_dir;

    store_dir = create_test_store_directory("/flb-s3-test-ordering-XXXXXX");
    TEST_CHECK(store_dir != NULL);
    if (store_dir == NULL) {
        return;
    }

    setenv("FLB_S3_PLUGIN_UNDER_TEST", "true", 1);

    ctx = flb_create();

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "s3", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "*", NULL);
    flb_output_set(ctx, out_ffd, "region", "us-west-2", NULL);
    flb_output_set(ctx, out_ffd, "bucket", "fluent", NULL);
    flb_output_set(ctx, out_ffd, "use_put_object", "true", NULL);
    flb_output_set(ctx, out_ffd, "total_file_size", "5M", NULL);
    flb_output_set(ctx, out_ffd, "preserve_data_ordering", "true", NULL);
    flb_output_set(ctx, out_ffd, "upload_timeout", S3_TEST_UPLOAD_TIMEOUT, NULL);
    flb_output_set(ctx, out_ffd, "store_dir", store_dir, NULL);
    flb_output_set(ctx, out_ffd, "Retry_Limit", "1", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    flb_lib_push(ctx, in_ffd, (char *) JSON_TD, (int) sizeof(JSON_TD) - 1);

    wait_for_s3_call_count("PutObject", 1);

    call_count_str = getenv("TEST_PutObject_CALL_COUNT");
    call_count = call_count_str ? atoi(call_count_str) : 0;
    TEST_CHECK_(call_count == 1,
                "Expected 1 PutObject call, got %d", call_count);

    flb_stop(ctx);
    flb_destroy(ctx);
    unsetenv("FLB_S3_PLUGIN_UNDER_TEST");
    unsetenv("TEST_PutObject_CALL_COUNT");
    flb_free(store_dir);
}


/*
 * Test that retry_limit=1 allows 1 initial attempt + 1 retry = 2 total PutObject calls.
 */
void flb_test_s3_putobject_retry_limit_semantics(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    char *call_count_str;
    int call_count;
    char *store_dir;

    store_dir = create_test_store_directory("/flb-s3-test-retry-XXXXXX");
    TEST_CHECK(store_dir != NULL);
    if (store_dir == NULL) {
        return;
    }

    /* Use mocks without flush bypass so the plugin's internal retry runs */
    setenv("FLB_S3_PLUGIN_UNDER_TEST", "true", 1);
    setenv("TEST_PUT_OBJECT_ERROR", ERROR_ACCESS_DENIED, 1);

    ctx = flb_create();

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "s3", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "*", NULL);
    flb_output_set(ctx, out_ffd, "region", "us-west-2", NULL);
    flb_output_set(ctx, out_ffd, "bucket", "fluent", NULL);
    flb_output_set(ctx, out_ffd, "use_put_object", "true", NULL);
    flb_output_set(ctx, out_ffd, "total_file_size", "5M", NULL);
    flb_output_set(ctx, out_ffd, "upload_timeout", S3_TEST_UPLOAD_TIMEOUT, NULL);
    flb_output_set(ctx, out_ffd, "store_dir", store_dir, NULL);
    flb_output_set(ctx, out_ffd, "Retry_Limit", "1", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Reset counter after startup so we only count test-driven attempts */
    unsetenv("TEST_PutObject_CALL_COUNT");

    /* Wait until the initial attempt and one retry have run. */
    flb_lib_push(ctx, in_ffd, (char *) JSON_TD, (int) sizeof(JSON_TD) - 1);
    wait_for_s3_call_count("PutObject", 2);

    flb_stop(ctx);
    flb_destroy(ctx);

    call_count_str = getenv("TEST_PutObject_CALL_COUNT");
    call_count = call_count_str ? atoi(call_count_str) : 0;

    /* retry_limit=1: 1 initial attempt + 1 retry = 2 PutObject calls */
    TEST_CHECK_(call_count == 2,
                "Expected 2 PutObject calls (1 attempt + 1 retry), got %d",
                call_count);

    unsetenv("FLB_S3_PLUGIN_UNDER_TEST");
    unsetenv("TEST_PUT_OBJECT_ERROR");
    unsetenv("TEST_PutObject_CALL_COUNT");
    flb_free(store_dir);
}

/*
 * Test that the S3 plugin defaults retry_limit to 5 when not explicitly set.
 */
void flb_test_s3_default_retry_limit(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    char *call_count_str;
    int call_count;
    char *store_dir;

    store_dir = create_test_store_directory("/flb-s3-test-default-XXXXXX");
    TEST_CHECK(store_dir != NULL);
    if (store_dir == NULL) {
        return;
    }

    setenv("FLB_S3_PLUGIN_UNDER_TEST", "true", 1);
    setenv("TEST_PUT_OBJECT_ERROR", ERROR_ACCESS_DENIED, 1);

    ctx = flb_create();

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "s3", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "*", NULL);
    flb_output_set(ctx, out_ffd, "region", "us-west-2", NULL);
    flb_output_set(ctx, out_ffd, "bucket", "fluent", NULL);
    flb_output_set(ctx, out_ffd, "use_put_object", "true", NULL);
    flb_output_set(ctx, out_ffd, "total_file_size", "5M", NULL);
    flb_output_set(ctx, out_ffd, "upload_timeout", S3_TEST_UPLOAD_TIMEOUT, NULL);
    flb_output_set(ctx, out_ffd, "store_dir", store_dir, NULL);
    /* No Retry_Limit — should default to 5 (MAX_UPLOAD_ERRORS) */

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    unsetenv("TEST_PutObject_CALL_COUNT");

    /* Wait for the initial attempt and all five default retries. */
    flb_lib_push(ctx, in_ffd, (char *) JSON_TD, (int) sizeof(JSON_TD) - 1);
    wait_for_s3_call_count("PutObject", 6);

    flb_stop(ctx);
    flb_destroy(ctx);

    call_count_str = getenv("TEST_PutObject_CALL_COUNT");
    call_count = call_count_str ? atoi(call_count_str) : 0;

    TEST_CHECK_(call_count == 6,
                "Expected 6 PutObject calls (default retry_limit=5), got %d",
                call_count);

    unsetenv("FLB_S3_PLUGIN_UNDER_TEST");
    unsetenv("TEST_PUT_OBJECT_ERROR");
    unsetenv("TEST_PutObject_CALL_COUNT");
    flb_free(store_dir);
}

void flb_test_s3_default_retry_exhausted_action_quarantine(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    int file_count;
    char postfix[128];
    char quarantine_dir[2048];
    char *store_dir;

    snprintf(postfix, sizeof(postfix),
             "/flb-s3-test-default-action-%u", (unsigned) rand());
    store_dir = flb_test_tmpdir_cat(postfix);
    TEST_CHECK(store_dir != NULL);
    TEST_CHECK(ensure_test_directory(store_dir) == 0);
    snprintf(quarantine_dir, sizeof(quarantine_dir),
             "%s/fluent/quarantine", store_dir);

    setenv("FLB_S3_PLUGIN_UNDER_TEST", "true", 1);
    setenv("TEST_PUT_OBJECT_ERROR", ERROR_ACCESS_DENIED, 1);

    ctx = flb_create();

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "s3", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "*", NULL);
    flb_output_set(ctx, out_ffd, "region", "us-west-2", NULL);
    flb_output_set(ctx, out_ffd, "bucket", "fluent", NULL);
    flb_output_set(ctx, out_ffd, "use_put_object", "true", NULL);
    flb_output_set(ctx, out_ffd, "total_file_size", "5M", NULL);
    flb_output_set(ctx, out_ffd, "upload_timeout", S3_TEST_UPLOAD_TIMEOUT, NULL);
    flb_output_set(ctx, out_ffd, "store_dir", store_dir, NULL);
    flb_output_set(ctx, out_ffd, "Retry_Limit", "1", NULL);
    /* do not set retry_exhausted_action to validate default behavior */

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    unsetenv("TEST_PutObject_CALL_COUNT");
    flb_lib_push(ctx, in_ffd, (char *) JSON_TD, (int) sizeof(JSON_TD) - 1);
    wait_for_s3_call_count("PutObject", 2);
    wait_for_file_count(quarantine_dir, 1);

    file_count = count_files_recursive(quarantine_dir);
    flb_stop(ctx);
    flb_destroy(ctx);

    TEST_CHECK_(file_count > 0,
                "Expected quarantined file(s), got %d",
                file_count);

    unsetenv("FLB_S3_PLUGIN_UNDER_TEST");
    unsetenv("TEST_PUT_OBJECT_ERROR");
    unsetenv("TEST_PutObject_CALL_COUNT");

    flb_free(store_dir);
}

/* Test list */
TEST_LIST = {
    {"multipart_success", flb_test_s3_multipart_success },
    {"putobject_success", flb_test_s3_putobject_success },
    {"putobject_error", flb_test_s3_putobject_error },
    {"putobject_retry_limit_semantics", flb_test_s3_putobject_retry_limit_semantics },
    {"default_retry_limit", flb_test_s3_default_retry_limit },
    {"default_retry_exhausted_action_quarantine", flb_test_s3_default_retry_exhausted_action_quarantine },
    {"create_upload_error", flb_test_s3_create_upload_error },
    {"upload_part_error", flb_test_s3_upload_part_error },
    {"complete_upload_error", flb_test_s3_complete_upload_error },
    {"compression_gzip", flb_test_s3_compression_gzip },
    {"compression_gzip_putobject", flb_test_s3_compression_gzip_putobject },
    {"compression_zstd", flb_test_s3_compression_zstd },
    {"compression_zstd_putobject", flb_test_s3_compression_zstd_putobject },
    {"compression_snappy", flb_test_s3_compression_snappy },
    {"compression_snappy_putobject", flb_test_s3_compression_snappy_putobject },
    {"preserve_data_ordering", flb_test_s3_preserve_data_ordering },
    {NULL, NULL}
};
