/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
#include <fluent-bit.h>
#include <fluent-bit/flb_time.h>
#include <cfl/cfl_atomic.h>
#include "../../plugins/out_s3/s3.h"
#include "../../plugins/out_s3/s3_store.h"
#include "flb_tests_runtime.h"
#include "../include/flb_tests_tmpdir.h"
#include <errno.h>
#include <inttypes.h>

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
#define S3_TEST_STARTUP_FILE_COUNT 3

/* not a real error code, but tests that the code can respond to any error */
#define ERROR_ACCESS_DENIED "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
                            <Error>\
                            <Code>AccessDenied</Code>\
                            <Message>Access Denied</Message>\
                            <RequestId>656c76696e6727732072657175657374</RequestId>\
                            <HostId>Uuag1LuByRx9e6j5Onimru9pO4ZVKnJ2Qz7/C1NPcfTWAtRPfTaOFg==</HostId>\
                            </Error>"

static struct flb_s3 *get_s3_context(flb_ctx_t *ctx)
{
    struct flb_output_instance *ins;

    if (ctx == NULL || mk_list_is_empty(&ctx->config->outputs) == 0) {
        return NULL;
    }

    ins = mk_list_entry_first(&ctx->config->outputs,
                              struct flb_output_instance, _head);
    return ins->context;
}

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

static void wait_for_s3_call_count_with_timeout(const char *api, int expected,
                                                uint64_t timeout_ms)
{
    uint64_t elapsed_ms;
    struct flb_time start_time;
    struct flb_time end_time;
    struct flb_time diff_time;

    elapsed_ms = 0;
    flb_time_get(&start_time);

    while (get_s3_call_count(api) < expected &&
           elapsed_ms < timeout_ms) {
        flb_time_msleep(S3_TEST_WAIT_STEP_MS);
        flb_time_get(&end_time);
        flb_time_diff(&end_time, &start_time, &diff_time);
        elapsed_ms = flb_time_to_nanosec(&diff_time) / 1000000;
    }
}

static void wait_for_s3_call_count(const char *api, int expected)
{
    wait_for_s3_call_count_with_timeout(api, expected,
                                        S3_TEST_WAIT_TIMEOUT_MS);
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

static void wait_for_file_count_at_most(const char *path, int expected)
{
    uint64_t elapsed_ms;
    struct flb_time start_time;
    struct flb_time end_time;
    struct flb_time diff_time;

    elapsed_ms = 0;
    flb_time_get(&start_time);

    while (count_files_recursive(path) > expected &&
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

static int test_directory_exists(const char *path)
{
#ifdef FLB_SYSTEM_WINDOWS
    DWORD attributes;

    attributes = GetFileAttributesA(path);
    return attributes != INVALID_FILE_ATTRIBUTES &&
           (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
#else
    struct stat st;

    return stat(path, &st) == 0 && S_ISDIR(st.st_mode);
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
    struct flb_s3 *s3_ctx;

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
    flb_output_set(ctx, out_ffd,"retry_exhausted_action", "delete", NULL);
    flb_output_set(ctx, out_ffd,"preserve_data_ordering", "false", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    flb_lib_push(ctx, in_ffd, (char *) JSON_TD , (int) sizeof(JSON_TD) - 1);

    s3_ctx = get_s3_context(ctx);
    TEST_CHECK(s3_ctx != NULL);

    wait_for_s3_call_count("CreateMultipartUpload", 2);
    wait_for_file_count_at_most(s3_ctx->stream_active->path, 0);

    call_count_str = getenv("TEST_CreateMultipartUpload_CALL_COUNT");
    call_count = call_count_str ? atoi(call_count_str) : 0;
    TEST_CHECK_(call_count == 2,
                "Expected CreateMultipartUpload to stop after two attempts, got %d",
                call_count);
    TEST_CHECK_(count_files_recursive(s3_ctx->stream_active->path) == 0,
                "Expected retry-exhausted chunk to be deleted");

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
    struct flb_s3 *s3_ctx;

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
    flb_output_set(ctx, out_ffd,"Retry_Limit", "1", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    s3_ctx = get_s3_context(ctx);
    TEST_CHECK(s3_ctx != NULL);

    flb_lib_push(ctx, in_ffd, (char *) JSON_TD , (int) sizeof(JSON_TD) - 1);

    wait_for_s3_call_count("CompleteMultipartUpload", 2);

    call_count_str = getenv("TEST_CompleteMultipartUpload_CALL_COUNT");
    call_count = call_count_str ? atoi(call_count_str) : 0;
    TEST_CHECK_(call_count >= 2,
                "Expected >= 2 CompleteMultipartUpload calls (retried), got %d",
                call_count);

    wait_for_file_count(s3_ctx->stream_upload->path, 1);
    TEST_CHECK_(count_files_recursive(s3_ctx->stream_upload->path) > 0,
                "Expected multipart metadata to remain recoverable after completion failure");

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

void flb_test_s3_ordered_retry_uses_backoff_deadline(void)
{
    int ret;
    int in_ffd;
    int out_ffd;
    flb_ctx_t *ctx;
    char *store_dir;
    struct flb_s3 *s3_ctx;
    struct s3_file *s3_file;

    store_dir = create_test_store_directory("/flb-s3-test-retry-deadline-XXXXXX");
    TEST_CHECK(store_dir != NULL);
    if (store_dir == NULL) {
        return;
    }

    setenv("FLB_S3_PLUGIN_UNDER_TEST", "true", 1);
    setenv("TEST_UPLOAD_PART_ERROR", ERROR_ACCESS_DENIED, 1);

    ctx = flb_create();
    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "retry-deadline", NULL);

    out_ffd = flb_output(ctx, (char *) "s3", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "*", NULL);
    flb_output_set(ctx, out_ffd, "region", "us-west-2", NULL);
    flb_output_set(ctx, out_ffd, "bucket", "fluent", NULL);
    flb_output_set(ctx, out_ffd, "use_put_object", "false", NULL);
    flb_output_set(ctx, out_ffd, "compression", "gzip", NULL);
    flb_output_set(ctx, out_ffd, "total_file_size", "100M", NULL);
    flb_output_set(ctx, out_ffd, "upload_chunk_size", "50M", NULL);
    flb_output_set(ctx, out_ffd, "upload_timeout", "60s", NULL);
    flb_output_set(ctx, out_ffd, "store_dir", store_dir, NULL);
    flb_output_set(ctx, out_ffd, "retry_limit", "1", NULL);
    flb_output_set(ctx, out_ffd, "retry_exhausted_action", "delete", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    ret = flb_lib_push(ctx, in_ffd, (char *) JSON_TD,
                       (int) sizeof(JSON_TD) - 1);
    TEST_CHECK(ret >= 0);
    s3_ctx = get_s3_context(ctx);
    TEST_CHECK(s3_ctx != NULL);
    wait_for_file_count(s3_ctx->stream_active->path, 1);

    s3_file = s3_store_file_get(s3_ctx, "retry-deadline", 14);
    TEST_CHECK(s3_file != NULL);
    s3_file->create_time = time(NULL) - 61;

    ret = flb_lib_push(ctx, in_ffd, (char *) JSON_TD,
                       (int) sizeof(JSON_TD) - 1);
    TEST_CHECK(ret >= 0);
    wait_for_s3_call_count("UploadPart", 1);
    wait_for_file_count_at_most(s3_ctx->stream_active->path, 0);

    TEST_CHECK_(get_s3_call_count("UploadPart") == 2,
                "Expected initial attempt and one retry at its deadline, got %d",
                get_s3_call_count("UploadPart"));
    TEST_CHECK_(count_files_recursive(s3_ctx->stream_active->path) == 0,
                "Expected retry-exhausted chunk to be deleted before periodic timer");

    flb_stop(ctx);
    flb_destroy(ctx);

    unsetenv("FLB_S3_PLUGIN_UNDER_TEST");
    unsetenv("TEST_UPLOAD_PART_ERROR");
    unsetenv("TEST_CreateMultipartUpload_CALL_COUNT");
    unsetenv("TEST_UploadPart_CALL_COUNT");
    flb_free(store_dir);
}

void flb_test_s3_ordered_timer_preserves_chunk_order(void)
{
    int ret;
    int index;
    int out_ffd;
    int input_fds[2];
    char *uri;
    flb_ctx_t *ctx;
    char *store_dir;
    struct flb_s3 *s3_ctx;
    struct s3_file *oldest_file;
    struct s3_file *later_file;

    store_dir = create_test_store_directory("/flb-s3-test-timer-order-XXXXXX");
    TEST_CHECK(store_dir != NULL);
    if (store_dir == NULL) {
        return;
    }

    setenv("FLB_S3_PLUGIN_UNDER_TEST", "true", 1);
    setenv("TEST_RECORD_S3_URIS", "true", 1);

    ctx = flb_create();
    for (index = 0; index < 2; index++) {
        input_fds[index] = flb_input(ctx, (char *) "lib", NULL);
        TEST_CHECK(input_fds[index] >= 0);
    }
    flb_input_set(ctx, input_fds[0], "tag", "oldest", NULL);
    flb_input_set(ctx, input_fds[1], "tag", "later", NULL);

    out_ffd = flb_output(ctx, (char *) "s3", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "*", NULL);
    flb_output_set(ctx, out_ffd, "region", "us-west-2", NULL);
    flb_output_set(ctx, out_ffd, "bucket", "fluent", NULL);
    flb_output_set(ctx, out_ffd, "use_put_object", "true", NULL);
    flb_output_set(ctx, out_ffd, "total_file_size", "5M", NULL);
    flb_output_set(ctx, out_ffd, "upload_timeout", "10s", NULL);
    flb_output_set(ctx, out_ffd, "store_dir", store_dir, NULL);
    flb_output_set(ctx, out_ffd, "s3_key_format", "/queue/$TAG", NULL);
    flb_output_set(ctx, out_ffd, "static_file_path", "true", NULL);
    flb_output_set(ctx, out_ffd, "retry_limit", "1", NULL);
    flb_output_set(ctx, out_ffd, "retry_exhausted_action", "delete", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);
    for (index = 0; index < 2; index++) {
        ret = flb_lib_push(ctx, input_fds[index], (char *) JSON_TD,
                           (int) sizeof(JSON_TD) - 1);
        TEST_CHECK(ret >= 0);
    }

    s3_ctx = get_s3_context(ctx);
    TEST_CHECK(s3_ctx != NULL);
    wait_for_file_count(s3_ctx->stream_active->path, 2);
    oldest_file = s3_store_file_get(s3_ctx, "oldest", 6);
    later_file = s3_store_file_get(s3_ctx, "later", 5);
    TEST_CHECK(oldest_file != NULL);
    TEST_CHECK(later_file != NULL);
    oldest_file->create_time = time(NULL) - 20;
    later_file->create_time = time(NULL) - 11;

    setenv("TEST_PUT_OBJECT_ERROR", ERROR_ACCESS_DENIED, 1);
    wait_for_s3_call_count("PutObject", 1);
    flb_time_msleep(500);

    TEST_CHECK_(get_s3_call_count("PutObject") == 1,
                "Expected later timed-out chunk to wait behind first failure, got %d calls",
                get_s3_call_count("PutObject"));
    uri = getenv("TEST_PutObject_URI_1");
    TEST_CHECK_(uri != NULL && strcmp(uri, "/fluent/queue/oldest") == 0,
                "Expected oldest timed-out chunk first, got %s",
                uri ? uri : "(null)");

    unsetenv("TEST_PUT_OBJECT_ERROR");
    wait_for_s3_call_count("PutObject", 3);
    uri = getenv("TEST_PutObject_URI_2");
    TEST_CHECK_(uri != NULL && strcmp(uri, "/fluent/queue/oldest") == 0,
                "Expected oldest chunk retry before later chunk, got %s",
                uri ? uri : "(null)");
    uri = getenv("TEST_PutObject_URI_3");
    TEST_CHECK_(uri != NULL && strcmp(uri, "/fluent/queue/later") == 0,
                "Expected later chunk after oldest retry, got %s",
                uri ? uri : "(null)");

    flb_stop(ctx);
    flb_destroy(ctx);

    unsetenv("FLB_S3_PLUGIN_UNDER_TEST");
    unsetenv("TEST_PUT_OBJECT_ERROR");
    unsetenv("TEST_RECORD_S3_URIS");
    unsetenv("TEST_PutObject_CALL_COUNT");
    unsetenv("TEST_PutObject_URI_1");
    unsetenv("TEST_PutObject_URI_2");
    unsetenv("TEST_PutObject_URI_3");
    flb_free(store_dir);
}

void flb_test_s3_ordered_construct_error_exhausts_chunk(void)
{
    int ret;
    int in_ffd;
    int out_ffd;
    flb_ctx_t *ctx;
    char *store_dir;
    struct flb_s3 *s3_ctx;
    struct s3_file *s3_file;

    store_dir = create_test_store_directory("/flb-s3-test-construct-error-XXXXXX");
    TEST_CHECK(store_dir != NULL);
    if (store_dir == NULL) {
        return;
    }

    setenv("FLB_S3_PLUGIN_UNDER_TEST", "true", 1);

    ctx = flb_create();
    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "construct-error", NULL);

    out_ffd = flb_output(ctx, (char *) "s3", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "*", NULL);
    flb_output_set(ctx, out_ffd, "region", "us-west-2", NULL);
    flb_output_set(ctx, out_ffd, "bucket", "fluent", NULL);
    flb_output_set(ctx, out_ffd, "use_put_object", "true", NULL);
    flb_output_set(ctx, out_ffd, "total_file_size", "5M", NULL);
    flb_output_set(ctx, out_ffd, "upload_timeout", "60s", NULL);
    flb_output_set(ctx, out_ffd, "store_dir", store_dir, NULL);
    flb_output_set(ctx, out_ffd, "retry_limit", "1", NULL);
    flb_output_set(ctx, out_ffd, "retry_exhausted_action", "delete", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    ret = flb_lib_push(ctx, in_ffd, (char *) JSON_TD,
                       (int) sizeof(JSON_TD) - 1);
    TEST_CHECK(ret >= 0);
    s3_ctx = get_s3_context(ctx);
    TEST_CHECK(s3_ctx != NULL);
    wait_for_file_count(s3_ctx->stream_active->path, 1);

    s3_file = s3_store_file_get(s3_ctx, "construct-error", 15);
    TEST_CHECK(s3_file != NULL);
    s3_file->create_time = time(NULL) - 61;
    setenv("TEST_CONSTRUCT_REQUEST_BUFFER_ERROR", "true", 1);

    ret = flb_lib_push(ctx, in_ffd, (char *) JSON_TD,
                       (int) sizeof(JSON_TD) - 1);
    TEST_CHECK(ret >= 0);
    wait_for_file_count_at_most(s3_ctx->stream_active->path, 0);

    TEST_CHECK_(count_files_recursive(s3_ctx->stream_active->path) == 0,
                "Expected unreadable queue head to reach terminal cleanup");
    TEST_CHECK_(mk_list_is_empty(&s3_ctx->upload_queue) == 0,
                "Expected queue to be empty after construction retry exhaustion");
    TEST_CHECK_(s3_ctx->retry_time == 0,
                "Expected retry delay to reset after terminal cleanup");

    unsetenv("TEST_CONSTRUCT_REQUEST_BUFFER_ERROR");
    flb_stop(ctx);
    flb_destroy(ctx);

    unsetenv("FLB_S3_PLUGIN_UNDER_TEST");
    unsetenv("TEST_PutObject_CALL_COUNT");
    flb_free(store_dir);
}

void flb_test_s3_ordered_backoff_does_not_starve_completion(void)
{
    int ret;
    int index;
    int out_ffd;
    int input_fds[2];
    flb_ctx_t *ctx;
    char *store_dir;
    struct flb_s3 *s3_ctx;
    struct s3_file *s3_file;

    store_dir = create_test_store_directory("/flb-s3-test-completion-backoff-XXXXXX");
    TEST_CHECK(store_dir != NULL);
    if (store_dir == NULL) {
        return;
    }

    setenv("FLB_S3_PLUGIN_UNDER_TEST", "true", 1);
    setenv("TEST_COMPLETE_MULTIPART_UPLOAD_ERROR", ERROR_ACCESS_DENIED, 1);

    ctx = flb_create();
    for (index = 0; index < 2; index++) {
        input_fds[index] = flb_input(ctx, (char *) "lib", NULL);
        TEST_CHECK(input_fds[index] >= 0);
    }
    flb_input_set(ctx, input_fds[0], "tag", "completing", NULL);
    flb_input_set(ctx, input_fds[1], "tag", "backoff", NULL);

    out_ffd = flb_output(ctx, (char *) "s3", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "*", NULL);
    flb_output_set(ctx, out_ffd, "region", "us-west-2", NULL);
    flb_output_set(ctx, out_ffd, "bucket", "fluent", NULL);
    flb_output_set(ctx, out_ffd, "use_put_object", "false", NULL);
    flb_output_set(ctx, out_ffd, "compression", "gzip", NULL);
    flb_output_set(ctx, out_ffd, "total_file_size", "100M", NULL);
    flb_output_set(ctx, out_ffd, "upload_chunk_size", "50M", NULL);
    flb_output_set(ctx, out_ffd, "upload_timeout", "60s", NULL);
    flb_output_set(ctx, out_ffd, "store_dir", store_dir, NULL);
    flb_output_set(ctx, out_ffd, "retry_limit", "5", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);
    s3_ctx = get_s3_context(ctx);
    TEST_CHECK(s3_ctx != NULL);

    ret = flb_lib_push(ctx, input_fds[0], (char *) JSON_TD,
                       (int) sizeof(JSON_TD) - 1);
    TEST_CHECK(ret >= 0);
    wait_for_file_count(s3_ctx->stream_active->path, 1);
    s3_file = s3_store_file_get(s3_ctx, "completing", 10);
    TEST_CHECK(s3_file != NULL);
    s3_file->create_time = time(NULL) - 61;
    ret = flb_lib_push(ctx, input_fds[0], (char *) JSON_TD,
                       (int) sizeof(JSON_TD) - 1);
    TEST_CHECK(ret >= 0);
    wait_for_s3_call_count("CompleteMultipartUpload", 1);

    ret = flb_lib_push(ctx, input_fds[1], (char *) JSON_TD,
                       (int) sizeof(JSON_TD) - 1);
    TEST_CHECK(ret >= 0);
    wait_for_file_count(s3_ctx->stream_active->path, 1);
    s3_file = s3_store_file_get(s3_ctx, "backoff", 7);
    TEST_CHECK(s3_file != NULL);
    s3_file->create_time = time(NULL) - 61;
    setenv("TEST_CREATE_MULTIPART_UPLOAD_ERROR", ERROR_ACCESS_DENIED, 1);
    ret = flb_lib_push(ctx, input_fds[1], (char *) JSON_TD,
                       (int) sizeof(JSON_TD) - 1);
    TEST_CHECK(ret >= 0);

    wait_for_s3_call_count("CreateMultipartUpload", 2);
    wait_for_s3_call_count("CompleteMultipartUpload", 2);
    TEST_CHECK_(get_s3_call_count("CompleteMultipartUpload") >= 2,
                "Expected pending completion to run while queue head was backing off");

    unsetenv("TEST_CREATE_MULTIPART_UPLOAD_ERROR");
    unsetenv("TEST_COMPLETE_MULTIPART_UPLOAD_ERROR");
    flb_stop(ctx);
    flb_destroy(ctx);

    unsetenv("FLB_S3_PLUGIN_UNDER_TEST");
    unsetenv("TEST_CreateMultipartUpload_CALL_COUNT");
    unsetenv("TEST_UploadPart_CALL_COUNT");
    unsetenv("TEST_CompleteMultipartUpload_CALL_COUNT");
    unsetenv("TEST_PutObject_CALL_COUNT");
    flb_free(store_dir);
}

void flb_test_s3_ordered_shared_upload_retries_safely(void)
{
    int ret;
    int in_ffd;
    int out_ffd;
    flb_ctx_t *ctx;
    char *store_dir;
    struct flb_s3 *s3_ctx;
    struct s3_file *s3_file;

    store_dir = create_test_store_directory("/flb-s3-test-shared-upload-XXXXXX");
    TEST_CHECK(store_dir != NULL);
    if (store_dir == NULL) {
        return;
    }

    setenv("FLB_S3_PLUGIN_UNDER_TEST", "true", 1);
    setenv("TEST_UPLOAD_PART_ERROR", ERROR_ACCESS_DENIED, 1);

    ctx = flb_create();
    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "shared-upload", NULL);

    out_ffd = flb_output(ctx, (char *) "s3", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "*", NULL);
    flb_output_set(ctx, out_ffd, "region", "us-west-2", NULL);
    flb_output_set(ctx, out_ffd, "bucket", "fluent", NULL);
    flb_output_set(ctx, out_ffd, "use_put_object", "false", NULL);
    flb_output_set(ctx, out_ffd, "compression", "gzip", NULL);
    flb_output_set(ctx, out_ffd, "total_file_size", "100M", NULL);
    flb_output_set(ctx, out_ffd, "upload_chunk_size", "50M", NULL);
    flb_output_set(ctx, out_ffd, "upload_timeout", "60s", NULL);
    flb_output_set(ctx, out_ffd, "store_dir", store_dir, NULL);
    flb_output_set(ctx, out_ffd, "retry_limit", "1", NULL);
    flb_output_set(ctx, out_ffd, "retry_exhausted_action", "delete", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);
    s3_ctx = get_s3_context(ctx);
    TEST_CHECK(s3_ctx != NULL);

    ret = flb_lib_push(ctx, in_ffd, (char *) JSON_TD,
                       (int) sizeof(JSON_TD) - 1);
    TEST_CHECK(ret >= 0);
    wait_for_file_count(s3_ctx->stream_active->path, 1);
    s3_file = s3_store_file_get(s3_ctx, "shared-upload", 13);
    TEST_CHECK(s3_file != NULL);
    s3_file->create_time = time(NULL) - 61;

    ret = flb_lib_push(ctx, in_ffd, (char *) JSON_TD,
                       (int) sizeof(JSON_TD) - 1);
    TEST_CHECK(ret >= 0);
    wait_for_s3_call_count("UploadPart", 1);

    ret = flb_lib_push(ctx, in_ffd, (char *) JSON_TD,
                       (int) sizeof(JSON_TD) - 1);
    TEST_CHECK(ret >= 0);
    wait_for_file_count(s3_ctx->stream_active->path, 2);
    s3_file = s3_store_file_get(s3_ctx, "shared-upload", 13);
    TEST_CHECK(s3_file != NULL);
    s3_file->create_time = time(NULL) - 61;

    ret = flb_lib_push(ctx, in_ffd, (char *) JSON_TD,
                       (int) sizeof(JSON_TD) - 1);
    TEST_CHECK(ret >= 0);
    wait_for_s3_call_count("UploadPart", 4);
    wait_for_file_count_at_most(s3_ctx->stream_active->path, 0);

    TEST_CHECK_(get_s3_call_count("UploadPart") == 4,
                "Expected both shared-upload chunks to exhaust safely, got %d attempts",
                get_s3_call_count("UploadPart"));
    TEST_CHECK_(count_files_recursive(s3_ctx->stream_active->path) == 0,
                "Expected both retry-exhausted chunks to be deleted");
    TEST_CHECK_(mk_list_is_empty(&s3_ctx->upload_queue) == 0,
                "Expected shared-upload queue to be empty");

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
    wait_for_s3_call_count_with_timeout("PutObject", 6, 40000);

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

void flb_test_s3_empty_upload_queue_file_deleted(void)
{
    int ret;
    int in_ffd;
    int out_ffd;
    int file_count;
    char empty_payload = '\0';
    flb_ctx_t *ctx;
    char *store_dir;
    struct flb_s3 *s3_ctx;
    struct s3_file *s3_file;
    struct upload_queue *upload_contents;

    store_dir = create_test_store_directory("/flb-s3-test-empty-queue-XXXXXX");
    TEST_CHECK(store_dir != NULL);
    if (store_dir == NULL) {
        return;
    }

    setenv("FLB_S3_PLUGIN_UNDER_TEST", "true", 1);

    ctx = flb_create();
    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "live", NULL);

    out_ffd = flb_output(ctx, (char *) "s3", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "*", NULL);
    flb_output_set(ctx, out_ffd, "region", "us-west-2", NULL);
    flb_output_set(ctx, out_ffd, "bucket", "fluent", NULL);
    flb_output_set(ctx, out_ffd, "use_put_object", "true", NULL);
    flb_output_set(ctx, out_ffd, "total_file_size", "5M", NULL);
    /* Keep the non-empty control chunk alive beyond the first queue timer tick. */
    flb_output_set(ctx, out_ffd, "upload_timeout", "12s", NULL);
    flb_output_set(ctx, out_ffd, "store_dir", store_dir, NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    s3_ctx = get_s3_context(ctx);
    TEST_CHECK(s3_ctx != NULL);
    ret = s3_store_buffer_put(s3_ctx, NULL, "empty", 5, &empty_payload,
                              0, time(NULL));
    TEST_CHECK(ret == 0);

    s3_file = s3_store_file_get(s3_ctx, "empty", 5);
    TEST_CHECK(s3_file != NULL);
    s3_store_file_lock(s3_file);

    upload_contents = flb_calloc(1, sizeof(struct upload_queue));
    TEST_CHECK(upload_contents != NULL);
    upload_contents->upload_file = s3_file;
    upload_contents->tag = flb_sds_create("empty");
    TEST_CHECK(upload_contents->tag != NULL);
    upload_contents->tag_len = 5;
    upload_contents->upload_time = -1;
    mk_list_add(&upload_contents->_head, &s3_ctx->upload_queue);

    ret = flb_lib_push(ctx, in_ffd, (char *) JSON_TD, (int) sizeof(JSON_TD) - 1);
    TEST_CHECK(ret >= 0);
    wait_for_file_count(s3_ctx->stream_active->path, 2);
    wait_for_file_count_at_most(s3_ctx->stream_active->path, 1);

    file_count = count_files_recursive(s3_ctx->stream_active->path);
    TEST_CHECK_(file_count == 1,
                "Expected only the non-empty live chunk to remain, got %d files",
                file_count);

    flb_stop(ctx);
    flb_destroy(ctx);

    unsetenv("FLB_S3_PLUGIN_UNDER_TEST");
    unsetenv("TEST_PutObject_CALL_COUNT");
    flb_free(store_dir);
}

void flb_test_s3_near_full_buffer_append_succeeds(void)
{
    int ret;
    int in_ffd;
    int out_ffd;
    char payload[96];
    char excess_payload[5];
    flb_ctx_t *ctx;
    char *store_dir;
    struct flb_s3 *s3_ctx;
    struct s3_file *s3_file;

    store_dir = create_test_store_directory("/flb-s3-test-near-full-XXXXXX");
    TEST_CHECK(store_dir != NULL);
    if (store_dir == NULL) {
        return;
    }

    memset(payload, 'a', sizeof(payload));
    memset(excess_payload, 'b', sizeof(excess_payload));
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
    flb_output_set(ctx, out_ffd, "upload_timeout", "1h", NULL);
    flb_output_set(ctx, out_ffd, "store_dir", store_dir, NULL);
    flb_output_set(ctx, out_ffd, "store_dir_limit_size", "100", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    s3_ctx = get_s3_context(ctx);
    TEST_CHECK(s3_ctx != NULL);
    ret = s3_store_buffer_put(s3_ctx, NULL, "test", 4, payload,
                              sizeof(payload), time(NULL));
    TEST_CHECK_(ret == 0,
                "Expected a committed near-full append to return success, got %d",
                ret);
    TEST_CHECK(cfl_atomic_load(&s3_ctx->current_buffer_size) == sizeof(payload));

    s3_file = s3_store_file_get(s3_ctx, "test", 4);
    TEST_CHECK(s3_file != NULL);
    TEST_CHECK(s3_store_file_size_get(s3_file) == sizeof(payload));

    ret = s3_store_buffer_put(s3_ctx, s3_file, "test", 4, excess_payload,
                              sizeof(excess_payload), time(NULL));
    TEST_CHECK_(ret == -1,
                "Expected an over-limit append to fail, got %d",
                ret);
    TEST_CHECK(cfl_atomic_load(&s3_ctx->current_buffer_size) == sizeof(payload));
    TEST_CHECK(s3_store_file_size_get(s3_file) == sizeof(payload));

    flb_stop(ctx);
    flb_destroy(ctx);

    unsetenv("FLB_S3_PLUGIN_UNDER_TEST");
    unsetenv("TEST_PutObject_CALL_COUNT");
    flb_free(store_dir);
}

void flb_test_s3_startup_index_order_after_failure(void)
{
    int ret;
    int index;
    int in_ffd;
    int out_ffd;
    int call_count;
    int input_fds[2];
    char tag[32];
    char *uri;
    flb_ctx_t *ctx;
    char *store_dir;
    struct flb_s3 *s3_ctx;

    store_dir = create_test_store_directory("/flb-s3-test-startup-index-XXXXXX");
    TEST_CHECK(store_dir != NULL);
    if (store_dir == NULL) {
        return;
    }

    setenv("FLB_S3_PLUGIN_UNDER_TEST", "true", 1);
    setenv("TEST_PUT_OBJECT_ERROR", ERROR_ACCESS_DENIED, 1);
    setenv("TEST_RECORD_S3_URIS", "true", 1);

    ctx = flb_create();
    for (index = 0; index < 2; index++) {
        input_fds[index] = flb_input(ctx, (char *) "lib", NULL);
        TEST_CHECK(input_fds[index] >= 0);
        snprintf(tag, sizeof(tag), "index-test-%d", index);
        flb_input_set(ctx, input_fds[index], "tag", tag, NULL);
    }

    out_ffd = flb_output(ctx, (char *) "s3", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "*", NULL);
    flb_output_set(ctx, out_ffd, "region", "us-west-2", NULL);
    flb_output_set(ctx, out_ffd, "bucket", "fluent", NULL);
    flb_output_set(ctx, out_ffd, "use_put_object", "true", NULL);
    flb_output_set(ctx, out_ffd, "total_file_size", "5M", NULL);
    flb_output_set(ctx, out_ffd, "upload_timeout", "1h", NULL);
    flb_output_set(ctx, out_ffd, "store_dir", store_dir, NULL);
    flb_output_set(ctx, out_ffd, "s3_key_format", "/recovery/$TAG/$INDEX", NULL);
    flb_output_set(ctx, out_ffd, "preserve_data_ordering", "false", NULL);
    flb_output_set(ctx, out_ffd, "retry_limit", "10", NULL);
    flb_output_set(ctx, out_ffd, "retry_exhausted_action", "delete", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    s3_ctx = get_s3_context(ctx);
    TEST_CHECK(s3_ctx != NULL);
    for (index = 0; index < 2; index++) {
        ret = flb_lib_push(ctx, input_fds[index],
                           (char *) JSON_TD, (int) sizeof(JSON_TD) - 1);
        TEST_CHECK(ret >= 0);
    }
    wait_for_file_count(s3_ctx->stream_active->path, 2);

    flb_stop(ctx);
    flb_destroy(ctx);
    flb_time_msleep(1100);

    unsetenv("TEST_PutObject_CALL_COUNT");
    unsetenv("TEST_PutObject_URI_1");

    ctx = flb_create();
    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "live", NULL);

    out_ffd = flb_output(ctx, (char *) "s3", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "*", NULL);
    flb_output_set(ctx, out_ffd, "region", "us-west-2", NULL);
    flb_output_set(ctx, out_ffd, "bucket", "fluent", NULL);
    flb_output_set(ctx, out_ffd, "use_put_object", "true", NULL);
    flb_output_set(ctx, out_ffd, "total_file_size", "5M", NULL);
    flb_output_set(ctx, out_ffd, "upload_timeout", "1h", NULL);
    flb_output_set(ctx, out_ffd, "store_dir", store_dir, NULL);
    flb_output_set(ctx, out_ffd, "s3_key_format", "/recovery/$TAG/$INDEX", NULL);
    flb_output_set(ctx, out_ffd, "preserve_data_ordering", "false", NULL);
    flb_output_set(ctx, out_ffd, "retry_limit", "10", NULL);
    flb_output_set(ctx, out_ffd, "retry_exhausted_action", "delete", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    call_count = get_s3_call_count("PutObject");
    TEST_CHECK_(call_count == 1,
                "Expected $INDEX recovery to stop after one failure, got %d attempts",
                call_count);
    uri = getenv("TEST_PutObject_URI_1");
    TEST_CHECK_(uri != NULL &&
                (strcmp(uri, "/fluent/recovery/index-test-0/0") == 0 ||
                 strcmp(uri, "/fluent/recovery/index-test-1/0") == 0),
                "Expected failed request to use an original chunk with index 0, got %s",
                uri ? uri : "(null)");

    s3_ctx = get_s3_context(ctx);
    TEST_CHECK(s3_ctx != NULL);
    TEST_CHECK_(s3_ctx->seq_index == 0,
                "Expected failed request to roll index back to 0, got %" PRIu64,
                s3_ctx->seq_index);

    unsetenv("TEST_PUT_OBJECT_ERROR");
    ret = flb_lib_push(ctx, in_ffd, (char *) JSON_TD, (int) sizeof(JSON_TD) - 1);
    TEST_CHECK(ret >= 0);
    wait_for_s3_call_count("PutObject", 3);

    uri = getenv("TEST_PutObject_URI_2");
    TEST_CHECK_(uri != NULL &&
                getenv("TEST_PutObject_URI_1") != NULL &&
                strcmp(uri, getenv("TEST_PutObject_URI_1")) == 0,
                "Expected failed chunk retry to keep its tag and index, got %s",
                uri ? uri : "(null)");
    uri = getenv("TEST_PutObject_URI_3");
    TEST_CHECK_(uri != NULL &&
                (strcmp(uri, "/fluent/recovery/index-test-0/1") == 0 ||
                 strcmp(uri, "/fluent/recovery/index-test-1/1") == 0),
                "Expected the other original chunk to receive index 1, got %s",
                uri ? uri : "(null)");
    TEST_CHECK_(s3_ctx->seq_index == 2,
                "Expected two recovered uploads to advance index to 2, got %" PRIu64,
                s3_ctx->seq_index);

    flb_stop(ctx);
    flb_destroy(ctx);

    unsetenv("FLB_S3_PLUGIN_UNDER_TEST");
    unsetenv("TEST_PUT_OBJECT_ERROR");
    unsetenv("TEST_RECORD_S3_URIS");
    unsetenv("TEST_PutObject_CALL_COUNT");
    unsetenv("TEST_PutObject_URI_1");
    unsetenv("TEST_PutObject_URI_2");
    unsetenv("TEST_PutObject_URI_3");
    unsetenv("TEST_PutObject_URI_4");
    flb_free(store_dir);
}

void flb_test_s3_startup_buffer_size_accounting(void)
{
    int ret;
    int index;
    int in_ffd;
    int out_ffd;
    int call_count;
    int file_count;
    int input_fds[S3_TEST_STARTUP_FILE_COUNT];
    char tag[32];
    char old_stream_dir[2048];
    uint64_t live_buffer_size;
    uint64_t restored_buffer_size;
    flb_ctx_t *ctx;
    char *store_dir;
    struct flb_s3 *s3_ctx;

    store_dir = create_test_store_directory("/flb-s3-test-startup-size-XXXXXX");
    TEST_CHECK(store_dir != NULL);
    if (store_dir == NULL) {
        return;
    }

    setenv("FLB_S3_PLUGIN_UNDER_TEST", "true", 1);
    setenv("TEST_PUT_OBJECT_ERROR", ERROR_ACCESS_DENIED, 1);

    ctx = flb_create();
    for (index = 0; index < S3_TEST_STARTUP_FILE_COUNT; index++) {
        input_fds[index] = flb_input(ctx, (char *) "lib", NULL);
        TEST_CHECK(input_fds[index] >= 0);
        snprintf(tag, sizeof(tag), "startup-test-%d", index);
        flb_input_set(ctx, input_fds[index], "tag", tag, NULL);
    }

    out_ffd = flb_output(ctx, (char *) "s3", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "*", NULL);
    flb_output_set(ctx, out_ffd, "region", "us-west-2", NULL);
    flb_output_set(ctx, out_ffd, "bucket", "fluent", NULL);
    flb_output_set(ctx, out_ffd, "use_put_object", "true", NULL);
    flb_output_set(ctx, out_ffd, "total_file_size", "5M", NULL);
    flb_output_set(ctx, out_ffd, "upload_timeout", S3_TEST_UPLOAD_TIMEOUT, NULL);
    flb_output_set(ctx, out_ffd, "store_dir", store_dir, NULL);
    flb_output_set(ctx, out_ffd, "store_dir_limit_size", "1M", NULL);
    flb_output_set(ctx, out_ffd, "retry_limit", "10", NULL);
    flb_output_set(ctx, out_ffd, "retry_exhausted_action", "delete", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    for (index = 0; index < S3_TEST_STARTUP_FILE_COUNT; index++) {
        ret = flb_lib_push(ctx, input_fds[index],
                           (char *) JSON_TD, (int) sizeof(JSON_TD) - 1);
        TEST_CHECK(ret >= 0);
    }
    wait_for_s3_call_count("PutObject", S3_TEST_STARTUP_FILE_COUNT);

    s3_ctx = get_s3_context(ctx);
    TEST_CHECK(s3_ctx != NULL);
    snprintf(old_stream_dir, sizeof(old_stream_dir), "%s",
             s3_ctx->stream_active->path);
    live_buffer_size = cfl_atomic_load(&s3_ctx->current_buffer_size);
    TEST_CHECK_(live_buffer_size > 0,
                "Expected live buffer accounting to contain payload bytes");

    flb_stop(ctx);
    flb_destroy(ctx);

    file_count = count_files_recursive(store_dir);
    TEST_CHECK_(file_count >= S3_TEST_STARTUP_FILE_COUNT,
                "Expected at least %d buffered files to survive the first run, got %d",
                S3_TEST_STARTUP_FILE_COUNT, file_count);

    /* Ensure the next process gets a distinct active stream directory. */
    flb_time_msleep(1100);

    unsetenv("TEST_PutObject_CALL_COUNT");

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
    flb_output_set(ctx, out_ffd, "store_dir_limit_size", "1M", NULL);
    flb_output_set(ctx, out_ffd, "retry_limit", "10", NULL);
    flb_output_set(ctx, out_ffd, "retry_exhausted_action", "delete", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    call_count = get_s3_call_count("PutObject");
    TEST_CHECK_(call_count == 1,
                "Expected ordered startup drain to stop after one failure, got %d attempts",
                call_count);

    s3_ctx = get_s3_context(ctx);
    TEST_CHECK(s3_ctx != NULL);
    restored_buffer_size = cfl_atomic_load(&s3_ctx->current_buffer_size);
    TEST_CHECK_(restored_buffer_size == live_buffer_size,
                "Expected restored payload bytes=%" PRIu64 ", got %" PRIu64,
                live_buffer_size, restored_buffer_size);

    flb_stop(ctx);
    flb_destroy(ctx);

    unsetenv("TEST_PUT_OBJECT_ERROR");
    unsetenv("TEST_PutObject_CALL_COUNT");

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
    flb_output_set(ctx, out_ffd, "store_dir_limit_size", "1M", NULL);
    flb_output_set(ctx, out_ffd, "retry_limit", "10", NULL);
    flb_output_set(ctx, out_ffd, "retry_exhausted_action", "delete", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);
    wait_for_s3_call_count("PutObject", S3_TEST_STARTUP_FILE_COUNT);

    TEST_CHECK_(test_directory_exists(old_stream_dir) == 0,
                "Expected drained startup stream directory to be removed: %s",
                old_stream_dir);

    ret = flb_lib_push(ctx, in_ffd, (char *) JSON_TD, (int) sizeof(JSON_TD) - 1);
    TEST_CHECK(ret >= 0);
    wait_for_s3_call_count("PutObject", S3_TEST_STARTUP_FILE_COUNT + 1);

    call_count = get_s3_call_count("PutObject");
    TEST_CHECK_(call_count == S3_TEST_STARTUP_FILE_COUNT + 1,
                "Expected %d startup resends and one new upload, got %d PutObject calls",
                S3_TEST_STARTUP_FILE_COUNT, call_count);

    flb_stop(ctx);
    flb_destroy(ctx);

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
    {"empty_upload_queue_file_deleted", flb_test_s3_empty_upload_queue_file_deleted },
    {"near_full_buffer_append_succeeds", flb_test_s3_near_full_buffer_append_succeeds },
    {"startup_index_order_after_failure", flb_test_s3_startup_index_order_after_failure },
    {"startup_buffer_size_accounting", flb_test_s3_startup_buffer_size_accounting },
    {"create_upload_error", flb_test_s3_create_upload_error },
    {"upload_part_error", flb_test_s3_upload_part_error },
    {"complete_upload_error", flb_test_s3_complete_upload_error },
    {"ordered_retry_uses_backoff_deadline", flb_test_s3_ordered_retry_uses_backoff_deadline },
    {"ordered_timer_preserves_chunk_order", flb_test_s3_ordered_timer_preserves_chunk_order },
    {"ordered_construct_error_exhausts_chunk", flb_test_s3_ordered_construct_error_exhausts_chunk },
    {"ordered_backoff_does_not_starve_completion", flb_test_s3_ordered_backoff_does_not_starve_completion },
    {"ordered_shared_upload_retries_safely", flb_test_s3_ordered_shared_upload_retries_safely },
    {"compression_gzip", flb_test_s3_compression_gzip },
    {"compression_gzip_putobject", flb_test_s3_compression_gzip_putobject },
    {"compression_zstd", flb_test_s3_compression_zstd },
    {"compression_zstd_putobject", flb_test_s3_compression_zstd_putobject },
    {"compression_snappy", flb_test_s3_compression_snappy },
    {"compression_snappy_putobject", flb_test_s3_compression_snappy_putobject },
    {"preserve_data_ordering", flb_test_s3_preserve_data_ordering },
    {NULL, NULL}
};
