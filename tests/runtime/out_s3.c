/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
#include <fluent-bit.h>
#include <fluent-bit/aws/flb_aws_compress.h>
#include <fluent-bit/flb_time.h>
#include <cfl/cfl_atomic.h>
#include "../../plugins/out_s3/s3.h"
#include "../../plugins/out_s3/s3_store.h"
#define TEST_FINI flb_s3_test_env_reset()
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
#define S3_TEST_STARTUP_FILE_COUNT (CIO_MAX_CHUNKS_UP + 2)
#define S3_TEST_CA_FILE FLB_TESTS_DATA_PATH "/data/tls/ca_certificate.pem"

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

static void flb_test_s3_hostname_verification_propagates(void)
{
    flb_ctx_t *ctx;
    struct flb_s3 *s3;
    int in_ffd;
    int out_ffd;
    int ret;
    int verify_hostname;

    setenv("FLB_S3_PLUGIN_UNDER_TEST", "true", 1);

    for (verify_hostname = FLB_FALSE; verify_hostname <= FLB_TRUE; verify_hostname++) {
        ctx = flb_create();
        TEST_CHECK(ctx != NULL);
        if (ctx == NULL) {
            break;
        }

        in_ffd = flb_input(ctx, (char *) "lib", NULL);
        TEST_CHECK(in_ffd >= 0);
        flb_input_set(ctx, in_ffd, "tag", "test", NULL);

        out_ffd = flb_output(ctx, (char *) "s3", NULL);
        TEST_CHECK(out_ffd >= 0);
        flb_output_set(ctx, out_ffd, "match", "*", NULL);
        flb_output_set(ctx, out_ffd, "region", "us-west-2", NULL);
        flb_output_set(ctx, out_ffd, "bucket", "fluent", NULL);
        flb_output_set(ctx, out_ffd, "authorization_endpoint_url",
                       "https://localhost:1443/authorize", NULL);
        flb_output_set(ctx, out_ffd, "tls.ca_file", S3_TEST_CA_FILE, NULL);
        if (verify_hostname == FLB_TRUE) {
            flb_output_set(ctx, out_ffd, "tls.verify_hostname", "on", NULL);
        }

        ret = flb_start(ctx);
        TEST_CHECK(ret == 0);
        if (ret == 0) {
            s3 = get_s3_context(ctx);
            TEST_CHECK(s3 != NULL);
            if (s3 != NULL) {
                TEST_CHECK(s3->client_tls != NULL);
                TEST_CHECK(s3->provider_tls != NULL);
                TEST_CHECK(s3->authorization_endpoint_tls_context != NULL);
                if (s3->client_tls != NULL && s3->provider_tls != NULL) {
                    TEST_CHECK(s3->client_tls->verify_hostname == verify_hostname);
                    TEST_CHECK(s3->provider_tls->verify_hostname == verify_hostname);
                }
                if (s3->authorization_endpoint_tls_context != NULL) {
                    TEST_CHECK(s3->authorization_endpoint_tls_context->verify == FLB_TRUE);
                    TEST_CHECK(s3->authorization_endpoint_tls_context->verify_hostname ==
                               FLB_TRUE);
                    TEST_CHECK(s3->authorization_endpoint_tls_context->ca_file != NULL);
                    if (s3->authorization_endpoint_tls_context->ca_file != NULL) {
                        TEST_CHECK(strcmp(s3->authorization_endpoint_tls_context->ca_file,
                                          S3_TEST_CA_FILE) == 0);
                    }
                }
            }
            flb_stop(ctx);
        }
        flb_destroy(ctx);
    }

    unsetenv("FLB_S3_PLUGIN_UNDER_TEST");
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

static int count_sized_down_s3_files(struct flb_s3 *ctx)
{
    int count;
    struct s3_file *s3_file;
    struct flb_fstore_file *fsf;
    struct flb_fstore_stream *fs_stream;
    struct mk_list *file_head;
    struct mk_list *stream_head;

    count = 0;

    mk_list_foreach(stream_head, &ctx->fs->streams) {
        fs_stream = mk_list_entry(stream_head, struct flb_fstore_stream, _head);
        if (fs_stream == ctx->stream_upload) {
            continue;
        }

        mk_list_foreach(file_head, &fs_stream->files) {
            fsf = mk_list_entry(file_head, struct flb_fstore_file, _head);
            if (fsf->chunk == NULL || fsf->data == NULL ||
                cio_chunk_is_up(fsf->chunk) == CIO_TRUE) {
                continue;
            }

            s3_file = fsf->data;
            if (cfl_atomic_load(&s3_file->size) > 0) {
                count++;
            }
        }
    }

    return count;
}

static int get_s3_call_count(const char *api)
{
    char name[64];
    char *value;

    snprintf(name, sizeof(name), "TEST_%s_CALL_COUNT", api);
    value = flb_s3_test_env_get(name);

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

static void wait_for_s3_retry_time(struct flb_s3 *ctx, time_t expected)
{
    uint64_t elapsed_ms;
    struct flb_time start_time;
    struct flb_time end_time;
    struct flb_time diff_time;

    elapsed_ms = 0;
    flb_time_get(&start_time);

    while (ctx->retry_time != expected && elapsed_ms < S3_TEST_WAIT_TIMEOUT_MS) {
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

static int wait_for_shared_upload_cleanup(struct flb_s3 *ctx,
                                          char *first_name, char *second_name)
{
    uint64_t elapsed_ms;
    struct flb_time start_time;
    struct flb_time end_time;
    struct flb_time diff_time;

    elapsed_ms = 0;
    flb_time_get(&start_time);

    while (elapsed_ms < S3_TEST_WAIT_TIMEOUT_MS) {
        pthread_mutex_lock(&ctx->files_mutex);
        if (flb_fstore_file_get(ctx->fs, ctx->stream_active,
                               first_name, strlen(first_name)) == NULL &&
            flb_fstore_file_get(ctx->fs, ctx->stream_active,
                               second_name, strlen(second_name)) == NULL &&
            mk_list_is_empty(&ctx->upload_queue) == 0) {
            pthread_mutex_unlock(&ctx->files_mutex);
            return 0;
        }
        pthread_mutex_unlock(&ctx->files_mutex);

        flb_time_msleep(S3_TEST_WAIT_STEP_MS);
        flb_time_get(&end_time);
        flb_time_diff(&end_time, &start_time, &diff_time);
        elapsed_ms = flb_time_to_nanosec(&diff_time) / 1000000;
    }

    return -1;
}

static int wait_for_s3_file_create_time(struct flb_s3 *ctx, const char *tag,
                                        int tag_len, time_t create_time,
                                        char *file_name, size_t file_name_size)
{
    uint64_t elapsed_ms;
    struct s3_file *s3_file;
    struct flb_time start_time;
    struct flb_time end_time;
    struct flb_time diff_time;

    elapsed_ms = 0;
    flb_time_get(&start_time);

    /* The backing file can be visible before its in-memory state is registered. */
    while (elapsed_ms < S3_TEST_WAIT_TIMEOUT_MS) {
        pthread_mutex_lock(&ctx->files_mutex);
        s3_file = s3_store_file_get(ctx, tag, tag_len);
        if (s3_file != NULL) {
            if (file_name != NULL) {
                snprintf(file_name, file_name_size, "%s", s3_file->fsf->name);
            }
            s3_file->create_time = create_time;
            pthread_mutex_unlock(&ctx->files_mutex);
            return 0;
        }
        pthread_mutex_unlock(&ctx->files_mutex);

        flb_time_msleep(S3_TEST_WAIT_STEP_MS);
        flb_time_get(&end_time);
        flb_time_diff(&end_time, &start_time, &diff_time);
        elapsed_ms = flb_time_to_nanosec(&diff_time) / 1000000;
    }

    return -1;
}

static int prepare_s3_ordered_files(struct flb_s3 *ctx)
{
    uint64_t elapsed_ms;
    time_t now;
    struct s3_file *oldest_file;
    struct s3_file *later_file;
    struct flb_time start_time;
    struct flb_time end_time;
    struct flb_time diff_time;

    elapsed_ms = 0;
    flb_time_get(&start_time);

    while (elapsed_ms < S3_TEST_WAIT_TIMEOUT_MS) {
        pthread_mutex_lock(&ctx->files_mutex);
        oldest_file = s3_store_file_get(ctx, "oldest", 6);
        later_file = s3_store_file_get(ctx, "later", 5);
        if (oldest_file != NULL && later_file != NULL) {
            /* Publish both deadlines together so the timer sees the intended order. */
            now = time(NULL);
            oldest_file->create_time = now - 30;
            later_file->create_time = now - 20;
            pthread_mutex_unlock(&ctx->files_mutex);
            return 0;
        }
        pthread_mutex_unlock(&ctx->files_mutex);

        flb_time_msleep(S3_TEST_WAIT_STEP_MS);
        flb_time_get(&end_time);
        flb_time_diff(&end_time, &start_time, &diff_time);
        elapsed_ms = flb_time_to_nanosec(&diff_time) / 1000000;
    }

    return -1;
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
    flb_s3_test_env_set("FLB_S3_PLUGIN_UNDER_TEST", "true", 1);

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

    call_count_str = flb_s3_test_env_get("TEST_CompleteMultipartUpload_CALL_COUNT");
    call_count = call_count_str ? atoi(call_count_str) : 0;
    TEST_CHECK_(call_count == 1,
                "Expected 1 CompleteMultipartUpload call, got %d", call_count);

    flb_stop(ctx);
    flb_destroy(ctx);
    flb_s3_test_env_unset("FLB_S3_PLUGIN_UNDER_TEST");
    flb_s3_test_env_unset("TEST_CreateMultipartUpload_CALL_COUNT");
    flb_s3_test_env_unset("TEST_UploadPart_CALL_COUNT");
    flb_s3_test_env_unset("TEST_CompleteMultipartUpload_CALL_COUNT");
    flb_s3_test_env_unset("TEST_PutObject_CALL_COUNT");
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
    flb_s3_test_env_set("FLB_S3_PLUGIN_UNDER_TEST", "true", 1);

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

    call_count_str = flb_s3_test_env_get("TEST_PutObject_CALL_COUNT");
    call_count = call_count_str ? atoi(call_count_str) : 0;
    TEST_CHECK_(call_count == 1,
                "Expected 1 PutObject call, got %d", call_count);

    flb_stop(ctx);
    flb_destroy(ctx);
    flb_s3_test_env_unset("FLB_S3_PLUGIN_UNDER_TEST");
    flb_s3_test_env_unset("TEST_PutObject_CALL_COUNT");
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
    flb_s3_test_env_set("FLB_S3_PLUGIN_UNDER_TEST", "true", 1);
    flb_s3_test_env_set("TEST_PUT_OBJECT_ERROR", ERROR_ACCESS_DENIED, 1);

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

    call_count_str = flb_s3_test_env_get("TEST_PutObject_CALL_COUNT");
    call_count = call_count_str ? atoi(call_count_str) : 0;
    TEST_CHECK_(call_count >= 1,
                "Expected >= 1 PutObject calls, got %d", call_count);

    flb_stop(ctx);
    flb_destroy(ctx);
    flb_s3_test_env_unset("FLB_S3_PLUGIN_UNDER_TEST");
    flb_s3_test_env_unset("TEST_PUT_OBJECT_ERROR");
    flb_s3_test_env_unset("TEST_PutObject_CALL_COUNT");
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
    flb_s3_test_env_set("FLB_S3_PLUGIN_UNDER_TEST", "true", 1);
    flb_s3_test_env_set("TEST_CREATE_MULTIPART_UPLOAD_ERROR", ERROR_ACCESS_DENIED, 1);

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

    call_count_str = flb_s3_test_env_get("TEST_CreateMultipartUpload_CALL_COUNT");
    call_count = call_count_str ? atoi(call_count_str) : 0;
    TEST_CHECK_(call_count == 2,
                "Expected CreateMultipartUpload to stop after two attempts, got %d",
                call_count);
    TEST_CHECK_(count_files_recursive(s3_ctx->stream_active->path) == 0,
                "Expected retry-exhausted chunk to be deleted");

    call_count_str = flb_s3_test_env_get("TEST_UploadPart_CALL_COUNT");
    call_count = call_count_str ? atoi(call_count_str) : 0;
    TEST_CHECK_(call_count == 0,
                "Expected 0 UploadPart calls, got %d", call_count);

    flb_stop(ctx);
    flb_destroy(ctx);
    flb_s3_test_env_unset("FLB_S3_PLUGIN_UNDER_TEST");
    flb_s3_test_env_unset("TEST_CREATE_MULTIPART_UPLOAD_ERROR");
    flb_s3_test_env_unset("TEST_CreateMultipartUpload_CALL_COUNT");
    flb_s3_test_env_unset("TEST_UploadPart_CALL_COUNT");
    flb_s3_test_env_unset("TEST_CompleteMultipartUpload_CALL_COUNT");
    flb_s3_test_env_unset("TEST_PutObject_CALL_COUNT");
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
    flb_s3_test_env_set("FLB_S3_PLUGIN_UNDER_TEST", "true", 1);
    flb_s3_test_env_set("TEST_UPLOAD_PART_ERROR", ERROR_ACCESS_DENIED, 1);

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

    call_count_str = flb_s3_test_env_get("TEST_UploadPart_CALL_COUNT");
    call_count = call_count_str ? atoi(call_count_str) : 0;
    TEST_CHECK_(call_count >= 1,
                "Expected >= 1 UploadPart calls, got %d", call_count);

    call_count_str = flb_s3_test_env_get("TEST_CompleteMultipartUpload_CALL_COUNT");
    call_count = call_count_str ? atoi(call_count_str) : 0;
    TEST_CHECK_(call_count == 0,
                "Expected 0 CompleteMultipartUpload calls, got %d", call_count);

    flb_stop(ctx);
    flb_destroy(ctx);
    flb_s3_test_env_unset("FLB_S3_PLUGIN_UNDER_TEST");
    flb_s3_test_env_unset("TEST_UPLOAD_PART_ERROR");
    flb_s3_test_env_unset("TEST_CreateMultipartUpload_CALL_COUNT");
    flb_s3_test_env_unset("TEST_UploadPart_CALL_COUNT");
    flb_s3_test_env_unset("TEST_CompleteMultipartUpload_CALL_COUNT");
    flb_s3_test_env_unset("TEST_PutObject_CALL_COUNT");
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
    flb_s3_test_env_set("FLB_S3_PLUGIN_UNDER_TEST", "true", 1);
    flb_s3_test_env_set("TEST_COMPLETE_MULTIPART_UPLOAD_ERROR", ERROR_ACCESS_DENIED, 1);

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

    call_count_str = flb_s3_test_env_get("TEST_CompleteMultipartUpload_CALL_COUNT");
    call_count = call_count_str ? atoi(call_count_str) : 0;
    TEST_CHECK_(call_count >= 2,
                "Expected >= 2 CompleteMultipartUpload calls (retried), got %d",
                call_count);

    wait_for_file_count(s3_ctx->stream_upload->path, 1);
    TEST_CHECK_(count_files_recursive(s3_ctx->stream_upload->path) > 0,
                "Expected multipart metadata to remain recoverable after completion failure");

    flb_stop(ctx);
    flb_destroy(ctx);
    flb_s3_test_env_unset("FLB_S3_PLUGIN_UNDER_TEST");
    flb_s3_test_env_unset("TEST_COMPLETE_MULTIPART_UPLOAD_ERROR");
    flb_s3_test_env_unset("TEST_CreateMultipartUpload_CALL_COUNT");
    flb_s3_test_env_unset("TEST_UploadPart_CALL_COUNT");
    flb_s3_test_env_unset("TEST_CompleteMultipartUpload_CALL_COUNT");
    flb_s3_test_env_unset("TEST_PutObject_CALL_COUNT");
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

    store_dir = create_test_store_directory("/flb-s3-test-retry-deadline-XXXXXX");
    TEST_CHECK(store_dir != NULL);
    if (store_dir == NULL) {
        return;
    }

    flb_s3_test_env_set("FLB_S3_PLUGIN_UNDER_TEST", "true", 1);
    flb_s3_test_env_set("TEST_UPLOAD_PART_ERROR", ERROR_ACCESS_DENIED, 1);

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
    ret = wait_for_s3_file_create_time(s3_ctx, "retry-deadline", 14,
                                       time(NULL) - 61, NULL, 0);
    TEST_CHECK_(ret == 0, "Expected retry-deadline chunk to be created");
    if (ret != 0) {
        flb_stop(ctx);
        flb_destroy(ctx);
        flb_s3_test_env_unset("FLB_S3_PLUGIN_UNDER_TEST");
        flb_s3_test_env_unset("TEST_UPLOAD_PART_ERROR");
        flb_s3_test_env_unset("TEST_CreateMultipartUpload_CALL_COUNT");
        flb_s3_test_env_unset("TEST_UploadPart_CALL_COUNT");
        flb_free(store_dir);
        return;
    }

    ret = flb_lib_push(ctx, in_ffd, (char *) JSON_TD,
                       (int) sizeof(JSON_TD) - 1);
    TEST_CHECK(ret >= 0);
    wait_for_s3_call_count("UploadPart", 1);
    wait_for_s3_retry_time(s3_ctx, 2);
    TEST_CHECK_(s3_ctx->retry_time == 2,
                "Expected first retry to add a 2 second timeout offset, got %lld",
                (long long) s3_ctx->retry_time);
    wait_for_file_count_at_most(s3_ctx->stream_active->path, 0);

    TEST_CHECK_(get_s3_call_count("UploadPart") == 2,
                "Expected initial attempt and one retry at its deadline, got %d",
                get_s3_call_count("UploadPart"));
    TEST_CHECK_(count_files_recursive(s3_ctx->stream_active->path) == 0,
                "Expected retry-exhausted chunk to be deleted before periodic timer");
    /* Unlinking the chunk precedes the worker's retry state reset. */
    wait_for_s3_retry_time(s3_ctx, 0);
    TEST_CHECK_(s3_ctx->retry_time == 0,
                "Expected terminal cleanup to reset the timeout offset");

    flb_stop(ctx);
    flb_destroy(ctx);

    flb_s3_test_env_unset("FLB_S3_PLUGIN_UNDER_TEST");
    flb_s3_test_env_unset("TEST_UPLOAD_PART_ERROR");
    flb_s3_test_env_unset("TEST_CreateMultipartUpload_CALL_COUNT");
    flb_s3_test_env_unset("TEST_UploadPart_CALL_COUNT");
    flb_free(store_dir);
}

void flb_test_s3_ordered_timer_isolates_tag_backoff(void)
{
    int ret;
    int index;
    int out_ffd;
    int input_fds[2];
    char *uri;
    flb_ctx_t *ctx;
    char *store_dir;
    struct flb_s3 *s3_ctx;

    store_dir = create_test_store_directory("/flb-s3-test-timer-order-XXXXXX");
    TEST_CHECK(store_dir != NULL);
    if (store_dir == NULL) {
        return;
    }

    flb_s3_test_env_set("FLB_S3_PLUGIN_UNDER_TEST", "true", 1);
    flb_s3_test_env_set("TEST_RECORD_S3_URIS", "true", 1);
    flb_s3_test_env_set("TEST_PUT_OBJECT_ERROR_TAG", "oldest", 1);

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
    flb_s3_test_env_set("TEST_PUT_OBJECT_ERROR", ERROR_ACCESS_DENIED, 1);
    ret = prepare_s3_ordered_files(s3_ctx);
    TEST_CHECK_(ret == 0, "Expected both ordered chunks to be created");
    if (ret != 0) {
        goto cleanup;
    }
    wait_for_s3_call_count("PutObject", 1);
    flb_time_msleep(500);

    TEST_CHECK_(get_s3_call_count("PutObject") == 2,
                "Expected the healthy tag to upload during another tag's backoff, got %d calls",
                get_s3_call_count("PutObject"));
    TEST_CHECK_(s3_ctx->retry_time == 0,
                "Expected the healthy upload to preserve the global retry reset behavior");
    uri = flb_s3_test_env_get("TEST_PutObject_URI_1");
    TEST_CHECK_(uri != NULL && strcmp(uri, "/fluent/queue/oldest") == 0,
                "Expected oldest timed-out chunk first, got %s",
                uri ? uri : "(null)");
    uri = flb_s3_test_env_get("TEST_PutObject_URI_2");
    TEST_CHECK_(uri != NULL && strcmp(uri, "/fluent/queue/later") == 0,
                "Expected healthy tag during oldest tag's backoff, got %s",
                uri ? uri : "(null)");

    flb_s3_test_env_unset("TEST_PUT_OBJECT_ERROR");
    wait_for_s3_call_count("PutObject", 3);
    uri = flb_s3_test_env_get("TEST_PutObject_URI_3");
    TEST_CHECK_(uri != NULL && strcmp(uri, "/fluent/queue/oldest") == 0,
                "Expected failed tag to retry at its deadline, got %s",
                uri ? uri : "(null)");

cleanup:
    flb_stop(ctx);
    flb_destroy(ctx);

    flb_s3_test_env_unset("FLB_S3_PLUGIN_UNDER_TEST");
    flb_s3_test_env_unset("TEST_PUT_OBJECT_ERROR");
    flb_s3_test_env_unset("TEST_PUT_OBJECT_ERROR_TAG");
    flb_s3_test_env_unset("TEST_RECORD_S3_URIS");
    flb_s3_test_env_unset("TEST_PutObject_CALL_COUNT");
    flb_s3_test_env_unset("TEST_PutObject_URI_1");
    flb_s3_test_env_unset("TEST_PutObject_URI_2");
    flb_s3_test_env_unset("TEST_PutObject_URI_3");
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

    store_dir = create_test_store_directory("/flb-s3-test-construct-error-XXXXXX");
    TEST_CHECK(store_dir != NULL);
    if (store_dir == NULL) {
        return;
    }

    flb_s3_test_env_set("FLB_S3_PLUGIN_UNDER_TEST", "true", 1);

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
    flb_s3_test_env_set("TEST_CONSTRUCT_REQUEST_BUFFER_ERROR", "true", 1);
    ret = wait_for_s3_file_create_time(s3_ctx, "construct-error", 15,
                                       time(NULL) - 61, NULL, 0);
    TEST_CHECK_(ret == 0, "Expected construct-error chunk to be created");
    if (ret != 0) {
        goto cleanup;
    }

    ret = flb_lib_push(ctx, in_ffd, (char *) JSON_TD,
                       (int) sizeof(JSON_TD) - 1);
    TEST_CHECK(ret >= 0);
    wait_for_file_count_at_most(s3_ctx->stream_active->path, 0);

    TEST_CHECK_(count_files_recursive(s3_ctx->stream_active->path) == 0,
                "Expected unreadable queue head to reach terminal cleanup");
    wait_for_s3_retry_time(s3_ctx, 0);
    TEST_CHECK_(mk_list_is_empty(&s3_ctx->upload_queue) == 0,
                "Expected queue to be empty after construction retry exhaustion");
    TEST_CHECK_(s3_ctx->retry_time == 0,
                "Expected retry delay to reset after terminal cleanup");

cleanup:
    flb_s3_test_env_unset("TEST_CONSTRUCT_REQUEST_BUFFER_ERROR");
    flb_stop(ctx);
    flb_destroy(ctx);

    flb_s3_test_env_unset("FLB_S3_PLUGIN_UNDER_TEST");
    flb_s3_test_env_unset("TEST_PutObject_CALL_COUNT");
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

    store_dir = create_test_store_directory("/flb-s3-test-completion-backoff-XXXXXX");
    TEST_CHECK(store_dir != NULL);
    if (store_dir == NULL) {
        return;
    }

    flb_s3_test_env_set("FLB_S3_PLUGIN_UNDER_TEST", "true", 1);
    flb_s3_test_env_set("TEST_COMPLETE_MULTIPART_UPLOAD_ERROR", ERROR_ACCESS_DENIED, 1);

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
    /* Wait for the requested tag's initialized chunk, not an on-disk file. */
    ret = wait_for_s3_file_create_time(s3_ctx, "completing", 10,
                                       time(NULL) - 61, NULL, 0);
    TEST_CHECK_(ret == 0, "Expected completing chunk to be initialized");
    if (ret != 0) {
        goto cleanup;
    }
    ret = flb_lib_push(ctx, input_fds[0], (char *) JSON_TD,
                       (int) sizeof(JSON_TD) - 1);
    TEST_CHECK(ret >= 0);
    wait_for_s3_call_count("CompleteMultipartUpload", 1);

    ret = flb_lib_push(ctx, input_fds[1], (char *) JSON_TD,
                       (int) sizeof(JSON_TD) - 1);
    TEST_CHECK(ret >= 0);
    ret = wait_for_s3_file_create_time(s3_ctx, "backoff", 7,
                                       time(NULL) - 61, NULL, 0);
    TEST_CHECK_(ret == 0, "Expected backoff chunk to be initialized");
    if (ret != 0) {
        goto cleanup;
    }
    flb_s3_test_env_set("TEST_CREATE_MULTIPART_UPLOAD_ERROR", ERROR_ACCESS_DENIED, 1);
    ret = flb_lib_push(ctx, input_fds[1], (char *) JSON_TD,
                       (int) sizeof(JSON_TD) - 1);
    TEST_CHECK(ret >= 0);

    wait_for_s3_call_count("CreateMultipartUpload", 2);
    wait_for_s3_call_count("CompleteMultipartUpload", 2);
    TEST_CHECK_(get_s3_call_count("CompleteMultipartUpload") >= 2,
                "Expected pending completion to run while queue head was backing off");

cleanup:
    flb_s3_test_env_unset("TEST_CREATE_MULTIPART_UPLOAD_ERROR");
    flb_s3_test_env_unset("TEST_COMPLETE_MULTIPART_UPLOAD_ERROR");
    flb_stop(ctx);
    flb_destroy(ctx);

    flb_s3_test_env_unset("FLB_S3_PLUGIN_UNDER_TEST");
    flb_s3_test_env_unset("TEST_CreateMultipartUpload_CALL_COUNT");
    flb_s3_test_env_unset("TEST_UploadPart_CALL_COUNT");
    flb_s3_test_env_unset("TEST_CompleteMultipartUpload_CALL_COUNT");
    flb_s3_test_env_unset("TEST_PutObject_CALL_COUNT");
    flb_free(store_dir);
}

void flb_test_s3_ordered_shared_upload_retries_safely(void)
{
    int ret;
    int in_ffd;
    int out_ffd;
    flb_ctx_t *ctx;
    char *store_dir;
    char first_file_name[128];
    char second_file_name[128];
    struct flb_s3 *s3_ctx;

    store_dir = create_test_store_directory("/flb-s3-test-shared-upload-XXXXXX");
    TEST_CHECK(store_dir != NULL);
    if (store_dir == NULL) {
        return;
    }

    flb_s3_test_env_set("FLB_S3_PLUGIN_UNDER_TEST", "true", 1);
    flb_s3_test_env_set("TEST_UPLOAD_PART_ERROR", ERROR_ACCESS_DENIED, 1);

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
    ret = wait_for_s3_file_create_time(s3_ctx, "shared-upload", 13,
                                       time(NULL) - 61,
                                       first_file_name, sizeof(first_file_name));
    TEST_CHECK_(ret == 0, "Expected first shared-upload chunk to be created");
    if (ret != 0) {
        goto cleanup;
    }

    ret = flb_lib_push(ctx, in_ffd, (char *) JSON_TD,
                       (int) sizeof(JSON_TD) - 1);
    TEST_CHECK(ret >= 0);
    wait_for_s3_call_count("UploadPart", 1);

    ret = flb_lib_push(ctx, in_ffd, (char *) JSON_TD,
                       (int) sizeof(JSON_TD) - 1);
    TEST_CHECK(ret >= 0);
    ret = wait_for_s3_file_create_time(s3_ctx, "shared-upload", 13,
                                       time(NULL) - 61,
                                       second_file_name, sizeof(second_file_name));
    TEST_CHECK_(ret == 0, "Expected second shared-upload chunk to be created");
    if (ret != 0) {
        goto cleanup;
    }
    TEST_CHECK_(strcmp(first_file_name, second_file_name) != 0,
                "Expected two distinct shared-upload chunks");

    wait_for_s3_call_count("UploadPart", 3);
    ret = flb_lib_push(ctx, in_ffd, (char *) JSON_TD,
                       (int) sizeof(JSON_TD) - 1);
    TEST_CHECK(ret >= 0);
    wait_for_file_count(s3_ctx->stream_active->path, 2);
    wait_for_s3_call_count("UploadPart", 4);
    ret = wait_for_shared_upload_cleanup(s3_ctx, first_file_name, second_file_name);
    TEST_CHECK_(ret == 0, "Expected both shared-upload chunks to finish cleanup");

    pthread_mutex_lock(&s3_ctx->files_mutex);
    TEST_CHECK_(get_s3_call_count("UploadPart") == 4,
                "Expected both shared-upload chunks to exhaust safely, got %d attempts",
                get_s3_call_count("UploadPart"));
    TEST_CHECK_(flb_fstore_file_get(s3_ctx->fs, s3_ctx->stream_active,
                                    first_file_name, strlen(first_file_name)) == NULL,
                "Expected first retry-exhausted chunk to be deleted");
    TEST_CHECK_(flb_fstore_file_get(s3_ctx->fs, s3_ctx->stream_active,
                                    second_file_name, strlen(second_file_name)) == NULL,
                "Expected second retry-exhausted chunk to be deleted");
    TEST_CHECK_(mk_list_is_empty(&s3_ctx->upload_queue) == 0,
                "Expected shared-upload queue to be empty");
    pthread_mutex_unlock(&s3_ctx->files_mutex);

cleanup:
    flb_stop(ctx);
    flb_destroy(ctx);

    flb_s3_test_env_unset("FLB_S3_PLUGIN_UNDER_TEST");
    flb_s3_test_env_unset("TEST_UPLOAD_PART_ERROR");
    flb_s3_test_env_unset("TEST_CreateMultipartUpload_CALL_COUNT");
    flb_s3_test_env_unset("TEST_UploadPart_CALL_COUNT");
    flb_s3_test_env_unset("TEST_CompleteMultipartUpload_CALL_COUNT");
    flb_s3_test_env_unset("TEST_PutObject_CALL_COUNT");
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
    flb_s3_test_env_set("FLB_S3_PLUGIN_UNDER_TEST", "true", 1);

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

    call_count_str = flb_s3_test_env_get("TEST_CompleteMultipartUpload_CALL_COUNT");
    call_count = call_count_str ? atoi(call_count_str) : 0;
    TEST_CHECK_(call_count == 1,
                "Expected 1 CompleteMultipartUpload call, got %d", call_count);

    flb_stop(ctx);
    flb_destroy(ctx);
    flb_s3_test_env_unset("FLB_S3_PLUGIN_UNDER_TEST");
    flb_s3_test_env_unset("TEST_CreateMultipartUpload_CALL_COUNT");
    flb_s3_test_env_unset("TEST_UploadPart_CALL_COUNT");
    flb_s3_test_env_unset("TEST_CompleteMultipartUpload_CALL_COUNT");
    flb_s3_test_env_unset("TEST_PutObject_CALL_COUNT");
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
    flb_s3_test_env_set("FLB_S3_PLUGIN_UNDER_TEST", "true", 1);

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

    call_count_str = flb_s3_test_env_get("TEST_PutObject_CALL_COUNT");
    call_count = call_count_str ? atoi(call_count_str) : 0;
    TEST_CHECK_(call_count == 1,
                "Expected 1 PutObject call, got %d", call_count);

    flb_stop(ctx);
    flb_destroy(ctx);
    flb_s3_test_env_unset("FLB_S3_PLUGIN_UNDER_TEST");
    flb_s3_test_env_unset("TEST_PutObject_CALL_COUNT");
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
    flb_s3_test_env_set("FLB_S3_PLUGIN_UNDER_TEST", "true", 1);

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

    call_count_str = flb_s3_test_env_get("TEST_CompleteMultipartUpload_CALL_COUNT");
    call_count = call_count_str ? atoi(call_count_str) : 0;
    TEST_CHECK_(call_count == 1,
                "Expected 1 CompleteMultipartUpload call, got %d", call_count);

    flb_stop(ctx);
    flb_destroy(ctx);
    flb_s3_test_env_unset("FLB_S3_PLUGIN_UNDER_TEST");
    flb_s3_test_env_unset("TEST_CreateMultipartUpload_CALL_COUNT");
    flb_s3_test_env_unset("TEST_UploadPart_CALL_COUNT");
    flb_s3_test_env_unset("TEST_CompleteMultipartUpload_CALL_COUNT");
    flb_s3_test_env_unset("TEST_PutObject_CALL_COUNT");
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
    flb_s3_test_env_set("FLB_S3_PLUGIN_UNDER_TEST", "true", 1);

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

    call_count_str = flb_s3_test_env_get("TEST_PutObject_CALL_COUNT");
    call_count = call_count_str ? atoi(call_count_str) : 0;
    TEST_CHECK_(call_count == 1,
                "Expected 1 PutObject call, got %d", call_count);

    flb_stop(ctx);
    flb_destroy(ctx);
    flb_s3_test_env_unset("FLB_S3_PLUGIN_UNDER_TEST");
    flb_s3_test_env_unset("TEST_PutObject_CALL_COUNT");
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
    flb_s3_test_env_set("FLB_S3_PLUGIN_UNDER_TEST", "true", 1);

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

    call_count_str = flb_s3_test_env_get("TEST_CompleteMultipartUpload_CALL_COUNT");
    call_count = call_count_str ? atoi(call_count_str) : 0;
    TEST_CHECK_(call_count == 1,
                "Expected 1 CompleteMultipartUpload call, got %d", call_count);

    flb_stop(ctx);
    flb_destroy(ctx);
    flb_s3_test_env_unset("FLB_S3_PLUGIN_UNDER_TEST");
    flb_s3_test_env_unset("TEST_CreateMultipartUpload_CALL_COUNT");
    flb_s3_test_env_unset("TEST_UploadPart_CALL_COUNT");
    flb_s3_test_env_unset("TEST_CompleteMultipartUpload_CALL_COUNT");
    flb_s3_test_env_unset("TEST_PutObject_CALL_COUNT");
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
    flb_s3_test_env_set("FLB_S3_PLUGIN_UNDER_TEST", "true", 1);

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

    call_count_str = flb_s3_test_env_get("TEST_PutObject_CALL_COUNT");
    call_count = call_count_str ? atoi(call_count_str) : 0;
    TEST_CHECK_(call_count == 1,
                "Expected 1 PutObject call, got %d", call_count);

    flb_stop(ctx);
    flb_destroy(ctx);
    flb_s3_test_env_unset("FLB_S3_PLUGIN_UNDER_TEST");
    flb_s3_test_env_unset("TEST_PutObject_CALL_COUNT");
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

    flb_s3_test_env_set("FLB_S3_PLUGIN_UNDER_TEST", "true", 1);

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

    call_count_str = flb_s3_test_env_get("TEST_PutObject_CALL_COUNT");
    call_count = call_count_str ? atoi(call_count_str) : 0;
    TEST_CHECK_(call_count == 1,
                "Expected 1 PutObject call, got %d", call_count);

    flb_stop(ctx);
    flb_destroy(ctx);
    flb_s3_test_env_unset("FLB_S3_PLUGIN_UNDER_TEST");
    flb_s3_test_env_unset("TEST_PutObject_CALL_COUNT");
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
    flb_s3_test_env_set("FLB_S3_PLUGIN_UNDER_TEST", "true", 1);
    flb_s3_test_env_set("TEST_PUT_OBJECT_ERROR", ERROR_ACCESS_DENIED, 1);

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
    flb_s3_test_env_unset("TEST_PutObject_CALL_COUNT");

    /* Wait until the initial attempt and one retry have run. */
    flb_lib_push(ctx, in_ffd, (char *) JSON_TD, (int) sizeof(JSON_TD) - 1);
    wait_for_s3_call_count("PutObject", 2);

    flb_stop(ctx);
    flb_destroy(ctx);

    call_count_str = flb_s3_test_env_get("TEST_PutObject_CALL_COUNT");
    call_count = call_count_str ? atoi(call_count_str) : 0;

    /* retry_limit=1: 1 initial attempt + 1 retry = 2 PutObject calls */
    TEST_CHECK_(call_count == 2,
                "Expected 2 PutObject calls (1 attempt + 1 retry), got %d",
                call_count);

    flb_s3_test_env_unset("FLB_S3_PLUGIN_UNDER_TEST");
    flb_s3_test_env_unset("TEST_PUT_OBJECT_ERROR");
    flb_s3_test_env_unset("TEST_PutObject_CALL_COUNT");
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

    flb_s3_test_env_set("FLB_S3_PLUGIN_UNDER_TEST", "true", 1);
    flb_s3_test_env_set("TEST_PUT_OBJECT_ERROR", ERROR_ACCESS_DENIED, 1);

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

    flb_s3_test_env_unset("TEST_PutObject_CALL_COUNT");

    /* Wait for the initial attempt and all five default retries. */
    flb_lib_push(ctx, in_ffd, (char *) JSON_TD, (int) sizeof(JSON_TD) - 1);
    wait_for_s3_call_count_with_timeout("PutObject", 6, 40000);

    flb_stop(ctx);
    flb_destroy(ctx);

    call_count_str = flb_s3_test_env_get("TEST_PutObject_CALL_COUNT");
    call_count = call_count_str ? atoi(call_count_str) : 0;

    TEST_CHECK_(call_count == 6,
                "Expected 6 PutObject calls (default retry_limit=5), got %d",
                call_count);

    flb_s3_test_env_unset("FLB_S3_PLUGIN_UNDER_TEST");
    flb_s3_test_env_unset("TEST_PUT_OBJECT_ERROR");
    flb_s3_test_env_unset("TEST_PutObject_CALL_COUNT");
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

    flb_s3_test_env_set("FLB_S3_PLUGIN_UNDER_TEST", "true", 1);
    flb_s3_test_env_set("TEST_PUT_OBJECT_ERROR", ERROR_ACCESS_DENIED, 1);

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

    flb_s3_test_env_unset("TEST_PutObject_CALL_COUNT");
    flb_lib_push(ctx, in_ffd, (char *) JSON_TD, (int) sizeof(JSON_TD) - 1);
    wait_for_s3_call_count("PutObject", 2);
    wait_for_file_count(quarantine_dir, 1);

    file_count = count_files_recursive(quarantine_dir);
    flb_stop(ctx);
    flb_destroy(ctx);

    TEST_CHECK_(file_count > 0,
                "Expected quarantined file(s), got %d",
                file_count);

    flb_s3_test_env_unset("FLB_S3_PLUGIN_UNDER_TEST");
    flb_s3_test_env_unset("TEST_PUT_OBJECT_ERROR");
    flb_s3_test_env_unset("TEST_PutObject_CALL_COUNT");

    flb_free(store_dir);
}

void flb_test_s3_ordered_index_keeps_global_queue_order(void)
{
    int ret;
    int index;
    int out_ffd;
    int input_fds[2];
    char *uri;
    flb_ctx_t *ctx;
    char *store_dir;
    struct flb_s3 *s3_ctx;

    store_dir = create_test_store_directory("/flb-s3-test-index-order-XXXXXX");
    TEST_CHECK(store_dir != NULL);
    if (store_dir == NULL) {
        return;
    }

    flb_s3_test_env_set("FLB_S3_PLUGIN_UNDER_TEST", "true", 1);
    flb_s3_test_env_set("TEST_RECORD_S3_URIS", "true", 1);
    flb_s3_test_env_set("TEST_PUT_OBJECT_ERROR_TAG", "oldest", 1);

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
    flb_output_set(ctx, out_ffd, "s3_key_format", "/queue/$TAG/$INDEX", NULL);
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
    flb_s3_test_env_set("TEST_PUT_OBJECT_ERROR", ERROR_ACCESS_DENIED, 1);
    ret = prepare_s3_ordered_files(s3_ctx);
    TEST_CHECK_(ret == 0, "Expected both ordered chunks to be created");
    if (ret != 0) {
        goto cleanup;
    }
    wait_for_s3_call_count("PutObject", 1);
    flb_time_msleep(500);

    TEST_CHECK_(get_s3_call_count("PutObject") == 1,
                "Expected $INDEX to preserve global stop-at-head ordering, got %d calls",
                get_s3_call_count("PutObject"));
    uri = flb_s3_test_env_get("TEST_PutObject_URI_1");
    TEST_CHECK_(uri != NULL && strcmp(uri, "/fluent/queue/oldest/0") == 0,
                "Expected oldest indexed chunk first, got %s",
                uri ? uri : "(null)");

    flb_s3_test_env_unset("TEST_PUT_OBJECT_ERROR");
    wait_for_s3_call_count("PutObject", 3);
    uri = flb_s3_test_env_get("TEST_PutObject_URI_2");
    TEST_CHECK_(uri != NULL && strcmp(uri, "/fluent/queue/oldest/0") == 0,
                "Expected failed indexed chunk to retry before later tag, got %s",
                uri ? uri : "(null)");
    uri = flb_s3_test_env_get("TEST_PutObject_URI_3");
    TEST_CHECK_(uri != NULL && strcmp(uri, "/fluent/queue/later/1") == 0,
                "Expected later indexed chunk after retry, got %s",
                uri ? uri : "(null)");

cleanup:
    flb_stop(ctx);
    flb_destroy(ctx);

    flb_s3_test_env_unset("FLB_S3_PLUGIN_UNDER_TEST");
    flb_s3_test_env_unset("TEST_PUT_OBJECT_ERROR");
    flb_s3_test_env_unset("TEST_PUT_OBJECT_ERROR_TAG");
    flb_s3_test_env_unset("TEST_RECORD_S3_URIS");
    flb_s3_test_env_unset("TEST_PutObject_CALL_COUNT");
    flb_s3_test_env_unset("TEST_PutObject_URI_1");
    flb_s3_test_env_unset("TEST_PutObject_URI_2");
    flb_s3_test_env_unset("TEST_PutObject_URI_3");
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

    flb_s3_test_env_set("FLB_S3_PLUGIN_UNDER_TEST", "true", 1);

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

    flb_s3_test_env_unset("FLB_S3_PLUGIN_UNDER_TEST");
    flb_s3_test_env_unset("TEST_PutObject_CALL_COUNT");
    flb_free(store_dir);
}

static void check_near_full_buffer(int uploader)
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
    flb_s3_test_env_set("FLB_S3_PLUGIN_UNDER_TEST", "true", 1);

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

    flb_output_set(ctx, out_ffd, "throttle", uploader ? "true" : "false", NULL);
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    s3_ctx = get_s3_context(ctx);
    TEST_CHECK(s3_ctx != NULL);
    pthread_mutex_lock(&s3_ctx->files_mutex);
    ret = s3_store_buffer_put(s3_ctx, NULL, "test", 4, payload,
                              sizeof(payload) - 1, time(NULL));
    TEST_CHECK_(ret == 0,
                "Expected a committed near-full append to return success, got %d",
                ret);
    s3_file = s3_store_file_get(s3_ctx, "test", 4);
    TEST_CHECK(s3_file != NULL);
    TEST_CHECK(cio_chunk_down(s3_file->fsf->chunk) == CIO_OK);
    ret = s3_store_buffer_put(s3_ctx, s3_file, "test", 4, payload, 1, time(NULL));
    TEST_CHECK(ret == 0);
    TEST_CHECK(cio_chunk_is_up(s3_file->fsf->chunk) == CIO_FALSE);
    TEST_CHECK(s3_store_file_size_get(s3_file) == sizeof(payload));

    ret = s3_store_buffer_put(s3_ctx, s3_file, "test", 4, excess_payload,
                              sizeof(excess_payload), time(NULL));
    TEST_CHECK_(ret == (uploader ? S3_STORE_BUFFER_FULL : -1),
                "Expected an over-limit append to fail, got %d",
                ret);
    TEST_CHECK(cfl_atomic_load(&s3_ctx->current_buffer_size) == sizeof(payload));
    TEST_CHECK(s3_store_file_size_get(s3_file) == sizeof(payload));

    TEST_CHECK(s3_file->sealed == uploader);
    pthread_mutex_unlock(&s3_ctx->files_mutex);

    flb_stop(ctx);
    flb_destroy(ctx);

    flb_s3_test_env_unset("FLB_S3_PLUGIN_UNDER_TEST");
    flb_s3_test_env_unset("TEST_PutObject_CALL_COUNT");
    flb_free(store_dir);
}

void flb_test_s3_near_full_buffer_append_succeeds(void)
{
    check_near_full_buffer(FLB_FALSE);
}

static void flb_test_s3_uploader_seals_full_buffer(void)
{
    check_near_full_buffer(FLB_TRUE);
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

    flb_s3_test_env_set("FLB_S3_PLUGIN_UNDER_TEST", "true", 1);
    flb_s3_test_env_set("TEST_PUT_OBJECT_ERROR", ERROR_ACCESS_DENIED, 1);
    flb_s3_test_env_set("TEST_RECORD_S3_URIS", "true", 1);

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

    flb_s3_test_env_unset("TEST_PutObject_CALL_COUNT");
    flb_s3_test_env_unset("TEST_PutObject_URI_1");

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
    uri = flb_s3_test_env_get("TEST_PutObject_URI_1");
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

    flb_s3_test_env_unset("TEST_PUT_OBJECT_ERROR");
    ret = flb_lib_push(ctx, in_ffd, (char *) JSON_TD, (int) sizeof(JSON_TD) - 1);
    TEST_CHECK(ret >= 0);
    wait_for_s3_call_count("PutObject", 3);

    uri = flb_s3_test_env_get("TEST_PutObject_URI_2");
    TEST_CHECK_(uri != NULL &&
                flb_s3_test_env_get("TEST_PutObject_URI_1") != NULL &&
                strcmp(uri, flb_s3_test_env_get("TEST_PutObject_URI_1")) == 0,
                "Expected failed chunk retry to keep its tag and index, got %s",
                uri ? uri : "(null)");
    uri = flb_s3_test_env_get("TEST_PutObject_URI_3");
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

    flb_s3_test_env_unset("FLB_S3_PLUGIN_UNDER_TEST");
    flb_s3_test_env_unset("TEST_PUT_OBJECT_ERROR");
    flb_s3_test_env_unset("TEST_RECORD_S3_URIS");
    flb_s3_test_env_unset("TEST_PutObject_CALL_COUNT");
    flb_s3_test_env_unset("TEST_PutObject_URI_1");
    flb_s3_test_env_unset("TEST_PutObject_URI_2");
    flb_s3_test_env_unset("TEST_PutObject_URI_3");
    flb_s3_test_env_unset("TEST_PutObject_URI_4");
    flb_free(store_dir);
}

void flb_test_s3_startup_buffer_size_accounting(void)
{
    int ret;
    int index;
    int in_ffd;
    int out_ffd;
    int call_count;
    int sized_down_file_count;
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

    flb_s3_test_env_set("FLB_S3_PLUGIN_UNDER_TEST", "true", 1);
    flb_s3_test_env_set("TEST_PUT_OBJECT_ERROR", ERROR_ACCESS_DENIED, 1);

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

    flb_s3_test_env_unset("TEST_PutObject_CALL_COUNT");

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
    sized_down_file_count = count_sized_down_s3_files(s3_ctx);
    TEST_CHECK_(sized_down_file_count >= 2,
                "Expected at least two restored down chunks with accounted bytes, got %d",
                sized_down_file_count);
    restored_buffer_size = cfl_atomic_load(&s3_ctx->current_buffer_size);
    TEST_CHECK_(restored_buffer_size == live_buffer_size,
                "Expected restored payload bytes=%" PRIu64 ", got %" PRIu64,
                live_buffer_size, restored_buffer_size);

    flb_stop(ctx);
    flb_destroy(ctx);

    flb_s3_test_env_unset("TEST_PUT_OBJECT_ERROR");
    flb_s3_test_env_unset("TEST_PutObject_CALL_COUNT");

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

    flb_s3_test_env_unset("FLB_S3_PLUGIN_UNDER_TEST");
    flb_s3_test_env_unset("TEST_PUT_OBJECT_ERROR");
    flb_s3_test_env_unset("TEST_PutObject_CALL_COUNT");
    flb_free(store_dir);
}

/* Detect overlapping cache reads/refreshes while requests remain concurrent. */
struct s3_credentials_test {
    pthread_mutex_t mutex;
    int requests_entered;
    int active;
    int max_active;
    int gets;
    int refreshes;
    int request_wait_failed;
};

static struct s3_credentials_test credentials_test;

static void s3_test_provider_access(int refresh)
{
    pthread_mutex_lock(&credentials_test.mutex);
    credentials_test.active++;
    if (credentials_test.active > credentials_test.max_active) {
        credentials_test.max_active = credentials_test.active;
    }
    if (refresh) {
        credentials_test.refreshes++;
    }
    else {
        credentials_test.gets++;
    }
    pthread_mutex_unlock(&credentials_test.mutex);

    flb_time_msleep(5);

    pthread_mutex_lock(&credentials_test.mutex);
    credentials_test.active--;
    pthread_mutex_unlock(&credentials_test.mutex);
}

static struct flb_aws_credentials *s3_test_get_credentials(struct flb_aws_provider *provider)
{
    s3_test_provider_access(FLB_FALSE);
    return flb_calloc(1, sizeof(struct flb_aws_credentials));
}

static int s3_test_refresh_credentials(struct flb_aws_provider *provider)
{
    s3_test_provider_access(FLB_TRUE);
    return 0;
}

static struct flb_http_client *s3_test_concurrent_request(struct flb_aws_client *client,
                                                         int method, const char *uri,
                                                         const char *body, size_t body_size,
                                                         struct flb_aws_header *headers,
                                                         size_t headers_count)
{
    struct flb_aws_credentials *credentials;
    int i;
    int ready = FLB_FALSE;

    pthread_mutex_lock(&credentials_test.mutex);
    credentials_test.requests_entered++;
    pthread_mutex_unlock(&credentials_test.mutex);

    /* A bounded rendezvous also catches accidentally serializing entire requests. */
    for (i = 0; i < 500; i++) {
        pthread_mutex_lock(&credentials_test.mutex);
        ready = credentials_test.requests_entered == 2;
        pthread_mutex_unlock(&credentials_test.mutex);
        if (ready) {
            break;
        }
        flb_time_msleep(10);
    }
    if (!ready) {
        pthread_mutex_lock(&credentials_test.mutex);
        credentials_test.request_wait_failed = FLB_TRUE;
        pthread_mutex_unlock(&credentials_test.mutex);
    }

    for (i = 0; i < 20; i++) {
        credentials = client->provider->provider_vtable->get_credentials(client->provider);
        flb_aws_credentials_destroy(credentials);
        client->provider->provider_vtable->refresh(client->provider);
    }
    return NULL;
}

static void *s3_test_request_worker(void *data)
{
    int deferred;
    struct flb_s3 *ctx = data;

    pthread_mutex_lock(&ctx->files_mutex);
    s3_request(ctx, FLB_HTTP_PUT, "/test", NULL, 0, NULL, 0, &deferred);
    pthread_mutex_unlock(&ctx->files_mutex);
    return NULL;
}

static void flb_test_s3_credentials_serialized(void)
{
    struct flb_s3 ctx = {0};
    struct flb_aws_provider provider = {0};
    struct flb_aws_client client = {0};
    struct flb_aws_provider_vtable provider_vtable = {
        .get_credentials = s3_test_get_credentials,
        .refresh = s3_test_refresh_credentials
    };
    struct flb_aws_client_vtable client_vtable = {
        .request = s3_test_concurrent_request
    };
    pthread_t workers[2];
    int created = 0;
    int ret;
    int i;

    memset(&credentials_test, 0, sizeof(credentials_test));
    pthread_mutex_init(&credentials_test.mutex, NULL);
    pthread_mutex_init(&ctx.files_mutex, NULL);
    provider.provider_vtable = &provider_vtable;
    client.client_vtable = &client_vtable;
    client.provider = &provider;
    ctx.provider = &provider;
    ctx.s3_client = &client;

    for (i = 0; i < 2; i++) {
        ret = pthread_create(&workers[i], NULL, s3_test_request_worker, &ctx);
        TEST_CHECK(ret == 0);
        if (ret != 0) {
            break;
        }
        created++;
    }
    for (i = 0; i < created; i++) {
        pthread_join(workers[i], NULL);
    }

    TEST_CHECK(credentials_test.request_wait_failed == FLB_FALSE);
    TEST_CHECK(credentials_test.requests_entered == 2);
    TEST_CHECK(credentials_test.max_active == 1);
    TEST_CHECK(credentials_test.gets == 40);
    TEST_CHECK(credentials_test.refreshes == 40);
    pthread_mutex_destroy(&ctx.files_mutex);
    pthread_mutex_destroy(&credentials_test.mutex);
}

static struct flb_http_client *check_last_part_request(struct flb_s3 *ctx, int method,
                                                       const char *uri, const char *body, size_t size,
                                                       struct flb_aws_header *headers, size_t count,
                                                       int *deferred)
{
    TEST_CHECK(strstr(body, "<Part><ETag>last-part</ETag><PartNumber>10000</PartNumber></Part>") != NULL);
    return mock_s3_call("TEST_COMPLETE_MULTIPART_UPLOAD_ERROR", "CompleteMultipartUpload");
}

static void flb_test_s3_restore_last_multipart_part(void)
{
    flb_ctx_t *ctx;
    struct flb_s3 *s3;
    struct multipart_upload *upload;
    struct flb_fstore_file *manifest;
    flb_sds_t key;
    flb_sds_t part;
    char *dir;
    int out;

    dir = create_test_store_directory("/flb-s3-manifest-XXXXXX");
    TEST_ASSERT(dir != NULL);
    flb_s3_test_env_set("FLB_S3_PLUGIN_UNDER_TEST", "true", 1);
    ctx = flb_create();
    flb_input(ctx, "lib", NULL);
    out = flb_output(ctx, "s3", NULL);
    flb_output_set(ctx, out, "match", "*", "region", "us-west-2", "bucket", "fluent",
                   "throttle", "true", "store_dir", dir, NULL);
    TEST_ASSERT(flb_start(ctx) == 0);
    s3 = get_s3_context(ctx);
    pthread_mutex_lock(&s3->files_mutex);
    key = flb_sds_create("/test-key\ntest-id");
    part = flb_sds_create("part_number=10000\tetag=last-part\n");
    TEST_ASSERT(s3_store_file_upload_put(s3, NULL, key, part, NULL) == 0);
    manifest = s3_store_file_upload_get(s3, key, flb_sds_len(key));
    TEST_ASSERT(manifest != NULL);
    TEST_CHECK(cio_chunk_down(manifest->chunk) == CIO_OK);
    TEST_CHECK(s3_store_file_upload_put(s3, manifest, key, part, NULL) == 0);
    TEST_CHECK(cio_chunk_is_up(manifest->chunk) == CIO_FALSE);

    TEST_ASSERT(sqlite3_exec(s3->uploader_db, "ALTER TABLE retry RENAME TO unavailable",
                             NULL, NULL, NULL) == SQLITE_OK);
    TEST_CHECK(multipart_read_uploads_from_fs(s3) < 0);
    TEST_CHECK(mk_list_size(&s3->uploads) == 0);
    TEST_ASSERT(sqlite3_exec(s3->uploader_db, "ALTER TABLE unavailable RENAME TO retry",
                             NULL, NULL, NULL) == SQLITE_OK);
    TEST_CHECK(s3_uploader_storage_recover(s3) == 0);
    TEST_ASSERT(multipart_read_uploads_from_fs(s3) == 0);
    upload = mk_list_entry_first(&s3->uploads, struct multipart_upload, _head);
    TEST_CHECK(upload->part_number == S3_MAX_PARTS + 1);
    TEST_CHECK(strcmp(upload->etags[S3_MAX_PARTS - 1], "last-part") == 0);
    upload->request = check_last_part_request;
    flb_s3_test_env_unset("FLB_S3_PLUGIN_UNDER_TEST");
    TEST_CHECK(complete_multipart_upload(s3, upload, NULL) == 0);
    flb_s3_test_env_set("FLB_S3_PLUGIN_UNDER_TEST", "true", 1);
    mk_list_del(&upload->_head);
    multipart_upload_destroy(upload);
    flb_sds_destroy(part);
    part = flb_sds_create("part_number=2\tetag=\n");
    TEST_ASSERT(s3_store_file_upload_put(s3, NULL, key, part, NULL) == 0);
    TEST_CHECK(multipart_read_uploads_from_fs(s3) < 0);
    TEST_CHECK(mk_list_size(&s3->uploads) == 0);
    flb_sds_destroy(part);
    flb_sds_destroy(key);
    pthread_mutex_unlock(&s3->files_mutex);
    flb_stop(ctx);
    flb_destroy(ctx);
    flb_s3_test_env_unset("FLB_S3_PLUGIN_UNDER_TEST");
    flb_free(dir);
}

static void flb_test_s3_retry_accepted_part_checkpoint(void)
{
    flb_ctx_t *ctx;
    struct flb_s3 *s3;
    struct multipart_upload *upload;
    struct flb_fstore_file *manifest;
    char held_dir[PATH_MAX];
    flb_sds_t key;
    flb_sds_t part;
    char *dir;
    int calls;
    int out;

    dir = create_test_store_directory("/flb-s3-part-checkpoint-XXXXXX");
    TEST_ASSERT(dir != NULL);
    flb_s3_test_env_set("FLB_S3_PLUGIN_UNDER_TEST", "true", 1);
    ctx = flb_create();
    flb_input(ctx, "lib", NULL);
    out = flb_output(ctx, "s3", NULL);
    flb_output_set(ctx, out, "match", "*", "region", "us-west-2", "bucket", "fluent",
                   "throttle", "true", "retry_limit", "0", "store_dir", dir, NULL);
    TEST_ASSERT(flb_start(ctx) == 0);
    s3 = get_s3_context(ctx);
    pthread_mutex_lock(&s3->files_mutex);
    key = flb_sds_create("/test-key\ntest-id");
    part = flb_sds_create("part_number=1\tetag=first-part\n");
    TEST_ASSERT(s3_store_file_upload_put(s3, NULL, key, part, NULL) == 0);
    TEST_ASSERT(multipart_read_uploads_from_fs(s3) == 0);
    upload = mk_list_entry_first(&s3->uploads, struct multipart_upload, _head);
    manifest = s3_store_file_upload_get(s3, key, flb_sds_len(key));
    TEST_ASSERT(manifest != NULL);
    if (cio_chunk_is_up(manifest->chunk)) {
        TEST_ASSERT(cio_chunk_down(manifest->chunk) == CIO_OK);
    }
    snprintf(held_dir, sizeof(held_dir), "%s.held", s3->stream_upload->path);
    TEST_ASSERT(rename(s3->stream_upload->path, held_dir) == 0);
    calls = get_s3_call_count("UploadPart");
    TEST_CHECK(upload_part(s3, upload, "body", 4, NULL) == S3_UPLOAD_DEFERRED);
    TEST_CHECK(s3_uploader_storage_recover(s3) < 0);
    TEST_CHECK(upload->part_number == 2);
    TEST_CHECK(upload->etags[1] == NULL);
    TEST_ASSERT(rename(held_dir, s3->stream_upload->path) == 0);
    TEST_CHECK(s3_uploader_storage_recover(s3) == 0);
    TEST_CHECK(upload->part_number == 3);
    TEST_CHECK(upload->etags[1] != NULL);
    TEST_CHECK(upload->bytes == 4);
    TEST_CHECK(get_s3_call_count("UploadPart") == calls + 1);
    mk_list_del(&upload->_head);
    multipart_upload_destroy(upload);
    TEST_ASSERT(multipart_read_uploads_from_fs(s3) == 0);
    upload = mk_list_entry_first(&s3->uploads, struct multipart_upload, _head);
    TEST_CHECK(upload->part_number == 3);
    TEST_CHECK(upload->etags[1] != NULL);
    flb_sds_destroy(part);
    flb_sds_destroy(key);
    pthread_mutex_unlock(&s3->files_mutex);
    flb_stop(ctx);
    flb_destroy(ctx);
    flb_s3_test_env_unset("FLB_S3_PLUGIN_UNDER_TEST");
    flb_free(dir);
}

static void flb_test_s3_uploader_spool_format_limit(void)
{
    struct flb_s3 ctx = {0};

    ctx.compression = FLB_AWS_COMPRESS_GZIP;
    ctx.upload_chunk_size = 4294000000ULL;
    TEST_CHECK(!s3_uploader_should_seal(&ctx, 4293000000ULL, UINT32_MAX - 4293000000ULL));
    TEST_CHECK(s3_uploader_should_seal(&ctx, 4293000000ULL, UINT32_MAX - 4293000000ULL + 1));
    TEST_CHECK(s3_uploader_should_seal(&ctx, 4293000000ULL, 3000000));
    TEST_CHECK(s3_uploader_should_seal(&ctx, ctx.upload_chunk_size, 1));
}

static void flb_test_s3_uploader_restored_deadline(void)
{
    struct flb_s3 ctx = {0};
    struct flb_output_instance ins = {0};
    struct s3_retry_state state = {0};
    char *dir;
    uint64_t before;
    int ret;

    dir = create_test_store_directory("/flb-s3-gate-XXXXXX");
    TEST_CHECK(dir != NULL);
    if (dir == NULL) {
        return;
    }
    ctx.buffer_dir = dir;
    ctx.ins = &ins;
    ins.throttle.enabled = FLB_TRUE;
    ins.throttle.base_ms = 100;
    ins.throttle.cap_ms = 1000;
    mk_list_init(&ctx.pending_checkpoints);
    ret = s3_uploader_init(&ctx);
    TEST_CHECK(ret == 0);
    if (ret == 0) {
        state.until_ms = INT64_MAX;
        TEST_CHECK(s3_uploader_state_write(&ctx, "gate", "", &state) == 0);
        s3_uploader_destroy(&ctx);
        before = s3_uploader_wall_ms();
        ret = s3_uploader_init(&ctx);
        TEST_CHECK(ret == 0);
        if (ret == 0) {
            TEST_CHECK(ctx.uploader_gate.until_ms - ctx.uploader_gate.started_ms == 1000);
            TEST_CHECK(s3_uploader_state_read(&ctx, "gate", "", &state) == 0);
            TEST_CHECK(state.until_ms >= before + 1000);
            TEST_CHECK(state.until_ms <= s3_uploader_wall_ms() + 1000);
            state.until_ms = INT64_MAX;
            state.failures = 2;
            TEST_CHECK(s3_uploader_state_write(&ctx, "complete", "old", &state) == 0);
            TEST_CHECK(s3_uploader_state_write(&ctx, "chunk", "old", &state) == 0);
            before = flb_output_throttle_now_ms();
            TEST_CHECK(s3_uploader_state_read(&ctx, "complete", "old", &state) == 0);
            TEST_CHECK(state.retry_at >= before + 4000);
            TEST_CHECK(state.retry_at <= flb_output_throttle_now_ms() + 4000);
            state.retry_at = 0;
            TEST_CHECK(s3_uploader_state_read(&ctx, "chunk", "old", &state) == 0);
            TEST_CHECK(state.retry_at >= before + 4000);
            TEST_CHECK(state.retry_at <= flb_output_throttle_now_ms() + 4000);
        }
    }
    s3_uploader_destroy(&ctx);
    flb_free(dir);
}

/* Test list */
TEST_LIST = {
    {"uploader_spool_format_limit", flb_test_s3_uploader_spool_format_limit},
    {"retry_accepted_part_checkpoint", flb_test_s3_retry_accepted_part_checkpoint},
    {"restore_last_multipart_part", flb_test_s3_restore_last_multipart_part},
    {"uploader_seals_full_buffer", flb_test_s3_uploader_seals_full_buffer},
    {"uploader_restored_deadline", flb_test_s3_uploader_restored_deadline},
    {"hostname_verification_propagates", flb_test_s3_hostname_verification_propagates },
    {"credentials_serialized", flb_test_s3_credentials_serialized },
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
    {"ordered_timer_isolates_tag_backoff", flb_test_s3_ordered_timer_isolates_tag_backoff },
    {"ordered_index_keeps_global_queue_order", flb_test_s3_ordered_index_keeps_global_queue_order },
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
