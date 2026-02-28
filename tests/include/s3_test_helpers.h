/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef S3_TEST_HELPERS_H
#define S3_TEST_HELPERS_H

#include <fluent-bit.h>
#ifndef _WIN32
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>
#include <time.h>
#include <stdlib.h>
#else
#include <windows.h>
#include <direct.h>
#include <io.h>
#endif

/* Test macros */
#define S3_TEST_DEFAULT_REGION "us-west-2"
#define S3_TEST_DEFAULT_BUCKET "test-bucket"

/* Mock response constants */
#define S3_TEST_MOCK_CREATE_RESP \
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" \
    "<InitiateMultipartUploadResult>\n" \
    "   <Bucket>test-bucket</Bucket>\n" \
    "   <Key>test-key</Key>\n" \
    "   <UploadId>test-upload-id</UploadId>\n" \
    "</InitiateMultipartUploadResult>"

#define S3_TEST_MOCK_UPLOAD_PART_RESP \
    "ETag: \"test-etag\"\r\n"

#define S3_TEST_MOCK_COMPLETE_RESP \
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" \
    "<CompleteMultipartUploadResult>\n" \
    "   <Location>https://test-bucket.s3.amazonaws.com/test-key</Location>\n" \
    "   <Bucket>test-bucket</Bucket>\n" \
    "   <Key>test-key</Key>\n" \
    "   <ETag>\"test-etag\"</ETag>\n" \
    "</CompleteMultipartUploadResult>"

#define S3_TEST_MOCK_ERROR_RESP \
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" \
    "<Error>\n" \
    "   <Code>InternalError</Code>\n" \
    "   <Message>We encountered an internal error. Please try again.</Message>\n" \
    "</Error>"

/* Sleep macro */
#ifdef _WIN32
#define S3_TEST_SLEEP_MS(ms) Sleep(ms)
#else
#define S3_TEST_SLEEP_MS(ms) usleep((ms) * 1000)
#endif

/* Wait for mock to be exhausted with timeout */
#define S3_TEST_WAIT_MOCK_EXHAUSTED(timeout_sec, test_name) \
    do { \
        int _wait_count = 0; \
        int _max_wait = (timeout_sec) * 10; \
        while (_wait_count < _max_wait) { \
            if (flb_aws_client_mock_generator_count_unused_requests() == 0) { \
                break; \
            } \
            S3_TEST_SLEEP_MS(100); \
            _wait_count++; \
        } \
        if (_wait_count >= _max_wait) { \
            TEST_MSG("[%s] Timeout waiting for mock exhaustion. Remaining requests: %d", \
                     test_name, flb_aws_client_mock_generator_count_unused_requests()); \
            TEST_CHECK(0); \
        } \
    } while (0)


/* Standard mock chain for successful 3-step multipart upload */
#define S3_TEST_STANDARD_MOCK_CHAIN() \
    FLB_AWS_CLIENT_MOCK( \
        response(expect(METHOD, FLB_HTTP_POST), \
                 set(STATUS, 200), set(PAYLOAD, S3_TEST_MOCK_CREATE_RESP), \
                 set(PAYLOAD_SIZE, sizeof(S3_TEST_MOCK_CREATE_RESP) - 1)), \
        response(expect(METHOD, FLB_HTTP_PUT), \
                 set(STATUS, 200), set(DATA, S3_TEST_MOCK_UPLOAD_PART_RESP), \
                 set(DATA_SIZE, sizeof(S3_TEST_MOCK_UPLOAD_PART_RESP) - 1)), \
        response(expect(METHOD, FLB_HTTP_POST), \
                 set(STATUS, 200), set(PAYLOAD, S3_TEST_MOCK_COMPLETE_RESP), \
                 set(PAYLOAD_SIZE, sizeof(S3_TEST_MOCK_COMPLETE_RESP) - 1)) \
    )

/* Declare common test variables */
#define S3_TEST_DECLARE_VARS() \
    flb_ctx_t *ctx; \
    int in_ffd, out_ffd, ret; \
    char *db_path, *store_dir; \
    struct flb_out_s3_init_options init_options = {0}; \
    struct flb_aws_client_mock_request_chain *chain

/* Setup standard mock chain */
#define S3_TEST_SETUP_STANDARD_MOCK() \
    do { \
        chain = S3_TEST_STANDARD_MOCK_CHAIN(); \
        flb_aws_client_mock_configure_generator(chain); \
        init_options.client_generator = flb_aws_client_get_mock_generator(); \
    } while (0)

/* Create temp paths and validate */
#define S3_TEST_CREATE_PATHS(prefix) \
    do { \
        db_path = s3_test_create_temp_db_path(prefix); \
        store_dir = s3_test_create_temp_store_dir(prefix); \
        TEST_CHECK(db_path != NULL); \
        TEST_CHECK(store_dir != NULL); \
        if (db_path == NULL || store_dir == NULL) { \
            s3_test_cleanup(NULL, db_path, store_dir); \
            return; \
        } \
    } while (0)

/* Set dummy credentials and test mode flag */
static inline void s3_test_set_env_vars(void)
{
#ifdef _WIN32
    SetEnvironmentVariableA("AWS_ACCESS_KEY_ID", "dummy-key");
    SetEnvironmentVariableA("AWS_SECRET_ACCESS_KEY", "dummy-secret");
    SetEnvironmentVariableA("AWS_SESSION_TOKEN", "dummy-token");
    SetEnvironmentVariableA("FLB_S3_PLUGIN_UNDER_TEST", "true");
#else
    setenv("AWS_ACCESS_KEY_ID", "dummy-key", 1);
    setenv("AWS_SECRET_ACCESS_KEY", "dummy-secret", 1);
    setenv("AWS_SESSION_TOKEN", "dummy-token", 1);
    setenv("FLB_S3_PLUGIN_UNDER_TEST", "true", 1);
#endif
}

/* Initialize context and service */
#define S3_TEST_INIT_CONTEXT() \
    do { \
        s3_test_set_env_vars(); \
        ctx = flb_create(); \
        S3_TEST_CHECK_CONTEXT(ctx, db_path, store_dir); \
        flb_service_set(ctx, "flush", "1", "grace", "1", NULL); \
    } while (0)

/* Setup input with tag */
#define S3_TEST_SETUP_INPUT(tag) \
    do { \
        in_ffd = flb_input(ctx, (char *)"lib", NULL); \
        TEST_CHECK(in_ffd >= 0); \
        flb_input_set(ctx, in_ffd, "tag", tag, NULL); \
    } while (0)

/* Setup output with basic config */
#define S3_TEST_SETUP_OUTPUT_BASIC() \
    do { \
        out_ffd = flb_output(ctx, (char *)"s3", (struct flb_lib_out_cb *)&init_options); \
        TEST_CHECK(out_ffd >= 0); \
        ret = flb_output_set(ctx, out_ffd, "match", "*", \
                       "region", S3_TEST_DEFAULT_REGION, \
                       "bucket", S3_TEST_DEFAULT_BUCKET, \
                       "blob_database_file", db_path, \
                       "store_dir", store_dir, \
                       "total_file_size", "1M", \
                       "upload_timeout", "1s", NULL); \
        TEST_CHECK(ret == 0); \
    } while (0)

/* Setup output with minimal config (for error tests that need to override defaults) */
#define S3_TEST_SETUP_OUTPUT_MINIMAL() \
    do { \
        out_ffd = flb_output(ctx, (char *)"s3", (struct flb_lib_out_cb *)&init_options); \
        TEST_CHECK(out_ffd >= 0); \
        ret = flb_output_set(ctx, out_ffd, "match", "*", \
                       "region", S3_TEST_DEFAULT_REGION, \
                       "blob_database_file", db_path, \
                       "store_dir", store_dir, \
                       "upload_timeout", "1s", NULL); \
        TEST_CHECK(ret == 0); \
    } while (0)

/* Start context and verify */
#define S3_TEST_START_AND_PUSH(test_data, test_data_size) \
    do { \
        ret = flb_start(ctx); \
        TEST_CHECK(ret == 0); \
        ret = flb_lib_push(ctx, in_ffd, test_data, test_data_size); \
        TEST_CHECK(ret >= 0); \
    } while (0)

/* Complete test workflow: setup, start, wait, cleanup */
#define S3_TEST_RUN_AND_CLEANUP(tag, test_name) \
    do { \
        S3_TEST_SETUP_STANDARD_MOCK(); \
        S3_TEST_CREATE_PATHS("cfg"); \
        S3_TEST_INIT_CONTEXT(); \
        S3_TEST_SETUP_INPUT(tag); \
        S3_TEST_SETUP_OUTPUT_BASIC(); \
    } while (0)

/* End of test: wait and cleanup */
#define S3_TEST_FINISH(test_name) \
    do { \
        S3_TEST_START_AND_PUSH((char *)JSON_TD, sizeof(JSON_TD) - 1); \
        S3_TEST_WAIT_MOCK_EXHAUSTED(5, test_name); \
        s3_test_cleanup(ctx, db_path, store_dir); \
    } while (0)

/* Complete simple test: setup -> configure -> run -> cleanup */
#define S3_TEST_SIMPLE(tag, test_name, ...) \
    do { \
        S3_TEST_RUN_AND_CLEANUP(tag, test_name); \
        ret = flb_output_set(ctx, out_ffd, ##__VA_ARGS__, NULL); \
        TEST_CHECK(ret == 0); \
        S3_TEST_FINISH(test_name); \
    } while (0)

/* Error test with custom mock chain - no extra params version */
#define S3_TEST_ERROR_WITH_MOCK_0(test_name, mock_chain_code) \
    do { \
        chain = mock_chain_code; \
        flb_aws_client_mock_configure_generator(chain); \
        init_options.client_generator = flb_aws_client_get_mock_generator(); \
        S3_TEST_CREATE_PATHS("err"); \
        S3_TEST_INIT_CONTEXT(); \
        S3_TEST_SETUP_INPUT("test"); \
        S3_TEST_SETUP_OUTPUT_MINIMAL(); \
        ret = flb_output_set(ctx, out_ffd, "bucket", S3_TEST_DEFAULT_BUCKET, "total_file_size", "1M", NULL); \
        TEST_CHECK(ret == 0); \
        S3_TEST_START_AND_PUSH((char *)JSON_TD, sizeof(JSON_TD) - 1); \
        S3_TEST_WAIT_MOCK_EXHAUSTED(5, test_name); \
        s3_test_cleanup(ctx, db_path, store_dir); \
    } while (0)

/* Error test with custom mock chain - with extra params version */
#define S3_TEST_ERROR_WITH_MOCK_N(test_name, mock_chain_code, ...) \
    do { \
        chain = mock_chain_code; \
        flb_aws_client_mock_configure_generator(chain); \
        init_options.client_generator = flb_aws_client_get_mock_generator(); \
        S3_TEST_CREATE_PATHS("err"); \
        S3_TEST_INIT_CONTEXT(); \
        S3_TEST_SETUP_INPUT("test"); \
        S3_TEST_SETUP_OUTPUT_MINIMAL(); \
        ret = flb_output_set(ctx, out_ffd, __VA_ARGS__, NULL); \
        TEST_CHECK(ret == 0); \
        S3_TEST_START_AND_PUSH((char *)JSON_TD, sizeof(JSON_TD) - 1); \
        S3_TEST_WAIT_MOCK_EXHAUSTED(5, test_name); \
        s3_test_cleanup(ctx, db_path, store_dir); \
    } while (0)

/* Get platform-specific temp directory */
static inline const char *s3_test_get_temp_dir(void)
{
#ifdef _WIN32
    /* On Windows, prefer TMP then TEMP environment variables */
    const char *temp_dir = getenv("TMP");
    if (!temp_dir || temp_dir[0] == '\0') {
        temp_dir = getenv("TEMP");
    }
    if (!temp_dir || temp_dir[0] == '\0') {
        temp_dir = "C:\\Temp";
    }
    return temp_dir;
#else
    /* On POSIX, prefer TMPDIR environment variable, fallback to /tmp */
    const char *temp_dir = getenv("TMPDIR");
    if (!temp_dir || temp_dir[0] == '\0') {
        temp_dir = "/tmp";
    }
    return temp_dir;
#endif
}

/* Create temporary database path */
static inline char *s3_test_create_temp_db_path(const char *prefix)
{
    char *path = flb_malloc(512);
    const char *temp_dir;
    
    if (!path) {
        return NULL;
    }
    
    temp_dir = s3_test_get_temp_dir();
    
#ifdef _WIN32
    /* Windows: use process ID + millisecond timestamp */
    DWORD pid = GetCurrentProcessId();
    ULONGLONG ticks = GetTickCount64();
    snprintf(path, 512, "%s\\flb_s3_%s_db_%lu_%llu.db",
             temp_dir, prefix, (unsigned long)pid, ticks);
#else
    /* POSIX: use process ID + nanosecond timestamp */
    pid_t pid = getpid();
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    snprintf(path, 512, "%s/flb_s3_%s_db_%d_%ld%09ld.db",
             temp_dir, prefix, pid, ts.tv_sec, ts.tv_nsec);
#endif
    
    return path;
}

/* Create temporary store directory */
static inline char *s3_test_create_temp_store_dir(const char *prefix)
{
    char *path = flb_malloc(512);
    const char *temp_dir;
    
    if (!path) {
        return NULL;
    }
    
    temp_dir = s3_test_get_temp_dir();
    
#ifdef _WIN32
    /* Windows: use process ID + millisecond timestamp */
    DWORD pid = GetCurrentProcessId();
    ULONGLONG ticks = GetTickCount64();
    snprintf(path, 512, "%s\\flb_s3_%s_store_%lu_%llu",
             temp_dir, prefix, (unsigned long)pid, ticks);
    if (_mkdir(path) != 0) {
        flb_free(path);
        return NULL;
    }
#else
    /* POSIX: use process ID + nanosecond timestamp */
    pid_t pid = getpid();
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    snprintf(path, 512, "%s/flb_s3_%s_store_%d_%ld%09ld",
             temp_dir, prefix, pid, ts.tv_sec, ts.tv_nsec);
    if (mkdir(path, 0755) != 0) {
        flb_free(path);
        return NULL;
    }
#endif
    
    return path;
}

/* Cleanup temp database */
static inline void s3_test_cleanup_temp_db(const char *db_path)
{
    if (db_path) {
#ifdef _WIN32
        _unlink(db_path);
#else
        unlink(db_path);
#endif
    }
}

/* Recursive directory removal helper */
static inline void s3_test_remove_dir_recursive(const char *path)
{
#ifdef _WIN32
    WIN32_FIND_DATA find_data;
    HANDLE h_find;
    char search_path[MAX_PATH];
    char sub_path[MAX_PATH];

    snprintf(search_path, sizeof(search_path), "%s\\*", path);
    h_find = FindFirstFile(search_path, &find_data);

    if (h_find == INVALID_HANDLE_VALUE) {
        return;
    }

    do {
        if (strcmp(find_data.cFileName, ".") == 0 || strcmp(find_data.cFileName, "..") == 0) {
            continue;
        }

        snprintf(sub_path, sizeof(sub_path), "%s\\%s", path, find_data.cFileName);

        if (find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            s3_test_remove_dir_recursive(sub_path);
        } else {
            DeleteFile(sub_path);
        }
    } while (FindNextFile(h_find, &find_data));

    FindClose(h_find);
    RemoveDirectory(path);
#else
    DIR *d;
    struct dirent *p;
    char *buf;
    struct stat statbuf;
    size_t path_len;
    size_t len;

    d = opendir(path);
    if (!d) {
        return;
    }

    path_len = strlen(path);

    while ((p = readdir(d))) {
        if (!strcmp(p->d_name, ".") || !strcmp(p->d_name, "..")) {
            continue;
        }

        len = path_len + strlen(p->d_name) + 2;
        buf = flb_malloc(len);
        if (buf) {
            snprintf(buf, len, "%s/%s", path, p->d_name);
            if (!stat(buf, &statbuf)) {
                if (S_ISDIR(statbuf.st_mode)) {
                    s3_test_remove_dir_recursive(buf);
                }
                else {
                    unlink(buf);
                }
            }
            flb_free(buf);
        }
    }
    closedir(d);
    rmdir(path);
#endif
}

/* Cleanup temp store directory */
static inline void s3_test_cleanup_temp_store_dir(const char *store_dir)
{
    if (store_dir) {
        /* Validate path prefix for safety using platform-specific temp directory */
        const char *temp_dir = s3_test_get_temp_dir();
        char expected_prefix[512];
        size_t prefix_len;
        
#ifdef _WIN32
        /* Normalize path separators for Windows comparison */
        char expected_prefix_bs[512];
        char expected_prefix_fs[512];
        
        snprintf(expected_prefix_bs, sizeof(expected_prefix_bs), "%s\\flb_s3_", temp_dir);
        snprintf(expected_prefix_fs, sizeof(expected_prefix_fs), "%s/flb_s3_", temp_dir);
        
        if (strncmp(store_dir, expected_prefix_bs, strlen(expected_prefix_bs)) == 0 ||
            strncmp(store_dir, expected_prefix_fs, strlen(expected_prefix_fs)) == 0) {
            s3_test_remove_dir_recursive(store_dir);
        }
#else
        snprintf(expected_prefix, sizeof(expected_prefix), "%s/flb_s3_", temp_dir);
        prefix_len = strlen(expected_prefix);
        if (strncmp(store_dir, expected_prefix, prefix_len) == 0) {
            s3_test_remove_dir_recursive(store_dir);
        }
#endif
    }
}

/*
 * Unified cleanup function for S3 tests
 * This handles proper cleanup order to avoid use-after-free errors:
 * 1. Stop the engine
 * 2. Destroy the context (this frees the AWS client)
 * 3. Clear the mock generator instance (just the pointer, not the memory)
 * 4. Clean up temp files
 */
static inline void s3_test_cleanup(flb_ctx_t *ctx, char *db_path, char *store_dir)
{
    if (ctx) {
        flb_stop(ctx);
        flb_destroy(ctx);
    }

    /* Clear the generator instance pointer (AWS client already freed by flb_destroy) */
    flb_aws_client_mock_destroy_generator();

    /* Clean up temp files */
    if (db_path) {
        s3_test_cleanup_temp_db(db_path);
        flb_free(db_path);
    }
    if (store_dir) {
        s3_test_cleanup_temp_store_dir(store_dir);
        flb_free(store_dir);
    }
}

/* Helper macro to check context creation and cleanup on failure */
#define S3_TEST_CHECK_CONTEXT(ctx, db_path, store_dir) \
    do { \
        if ((ctx) == NULL) { \
            TEST_MSG("Failed to create flb context"); \
            if (db_path) { \
                s3_test_cleanup_temp_db(db_path); \
                flb_free(db_path); \
            } \
            if (store_dir) { \
                s3_test_cleanup_temp_store_dir(store_dir); \
                flb_free(store_dir); \
            } \
            flb_aws_client_mock_destroy_generator(); \
            TEST_CHECK(false); \
            return; \
        } \
    } while (0)

#endif /* S3_TEST_HELPERS_H */