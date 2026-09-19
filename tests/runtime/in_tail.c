/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2022 The Fluent Bit Authors
 *  Copyright (C) 2015-2018 Treasure Data Inc.
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

/*
Approach for this tests is basing on filter_kubernetes tests
*/

#include <fluent-bit.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_pthread.h>
#include <fluent-bit/flb_compat.h>
#ifdef FLB_HAVE_UNICODE_ENCODER
#include <fluent-bit/flb_unicode.h>
#endif
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <string.h>
#ifdef _WIN32
#include <io.h>
#include <sys/utime.h>
#include "../../plugins/in_tail/win32/interface.h"
#endif
#include <fluent-bit/flb_gzip.h>
#include "flb_tests_runtime.h"

#ifdef _WIN32
#define fsync _commit
#ifndef S_IRUSR
#define S_IRUSR _S_IREAD
#endif
#ifndef S_IWUSR
#define S_IWUSR _S_IWRITE
#endif
#ifndef S_IRGRP
#define S_IRGRP 0
#endif
#ifndef S_IWGRP
#define S_IWGRP 0
#endif
#ifndef S_IRWXU
#define S_IRWXU (S_IRUSR | S_IWUSR)
#endif
#ifndef AT_FDCWD
#define AT_FDCWD -100
#endif

static int flb_test_utimensat(int dirfd, const char *path,
                              const struct timespec times[2], int flags)
{
    struct _utimbuf tm;

    (void) dirfd;
    (void) flags;

    tm.actime = times[0].tv_sec;
    tm.modtime = times[1].tv_sec;

    return _utime(path, &tm);
}

#define utimensat flb_test_utimensat
#endif

#ifdef FLB_HAVE_INOTIFY
#include "../../plugins/in_tail/tail_config.h"
#endif

#define NEW_LINE "\n"
#define PATH_SEPARATOR "/"

#define DPATH_COMMON       FLB_TESTS_DATA_PATH "/data/common"

#ifdef _WIN32
    #define TIME_EPSILON_MS 30
#else
    #define TIME_EPSILON_MS 10
#endif

struct test_tail_ctx {
    flb_ctx_t *flb;    /* Fluent Bit library context */
    int i_ffd;         /* Input fd  */
    int o_ffd;         /* Output fd */
    char **filepaths;
    int *fds;
    int fd_num;
};

pthread_mutex_t result_mutex = PTHREAD_MUTEX_INITIALIZER;
int num_output = 0;
static int get_output_num()
{
    int ret;
    pthread_mutex_lock(&result_mutex);
    ret = num_output;
    pthread_mutex_unlock(&result_mutex);

    return ret;
}

static void set_output_num(int num)
{
    pthread_mutex_lock(&result_mutex);
    num_output = num;
    pthread_mutex_unlock(&result_mutex);
}

static void clear_output_num()
{
    set_output_num(0);
}

static int cb_count_msgpack(void *record, size_t size, void *data)
{
    msgpack_unpacked result;
    size_t off = 0;

    /* Iterate each item array and apply rules */
    msgpack_unpacked_init(&result);
    while (msgpack_unpack_next(&result, record, size, &off) == MSGPACK_UNPACK_SUCCESS) {
        pthread_mutex_lock(&result_mutex);
        num_output++;
        /*
        msgpack_object_print(stdout, result.data);
        puts(NEW_LINE);
        */
        pthread_mutex_unlock(&result_mutex);
    }
    msgpack_unpacked_destroy(&result);

    flb_free(record);
    return 0;
}

struct str_list {
    size_t size;
    char **lists;
};

/* Callback to check expected results */
static int cb_check_json_str_list(void *record, size_t size, void *data)
{
    char *p;
    char *result;
    int num = get_output_num();
    size_t i;
    struct str_list *l = (struct str_list*)data;

    if (!TEST_CHECK(l != NULL)) {
        TEST_MSG("Data is NULL");
        flb_free(record);
        return 0;
    }


    set_output_num(num+1);

    result = (char *) record;

    for (i=0; i<l->size; i++) {
        p = strstr(result, l->lists[i]);
        if(!TEST_CHECK(p != NULL)) {
            TEST_MSG("Expected to find: '%s' in result '%s'",
                      l->lists[i], result);
        }
    }

    flb_free(record);
    return 0;
}

static struct test_tail_ctx *test_tail_ctx_create(struct flb_lib_out_cb *data,
                                                  char **paths, int path_num, int override)
{
    int i_ffd;
    int o_ffd;
    int i;
    int j;
    int fd;
    int o_flags;
    struct test_tail_ctx *ctx = NULL;

    if (!TEST_CHECK(data != NULL)){
        TEST_MSG("data is NULL");
        return NULL;
    }

    ctx = flb_malloc(sizeof(struct test_tail_ctx));
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("malloc failed");
        flb_errno();
        return NULL;
    }
    ctx->fds = NULL;
    ctx->filepaths = NULL;
    ctx->fd_num = path_num;

    /* Service config */
    ctx->flb = flb_create();
    flb_service_set(ctx->flb,
                    "Flush", "0.200000000",
                    "Grace", "1",
                    "Log_Level", "info",
                    "Parsers_File", DPATH_COMMON "/parsers.conf",
                    NULL);

    /* Input */
    i_ffd = flb_input(ctx->flb, (char *) "tail", NULL);
    TEST_CHECK(i_ffd >= 0);
    ctx->i_ffd = i_ffd;

    /* Output */
    o_ffd = flb_output(ctx->flb, (char *) "lib", (void *) data);
    ctx->o_ffd = o_ffd;

    /* open() flags */
    o_flags = O_RDWR | O_CREAT;
#ifdef FLB_SYSTEM_WINDOWS
    o_flags |= O_BINARY;
#endif

    if (paths != NULL) {
        ctx->fds = flb_malloc(sizeof(int) * path_num);
        ctx->filepaths = paths;
        if (!TEST_CHECK(ctx->fds != NULL)) {
            TEST_MSG("malloc failed");
            flb_destroy(ctx->flb);
            flb_free(ctx);
            flb_errno();
            return NULL;
        }

        for (i=0; i<path_num; i++) {
            if (override) {
                unlink(paths[i]);
            }
            else {
                o_flags |= O_APPEND;
            }

            fd = open(paths[i], o_flags, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
            if (!TEST_CHECK(fd >= 0)) {
                TEST_MSG("open failed. errno=%d path[%d]=%s", errno, i, paths[i]);
                flb_destroy(ctx->flb);
                for (j=0; j<i; j++) {
                    close(ctx->fds[j]);
                }
                flb_free(ctx->fds);
                flb_free(ctx);
                flb_errno();
                return NULL;
            }
            ctx->fds[i] = fd;
        }
    }

    return ctx;
}

static void test_tail_ctx_destroy(struct test_tail_ctx *ctx)
{
    int i;
    TEST_CHECK(ctx != NULL);

    if (ctx->fds != NULL) {
        for (i=0; i <ctx->fd_num; i++) {
            close(ctx->fds[i]);
            unlink(ctx->filepaths[i]);
        }
        flb_free(ctx->fds);
    }

    sleep(1);
    flb_stop(ctx->flb);
    flb_destroy(ctx->flb);
    flb_free(ctx);
}

static ssize_t write_msg(struct test_tail_ctx *ctx, char *msg, size_t msg_len)
{
    int i;
    ssize_t w_byte;

    for (i = 0; i <ctx->fd_num; i++) {
        flb_time_msleep(100);
        w_byte = write(ctx->fds[i], msg, msg_len);
        if (!TEST_CHECK(w_byte == msg_len)) {
            TEST_MSG("write failed ret=%ld", w_byte);
            return -1;
        }
        /* new line */
        w_byte = write(ctx->fds[i], NEW_LINE, strlen(NEW_LINE));
        if (!TEST_CHECK(w_byte == strlen(NEW_LINE))) {
            TEST_MSG("write failed ret=%ld", w_byte);
            return -1;
        }
        fsync(ctx->fds[i]);
        flb_time_msleep(100);
    }
    return w_byte;
}

/*
 * Write raw data to file with optional newline.
 * If msg is NULL, only writes a newline (useful for completing incomplete lines).
 * If add_newline is FLB_FALSE, data remains in tail buffer as incomplete line.
 */
static ssize_t write_raw(struct test_tail_ctx *ctx, char *msg, size_t msg_len,
                         int add_newline)
{
    int i;
    ssize_t w_byte = 0;

    for (i = 0; i < ctx->fd_num; i++) {
        if (msg != NULL && msg_len > 0) {
            w_byte = write(ctx->fds[i], msg, msg_len);
            if (!TEST_CHECK(w_byte == msg_len)) {
                TEST_MSG("write failed ret=%ld", w_byte);
                return -1;
            }
        }
        if (add_newline) {
            w_byte = write(ctx->fds[i], NEW_LINE, strlen(NEW_LINE));
            if (!TEST_CHECK(w_byte == strlen(NEW_LINE))) {
                TEST_MSG("write newline failed ret=%ld", w_byte);
                return -1;
            }
        }
        fsync(ctx->fds[i]);
    }
    return w_byte;
}


#define DPATH            FLB_TESTS_DATA_PATH "/data/tail"
#define MAX_LINES        32

/* Gzip helpers */
static int create_gzip_file(const char *path, const char *data, size_t len)
{
    int ret;
    void *gz_data;
    size_t gz_len;
    FILE *fp;

    ret = flb_gzip_compress((void *)data, len, &gz_data, &gz_len);
    if (ret != 0) {
        return -1;
    }

    fp = fopen(path, "wb");
    if (!fp) {
        flb_free(gz_data);
        return -1;
    }

    if (fwrite(gz_data, 1, gz_len, fp) != gz_len) {
        fclose(fp);
        flb_free(gz_data);
        return -1;
    }
    fclose(fp);
    printf("Created gzip file %s size=%lu\n", path, (unsigned long)gz_len);
    flb_free(gz_data);

    return 0;
}

static int append_gzip_file(const char *path, const char *data, size_t len)
{
    int ret;
    void *gz_data;
    size_t gz_len;
    FILE *fp;

    ret = flb_gzip_compress((void *)data, len, &gz_data, &gz_len);
    if (ret != 0) {
        return -1;
    }

    fp = fopen(path, "ab");
    if (!fp) {
        flb_free(gz_data);
        return -1;
    }

    if (fwrite(gz_data, 1, gz_len, fp) != gz_len) {
        fclose(fp);
        flb_free(gz_data);
        return -1;
    }
    fclose(fp);
    flb_free(gz_data);

    return 0;
}

struct test_ctx {
    int count;
    int found_line2;
    const char *expected_line;   /* line the current run must emit */
    int found_expected;
    uint64_t last_offset;        /* offset_key of the newest record */
    int has_offset;
};

/*
 * The output callback runs on the engine thread while the test thread polls
 * and asserts, so every access to test_ctx goes through result_mutex.
 */
static void test_ctx_begin_run(struct test_ctx *ctx, const char *expected_line)
{
    pthread_mutex_lock(&result_mutex);
    ctx->count = 0;
    ctx->found_line2 = 0;
    ctx->found_expected = 0;
    ctx->expected_line = expected_line;
    ctx->has_offset = 0;
    pthread_mutex_unlock(&result_mutex);
}

static int test_ctx_get_count(struct test_ctx *ctx)
{
    int count;

    pthread_mutex_lock(&result_mutex);
    count = ctx->count;
    pthread_mutex_unlock(&result_mutex);

    return count;
}

static int test_ctx_get_found_line2(struct test_ctx *ctx)
{
    int found;

    pthread_mutex_lock(&result_mutex);
    found = ctx->found_line2;
    pthread_mutex_unlock(&result_mutex);

    return found;
}

static int test_ctx_get_found_expected(struct test_ctx *ctx)
{
    int found;

    pthread_mutex_lock(&result_mutex);
    found = ctx->found_expected;
    pthread_mutex_unlock(&result_mutex);

    return found;
}

/* Returns FLB_TRUE when an offset_key value was seen; stores it in 'out'. */
static int test_ctx_get_offset(struct test_ctx *ctx, uint64_t *out)
{
    int has;

    pthread_mutex_lock(&result_mutex);
    has = ctx->has_offset;
    *out = ctx->last_offset;
    pthread_mutex_unlock(&result_mutex);

    return has;
}

static int cb_check_gzip_resume(void *record, size_t size, void *data)
{
    struct test_ctx *ctx = data;
    msgpack_unpacked result;
    msgpack_object root;
    msgpack_object key;
    msgpack_object val;
    msgpack_object v;
    size_t off = 0;
    size_t expected_len = 0;
    const char *expected;
    int is_line2;
    int is_expected;
    int has_record_offset;
    uint64_t record_offset;
    int i;

    pthread_mutex_lock(&result_mutex);
    expected = ctx->expected_line;
    pthread_mutex_unlock(&result_mutex);

    if (expected != NULL) {
        expected_len = strlen(expected);
    }

    msgpack_unpacked_init(&result);
    while (msgpack_unpack_next(&result, record, size, &off) == MSGPACK_UNPACK_SUCCESS) {
        root = result.data;
        if (root.type == MSGPACK_OBJECT_ARRAY && root.via.array.size == 2) {
            is_line2 = 0;
            is_expected = 0;
            has_record_offset = 0;
            record_offset = 0;

            /* Check content for "line2" and for this run's expected line */
            val = root.via.array.ptr[1]; /* map */
            if (val.type == MSGPACK_OBJECT_MAP) {
                for (i = 0; i < val.via.map.size; i++) {
                    key = val.via.map.ptr[i].key;
                    v = val.via.map.ptr[i].val;
                    if (key.type == MSGPACK_OBJECT_STR &&
                        key.via.str.size == 3 &&
                        memcmp(key.via.str.ptr, "log", 3) == 0) {
                        if (v.type == MSGPACK_OBJECT_STR) {
                            if (v.via.str.size >= 5 &&
                                memcmp(v.via.str.ptr, "line2", 5) == 0) {
                                is_line2 = 1;
                            }
                            if (expected != NULL &&
                                v.via.str.size >= expected_len &&
                                memcmp(v.via.str.ptr, expected, expected_len) == 0) {
                                is_expected = 1;
                            }
                        }
                    }
                    else if (key.type == MSGPACK_OBJECT_STR &&
                             key.via.str.size == 3 &&
                             memcmp(key.via.str.ptr, "off", 3) == 0) {
                        if (v.type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
                            record_offset = v.via.u64;
                            has_record_offset = 1;
                        }
                    }
                }
            }

            pthread_mutex_lock(&result_mutex);
            ctx->count++;
            if (is_line2) {
                ctx->found_line2 = 1;
            }
            if (is_expected) {
                ctx->found_expected = 1;
            }
            if (has_record_offset) {
                ctx->last_offset = record_offset;
                ctx->has_offset = 1;
            }
            pthread_mutex_unlock(&result_mutex);
        }
    }
    msgpack_unpacked_destroy(&result);

    flb_free(record);
    return 0;
}


int64_t result_time;
struct tail_test_result {
    const char *target;
    int   nMatched;
    int   nNotMatched;
    int   nLines;
};

struct tail_file_lines {
  char *lines[MAX_LINES];
  int lines_c;
};

void wait_with_timeout(uint32_t timeout_ms, struct tail_test_result *result, int nExpected)
{
    struct flb_time start_time;
    struct flb_time end_time;
    struct flb_time diff_time;
    uint64_t elapsed_time_flb = 0;

    flb_time_get(&start_time);

    while (true) {
        if (result->nMatched == nExpected) {
            break;
        }

        flb_time_msleep(100);
        flb_time_get(&end_time);
        flb_time_diff(&end_time, &start_time, &diff_time);
        elapsed_time_flb = flb_time_to_nanosec(&diff_time) / 1000000;

        if (elapsed_time_flb > timeout_ms - TIME_EPSILON_MS) {
            flb_warn("[timeout] elapsed_time: %ld", elapsed_time_flb);
            // Reached timeout.
            break;
        }
    }
}

/*
 * Wait until output count reaches expected value or timeout.
 * Returns the final count.
 */
static int wait_for_count_with_timeout(struct test_ctx *ctx, int expected,
                                       uint32_t timeout_ms)
{
    struct flb_time start_time;
    struct flb_time end_time;
    struct flb_time diff_time;
    uint64_t elapsed_time_flb = 0;
    int count;

    flb_time_get(&start_time);

    while (1) {
        count = test_ctx_get_count(ctx);
        if (count >= expected) {
            return count;
        }

        flb_time_msleep(50);
        flb_time_get(&end_time);
        flb_time_diff(&end_time, &start_time, &diff_time);
        elapsed_time_flb = flb_time_to_nanosec(&diff_time) / 1000000;

        if (elapsed_time_flb > timeout_ms) {
            break;
        }
    }

    return test_ctx_get_count(ctx);
}

void wait_num_with_timeout(uint32_t timeout_ms, int *output_num)
{
    struct flb_time start_time;
    struct flb_time end_time;
    struct flb_time diff_time;
    uint64_t elapsed_time_flb = 0;

    flb_time_get(&start_time);

    while (true) {
        *output_num = get_output_num();

        if (*output_num > 0) {
            break;
        }

        flb_time_msleep(100);
        flb_time_get(&end_time);
        flb_time_diff(&end_time, &start_time, &diff_time);
        elapsed_time_flb = flb_time_to_nanosec(&diff_time) / 1000000;

        if (elapsed_time_flb > timeout_ms) {
            flb_warn("[timeout] elapsed_time: %ld", elapsed_time_flb);
            /* Reached timeout. */
            break;
        }
    }
}

void wait_expected_num_with_timeout(uint32_t timeout_ms, int expected_num, int *output_num)
{
    struct flb_time start_time;
    struct flb_time end_time;
    struct flb_time diff_time;
    uint64_t elapsed_time_flb = 0;

    flb_time_get(&start_time);

    while (true) {
        *output_num = get_output_num();

        if (*output_num >= expected_num) {
            break;
        }

        flb_time_msleep(100);
        flb_time_get(&end_time);
        flb_time_diff(&end_time, &start_time, &diff_time);
        elapsed_time_flb = flb_time_to_nanosec(&diff_time) / 1000000;

        if (elapsed_time_flb > timeout_ms) {
            flb_warn("[timeout] elapsed_time: %ld", elapsed_time_flb);
            /* Reached timeout. */
            break;
        }
    }
}

static inline int64_t set_result(int64_t v)
{
#ifdef _WIN32
    return InterlockedExchange64((volatile LONG64 *)&result_time, v);
#else
    int64_t old = __sync_lock_test_and_set(&result_time, v);
    return old;
#endif
}


static int file_to_buf(const char *path, char **out_buf, size_t *out_size)
{
    int ret;
    long bytes;
    char *buf;
    FILE *fp;
    struct stat st;
    const char *file_mode = "r";

#ifdef FLB_SYSTEM_WINDOWS
    file_mode = "rb";
#endif

    ret = stat(path, &st);
    if (ret == -1) {
        return -1;
    }

    fp = fopen(path, file_mode);
    if (!fp) {
        return -1;
    }

    buf = flb_malloc(st.st_size+1);
    if (!buf) {
        flb_errno();
        fclose(fp);
        return -1;
    }

    bytes = fread(buf, st.st_size, 1, fp);
    if (bytes != 1) {
        flb_errno();
        flb_free(buf);
        fclose(fp);
        return -1;
    }

    fclose(fp);
    buf[st.st_size] = '\0';
    *out_buf = buf;
    *out_size = st.st_size;

    return 0;
}

/* Given a target, lookup the .out file and return it content in a tail_file_lines structure */
static struct tail_file_lines *get_out_file_content(const char *target)
{
    int ret;
    char file[PATH_MAX];
    char *p;
    char *out_buf;
    size_t out_size;
    struct tail_file_lines *file_lines = flb_malloc(sizeof (struct tail_file_lines));
    file_lines->lines_c = 0;

    snprintf(file, sizeof(file) - 1, DPATH "/out/%s.out", target);

    ret = file_to_buf(file, &out_buf, &out_size);
    TEST_CHECK_(ret == 0, "getting output file content: %s", file);
    if (ret != 0) {
        file_lines->lines_c = 0;
        return file_lines;
    }

    file_lines->lines[file_lines->lines_c++] = out_buf;

    int i;
    for (i=0; i<out_size; i++) {
      // Nullify \n and \r characters
      p = (char *)(out_buf + i);
      if (*p == '\n' || *p == '\r') {
        *p = '\0';

        if (i == out_size - 1) {
          break;
        }

        if (*++p != '\0' && *p != '\n' && *p != '\r' && file_lines->lines_c < MAX_LINES) {
          file_lines->lines[file_lines->lines_c++] = p;
        }
      }
    }

    return file_lines;
}

static int cb_check_result(void *record, size_t size, void *data)
{
    struct tail_test_result *result;
    struct tail_file_lines *out;

    result = (struct tail_test_result *) data;

    char *check;

    out = get_out_file_content(result->target);
    if (!out->lines_c) {
        goto exit;
    }
    /*
      * Our validation is: check that the one of the output lines
      * in the output record.
      */
    int i;
    result->nLines = out->lines_c;
    for (i=0; i<out->lines_c; i++) {
      check = strstr(record, out->lines[i]);
      if (check != NULL) {
          result->nMatched++;
          goto exit;
      }
    }
    result->nNotMatched++;
exit:
    if (size > 0) {
        flb_free(record);
    }
    if (out->lines_c) {
        flb_free(out->lines[0]);
        flb_free(out);
    }
    return 0;
}

void do_test(char *system, const char *target, int tExpected, int nExpected, ...)
{
    int64_t ret;
    flb_ctx_t    *ctx    = NULL;
    int in_ffd;
    int out_ffd;
    va_list va;
    char *key;
    char *value;
    char path[PATH_MAX];
    struct tail_test_result result = {0};

    result.nMatched = 0;
    result.target = target;

    struct flb_lib_out_cb cb;
    cb.cb   = cb_check_result;
    cb.data = &result;

    /* initialize */
    set_result(0);

    ctx = flb_create();

    ret = flb_service_set(ctx,
                          "Log_Level", "error",
                          "Parsers_File", DPATH "/parsers.conf",
                          NULL);
    TEST_CHECK_(ret == 0, "setting service options");

    in_ffd = flb_input(ctx, (char *) system, NULL);
    TEST_CHECK(in_ffd >= 0);
    TEST_CHECK(flb_input_set(ctx, in_ffd, "tag", "test", NULL) == 0);

    /* Compose path based on target */
    snprintf(path, sizeof(path) - 1, DPATH "/log/%s.log", target);
    TEST_CHECK_(access(path, R_OK) == 0, "accessing log file: %s", path);

    TEST_CHECK(flb_input_set(ctx, in_ffd,
                             "path"          , path,
                             "docker_mode"   , "on",
                             "parser"        , "docker",
                             "read_from_head", "true",
                             NULL) == 0);

    va_start(va, nExpected);
    while ((key = va_arg(va, char *))) {
        value = va_arg(va, char *);
        TEST_CHECK(value != NULL);
        TEST_CHECK(flb_input_set(ctx, in_ffd, key, value, NULL) == 0);
    }
    va_end(va);

    out_ffd = flb_output(ctx, (char *) "lib", &cb);
    TEST_CHECK(out_ffd >= 0);
    TEST_CHECK(flb_output_set(ctx, out_ffd,
                              "match", "test",
                              "format", "json",
                              NULL) == 0);

    TEST_CHECK(flb_service_set(ctx, "Flush", "0.5",
                                    "Grace", "1",
                                    NULL) == 0);

    /* Start test */
    /* Start the engine */
    ret = flb_start(ctx);
    TEST_CHECK_(ret == 0, "starting engine");

    /* Poll for up to 5 seconds or until we got a match */
    for (ret = 0; ret < tExpected && result.nMatched < nExpected; ret++) {
        usleep(1000);
    }

    /* Wait until matching nExpected results */
    wait_with_timeout(5000, &result, nExpected);

    TEST_CHECK(result.nMatched == nExpected);
    TEST_MSG("result.nMatched: %i\nnExpected: %i", result.nMatched, nExpected);

    ret = flb_stop(ctx);
    TEST_CHECK_(ret == 0, "stopping engine");

    if (ctx) {
        flb_destroy(ctx);
    }
}

void flb_test_in_tail_dockermode()
{
    do_test("tail", "dockermode", 20000, 3,
            NULL);
}

void flb_test_in_tail_dockermode_splitted_line()
{
    do_test("tail", "dockermode_splitted_line", 20000, 2,
            NULL);
}

void flb_test_in_tail_dockermode_multiple_lines()
{
    do_test("tail", "dockermode_multiple_lines", 20000, 2,
            "Docker_Mode_Parser", "docker_multiline",
            NULL);
}

void flb_test_in_tail_dockermode_splitted_multiple_lines()
{
    do_test("tail", "dockermode_splitted_multiple_lines", 20000, 2,
            "Docker_Mode_Parser", "docker_multiline",
            NULL);
}

void flb_test_in_tail_dockermode_firstline_detection()
{
    do_test("tail", "dockermode_firstline_detection", 20000, 5,
            "Docker_Mode_Parser", "docker_multiline",
            NULL);
}

void do_test_generic_enctype(char *system, const char *target, const char *enc, int tExpected, int nExpected, ...)
{
    int64_t ret;
    flb_ctx_t    *ctx    = NULL;
    int in_ffd;
    int out_ffd;
    va_list va;
    char *key;
    char *value;
    char path[PATH_MAX];
    struct tail_test_result result = {0};

    result.nMatched = 0;
    result.target = target;

    struct flb_lib_out_cb cb;
    cb.cb   = cb_check_result;
    cb.data = &result;

    /* initialize */
    set_result(0);

    ctx = flb_create();

    ret = flb_service_set(ctx,
                          "Log_Level", "error",
                          "Parsers_File", DPATH "/parsers.conf",
                          NULL);
    TEST_CHECK_(ret == 0, "setting service options");

    in_ffd = flb_input(ctx, (char *) system, NULL);
    TEST_CHECK(in_ffd >= 0);
    TEST_CHECK(flb_input_set(ctx, in_ffd, "tag", "test", NULL) == 0);

    /* Compose path based on target */
    snprintf(path, sizeof(path) - 1, DPATH "/log/%s.log", target);
    TEST_CHECK_(access(path, R_OK) == 0, "accessing log file: %s", path);

    TEST_CHECK(flb_input_set(ctx, in_ffd,
                             "path"          , path,
                             "generic.encoding", enc,
                             "read_from_head", "true",
                             NULL) == 0);

    va_start(va, nExpected);
    while ((key = va_arg(va, char *))) {
        value = va_arg(va, char *);
        TEST_CHECK(value != NULL);
        TEST_CHECK(flb_input_set(ctx, in_ffd, key, value, NULL) == 0);
    }
    va_end(va);

    out_ffd = flb_output(ctx, (char *) "lib", &cb);
    TEST_CHECK(out_ffd >= 0);
    TEST_CHECK(flb_output_set(ctx, out_ffd,
                              "match", "test",
                              "format", "json",
                              NULL) == 0);

    TEST_CHECK(flb_service_set(ctx, "Flush", "0.5",
                                    "Grace", "1",
                                    NULL) == 0);

    /* Start test */
    /* Start the engine */
    ret = flb_start(ctx);
    TEST_CHECK_(ret == 0, "starting engine");

    /* Poll for up to 5 seconds or until we got a match */
    for (ret = 0; ret < tExpected && result.nMatched < nExpected; ret++) {
        usleep(1000);
    }

    /* Wait until matching nExpected results */
    wait_with_timeout(5000, &result, nExpected);

    TEST_CHECK(result.nMatched == nExpected);
    TEST_MSG("result.nMatched: %i\nnExpected: %i", result.nMatched, nExpected);

    ret = flb_stop(ctx);
    TEST_CHECK_(ret == 0, "stopping engine");

    if (ctx) {
        flb_destroy(ctx);
    }
}

void flb_test_in_tail_generic_enc_big5()
{
    do_test_generic_enctype("tail", "generic_enc_big5", "BIG5",
                            20000, 10, NULL);
}

void flb_test_in_tail_generic_enc_gb18030()
{
    do_test_generic_enctype("tail", "generic_enc_gb18030", "GB18030",
                            20000, 12, NULL);
}

void flb_test_in_tail_generic_enc_gbk()
{
    do_test_generic_enctype("tail", "generic_enc_gbk", "GBK",
                            20000, 11, NULL);
}

void flb_test_in_tail_generic_enc_sjis()
{
    do_test_generic_enctype("tail", "generic_enc_sjis", "ShiftJIS",
                            20000, 11, NULL);
}

void flb_test_in_tail_generic_enc_win1250()
{
    do_test_generic_enctype("tail", "generic_enc_win1250", "WIN1250",
                            20000, 6, NULL);
}

void flb_test_in_tail_generic_enc_win1251()
{
    do_test_generic_enctype("tail", "generic_enc_win1251", "WIN1251",
                            20000, 9, NULL);
}

void flb_test_in_tail_generic_enc_win1252()
{
    do_test_generic_enctype("tail", "generic_enc_win1252", "WIN1252",
                            20000, 14, NULL);
}

void flb_test_in_tail_generic_enc_win1253()
{
    do_test_generic_enctype("tail", "generic_enc_win1253", "WIN1253",
                            20000, 8, NULL);
}

void flb_test_in_tail_generic_enc_win1254()
{
    do_test_generic_enctype("tail", "generic_enc_win1254", "WIN1254",
                            20000, 13, NULL);
}

void flb_test_in_tail_generic_enc_win1255()
{
    do_test_generic_enctype("tail", "generic_enc_win1255", "WIN1255",
                            20000, 8, NULL);
}

void flb_test_in_tail_generic_enc_win1256()
{
    do_test_generic_enctype("tail", "generic_enc_win1256", "WIN1256",
                            20000, 8, NULL);
}

#ifdef FLB_HAVE_UNICODE_ENCODER
void do_test_unicode(char *system, const char *target, int nExpected, ...)
{
    int64_t ret;
    flb_ctx_t    *ctx    = NULL;
    int in_ffd;
    int out_ffd;
    va_list va;
    char *key;
    char *value;
    char path[PATH_MAX];
    int num;
    int unused;

    struct flb_lib_out_cb cb;

    /* For UTF-16LE/BE encodings, there are test cases that include
     * multibyte characters. We didn't fully support for escaping
     * Unicode code points especially SIMD enabled situations.
     * So, it's just counting for the consumed record(s) here.
     */
    cb.cb   = cb_count_msgpack;
    cb.data = &unused;

    ctx = flb_create();

    ret = flb_service_set(ctx,
                          "Log_Level", "error",
                          NULL);
    TEST_CHECK_(ret == 0, "setting service options");

    in_ffd = flb_input(ctx, (char *) system, NULL);
    TEST_CHECK(in_ffd >= 0);
    TEST_CHECK(flb_input_set(ctx, in_ffd, "tag", "test", NULL) == 0);

    /* Compose path based on target */
    snprintf(path, sizeof(path) - 1, DPATH "/log/%s.log", target);
    TEST_CHECK_(access(path, R_OK) == 0, "accessing log file: %s", path);

    TEST_CHECK(flb_input_set(ctx, in_ffd,
                             "path"          , path,
                             "read_from_head", "true",
                             NULL) == 0);

    va_start(va, nExpected);
    while ((key = va_arg(va, char *))) {
        value = va_arg(va, char *);
        TEST_CHECK(value != NULL);
        TEST_CHECK(flb_input_set(ctx, in_ffd, key, value, NULL) == 0);
    }
    va_end(va);

    out_ffd = flb_output(ctx, (char *) "lib", &cb);
    TEST_CHECK(out_ffd >= 0);
    TEST_CHECK(flb_output_set(ctx, out_ffd,
                              "match", "test",
                              "format", "json",
                              NULL) == 0);

    TEST_CHECK(flb_service_set(ctx, "Flush", "0.5",
                                    "Grace", "1",
                                    NULL) == 0);

    /* Start test */
    /* Start the engine */
    ret = flb_start(ctx);
    TEST_CHECK_(ret == 0, "starting engine");

    /* /\* Poll for up to 5 seconds or until we got a match *\/ */
    /* for (ret = 0; result.nMatched <= nExpected; ret++) { */
    /*     usleep(1000); */
    /* } */

    /* waiting to flush */
    wait_num_with_timeout(5000, &num);
    if (!TEST_CHECK(num > 0))  {
        TEST_MSG("no output");
    }

    ret = flb_stop(ctx);
    TEST_CHECK_(ret == 0, "stopping engine");

    if (ctx) {
        flb_destroy(ctx);
    }
}

void flb_test_in_tail_utf16le_c()
{
    do_test_unicode("tail", "unicode_c", 1,
                    "Unicode.Encoding", "auto",
                    NULL);
}

void flb_test_in_tail_utf16be_c()
{
    do_test_unicode("tail", "unicode_be_c", 1,
                    "Unicode.Encoding", "auto",
                    NULL);
}

void flb_test_in_tail_utf16le_j()
{
    do_test_unicode("tail", "unicode_j", 1,
                    "Unicode.Encoding", "auto",
                    NULL);
}

void flb_test_in_tail_utf16be_j()
{
    do_test_unicode("tail", "unicode_be_j", 1,
                    "Unicode.Encoding", "auto",
                    NULL);
}

void flb_test_in_tail_utf16le_subdivision_flags()
{
    do_test_unicode("tail", "unicode_subdivision_flags", 1,
                    "Unicode.Encoding", "auto",
                    NULL);
}

void flb_test_in_tail_utf16be_subdivision_flags()
{
    do_test_unicode("tail", "unicode_subdivision_flags_be", 1,
                    "Unicode.Encoding", "auto",
                    NULL);
}
#endif

int write_long_lines(int fd) {
    ssize_t ret;
    int i;
    const char* data = "0123456789abcdef" "0123456789abcdef";
    size_t len = strlen(data);

    for (i=0; i<1024; i++) {
        ret = write(fd, data, strlen(data));
        if (ret < 0) {
            flb_errno();
            return -1;
        }
        else if(ret != len) {
            write(fd, &data[ret], len-ret);
        }
    }

    write(fd, "\n", 1);
    return 0;
}

void flb_test_in_tail_skip_long_lines()
{
    int64_t ret;
    flb_ctx_t    *ctx    = NULL;
    int in_ffd;
    int out_ffd;
    char path[PATH_MAX];
    struct tail_test_result result = {0};
    int fd;

    char *target = "skip_long_lines";
    int nExpected = 2;
    int nExpectedNotMatched = 0;
    int nExpectedLines = 2;

    result.nMatched = 0;
    result.target = target;

    struct flb_lib_out_cb cb;
    cb.cb   = cb_check_result;
    cb.data = &result;

    /* initialize */
    set_result(0);

    ctx = flb_create();

    ret = flb_service_set(ctx,
                          "Log_Level", "error",
                          NULL);
    TEST_CHECK_(ret == 0, "setting service options");

    in_ffd = flb_input(ctx, "tail", NULL);
    TEST_CHECK(in_ffd >= 0);
    TEST_CHECK(flb_input_set(ctx, in_ffd, "tag", "test", NULL) == 0);

    /* Compose path based on target */
    snprintf(path, sizeof(path) - 1, DPATH "/log/%s.log", target);
    fd = creat(path, S_IRWXU | S_IRGRP);
    TEST_CHECK(fd >= 0);

    /* Write log
         =======
         before_long_line
         (long line which should be skipped)
         after_long_line
         =======

      Output should be "before_long_line" and "after_long_line"
     */
    write(fd, "before_long_line\n", strlen("before_long_line\n"));
    write_long_lines(fd);
    write(fd, "after_long_line\n", strlen("after_long_line\n"));
    close(fd);

    TEST_CHECK_(access(path, R_OK) == 0, "accessing log file: %s", path);

    TEST_CHECK(flb_input_set(ctx, in_ffd,
                             "path"          , path,
                             "read_from_head", "true",
                             "skip_long_lines", "on",
                             NULL) == 0);

    out_ffd = flb_output(ctx, (char *) "lib", &cb);
    TEST_CHECK(out_ffd >= 0);
    TEST_CHECK(flb_output_set(ctx, out_ffd,
                              "match", "test",
                              "format", "json",
                              NULL) == 0);

    TEST_CHECK(flb_service_set(ctx, "Flush", "0.5",
                                    "Grace", "1",
                                    NULL) == 0);

    /* Start test */
    /* Start the engine */
    ret = flb_start(ctx);
    TEST_CHECK_(ret == 0, "starting engine");

    wait_with_timeout(5000, &result, nExpected);

    TEST_CHECK(result.nMatched == nExpected);
    TEST_MSG("result.nMatched: %i\nnExpected: %i", result.nMatched, nExpected);
    TEST_CHECK(result.nNotMatched == nExpectedNotMatched);
    TEST_MSG("result.nNotMatched: %i\nnExpectedNotMatched: %i", result.nNotMatched, nExpectedNotMatched);
    TEST_CHECK(result.nLines == nExpectedLines);
    TEST_MSG("result.nLines: %i\nnExpectedLines: %i", result.nLines, nExpectedLines);

    ret = flb_stop(ctx);
    TEST_CHECK_(ret == 0, "stopping engine");

    if (ctx) {
        flb_destroy(ctx);
    }

    unlink(path);
}

static int write_long_ascii_line(int fd, size_t total_bytes)
{
    const char *chunk = "0123456789abcdef0123456789abcdef"; /* 32 bytes */
    size_t chunk_len = strlen(chunk);
    size_t written = 0;
    ssize_t ret;
    size_t rest = 0;

    while (written + chunk_len <= total_bytes) {
        ret = write(fd, chunk, chunk_len);
        if (ret < 0) {
            flb_errno();
            return -1;
        }
        written += (size_t) ret;
    }
    if (written < total_bytes) {
        rest = total_bytes - written;
        ret = write(fd, chunk, rest);
        if (ret < 0) {
            flb_errno();
            return -1;
        }
        written += (size_t) ret;
    }
    if (write(fd, "\n", 1) != 1) {
        flb_errno();
        return -1;
    }
    return 0;
}

static int write_long_utf8_line(int fd, size_t total_bytes)
{
    const char *u8_aa = "あ";
    size_t u8_len = strlen(u8_aa); /* 3 */
    size_t written = 0;
    ssize_t ret;
    const char *ascii = "XYZ";
    size_t rest = 0;

    while (written + u8_len <= total_bytes) {
        ret = write(fd, u8_aa, u8_len);
        if (ret < 0) {
            flb_errno();
            return -1;
        }
        written += (size_t) ret;
    }

    if (written < total_bytes) {
        rest = total_bytes - written;
        if (rest > strlen(ascii)) {
            rest = strlen(ascii);
        }
        ret = write(fd, ascii, rest);
        if (ret < 0) {
            flb_errno();
            return -1;
        }
        written += (size_t) ret;
    }
    if (write(fd, "\n", 1) != 1) {
        flb_errno();
        return -1;
    }
    return 0;
}

void flb_test_in_tail_truncate_long_lines()
{
    int64_t ret;
    flb_ctx_t    *ctx = NULL;
    int in_ffd, out_ffd;
    char path[PATH_MAX];
    int fd;

    const char *target = "truncate_long_lines_basic";
    int nExpected = 3;              /* before + truncated long line + after */

    struct flb_lib_out_cb cb;
    int unused = 0;
    int num = 0;

    cb.cb   = cb_count_msgpack;
    cb.data = &unused;

    clear_output_num();

    ctx = flb_create();
    TEST_CHECK_(ctx != NULL, "flb_create failed");

    TEST_CHECK_(flb_service_set(ctx, "Log_Level", "error", NULL) == 0,
                "setting service options");

    in_ffd = flb_input(ctx, "tail", NULL);
    TEST_CHECK(in_ffd >= 0);
    TEST_CHECK(flb_input_set(ctx, in_ffd, "tag", "test", NULL) == 0);

    snprintf(path, sizeof(path) - 1, DPATH "/log/%s.log", target);
    fd = creat(path, S_IRWXU | S_IRGRP);
    TEST_CHECK(fd >= 0);

    write(fd, "before_long_line\n", strlen("before_long_line\n"));

    TEST_CHECK(write_long_ascii_line(fd, 10 * 1024) == 0);

    write(fd, "after_long_line\n", strlen("after_long_line\n"));
    close(fd);

    TEST_CHECK_(access(path, R_OK) == 0, "accessing log file: %s", path);

    TEST_CHECK(flb_input_set(ctx, in_ffd,
                             "path", path,
                             "read_from_head", "true",
                             "truncate_long_lines", "on",
                             "skip_long_lines", "off",
                             "Buffer_Chunk_Size", "1k",
                             "Buffer_Max_Size",   "4k",
                             NULL) == 0);

    out_ffd = flb_output(ctx, "lib", &cb);
    TEST_CHECK(out_ffd >= 0);
    TEST_CHECK(flb_output_set(ctx, out_ffd,
                              "match", "test",
                              NULL) == 0);

    TEST_CHECK(flb_service_set(ctx, "Flush", "0.5",
                                    "Grace", "1",
                                    NULL) == 0);

    ret = flb_start(ctx);
    TEST_CHECK_(ret == 0, "starting engine");

    wait_expected_num_with_timeout(5000, nExpected, &num);

    num = get_output_num();
    TEST_CHECK(num == nExpected);
    TEST_MSG("output count (truncate basic): got=%d expected=%d", num, nExpected);

    ret = flb_stop(ctx);
    TEST_CHECK_(ret == 0, "stopping engine");

    if (ctx) {
        flb_destroy(ctx);
    }

    unlink(path);
}

void flb_test_in_tail_truncate_long_lines_utf8()
{
    int64_t ret;
    flb_ctx_t    *ctx = NULL;
    int in_ffd, out_ffd;
    char path[PATH_MAX];
    int fd;

    const char *target = "truncate_long_lines_utf8";
    int nExpected = 1;

    struct flb_lib_out_cb cb;
    int unused = 0;
    int num = 0;

    cb.cb   = cb_count_msgpack;
    cb.data = &unused;

    clear_output_num();

    ctx = flb_create();
    TEST_CHECK_(ctx != NULL, "flb_create failed");

    TEST_CHECK_(flb_service_set(ctx, "Log_Level", "error", NULL) == 0,
                "setting service options");

    in_ffd = flb_input(ctx, "tail", NULL);
    TEST_CHECK(in_ffd >= 0);
    TEST_CHECK(flb_input_set(ctx, in_ffd, "tag", "test", NULL) == 0);

    snprintf(path, sizeof(path) - 1, DPATH "/log/%s.log", target);
    fd = creat(path, S_IRWXU | S_IRGRP);
    TEST_CHECK(fd >= 0);

    TEST_CHECK(write_long_utf8_line(fd, 10 * 1024) == 0);
    close(fd);

    TEST_CHECK_(access(path, R_OK) == 0, "accessing log file: %s", path);

    TEST_CHECK(flb_input_set(ctx, in_ffd,
                             "path", path,
                             "read_from_head", "true",
                             "truncate_long_lines", "on",
                             "skip_long_lines", "off",
                             "Buffer_Chunk_Size", "1k",
                             "Buffer_Max_Size",   "4k",
                             NULL) == 0);

    out_ffd = flb_output(ctx, "lib", &cb);
    TEST_CHECK(out_ffd >= 0);
    TEST_CHECK(flb_output_set(ctx, out_ffd,
                              "match", "test",
                              NULL) == 0);

    TEST_CHECK(flb_service_set(ctx, "Flush", "0.5",
                                    "Grace", "1",
                                    NULL) == 0);

    ret = flb_start(ctx);
    TEST_CHECK_(ret == 0, "starting engine");

    wait_num_with_timeout(5000, &num);

    num = get_output_num();
    TEST_CHECK(num == nExpected);
    TEST_MSG("output count (truncate utf8): got=%d expected=%d", num, nExpected);

    ret = flb_stop(ctx);
    TEST_CHECK_(ret == 0, "stopping engine");

    if (ctx) {
        flb_destroy(ctx);
    }

    unlink(path);
}

/*
 * test case for https://github.com/fluent/fluent-bit/issues/3943
 *
 * test to read the lines "CRLF + empty_line + LF"
 */
void flb_test_in_tail_issue_3943()
{
    int64_t ret;
    flb_ctx_t    *ctx    = NULL;
    int in_ffd;
    int out_ffd;
    char path[PATH_MAX];
    struct tail_test_result result = {0};

    char *target = "3943";
    int nExpected = 2;
    int nExpectedNotMatched = 0;
    int nExpectedLines = 2;

    result.nMatched = 0;
    result.target = target;

    struct flb_lib_out_cb cb;
    cb.cb   = cb_check_result;
    cb.data = &result;

    /* initialize */
    set_result(0);

    ctx = flb_create();

    ret = flb_service_set(ctx,
                          "Log_Level", "error",
                          NULL);
    TEST_CHECK_(ret == 0, "setting service options");

    in_ffd = flb_input(ctx, "tail", NULL);
    TEST_CHECK(in_ffd >= 0);
    TEST_CHECK(flb_input_set(ctx, in_ffd, "tag", "test", NULL) == 0);

    snprintf(path, sizeof(path) - 1, DPATH "/log/%s.log", target);
    TEST_CHECK_(access(path, R_OK) == 0, "accessing log file: %s", path);

    TEST_CHECK(flb_input_set(ctx, in_ffd,
                             "path"          , path,
                             "read_from_head", "true",
                             NULL) == 0);

    out_ffd = flb_output(ctx, (char *) "lib", &cb);
    TEST_CHECK(out_ffd >= 0);
    TEST_CHECK(flb_output_set(ctx, out_ffd,
                              "match", "test",
                              "format", "json",
                              NULL) == 0);

    TEST_CHECK(flb_service_set(ctx, "Flush", "0.5",
                                    "Grace", "1",
                                    NULL) == 0);

    /* Start test */
    /* Start the engine */
    ret = flb_start(ctx);
    TEST_CHECK_(ret == 0, "starting engine");

    wait_with_timeout(3000, &result, nExpected);

    TEST_CHECK(result.nMatched == nExpected);
    TEST_MSG("result.nMatched: %i\nnExpected: %i", result.nMatched, nExpected);
    TEST_CHECK(result.nNotMatched == nExpectedNotMatched);
    TEST_MSG("result.nNotMatched: %i\nnExpectedNotMatched: %i", result.nNotMatched, nExpectedNotMatched);
    TEST_CHECK(result.nLines == nExpectedLines);
    TEST_MSG("result.nLines: %i\nnExpectedLines: %i", result.nLines, nExpectedLines);

    ret = flb_stop(ctx);
    TEST_CHECK_(ret == 0, "stopping engine");

    if (ctx) {
        flb_destroy(ctx);
    }
}

void flb_test_in_tail_multiline_json_and_regex()
{
    int64_t ret;
    int in_ffd;
    int out_ffd;
    int n_expected;
    int t_expected;
    char *target;
    char path[PATH_MAX];
    struct tail_test_result result = {0};
    flb_ctx_t *ctx;

    target = "multiline_001";
    result.nMatched = 0;
    result.target = target;

    struct flb_lib_out_cb cb;
    cb.cb   = cb_check_result;
    cb.data = &result;

    /* initialize */
    set_result(0);

    ctx = flb_create();

    TEST_CHECK(flb_service_set(ctx, "Flush", "0.5",
                                    "Grace", "5",
                                    NULL) == 0);

    ret = flb_service_set(ctx,
                          "Log_Level", "info",
                          "Parsers_File", DPATH "/parsers_multiline_json.conf",
                          NULL);
    TEST_CHECK_(ret == 0, "setting service options");

    in_ffd = flb_input(ctx, (char *) "tail", NULL);
    TEST_CHECK(in_ffd >= 0);
    TEST_CHECK(flb_input_set(ctx, in_ffd, "tag", "test", NULL) == 0);

    /* Compose path based on target */
    snprintf(path, sizeof(path) - 1, DPATH "/log/%s.log", target);
    TEST_CHECK_(access(path, R_OK) == 0, "accessing log file: %s", path);

    TEST_CHECK(flb_input_set(ctx, in_ffd,
                             "path"            , path,
                             "read_from_head"  , "true",
                             "multiline.parser", "multiline-json-regex",
                             NULL) == 0);


    out_ffd = flb_output(ctx, (char *) "lib", &cb);
    TEST_CHECK(out_ffd >= 0);
    TEST_CHECK(flb_output_set(ctx, out_ffd,
                              "match", "test",
                              "format", "json",
                              NULL) == 0);

    /* Start test */
    /* Start the engine */
    ret = flb_start(ctx);
    TEST_CHECK_(ret == 0, "starting engine");

    /* Expect 1 final record */
    n_expected = 1;
    t_expected = 5000;

    /* Poll for up to 5 seconds or until we got a match */
    for (ret = 0; ret < t_expected && result.nMatched < n_expected; ret++) {
        usleep(1000);
    }
    wait_with_timeout(5000, &result, n_expected);

    TEST_CHECK(result.nMatched == n_expected);
    TEST_MSG("result.nMatched: %i\nnExpected: %i", result.nMatched, n_expected);

    ret = flb_stop(ctx);
    TEST_CHECK_(ret == 0, "stopping engine");

    if (ctx) {
        flb_destroy(ctx);
    }
}

void flb_test_path_comma()
{
    struct flb_lib_out_cb cb_data;
    struct test_tail_ctx *ctx;
    char *file[] = {"a.log", "b.log", "c.log", "d.log"};
    char *path = "a.log, b.log, c.log, d.log";
    char *msg = "hello world";
    int ret;
    int num;
    int unused;

    clear_output_num();

    cb_data.cb = cb_count_msgpack;
    cb_data.data = &unused;

    ctx = test_tail_ctx_create(&cb_data, &file[0], sizeof(file)/sizeof(char*), FLB_TRUE);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
        exit(EXIT_FAILURE);
    }

    ret = flb_input_set(ctx->flb, ctx->o_ffd,
                        "path", path,
                        NULL);
    TEST_CHECK(ret == 0);

    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         NULL);
    TEST_CHECK(ret == 0);

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    ret = write_msg(ctx, msg, strlen(msg));
    if (!TEST_CHECK(ret > 0)) {
        test_tail_ctx_destroy(ctx);
        exit(EXIT_FAILURE);
    }

    /* waiting to flush */
    flb_time_msleep(500);

    num = get_output_num();
    if (!TEST_CHECK(num == sizeof(file)/sizeof(char*)))  {
        TEST_MSG("output num error. expect=%lu got=%d", sizeof(file)/sizeof(char*), num);
    }

    test_tail_ctx_destroy(ctx);
}

void flb_test_path_key()
{
    struct flb_lib_out_cb cb_data;
    struct test_tail_ctx *ctx;
    char *file[] = {"path_key.log"};
    char *path_key = "path_key_is";
    char *msg = "hello world";
    int ret;
    int num;

    char *expected_strs[] = {path_key, msg, file[0]};
    struct str_list expected = {
                                .size = sizeof(expected_strs)/sizeof(char*),
                                .lists = &expected_strs[0],
    };

    clear_output_num();

    cb_data.cb = cb_check_json_str_list;
    cb_data.data = &expected;

    ctx = test_tail_ctx_create(&cb_data, &file[0], sizeof(file)/sizeof(char*), FLB_TRUE);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
        exit(EXIT_FAILURE);
    }

    ret = flb_input_set(ctx->flb, ctx->o_ffd,
                        "path", file[0],
                        "path_key", path_key,
                        NULL);
    TEST_CHECK(ret == 0);

    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "format", "json",
                         NULL);
    TEST_CHECK(ret == 0);

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    ret = write_msg(ctx, msg, strlen(msg));
    if (!TEST_CHECK(ret > 0)) {
        test_tail_ctx_destroy(ctx);
        exit(EXIT_FAILURE);
    }

    /* waiting to flush */
    flb_time_msleep(500);

    num = get_output_num();
    if (!TEST_CHECK(num > 0))  {
        TEST_MSG("no outputs");
    }

    test_tail_ctx_destroy(ctx);
}

void flb_test_exclude_path()
{
    struct flb_lib_out_cb cb_data;
    struct test_tail_ctx *ctx;
    char *exclude_path = "ep_ignore*.txt";
    char *path = "ep_*.txt";
    char *file[] = {"ep_ignore_1.txt", "ep_ignore_2.txt", "ep_file1.txt", "ep_file2.txt", "ep_file3.txt"};
    char *msg = "hello world";
    int unused;
    int ret;
    int num;

    clear_output_num();

    cb_data.cb = cb_count_msgpack;
    cb_data.data = &unused;

    ctx = test_tail_ctx_create(&cb_data, &file[0], sizeof(file)/sizeof(char*), FLB_TRUE);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
        exit(EXIT_FAILURE);
    }

    ret = flb_input_set(ctx->flb, ctx->o_ffd,
                        "path", path,
                        "exclude_path", exclude_path,
                        NULL);
    TEST_CHECK(ret == 0);

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    ret = write_msg(ctx, msg, strlen(msg));
    if (!TEST_CHECK(ret > 0)) {
        test_tail_ctx_destroy(ctx);
        exit(EXIT_FAILURE);
    }

    /* waiting to flush */
    flb_time_msleep(500);

    num = get_output_num();
    if (!TEST_CHECK(num == 3 /* 3files. "ep_file1.txt", "ep_file2.txt", "ep_file3.txt" */))  {
        TEST_MSG("output num error. expect=3 got=%d", num);
    }

    test_tail_ctx_destroy(ctx);
}

#ifdef _WIN32
void flb_test_windows_extended_path_prefixes(void)
{
    size_t length;
    wchar_t local_path[] = L"\\\\?\\C:\\logs\\unicode.log";
    wchar_t unc_path[] = L"\\\\?\\UNC\\server\\share\\unicode.log";
    const wchar_t expected_local_path[] = L"C:\\logs\\unicode.log";
    const wchar_t expected_unc_path[] = L"\\\\server\\share\\unicode.log";

    length = win32_remove_extended_path_prefix(local_path, wcslen(local_path));
    TEST_CHECK(length == wcslen(expected_local_path));
    TEST_CHECK(wcscmp(local_path, expected_local_path) == 0);

    length = win32_remove_extended_path_prefix(unc_path, wcslen(unc_path));
    TEST_CHECK(length == wcslen(expected_unc_path));
    TEST_CHECK(wcscmp(unc_path, expected_unc_path) == 0);
}
#endif

void flb_test_offset_key()
{
    struct flb_lib_out_cb cb_data;
    struct test_tail_ctx *ctx;
    char *file[] = {"offset_key.log"};
    char *offset_key = "OffsetKey";
    char *msg_before_tail = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    char *msg_after_tail = "test test";
    char expected_msg[1024] = {0};
    int ret;
    int num;

    char *expected_strs[] = {msg_after_tail, &expected_msg[0]};
    struct str_list expected = {
                                .size = sizeof(expected_strs)/sizeof(char*),
                                .lists = &expected_strs[0],
    };

    clear_output_num();

    cb_data.cb = cb_check_json_str_list;
    cb_data.data = &expected;

    ret = snprintf(&expected_msg[0], sizeof(expected_msg), "\"%s\":%ld", offset_key, strlen(msg_before_tail)+strlen(NEW_LINE));
    if(!TEST_CHECK(ret >= 0)) {
        TEST_MSG("snprintf failed");
        exit(EXIT_FAILURE);
    }


    ctx = test_tail_ctx_create(&cb_data, &file[0], sizeof(file)/sizeof(char *), FLB_TRUE);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
        exit(EXIT_FAILURE);
    }

    ret = flb_input_set(ctx->flb, ctx->o_ffd,
                        "path", file[0],
                        "offset_key", offset_key,
                        NULL);
    TEST_CHECK(ret == 0);

    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "format", "json",
                         NULL);
    TEST_CHECK(ret == 0);

    ret = write_msg(ctx, msg_before_tail, strlen(msg_before_tail));
    if (!TEST_CHECK(ret > 0)) {
        test_tail_ctx_destroy(ctx);
        exit(EXIT_FAILURE);
    }

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    ret = write_msg(ctx, msg_after_tail, strlen(msg_after_tail));
    if (!TEST_CHECK(ret > 0)) {
        test_tail_ctx_destroy(ctx);
        exit(EXIT_FAILURE);
    }

    /* waiting to flush */
    flb_time_msleep(500);

    num = get_output_num();
    if (!TEST_CHECK(num > 0))  {
        TEST_MSG("no outputs");
    }

    test_tail_ctx_destroy(ctx);
}

void flb_test_multiline_offset_key()
{
    struct flb_lib_out_cb cb_data;
    struct test_tail_ctx *ctx;
    char *file[] = {"multiline_offset.log"};
    char *offset_key = "OffsetKey";
    char *msg_before_tail = "[2025-06-16 20:42:22,291] INFO - aaaaaaaaaaa";
    char *msg_before_tail2 = "[2025-06-16 20:42:22,500] Error";
    char *msg_final = "[2025-06-16 20:45:29,234] Fatal";
    char expected_msg[1024] = {0};
    int ret;
    int num;

    char *expected_strs[] = {msg_final, &expected_msg[0]};
    struct str_list expected = {
                                .size = sizeof(expected_strs)/sizeof(char*),
                                .lists = &expected_strs[0],
    };

    clear_output_num();

    cb_data.cb = cb_check_json_str_list;
    cb_data.data = &expected;

    // multiline offset is at the end of the message
    ret = snprintf(&expected_msg[0], sizeof(expected_msg), "\"%s\":%ld", offset_key, strlen(msg_before_tail)+strlen(NEW_LINE)+strlen(msg_before_tail2)+strlen(NEW_LINE)+strlen(msg_final)+strlen(NEW_LINE));
    if(!TEST_CHECK(ret >= 0)) {
        TEST_MSG("snprintf failed");
        exit(EXIT_FAILURE);
    }

    ctx = test_tail_ctx_create(&cb_data, &file[0], sizeof(file)/sizeof(char *), FLB_TRUE);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
        exit(EXIT_FAILURE);
    }

    ret = flb_service_set(ctx->flb, "Parsers_File", DPATH "/parsers_multiline.conf", NULL);
    TEST_CHECK(ret == 0);

    ret = flb_input_set(ctx->flb, ctx->o_ffd,
                        "path", file[0],
                        "offset_key", offset_key,
                        "multiline.parser", "multiline-regex",
                        NULL);
    TEST_CHECK(ret == 0);

    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "format", "json",
                         NULL);
    TEST_CHECK(ret == 0);

    ret = write_msg(ctx, msg_before_tail, strlen(msg_before_tail));
    if (!TEST_CHECK(ret > 0)) {
        test_tail_ctx_destroy(ctx);
        exit(EXIT_FAILURE);
    }

    ret = write_msg(ctx, msg_before_tail2, strlen(msg_before_tail2));
    if (!TEST_CHECK(ret > 0)) {
        test_tail_ctx_destroy(ctx);
        exit(EXIT_FAILURE);
    }

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    ret = write_msg(ctx, msg_final, strlen(msg_final));
    if (!TEST_CHECK(ret > 0)) {
        test_tail_ctx_destroy(ctx);
        exit(EXIT_FAILURE);
    }

    /* wait up to 5s for at least one output */
    wait_num_with_timeout(5000, &num);

    num = get_output_num();
    if (!TEST_CHECK(num > 0))  {
        TEST_MSG("no outputs");
    }

    test_tail_ctx_destroy(ctx);
}

void flb_test_skip_empty_lines()
{
    struct flb_lib_out_cb cb_data;
    struct test_tail_ctx *ctx;
    char *file[] = {"skip_empty_lines.log"};
    char *empty_lines[] = {NEW_LINE, NEW_LINE};
    char *msg = "lalala";
    int ret;
    int num;
    int i;

    char *expected_strs[] = {msg};
    struct str_list expected = {
                                .size = sizeof(expected_strs)/sizeof(char*),
                                .lists = &expected_strs[0],
    };

    clear_output_num();

    cb_data.cb = cb_check_json_str_list;
    cb_data.data = &expected;

    ctx = test_tail_ctx_create(&cb_data, &file[0], sizeof(file)/sizeof(char *), FLB_TRUE);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
        exit(EXIT_FAILURE);
    }

    ret = flb_input_set(ctx->flb, ctx->o_ffd,
                        "path", file[0],
                        "skip_empty_lines", "true",
                        "Read_From_Head", "true",
                        NULL);
    TEST_CHECK(ret == 0);

    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "format", "json",
                         NULL);
    TEST_CHECK(ret == 0);

    ret = write_msg(ctx, msg, strlen(msg));
    if (!TEST_CHECK(ret > 0)) {
        test_tail_ctx_destroy(ctx);
        exit(EXIT_FAILURE);
    }

    for (i=0; i<sizeof(empty_lines)/sizeof(char*); i++) {
        ret = write_msg(ctx, empty_lines[i], strlen(empty_lines[i]));
        if (!TEST_CHECK(ret > 0)) {
            test_tail_ctx_destroy(ctx);
            exit(EXIT_FAILURE);
        }
    }

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* waiting to flush */
    flb_time_msleep(500);

    num = get_output_num();
    if (!TEST_CHECK(num == 1))  {
        TEST_MSG("output error: expect=1 got=%d", num);
    }

    test_tail_ctx_destroy(ctx);
}

void flb_test_skip_empty_lines_crlf()
{
    struct flb_lib_out_cb cb_data;
    struct test_tail_ctx *ctx;
    char *file[] = {"skip_empty_lines_crlf.log"};
    char *empty_lines[] = {"\r\n", "\r\n"};
    char *msg = "lalala";
    int ret;
    int num;
    int i;

    char *expected_strs[] = {msg};
    struct str_list expected = {
                                .size = sizeof(expected_strs)/sizeof(char*),
                                .lists = &expected_strs[0],
    };

    clear_output_num();

    cb_data.cb = cb_check_json_str_list;
    cb_data.data = &expected;

    ctx = test_tail_ctx_create(&cb_data, &file[0], sizeof(file)/sizeof(char *), FLB_TRUE);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
        exit(EXIT_FAILURE);
    }

    ret = flb_input_set(ctx->flb, ctx->o_ffd,
                        "path", file[0],
                        "skip_empty_lines", "true",
                        "Read_From_Head", "true",
                        NULL);
    TEST_CHECK(ret == 0);

    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "format", "json",
                         NULL);
    TEST_CHECK(ret == 0);

    ret = write_msg(ctx, msg, strlen(msg));
    if (!TEST_CHECK(ret > 0)) {
        test_tail_ctx_destroy(ctx);
        exit(EXIT_FAILURE);
    }

    for (i=0; i<sizeof(empty_lines)/sizeof(char*); i++) {
        ret = write_msg(ctx, empty_lines[i], strlen(empty_lines[i]));
        if (!TEST_CHECK(ret > 0)) {
            test_tail_ctx_destroy(ctx);
            exit(EXIT_FAILURE);
        }
    }

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* waiting to flush */
    flb_time_msleep(500);

    num = get_output_num();
    if (!TEST_CHECK(num == 1))  {
        TEST_MSG("output error: expect=1 got=%d", num);
    }

    test_tail_ctx_destroy(ctx);
}

static int ignore_older(int expected, char *ignore_older)
{
    struct flb_lib_out_cb cb_data;
    struct test_tail_ctx *ctx;
    struct timespec times[2];
    struct flb_time tm;
    char *file[] = {"time_now.log", "time_30m.log", "time_3h.log", "time_3d.log"};
    char *path = "time_*.log";
    char *msg = "hello world";
    int ret;
    int num;
    int unused;

    clear_output_num();

    cb_data.cb = cb_count_msgpack;
    cb_data.data = &unused;

    ctx = test_tail_ctx_create(&cb_data, &file[0], sizeof(file)/sizeof(char *), FLB_TRUE);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
        return -1;
    }

    times[0].tv_nsec = 0;
    times[1].tv_nsec = 0;

    flb_time_get(&tm);
    times[0].tv_sec = tm.tm.tv_sec - 3 * 24 * 60 * 60;
    times[1].tv_sec = tm.tm.tv_sec - 3 * 24 * 60 * 60;
    ret = utimensat(AT_FDCWD, file[3], times, 0);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("utimensat failed. errno=%d file=%s", errno, file[3]);
        return -1;
    }

    times[0].tv_sec = tm.tm.tv_sec - 3 * 60 * 60;
    times[1].tv_sec = tm.tm.tv_sec - 3 * 60 * 60;
    ret = utimensat(AT_FDCWD, file[2], times, 0);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("utimensat failed. errno=%d file=%s", errno, file[2]);
        return -1;
    }

    times[0].tv_sec = tm.tm.tv_sec - 30 * 60;
    times[1].tv_sec = tm.tm.tv_sec - 30 * 60;
    ret = utimensat(AT_FDCWD, file[1], times, 0);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("utimensat failed. errno=%d file=%s", errno, file[1]);
        return -1;
    }

    ret = flb_input_set(ctx->flb, ctx->o_ffd,
                        "path", path,
                        "ignore_older", ignore_older,
                        NULL);
    TEST_CHECK(ret == 0);

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    ret = write_msg(ctx, msg, strlen(msg));
    if (!TEST_CHECK(ret > 0)) {
        test_tail_ctx_destroy(ctx);
        return -1;
    }

    /* waiting to flush */
    flb_time_msleep(500);

    num = get_output_num();
    if (!TEST_CHECK(num == expected))  {
        TEST_MSG("output num error. expect=%d got=%d", expected, num);
        return -1;
    }

    test_tail_ctx_destroy(ctx);
    return 0;
}

void flb_test_ignore_older()
{
    int ret;
    char *ignore_olders[] = {"10m", "40m", "4h", "4d"};
    int expecteds[] = {1/*10m*/, 2/*10m, 40m*/, 3/*10m, 40m, 4h*/, 4 /*all*/};
    int i;

    TEST_CHECK(sizeof(ignore_olders)/sizeof(char*) == sizeof(expecteds)/sizeof(int));

    for (i=0; i<sizeof(expecteds)/sizeof(int); i++) {
        ret = ignore_older(expecteds[i], ignore_olders[i]);
        if (!TEST_CHECK(ret == 0)) {
            TEST_MSG("case %d failed. ignore_older=%s", i, ignore_olders[i]);
            exit(EXIT_FAILURE);
        }
    }
}

void flb_test_in_tail_ignore_active_older_files()
{
    struct flb_lib_out_cb cb_data;
    struct test_tail_ctx *ctx;
    char *file[] = {"source_file.log"};
    char *path = "source_file.log";
    char *msg = "TEST LINE";
    const int expected = 1;
    int ret;
    int num;
    int unused;

    clear_output_num();

    cb_data.cb = cb_count_msgpack;
    cb_data.data = &unused;

    ctx = test_tail_ctx_create(&cb_data, &file[0], sizeof(file)/sizeof(char *), FLB_TRUE);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
        return;
    }

    ret = flb_input_set(ctx->flb, ctx->o_ffd,
                        "path", path,
                        "ignore_older", "2s",
                        "read_from_head", "on",
                        "ignore_active_older_files", "on",
                        NULL);
    TEST_CHECK(ret == 0);

    /* Start the engine */
    ret = flb_start(ctx->flb);

    if (!TEST_CHECK(ret == 0)) {
        test_tail_ctx_destroy(ctx);

        return;
    }

    ret = write_msg(ctx, msg, strlen(msg));

    if (!TEST_CHECK(ret > 0)) {
        test_tail_ctx_destroy(ctx);

        return;
    }

    /* waiting to flush */
    flb_time_msleep(6000);

    ret = write_msg(ctx, msg, strlen(msg));

    if (!TEST_CHECK(ret > 0)) {
        test_tail_ctx_destroy(ctx);

        return;
    }

    /* waiting to flush */
    flb_time_msleep(1500);

    num = get_output_num();
    if (!TEST_CHECK(num == expected))  {
        TEST_MSG("output num error. expect=%d got=%d", expected, num);
    }

    test_tail_ctx_destroy(ctx);
}

/*
 * Verify that a file excluded by ignore_active_older_files is re-picked up
 * once its mtime is refreshed by a new write.
 *
 * Sequence:
 *   1. Write msg1  → engine reads it (count = 1)
 *   2. Wait 4 s    → purge fires (rotate_wait=1s), file is >2s old; inode
 *                    registered as aged-out and file removed from monitoring
 *   3. Write msg2  → mtime is now fresh
 *   4. Wait 3 s    → scan fires (refresh_interval=1s), sees fresh mtime;
 *                    unregisters aged-out entry and re-adds file at the
 *                    stored offset (file->offset saved at age-out time);
 *                    engine reads only msg2 (count += 1)
 *   5. Assert count == 2
 */
void flb_test_in_tail_ignore_active_older_files_reread_on_update()
{
    struct flb_lib_out_cb cb_data;
    struct test_tail_ctx *ctx;
    char *file[] = {"source_file_reread.log"};
    char *path = "source_file_reread.log";
    char *msg = "TEST LINE";
    const int expected = 2;
    const int expected_before_rotate = 1;
    int ret;
    int num;
    int unused;

    clear_output_num();

    cb_data.cb = cb_count_msgpack;
    cb_data.data = &unused;

    ctx = test_tail_ctx_create(&cb_data, &file[0], sizeof(file)/sizeof(char *), FLB_TRUE);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
        return;
    }

    ret = flb_input_set(ctx->flb, ctx->o_ffd,
                        "path",                               path,
                        "ignore_older",                      "2s",
                        "rotate_wait",                       "1s",
                        "refresh_interval",                  "1s",
                        "read_newly_discovered_files_from_head", "false",
                        "ignore_active_older_files",         "on",
                        NULL);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx->flb);
    if (!TEST_CHECK(ret == 0)) {
        test_tail_ctx_destroy(ctx);
        return;
    }

    /* Write first message and allow it to be flushed */
    ret = write_msg(ctx, msg, strlen(msg));
    if (!TEST_CHECK(ret > 0)) {
        test_tail_ctx_destroy(ctx);
        return;
    }

    /* Wait until msg1 is consumed before starting the aging clock. */
    wait_expected_num_with_timeout(5000, expected_before_rotate, &num);
    if (!TEST_CHECK(num == expected_before_rotate)) {
        TEST_MSG("msg1 not consumed in time. got=%d", num);
        test_tail_ctx_destroy(ctx);
        return;
    }

    /*
     * Wait long enough for the purge callback (rotate_wait=1s) to fire and
     * detect that the file's mtime is older than ignore_older=2s, which
     * removes the file from monitoring and registers its inode as aged-out.
     */
    flb_time_msleep(4000);

    /* Append new content: this updates mtime so the file is no longer old */
    ret = write_msg(ctx, msg, strlen(msg));
    if (!TEST_CHECK(ret > 0)) {
        test_tail_ctx_destroy(ctx);
        return;
    }

    /*
     * Wait for the scan callback (refresh_interval=1s) to re-evaluate the
     * aged-out entry, find the fresh mtime, unregister the entry, and
     * re-add the file.  The file is re-added at the stored offset (the read
     * position saved when the file was aged out), so only msg2 — the content
     * that refreshed the mtime — is flushed (count += 1).
     */
    wait_expected_num_with_timeout(5000, expected, &num);

    if (!TEST_CHECK(num == expected)) {
        TEST_MSG("output num error. expect=%d got=%d", expected, num);
    }

    test_tail_ctx_destroy(ctx);
}

void flb_test_in_tail_ignore_active_older_files_reread_on_update_default_read_from_head()
{
    struct flb_lib_out_cb cb_data;
    struct test_tail_ctx *ctx;
    char *file[] = {"source_file_reread_default.log"};
    char *path = "source_file_reread_default.log";
    char *msg = "TEST LINE";
    const int expected = 2;
    const int expected_before_rotate = 1;
    int ret;
    int num;
    int unused;

    clear_output_num();

    cb_data.cb = cb_count_msgpack;
    cb_data.data = &unused;

    ctx = test_tail_ctx_create(&cb_data, &file[0], sizeof(file)/sizeof(char *), FLB_TRUE);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
        return;
    }

    /*
     * Do not set read_newly_discovered_files_from_head — leave it at its
     * default (true).  The fix in set_file_position must honour the saved
     * offset even when ctx->read_from_head is true, so only msg2 is flushed
     * on re-pickup rather than replaying msg1 from the start.
     */
    ret = flb_input_set(ctx->flb, ctx->o_ffd,
                        "path",                      path,
                        "ignore_older",              "2s",
                        "rotate_wait",               "1s",
                        "refresh_interval",          "1s",
                        "ignore_active_older_files", "on",
                        NULL);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx->flb);
    if (!TEST_CHECK(ret == 0)) {
        test_tail_ctx_destroy(ctx);
        return;
    }

    /* Write first message and allow it to be flushed */
    ret = write_msg(ctx, msg, strlen(msg));
    if (!TEST_CHECK(ret > 0)) {
        test_tail_ctx_destroy(ctx);
        return;
    }

    /* Wait until msg1 is consumed before starting the aging clock. */
    wait_expected_num_with_timeout(5000, expected_before_rotate, &num);
    if (!TEST_CHECK(num == expected_before_rotate)) {
        TEST_MSG("msg1 not consumed in time. got=%d", num);
        test_tail_ctx_destroy(ctx);
        return;
    }

    /*
     * Wait long enough for the purge callback (rotate_wait=1s) to fire and
     * age out the file.
     */
    flb_time_msleep(4000);

    /* Append new content: updates mtime so the file is no longer old */
    ret = write_msg(ctx, msg, strlen(msg));
    if (!TEST_CHECK(ret > 0)) {
        test_tail_ctx_destroy(ctx);
        return;
    }

    /*
     * The scan callback re-adds the file from the stored offset.  With the
     * default read_newly_discovered_files_from_head=true, set_file_position
     * must still seek to the saved offset so msg1 is not replayed.
     * Total expected: 1 (msg1) + 1 (msg2) = 2.
     */
    wait_expected_num_with_timeout(5000, expected, &num);

    if (!TEST_CHECK(num == expected)) {
        TEST_MSG("output num error. expect=%d got=%d", expected, num);
    }

    test_tail_ctx_destroy(ctx);
}

void flb_test_inotify_watcher_false()
{
    struct flb_lib_out_cb cb_data;
    struct test_tail_ctx *ctx;
    char *file[] = {"inotify_watcher_false.log"};
    char *msg = "hello world";
    int ret;
    int num;

    char *expected_strs[] = {msg};
    struct str_list expected = {
                                .size = sizeof(expected_strs)/sizeof(char*),
                                .lists = &expected_strs[0],
    };

    clear_output_num();

    cb_data.cb = cb_check_json_str_list;
    cb_data.data = &expected;

    ctx = test_tail_ctx_create(&cb_data, &file[0], sizeof(file)/sizeof(char *), FLB_TRUE);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
        exit(EXIT_FAILURE);
    }

    ret = flb_input_set(ctx->flb, ctx->o_ffd,
                        "path", file[0],
                        "inotify_watcher", "false",
                        NULL);
    TEST_CHECK(ret == 0);

    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "format", "json",
                         NULL);
    TEST_CHECK(ret == 0);

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    ret = write_msg(ctx, msg, strlen(msg));
    if (!TEST_CHECK(ret > 0)) {
        test_tail_ctx_destroy(ctx);
        exit(EXIT_FAILURE);
    }

    /* waiting to flush */
    flb_time_msleep(1500);

    num = get_output_num();
    if (!TEST_CHECK(num > 0))  {
        TEST_MSG("no output");
    }

    test_tail_ctx_destroy(ctx);
}

#ifdef FLB_HAVE_INOTIFY
static int wait_tail_collectors_state(struct flb_tail_config *tail_ctx,
                                      struct flb_input_instance *ins,
                                      int expected)
{
    int i;
    int fs_running;
    int progress_running;

    for (i = 0; i < 50; i++) {
        fs_running = flb_input_collector_running(tail_ctx->coll_fd_fs1, ins);
        progress_running = flb_input_collector_running(tail_ctx->coll_fd_progress_check,
                                                       ins);
        if (fs_running == expected && progress_running == expected) {
            return 0;
        }

        flb_time_msleep(100);
    }

    return -1;
}

void flb_test_inotify_pause_collectors()
{
    int ret;
    struct mk_list *head;
    struct flb_input_instance *ins;
    struct flb_tail_config *tail_ctx;
    struct flb_lib_out_cb cb_data;
    struct test_tail_ctx *ctx;
    char *file[] = {"inotify_pause_collectors.log"};

    cb_data.cb = cb_count_msgpack;
    cb_data.data = NULL;

    ctx = test_tail_ctx_create(&cb_data, &file[0], 1, FLB_TRUE);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
        exit(EXIT_FAILURE);
    }

    ret = flb_input_set(ctx->flb, ctx->i_ffd,
                        "path", file[0],
                        NULL);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    head = ctx->flb->config->inputs.next;
    ins = mk_list_entry(head, struct flb_input_instance, _head);
    tail_ctx = ins->context;

    TEST_CHECK(flb_input_collector_running(tail_ctx->coll_fd_fs1, ins) == FLB_TRUE);
    TEST_CHECK(flb_input_collector_running(tail_ctx->coll_fd_progress_check,
                                           ins) == FLB_TRUE);

    ret = flb_input_pause(ins);
    TEST_CHECK(ret == 0);
    TEST_CHECK(flb_input_collector_running(tail_ctx->coll_fd_fs1, ins) == FLB_FALSE);
    TEST_CHECK(flb_input_collector_running(tail_ctx->coll_fd_progress_check,
                                           ins) == FLB_FALSE);

    ret = flb_input_resume(ins);
    TEST_CHECK(ret == 0);
    TEST_CHECK(flb_input_collector_running(tail_ctx->coll_fd_fs1, ins) == FLB_TRUE);
    TEST_CHECK(flb_input_collector_running(tail_ctx->coll_fd_progress_check,
                                           ins) == FLB_TRUE);

    test_tail_ctx_destroy(ctx);
}

void flb_test_inotify_threaded_pause_collectors()
{
    int ret;
    struct mk_list *head;
    struct flb_input_instance *ins;
    struct flb_tail_config *tail_ctx;
    struct flb_lib_out_cb cb_data;
    struct test_tail_ctx *ctx;
    char *file[] = {"inotify_threaded_pause_collectors.log"};

    cb_data.cb = cb_count_msgpack;
    cb_data.data = NULL;

    ctx = test_tail_ctx_create(&cb_data, &file[0], 1, FLB_TRUE);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
        exit(EXIT_FAILURE);
    }

    ret = flb_input_set(ctx->flb, ctx->i_ffd,
                        "path", file[0],
                        "threaded", "true",
                        NULL);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    head = ctx->flb->config->inputs.next;
    ins = mk_list_entry(head, struct flb_input_instance, _head);
    tail_ctx = ins->context;

    ret = wait_tail_collectors_state(tail_ctx, ins, FLB_TRUE);
    TEST_CHECK(ret == 0);

    ret = flb_input_pause(ins);
    TEST_CHECK(ret == 0);
    ret = wait_tail_collectors_state(tail_ctx, ins, FLB_FALSE);
    TEST_CHECK(ret == 0);

    ret = flb_input_resume(ins);
    TEST_CHECK(ret == 0);
    ret = wait_tail_collectors_state(tail_ctx, ins, FLB_TRUE);
    TEST_CHECK(ret == 0);

    test_tail_ctx_destroy(ctx);
}
#endif

#ifdef FLB_HAVE_REGEX
void flb_test_parser()
{
    struct flb_lib_out_cb cb_data;
    struct test_tail_ctx *ctx;
    char *file[] = {"parser.log"};
    /* https://httpd.apache.org/docs/2.4/en/logs.html */
    char *msg = "127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] \"GET /apache_pb.gif HTTP/1.0\" 200 2326";
    int ret;
    int num;

    char *expected_strs[] = {"\"method\":\"GET\"", "\"host\":\"127.0.0.1\"","\"user\":\"frank\"",
                             "\"path\":\"/apache_pb.gif\"","\"code\":\"200\"","\"size\":\"2326\""};
    struct str_list expected = {
                                .size = sizeof(expected_strs)/sizeof(char*),
                                .lists = &expected_strs[0],
    };

    clear_output_num();

    cb_data.cb = cb_check_json_str_list;
    cb_data.data = &expected;

    ctx = test_tail_ctx_create(&cb_data, &file[0], sizeof(file)/sizeof(char *), FLB_TRUE);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
        exit(EXIT_FAILURE);
    }

    ret = flb_input_set(ctx->flb, ctx->o_ffd,
                        "path", file[0],
                        "parser", "apache2",
                        NULL);
    TEST_CHECK(ret == 0);

    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "format", "json",
                         NULL);
    TEST_CHECK(ret == 0);

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    ret = write_msg(ctx, msg, strlen(msg));
    if (!TEST_CHECK(ret > 0)) {
        test_tail_ctx_destroy(ctx);
        exit(EXIT_FAILURE);
    }

    /* waiting to flush */
    flb_time_msleep(500);

    num = get_output_num();
    if (!TEST_CHECK(num > 0))  {
        TEST_MSG("no outputs");
    }

    test_tail_ctx_destroy(ctx);
}

void flb_test_tag_regex()
{
    struct flb_lib_out_cb cb_data;
    struct test_tail_ctx *ctx;
    char *file[] = {"aa_bb_cc.log"};
    char *tag_regex = "(?<first>[a-z]+)_(?<second>[a-z]+)_(?<third>[a-z]+)\\.log";
    char *tag = "<first>.<second>.<third>"; /* tag will be "aa.bb.cc" */
    char *msg = "hello world";
    int ret;
    int num;

    char *expected_strs[] = {msg};
    struct str_list expected = {
                                .size = sizeof(expected_strs)/sizeof(char*),
                                .lists = &expected_strs[0],
    };

    clear_output_num();

    cb_data.cb = cb_check_json_str_list;
    cb_data.data = &expected;

    ctx = test_tail_ctx_create(&cb_data, &file[0], sizeof(file)/sizeof(char *), FLB_TRUE);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
        exit(EXIT_FAILURE);
    }

    ret = flb_input_set(ctx->flb, ctx->o_ffd,
                        "path", file[0],
                        "tag", tag,
                        "tag_regex", tag_regex,
                        NULL);
    TEST_CHECK(ret == 0);

    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "match", "aa.bb.cc",
                         "format", "json",
                         NULL);
    TEST_CHECK(ret == 0);

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    ret = write_msg(ctx, msg, strlen(msg));
    if (!TEST_CHECK(ret > 0)) {
        test_tail_ctx_destroy(ctx);
        exit(EXIT_FAILURE);
    }

    /* waiting to flush */
    flb_time_msleep(500);

    num = get_output_num();
    if (!TEST_CHECK(num > 0))  {
        TEST_MSG("no outputs");
    }

    test_tail_ctx_destroy(ctx);
}
#endif /* FLB_HAVE_REGEX */

#ifdef FLB_HAVE_SQLDB
void flb_test_db()
{
    struct flb_lib_out_cb cb_data;
    struct test_tail_ctx *ctx;
    char *file[] = {"test_db.log"};
    char *db = "test_db.db";
    char *msg_init = "hello world";
    char *msg = "hello db";
    char *msg_end = "hello db end";
    int i;
    int ret;
    int num;
    int unused;

    unlink(db);

    clear_output_num();

    cb_data.cb = cb_count_msgpack;
    cb_data.data = &unused;

    ctx = test_tail_ctx_create(&cb_data, &file[0], sizeof(file)/sizeof(char *), FLB_FALSE);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
        exit(EXIT_FAILURE);
    }

    ret = flb_input_set(ctx->flb, ctx->o_ffd,
                        "path", file[0],
                        "db", db,
                        NULL);
    TEST_CHECK(ret == 0);

    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         NULL);
    TEST_CHECK(ret == 0);

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    ret = write_msg(ctx, msg_init, strlen(msg_init));
    if (!TEST_CHECK(ret > 0)) {
        test_tail_ctx_destroy(ctx);
        unlink(db);
        exit(EXIT_FAILURE);
    }

    /* waiting to flush */
    flb_time_msleep(500);

    num = get_output_num();
    if (!TEST_CHECK(num > 0))  {
        TEST_MSG("no output");
    }

    if (ctx->fds != NULL) {
        for (i=0; i<ctx->fd_num; i++) {
            close(ctx->fds[i]);
        }
        flb_free(ctx->fds);
    }
    flb_stop(ctx->flb);
    flb_destroy(ctx->flb);
    flb_free(ctx);

    /* re-init to use db */
    clear_output_num();

    cb_data.cb = cb_count_msgpack;
    cb_data.data = &unused;

    ctx = test_tail_ctx_create(&cb_data, &file[0], sizeof(file)/sizeof(char *), FLB_FALSE);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
        unlink(db);
        exit(EXIT_FAILURE);
    }

    ret = flb_input_set(ctx->flb, ctx->o_ffd,
                        "path", file[0],
                        "db", db,
                        "db.sync", "full",
                        NULL);
    TEST_CHECK(ret == 0);

    ret = write_msg(ctx, msg, strlen(msg));
    if (!TEST_CHECK(ret > 0)) {
        test_tail_ctx_destroy(ctx);
        unlink(db);
        exit(EXIT_FAILURE);
    }

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* waiting to flush */
    flb_time_msleep(500);

    ret = write_msg(ctx, msg_end, strlen(msg_end));
    if (!TEST_CHECK(ret > 0)) {
        test_tail_ctx_destroy(ctx);
        unlink(db);
        exit(EXIT_FAILURE);
    }

    /* waiting to flush */
    flb_time_msleep(500);

    num = get_output_num();
    if (!TEST_CHECK(num == 2))  {
        /* 2 = msg + msg_end */
        TEST_MSG("num error. expect=2 got=%d", num);
    }

    test_tail_ctx_destroy(ctx);
    unlink(db);
}

void flb_test_db_delete_stale_file()
{
    struct flb_lib_out_cb cb_data;
    struct test_tail_ctx *ctx;
    char *org_file[] = {"test_db.log", "test_db_stale.log"};
    char *tmp_file[] = {"test_db.log"};
    char *path = "test_db.log, test_db_stale.log";
    char *move_file[] = {"test_db_stale.log", "test_db_stale_new.log"};
    char *new_file[] = {"test_db.log", "test_db_stale_new.log"};
    char *new_path = "test_db.log, test_db_stale_new.log";
    char *db = "test_db.db";
    char *msg_init = "hello world";
    char *msg_end = "hello db end";
    int i;
    int ret;
    int num;
    int unused;

    unlink(db);

    clear_output_num();

    cb_data.cb = cb_count_msgpack;
    cb_data.data = &unused;

    ctx = test_tail_ctx_create(&cb_data,
                               &org_file[0],
                               sizeof(org_file)/sizeof(char *),
                               FLB_FALSE);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
        exit(EXIT_FAILURE);
    }

    ret = flb_input_set(ctx->flb, ctx->o_ffd,
                        "path", path,
                        "read_from_head", "true",
                        "db", db,
                        "db.sync", "full",
                        NULL);
    TEST_CHECK(ret == 0);

    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         NULL);
    TEST_CHECK(ret == 0);

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    ret = write_msg(ctx, msg_init, strlen(msg_init));
    if (!TEST_CHECK(ret > 0)) {
        test_tail_ctx_destroy(ctx);
        unlink(db);
        exit(EXIT_FAILURE);
    }

    /* waiting to flush */
    flb_time_msleep(500);

    num = get_output_num();
    if (!TEST_CHECK(num > 0))  {
        TEST_MSG("no output");
    }

    if (ctx->fds != NULL) {
        for (i=0; i<ctx->fd_num; i++) {
            close(ctx->fds[i]);
        }
        flb_free(ctx->fds);
    }
    flb_stop(ctx->flb);
    flb_destroy(ctx->flb);
    flb_free(ctx);

    /* re-init to use db */
    clear_output_num();

    /*
     * Changing the file name from 'test_db_stale.log' to
     * 'test_db_stale_new.log.' In this scenario, it is assumed that the
     * file was deleted after the FluentBit was terminated. However, since
     * the FluentBit was shutdown, the inode remains in the database.
     * The reason for renaming is to preserve the existing file for later use.
     */
    ret = rename(move_file[0], move_file[1]);
    TEST_CHECK(ret == 0);

    cb_data.cb = cb_count_msgpack;
    cb_data.data = &unused;

    ctx = test_tail_ctx_create(&cb_data,
                               &tmp_file[0],
                               sizeof(tmp_file)/sizeof(char *),
                               FLB_FALSE);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
        unlink(db);
        exit(EXIT_FAILURE);
    }

    ret = flb_input_set(ctx->flb, ctx->o_ffd,
                        "path", path,
                        "read_from_head", "true",
                        "db", db,
                        "db.sync", "full",
                        NULL);
    TEST_CHECK(ret == 0);

    /*
     * Start the engine
     * FluentBit will delete stale inodes.
     */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* waiting to flush */
    flb_time_msleep(500);

    if (ctx->fds != NULL) {
        for (i=0; i<ctx->fd_num; i++) {
            close(ctx->fds[i]);
        }
        flb_free(ctx->fds);
    }
    flb_stop(ctx->flb);
    flb_destroy(ctx->flb);
    flb_free(ctx);

    /* re-init to use db */
    clear_output_num();

    cb_data.cb = cb_count_msgpack;
    cb_data.data = &unused;

    ctx = test_tail_ctx_create(&cb_data,
                               &new_file[0],
                               sizeof(new_file)/sizeof(char *),
                               FLB_FALSE);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
        unlink(db);
        exit(EXIT_FAILURE);
    }

    ret = flb_input_set(ctx->flb, ctx->o_ffd,
                        "path", new_path,
                        "read_from_head", "true",
                        "db", db,
                        "db.sync", "full",
                        NULL);
    TEST_CHECK(ret == 0);

    /*
     * Start the engine
     * 'test_db_stale_new.log.' is a new file.
     * The inode of 'test_db_stale.log' was deleted previously.
     * So, it reads from the beginning of the file.
     */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* waiting to flush */
    flb_time_msleep(500);

    ret = write_msg(ctx, msg_end, strlen(msg_end));
    if (!TEST_CHECK(ret > 0)) {
        test_tail_ctx_destroy(ctx);
        unlink(db);
        exit(EXIT_FAILURE);
    }

    /* waiting to flush */
    flb_time_msleep(500);

    num = get_output_num();
    if (!TEST_CHECK(num == 3))  {
        /* 3 =
         * test_db.log : "hello db end"
         * test_db_stale.log : "msg_init" + "hello db end"
         */
        TEST_MSG("num error. expect=3 got=%d", num);
    }

    test_tail_ctx_destroy(ctx);
    unlink(db);
}

void flb_test_db_compare_filename()
{
    struct flb_lib_out_cb cb_data;
    struct test_tail_ctx *ctx;
    char *org_file[] = {"test_db.log"};
    char *moved_file[] = {"test_db_moved.log"};
    char *db = "test_db.db";
    char *msg_init = "hello world";
    char *msg_moved = "hello world moved";
    char *msg_end = "hello db end";
    int i;
    int ret;
    int num;
    int unused;

    unlink(db);

    clear_output_num();

    cb_data.cb = cb_count_msgpack;
    cb_data.data = &unused;

    ctx = test_tail_ctx_create(&cb_data,
                               &org_file[0],
                               sizeof(org_file)/sizeof(char *),
                               FLB_FALSE);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
        exit(EXIT_FAILURE);
    }

    ret = flb_input_set(ctx->flb, ctx->o_ffd,
                        "path", org_file[0],
                        "read_from_head", "true",
                        "db", db,
                        "db.sync", "full",
                        "db.compare_filename", "true",
                        NULL);
    TEST_CHECK(ret == 0);

    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         NULL);
    TEST_CHECK(ret == 0);

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    ret = write_msg(ctx, msg_init, strlen(msg_init));
    if (!TEST_CHECK(ret > 0)) {
        test_tail_ctx_destroy(ctx);
        unlink(db);
        exit(EXIT_FAILURE);
    }

    /* waiting to flush */
    flb_time_msleep(500);

    num = get_output_num();
    if (!TEST_CHECK(num > 0))  {
        TEST_MSG("no output");
    }

    if (ctx->fds != NULL) {
        for (i=0; i<ctx->fd_num; i++) {
            close(ctx->fds[i]);
        }
        flb_free(ctx->fds);
    }
    flb_stop(ctx->flb);
    flb_destroy(ctx->flb);
    flb_free(ctx);

    /* re-init to use db */
    clear_output_num();

    /*
     * Changing the file name from 'test_db.log' to 'test_db_moved.log.'
     * In this scenario, it is assumed that the FluentBit has been terminated,
     * and the file has been recreated with the same inode, with offsets equal
     * to or greater than the previous file.
     */
    ret = rename(org_file[0], moved_file[0]);
    TEST_CHECK(ret == 0);

    cb_data.cb = cb_count_msgpack;
    cb_data.data = &unused;

    ctx = test_tail_ctx_create(&cb_data,
                               &moved_file[0],
                               sizeof(moved_file)/sizeof(char *),
                               FLB_FALSE);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
        unlink(db);
        exit(EXIT_FAILURE);
    }

    ret = flb_input_set(ctx->flb, ctx->o_ffd,
                        "path", moved_file[0],
                        "read_from_head", "true",
                        "db", db,
                        "db.sync", "full",
                        "db.compare_filename", "true",
                        NULL);
    TEST_CHECK(ret == 0);

    /*
     * Start the engine
     * The file has been newly created, and due to the 'db.compare_filename'
     * option being set to true, it compares filenames to consider it a new
     * file even if the inode is the same. If the option is set to false,
     * it can be assumed to be the same file as before.
     */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* waiting to flush */
    flb_time_msleep(500);

    ret = write_msg(ctx, msg_moved, strlen(msg_moved));
    if (!TEST_CHECK(ret > 0)) {
        test_tail_ctx_destroy(ctx);
        unlink(db);
        exit(EXIT_FAILURE);
    }

    ret = write_msg(ctx, msg_end, strlen(msg_end));
    if (!TEST_CHECK(ret > 0)) {
        test_tail_ctx_destroy(ctx);
        unlink(db);
        exit(EXIT_FAILURE);
    }

    /* waiting to flush */
    flb_time_msleep(500);

    num = get_output_num();
    if (!TEST_CHECK(num == 3))  {
        /* 3 = msg_init + msg_moved + msg_end */
        TEST_MSG("num error. expect=3 got=%d", num);
    }

    test_tail_ctx_destroy(ctx);
    unlink(db);
}

/*
 * Test: flb_test_db_offset_rewind_on_shutdown
 *
 * This test verifies that unprocessed buffered data is not lost on shutdown.
 * When Fluent Bit shuts down with data still in the buffer, the offset should
 * be rewound so that the data is re-read on restart.
 *
 * Scenario:
 * 1. Start Fluent Bit with DB enabled
 * 2. Write initial data and wait for it to be processed
 * 3. Write additional data and immediately stop (before flush)
 * 4. Restart Fluent Bit
 * 5. Verify that the data written before shutdown is re-read
 */

void flb_test_db_offset_rewind_on_shutdown()
{
    struct flb_lib_out_cb cb_data;
    struct test_tail_ctx *ctx;
    char *file[] = {"test_offset_rewind.log"};
    char *db = "test_offset_rewind.db";
    char *msg_init = "initial message";
    char *msg_before_shutdown = "message before shutdown";
    int i;
    int ret;
    int num;
    int unused;

    unlink(file[0]);
    unlink(db);

    clear_output_num();

    cb_data.cb = cb_count_msgpack;
    cb_data.data = &unused;

    /* First run: write initial data */
    ctx = test_tail_ctx_create(&cb_data, &file[0], sizeof(file)/sizeof(char *), FLB_TRUE);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
        exit(EXIT_FAILURE);
    }

    /* Set debug log level to see offset rewind messages */
    flb_service_set(ctx->flb, "Log_Level", "debug", NULL);

    ret = flb_input_set(ctx->flb, ctx->i_ffd,
                        "path", file[0],
                        "read_from_head", "true",
                        "db", db,
                        "db.sync", "full",
                        NULL);
    TEST_CHECK(ret == 0);

    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         NULL);
    TEST_CHECK(ret == 0);

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* Write initial message */
    ret = write_msg(ctx, msg_init, strlen(msg_init));
    if (!TEST_CHECK(ret > 0)) {
        test_tail_ctx_destroy(ctx);
        unlink(file[0]);
        unlink(db);
        exit(EXIT_FAILURE);
    }

    /* Wait for data to be processed */
    flb_time_msleep(500);

    num = get_output_num();
    if (!TEST_CHECK(num == 1)) {
        TEST_MSG("initial message not received. expect=1 got=%d", num);
    }

    /*
     * Write message WITHOUT newline - this will remain in the tail buffer
     * as an incomplete line, which is the scenario we want to test.
     * The tail plugin processes complete lines (ending with \n), so
     * data without newline stays in buf_len until more data arrives.
     *
     * Note: flb_tail_file_db_offset() automatically persists the resumable
     * offset (offset - buf_len) rather than the raw read position, so the
     * DB offset will NOT advance past the initial message until the
     * incomplete line is completed with a newline.
     */
    ret = write_raw(ctx, msg_before_shutdown, strlen(msg_before_shutdown), FLB_FALSE);
    if (!TEST_CHECK(ret > 0)) {
        test_tail_ctx_destroy(ctx);
        unlink(file[0]);
        unlink(db);
        exit(EXIT_FAILURE);
    }

    /* Wait for tail to read the incomplete line into its buffer */
    flb_time_msleep(500);

    /* Close file descriptors before stopping */
    if (ctx->fds != NULL) {
        for (i = 0; i < ctx->fd_num; i++) {
            close(ctx->fds[i]);
        }
        flb_free(ctx->fds);
        ctx->fds = NULL;
    }

    /* Stop immediately - simulating abrupt shutdown */
    flb_stop(ctx->flb);
    flb_destroy(ctx->flb);
    flb_free(ctx);

    /* Second run: restart and verify data is re-read */
    clear_output_num();
    num = get_output_num();
    if (!TEST_CHECK(num == 0)) {
        TEST_MSG("output count not cleared. expect=0 got=%d", num);
    }

    cb_data.cb = cb_count_msgpack;
    cb_data.data = &unused;

    ctx = test_tail_ctx_create(&cb_data, &file[0], sizeof(file)/sizeof(char *), FLB_FALSE);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed on restart");
        unlink(file[0]);
        unlink(db);
        exit(EXIT_FAILURE);
    }

    /* Set debug log level to see offset rewind messages */
    flb_service_set(ctx->flb, "Log_Level", "debug", NULL);

    ret = flb_input_set(ctx->flb, ctx->i_ffd,
                        "path", file[0],
                        "read_from_head", "true",
                        "db", db,
                        "db.sync", "full",
                        NULL);
    TEST_CHECK(ret == 0);

    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         NULL);
    TEST_CHECK(ret == 0);

    /* Restart the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /*
     * Write a newline to complete the incomplete line from before shutdown.
     * This simulates the scenario where more data arrives after restart,
     * completing the previously incomplete line.
     */
    ret = write_raw(ctx, NULL, 0, FLB_TRUE);
    if (!TEST_CHECK(ret > 0)) {
        TEST_MSG("write newline failed");
    }

    /* Wait for data to be processed */
    flb_time_msleep(500);

    num = get_output_num();
    /*
     * After restart, we expect to receive the message that was written
     * before shutdown. If the offset rewind fix works correctly,
     * msg_before_shutdown should be re-read.
     * We expect at least 1 message (msg_before_shutdown).
     */
    if (!TEST_CHECK(num == 1)) {
        TEST_MSG("data loss detected after restart. expect==1 got=%d", num);
    }

    test_tail_ctx_destroy(ctx);
    unlink(file[0]);
    unlink(db);
}

/* Test case for Gzip resume data loss regression */
void flb_test_db_gzip_resume_loss()
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    struct test_ctx t_ctx = {0};
    struct flb_lib_out_cb cb;
    char *log_file = "test_gzip_resume.log.gz";
    char *db_file = "test_gzip_resume.db";
    const char *content1 = "line1\nline2";
    const char *content2 = "\nline3\n";

    cb.cb = cb_check_gzip_resume;
    cb.data = &t_ctx;

    unlink(log_file);
    unlink(db_file);

    /* 1. Create Gzip file with incomplete line at end */
    TEST_CHECK(create_gzip_file(log_file, content1, strlen(content1)) == 0);

    /* 2. Start Fluent Bit */
    ctx = flb_create();
    flb_service_set(ctx, "Flush", "0.5", "Grace", "1", NULL);

    in_ffd = flb_input(ctx, "tail", NULL);
    flb_input_set(ctx, in_ffd,
                  "path", log_file,
                  "read_from_head", "true",
                  "db", db_file,
                  "db.sync", "full",
                  NULL);

    out_ffd = flb_output(ctx, "lib", &cb);
    flb_output_set(ctx, out_ffd, "match", "*", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Wait for output count to reach 1 */
    wait_for_count_with_timeout(&t_ctx, 1, 2000);

    flb_stop(ctx);
    flb_destroy(ctx);

    TEST_CHECK(test_ctx_get_count(&t_ctx) == 1); /* Only line1 */

    /* 3. Restart Fluent Bit */
    TEST_CHECK(append_gzip_file(log_file, content2, strlen(content2)) == 0);

    test_ctx_begin_run(&t_ctx, NULL);

    ctx = flb_create();
    flb_service_set(ctx, "Flush", "0.5", "Grace", "1", NULL);

    in_ffd = flb_input(ctx, "tail", NULL);
    flb_input_set(ctx, in_ffd,
                  "path", log_file,
                  "db", db_file,
                  "db.sync", "full",
                  NULL);

    out_ffd = flb_output(ctx, "lib", &cb);
    flb_output_set(ctx, out_ffd, "match", "*", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Wait for output count to reach 2 (line2 + line3) */
    wait_for_count_with_timeout(&t_ctx, 2, 2000);

    flb_stop(ctx);
    flb_destroy(ctx);

    TEST_CHECK(test_ctx_get_found_line2(&t_ctx) == 1);
    TEST_CHECK(test_ctx_get_count(&t_ctx) == 2);

    unlink(log_file);
    unlink(db_file);
}


void flb_test_db_gzip_inotify_append()
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    struct test_ctx t_ctx = {0};
    struct flb_lib_out_cb cb;
    char *log_file = "test_gzip_inotify.log.gz";
    char *db_file = "test_gzip_inotify.db";
    const char *content1 = "line1\n";
    const char *content2 = "line2\n";

    cb.cb = cb_check_gzip_resume; /* Reusing callback as it counts lines */
    cb.data = &t_ctx;

    unlink(log_file);
    unlink(db_file);

    /* 1. Create initial Gzip file */
    TEST_CHECK(create_gzip_file(log_file, content1, strlen(content1)) == 0);

    /* 2. Start Fluent Bit */
    ctx = flb_create();
    flb_service_set(ctx, "Flush", "0.5", "Grace", "1", NULL);

    in_ffd = flb_input(ctx, "tail", NULL);
    flb_input_set(ctx, in_ffd,
                  "path", log_file,
                  "read_from_head", "true",
                  /* explicit refresh_interval to be sure, though inotify is default */
                  "refresh_interval", "1",
                  "db", db_file,
                  "db.sync", "full",
                  NULL);

    out_ffd = flb_output(ctx, "lib", &cb);
    flb_output_set(ctx, out_ffd, "match", "*", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Wait for initial read */
    wait_for_count_with_timeout(&t_ctx, 1, 2000);
    TEST_CHECK(test_ctx_get_count(&t_ctx) == 1);

    /* 3. Append to Gzip file while running (Simulate Inotify Event) */
    TEST_CHECK(append_gzip_file(log_file, content2, strlen(content2)) == 0);

    /* Wait for inotify/refresh and processing */
    wait_for_count_with_timeout(&t_ctx, 2, 2000);

    /* 4. Verify total count */
    TEST_CHECK(test_ctx_get_count(&t_ctx) == 2);
    /* Verify line2 was actually processed */
    TEST_CHECK(test_ctx_get_found_line2(&t_ctx) == 1);

    flb_stop(ctx);
    flb_destroy(ctx);
    unlink(log_file);
    unlink(db_file);
}


void flb_test_db_gzip_rotation()
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    struct test_ctx t_ctx = {0};
    struct flb_lib_out_cb cb;
    char *log_file = "test_gzip_rotate.log.gz";
    char *rot_file = "test_gzip_rotate.log.gz.1";
    char *db_file = "test_gzip_rotate.db";
    const char *content1 = "line1\n";
    const char *content2 = "line2\n";
    const char *content3 = "line3_new\n";
    const char *content4 = "line4_old\n";

    cb.cb = cb_check_gzip_resume;
    cb.data = &t_ctx;

    unlink(log_file);
    unlink(rot_file);
    unlink(db_file);

    /* 1. Create initial Gzip file */
    TEST_CHECK(create_gzip_file(log_file, content1, strlen(content1)) == 0);

    /* 2. Start Fluent Bit */
    ctx = flb_create();
    flb_service_set(ctx, "Flush", "0.5", "Grace", "1", NULL);

    in_ffd = flb_input(ctx, "tail", NULL);
    flb_input_set(ctx, in_ffd,
                  "path", log_file,
                  "read_from_head", "true",
                  "refresh_interval", "1",
                  "rotate_wait", "5",
                  "db", db_file,
                  "db.sync", "full",
                  NULL);

    out_ffd = flb_output(ctx, "lib", &cb);
    flb_output_set(ctx, out_ffd, "match", "*", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Wait for initial read */
    wait_for_count_with_timeout(&t_ctx, 1, 2000);
    TEST_CHECK(test_ctx_get_count(&t_ctx) == 1);

    /* 3. Rotate file: Rename .gz -> .gz.1 */
    ret = rename(log_file, rot_file);
    TEST_CHECK(ret == 0);

    /* 4. Create NEW file with same name immediately */
    TEST_CHECK(create_gzip_file(log_file, content2, strlen(content2)) == 0);

    /* Wait for rotation detection and new file processing */
    wait_for_count_with_timeout(&t_ctx, 2, 2000);

    /* 5. Append to BOTH files within rotate_wait window */
    /* 5a. Append to new file */
    TEST_CHECK(append_gzip_file(log_file, content3, strlen(content3)) == 0);

    /* 5b. Append to OLD file (rotated) - should still be monitored */
    TEST_CHECK(append_gzip_file(rot_file, content4, strlen(content4)) == 0);

    /* Wait for processing */
    wait_for_count_with_timeout(&t_ctx, 4, 2000);

    /* 6. Verify total count */
    TEST_CHECK(test_ctx_get_count(&t_ctx) == 4);

    flb_stop(ctx);
    flb_destroy(ctx);
    unlink(log_file);
    unlink(rot_file);
    unlink(db_file);
}


void flb_test_db_gzip_multi_resume()
{
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    struct test_ctx t_ctx = {0};
    struct flb_lib_out_cb cb;
    char *log_file = "test_gzip_multi.log.gz";
    char *db_file = "test_gzip_multi.db";
    const char *content1 = "line1\n";
    const char *content2 = "line2\n";
    const char *content3 = "line3\n";
    uint64_t off1 = 0;
    uint64_t off2 = 0;
    uint64_t off3 = 0;

    cb.cb = cb_check_gzip_resume;
    cb.data = &t_ctx;

    unlink(log_file);
    unlink(db_file);

    /* 1. Create file with Line1 */
    TEST_CHECK(create_gzip_file(log_file, content1, strlen(content1)) == 0);

    test_ctx_begin_run(&t_ctx, "line1");

    /* 2. Start (Run 1) */
    ctx = flb_create();
    flb_service_set(ctx, "Flush", "0.5", "Grace", "1", NULL);
    in_ffd = flb_input(ctx, "tail", NULL);
    flb_input_set(ctx, in_ffd,
                  "path", log_file,
                  "read_from_head", "true",
                  "db", db_file,
                  "db.sync", "full",
                  "offset_key", "off",
                  NULL);

    out_ffd = flb_output(ctx, "lib", &cb);
    flb_output_set(ctx, out_ffd, "match", "*", NULL);

    flb_start(ctx);
    wait_for_count_with_timeout(&t_ctx, 1, 2000);
    flb_stop(ctx);
    flb_destroy(ctx);

    TEST_CHECK(test_ctx_get_count(&t_ctx) == 1); /* Processed Line1 */
    TEST_CHECK(test_ctx_get_found_expected(&t_ctx) == 1);
    TEST_CHECK(test_ctx_get_offset(&t_ctx, &off1) == FLB_TRUE);
    test_ctx_begin_run(&t_ctx, "line2");

    /* 3. Restart (Run 2) -> Should SKIP Line1 and process Line2 */
    TEST_CHECK(append_gzip_file(log_file, content2, strlen(content2)) == 0);

    ctx = flb_create();
    flb_service_set(ctx, "Flush", "0.5", "Grace", "1", NULL);
    in_ffd = flb_input(ctx, "tail", NULL);
    flb_input_set(ctx, in_ffd,
                  "path", log_file,
                  "read_from_head", "true",
                  "db", db_file,
                  "db.sync", "full",
                  "offset_key", "off",
                  NULL);

    out_ffd = flb_output(ctx, "lib", &cb);
    flb_output_set(ctx, out_ffd, "match", "*", NULL);

    flb_start(ctx);
    wait_for_count_with_timeout(&t_ctx, 1, 2000);
    flb_stop(ctx);
    flb_destroy(ctx);

    TEST_CHECK(test_ctx_get_count(&t_ctx) == 1); /* Should process ONLY line2 */
    TEST_CHECK(test_ctx_get_found_expected(&t_ctx) == 1);
    TEST_CHECK(test_ctx_get_offset(&t_ctx, &off2) == FLB_TRUE);
    /* offset_key must keep growing across gzip members */
    TEST_CHECK(off2 > off1);
    test_ctx_begin_run(&t_ctx, "line3");

    /* 4. Restart (Run 3) -> Should SKIP Line1+Line2 and process Line3 */
    TEST_CHECK(append_gzip_file(log_file, content3, strlen(content3)) == 0);

    ctx = flb_create();
    flb_service_set(ctx, "Flush", "0.5", "Grace", "1", NULL);
    in_ffd = flb_input(ctx, "tail", NULL);
    flb_input_set(ctx, in_ffd,
                  "path", log_file,
                  "read_from_head", "true",
                  "db", db_file,
                  "db.sync", "full",
                  "offset_key", "off",
                  NULL);

    out_ffd = flb_output(ctx, "lib", &cb);
    flb_output_set(ctx, out_ffd, "match", "*", NULL);

    flb_start(ctx);
    wait_for_count_with_timeout(&t_ctx, 1, 2000);
    flb_stop(ctx);
    flb_destroy(ctx);

    TEST_CHECK(test_ctx_get_count(&t_ctx) == 1);
    TEST_CHECK(test_ctx_get_found_expected(&t_ctx) == 1);
    TEST_CHECK(test_ctx_get_offset(&t_ctx, &off3) == FLB_TRUE);
    TEST_CHECK(off3 > off2);

    unlink(log_file);
    unlink(db_file);
}

#endif /* FLB_HAVE_SQLDB */

/* Test list */
TEST_LIST = {
    {"issue_3943", flb_test_in_tail_issue_3943},
    /* Properties */
    {"skip_long_lines", flb_test_in_tail_skip_long_lines},
    {"truncate_long_lines",          flb_test_in_tail_truncate_long_lines},
    {"truncate_long_lines_utf8",     flb_test_in_tail_truncate_long_lines_utf8},
    {"path_comma", flb_test_path_comma},
    {"path_key", flb_test_path_key},
    {"exclude_path", flb_test_exclude_path},
#ifdef _WIN32
    {"windows_extended_path_prefixes", flb_test_windows_extended_path_prefixes},
#endif
    {"offset_key", flb_test_offset_key},
    {"multiline_offset_key", flb_test_multiline_offset_key},
    {"skip_empty_lines", flb_test_skip_empty_lines},
    {"skip_empty_lines_crlf", flb_test_skip_empty_lines_crlf},
    {"ignore_older", flb_test_ignore_older},
    {"ignore_active_older_files", flb_test_in_tail_ignore_active_older_files},
    {"ignore_active_older_files_reread_on_update", flb_test_in_tail_ignore_active_older_files_reread_on_update},
    {"ignore_active_older_files_reread_on_update_default_read_from_head", flb_test_in_tail_ignore_active_older_files_reread_on_update_default_read_from_head},
#ifdef FLB_HAVE_INOTIFY
    {"inotify_watcher_false", flb_test_inotify_watcher_false},
    {"inotify_pause_collectors", flb_test_inotify_pause_collectors},
    {"inotify_threaded_pause_collectors", flb_test_inotify_threaded_pause_collectors},
#endif /* FLB_HAVE_INOTIFY */

#ifdef FLB_HAVE_REGEX
    {"parser", flb_test_parser},
    {"tag_regex", flb_test_tag_regex},
#endif /* FLB_HAVE_INOTIFY */

#ifdef FLB_HAVE_SQLDB
    {"db", flb_test_db},
    {"db_delete_stale_file", flb_test_db_delete_stale_file},
    {"db_compare_filename", flb_test_db_compare_filename},
    {"db_offset_rewind_on_shutdown", flb_test_db_offset_rewind_on_shutdown},
    {"db_gzip_resume_loss", flb_test_db_gzip_resume_loss },
    {"db_gzip_inotify_append", flb_test_db_gzip_inotify_append },
    {"db_gzip_rotation", flb_test_db_gzip_rotation },
    {"db_gzip_multi_resume", flb_test_db_gzip_multi_resume },
#endif

#ifdef FLB_HAVE_UNICODE_ENCODER
    {"utf16le_c", flb_test_in_tail_utf16le_c},
    {"utf16be_c", flb_test_in_tail_utf16be_c},
    {"utf16le_j", flb_test_in_tail_utf16le_j},
    {"utf16be_j", flb_test_in_tail_utf16be_j},
    {"utf16le_subdivision_flags", flb_test_in_tail_utf16le_subdivision_flags},
    {"utf16be_subdivision_flags", flb_test_in_tail_utf16be_subdivision_flags},
#endif

#ifdef in_tail
    {"in_tail_dockermode",                          flb_test_in_tail_dockermode},
    {"in_tail_dockermode_splitted_line",            flb_test_in_tail_dockermode_splitted_line},
    {"in_tail_dockermode_multiple_lines",           flb_test_in_tail_dockermode_multiple_lines},
    {"in_tail_dockermode_splitted_multiple_lines",  flb_test_in_tail_dockermode_splitted_multiple_lines},
    {"in_tail_dockermode_firstline_detection",      flb_test_in_tail_dockermode_firstline_detection},
    {"in_tail_multiline_json_and_regex",            flb_test_in_tail_multiline_json_and_regex},
    {"in_tail_generic_enc_big5",                    flb_test_in_tail_generic_enc_big5},
    {"in_tail_generic_enc_gb18030",                 flb_test_in_tail_generic_enc_gb18030},
    {"in_tail_generic_enc_gbk",                     flb_test_in_tail_generic_enc_gbk},
    {"in_tail_generic_enc_sjis",                    flb_test_in_tail_generic_enc_sjis},
    {"in_tail_generic_enc_win1250",                 flb_test_in_tail_generic_enc_win1250},
    {"in_tail_generic_enc_win1251",                 flb_test_in_tail_generic_enc_win1251},
    {"in_tail_generic_enc_win1252",                 flb_test_in_tail_generic_enc_win1252},
    {"in_tail_generic_enc_win1253",                 flb_test_in_tail_generic_enc_win1253},
    {"in_tail_generic_enc_win1254",                 flb_test_in_tail_generic_enc_win1254},
    {"in_tail_generic_enc_win1255",                 flb_test_in_tail_generic_enc_win1255},
    {"in_tail_generic_enc_win1256",                 flb_test_in_tail_generic_enc_win1256},
#endif
    {NULL, NULL}
};
