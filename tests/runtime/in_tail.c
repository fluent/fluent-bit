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
#include "flb_tests_runtime.h"

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


#define DPATH            FLB_TESTS_DATA_PATH "/data/tail"
#define MAX_LINES        32

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

static inline int64_t set_result(int64_t v)
{
    int64_t old = __sync_lock_test_and_set(&result_time, v);
    return old;
}


static int file_to_buf(const char *path, char **out_buf, size_t *out_size)
{
    int ret;
    long bytes;
    char *buf;
    FILE *fp;
    struct stat st;

    ret = stat(path, &st);
    if (ret == -1) {
        return -1;
    }

    fp = fopen(path, "r");
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
#endif /* FLB_HAVE_SQLDB */

/* Test list */
TEST_LIST = {
    {"issue_3943", flb_test_in_tail_issue_3943},
    /* Properties */
    {"skip_long_lines", flb_test_in_tail_skip_long_lines},
    {"path_comma", flb_test_path_comma},
    {"path_key", flb_test_path_key},
    {"exclude_path", flb_test_exclude_path},
    {"offset_key", flb_test_offset_key},
    {"skip_empty_lines", flb_test_skip_empty_lines},
    {"skip_empty_lines_crlf", flb_test_skip_empty_lines_crlf},
    {"ignore_older", flb_test_ignore_older},
    {"ignore_active_older_files", flb_test_in_tail_ignore_active_older_files},
#ifdef FLB_HAVE_INOTIFY
    {"inotify_watcher_false", flb_test_inotify_watcher_false},
#endif /* FLB_HAVE_INOTIFY */

#ifdef FLB_HAVE_REGEX
    {"parser", flb_test_parser},
    {"tag_regex", flb_test_tag_regex},
#endif /* FLB_HAVE_INOTIFY */

#ifdef FLB_HAVE_SQLDB
    {"db", flb_test_db},
    {"db_delete_stale_file", flb_test_db_delete_stale_file},
    {"db_compare_filename", flb_test_db_compare_filename},
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
