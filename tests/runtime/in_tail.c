/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2016 Treasure Data Inc.
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
#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include "flb_tests_runtime.h"



#define DPATH            FLB_TESTS_DATA_PATH "/data/tail"
#define MAX_LINES        32

int64_t result_time;
struct tail_test_result {
    const char *target;
    int   nMatched;
};

struct tail_file_lines {
  char *lines[MAX_LINES];
  int lines_c;
};


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

    buf = flb_malloc(st.st_size);
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

    for (int i=0; i<out_size; i++) {
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
    for (int i=0; i<out->lines_c; i++) {
      check = strstr(record, out->lines[i]);
      if (check != NULL) {
          result->nMatched++;
          goto exit;
      }
    }

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

    /* Poll for up to 2 seconds or until we got a match */
    for (ret = 0; ret < tExpected && result.nMatched < nExpected; ret++) {
        usleep(1000);
    }

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


/* Test list */
TEST_LIST = {
#ifdef in_tail
    {"in_tail_dockermode",                          flb_test_in_tail_dockermode},
    {"in_tail_dockermode_splitted_line",            flb_test_in_tail_dockermode_splitted_line},
    {"in_tail_dockermode_multiple_lines",           flb_test_in_tail_dockermode_multiple_lines},
    {"in_tail_dockermode_splitted_multiple_lines",  flb_test_in_tail_dockermode_splitted_multiple_lines},
    {"in_tail_dockermode_firstline_detection",      flb_test_in_tail_dockermode_firstline_detection},
#endif
    {NULL, NULL}
};
