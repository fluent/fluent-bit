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

#include <fluent-bit.h>
#include <fluent-bit/flb_time.h>
#include <msgpack.h>
#include "flb_tests_runtime.h"

struct filter_test {
    flb_ctx_t *flb;    /* Fluent Bit library context */
    int i_ffd;         /* Input fd  */
    int f_ffd;         /* Filter fd */
    int o_ffd;         /* Output fd */
};

struct expect_str {
    char *str;
    int  found;
};

pthread_mutex_t result_mutex = PTHREAD_MUTEX_INITIALIZER;
int  num_output = 0;

static int cb_count_msgpack(void *record, size_t size, void *data)
{
    msgpack_unpacked result;
    size_t off = 0;

    if (!TEST_CHECK(data != NULL)) {
        flb_error("data is NULL");
    }

    /* Iterate each item array and apply rules */
    msgpack_unpacked_init(&result);
    while (msgpack_unpack_next(&result, record, size, &off) == MSGPACK_UNPACK_SUCCESS) {
        pthread_mutex_lock(&result_mutex);
        num_output++;
        pthread_mutex_unlock(&result_mutex);
    }
    msgpack_unpacked_destroy(&result);

    flb_free(record);
    return 0;
}

static void clear_output_num()
{
    pthread_mutex_lock(&result_mutex);
    num_output = 0;
    pthread_mutex_unlock(&result_mutex);
}

static int get_output_num()
{
    int ret;
    pthread_mutex_lock(&result_mutex);
    ret = num_output;
    pthread_mutex_unlock(&result_mutex);

    return ret;
}

static struct filter_test *filter_test_create(struct flb_lib_out_cb *data)
{
    int i_ffd;
    int f_ffd;
    int o_ffd;
    struct filter_test *ctx;

    ctx = flb_malloc(sizeof(struct filter_test));
    if (!ctx) {
        flb_errno();
        return NULL;
    }

    /* Service config */
    ctx->flb = flb_create();
    flb_service_set(ctx->flb,
                    "Flush", "0.200000000",
                    "Grace", "1",
                    "Log_Level", "error",
                    NULL);

    /* Input */
    i_ffd = flb_input(ctx->flb, (char *) "lib", NULL);
    TEST_CHECK(i_ffd >= 0);
    flb_input_set(ctx->flb, i_ffd, "tag", "rewrite", NULL);
    ctx->i_ffd = i_ffd;

    /* Filter configuration */
    f_ffd = flb_filter(ctx->flb, (char *) "rewrite_tag", NULL);
    TEST_CHECK(f_ffd >= 0);
    flb_filter_set(ctx->flb, f_ffd, "match", "rewrite", NULL);
    ctx->f_ffd = f_ffd;

    /* Output */
    o_ffd = flb_output(ctx->flb, (char *) "lib", (void *) data);
    ctx->o_ffd = o_ffd;

    return ctx;
}

static void filter_test_destroy(struct filter_test *ctx)
{
    sleep(1);
    flb_stop(ctx->flb);
    flb_destroy(ctx->flb);
    flb_free(ctx);
}


/* 
 * Original  tag: rewrite
 * Rewritten tag: updated
 */
static void flb_test_matched()
{
    struct flb_lib_out_cb cb_data;
    struct filter_test *ctx;
    int ret;
    int not_used = 0;
    int bytes;
    int got;
    char *p = "[0, {\"key\":\"rewrite\"}]";

    /* Prepare output callback with expected result */
    cb_data.cb = cb_count_msgpack;
    cb_data.data = &not_used;

    /* Create test context */
    ctx = filter_test_create((void *) &cb_data);
    if (!ctx) {
        exit(EXIT_FAILURE);
    }
    clear_output_num();
    /* Configure filter */
    ret = flb_filter_set(ctx->flb, ctx->f_ffd,
                         "Rule", "$key ^(rewrite)$ updated false",
                         NULL);
    TEST_CHECK(ret == 0);

    /* Configure output */
    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "Match", "updated",
                         NULL);
    TEST_CHECK(ret == 0);

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* ingest record */
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, strlen(p));
    TEST_CHECK(bytes == strlen(p));

    flb_time_msleep(1500); /* waiting flush */
    got = get_output_num();

    if (!TEST_CHECK(got != 0)) {
        TEST_MSG("expect: %d got: %d", 1, got);
    }

    filter_test_destroy(ctx);
}

/* 
 * Original  tag: rewrite
 * Rewritten tag: updated
 */
static void flb_test_not_matched()
{
    struct flb_lib_out_cb cb_data;
    struct filter_test *ctx;
    int ret;
    int not_used = 0;
    int bytes;
    int got;
    char *p = "[0, {\"key\":\"not_match\"}]";

    /* Prepare output callback with expected result */
    cb_data.cb = cb_count_msgpack;
    cb_data.data = &not_used;

    /* Create test context */
    ctx = filter_test_create((void *) &cb_data);
    if (!ctx) {
        exit(EXIT_FAILURE);
    }
    clear_output_num();
    /* Configure filter */
    ret = flb_filter_set(ctx->flb, ctx->f_ffd,
                         "Rule", "$key ^(rewrite)$ updated false",
                         NULL);
    TEST_CHECK(ret == 0);

    /* Configure output */
    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "Match", "rewrite",
                         NULL);
    TEST_CHECK(ret == 0);


    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* ingest record */
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, strlen(p));
    TEST_CHECK(bytes == strlen(p));

    flb_time_msleep(1500); /* waiting flush */
    got = get_output_num();

    if (!TEST_CHECK(got != 0)) {
        TEST_MSG("expect: %d got: %d", 1, got);
    }

    filter_test_destroy(ctx);
}

/* 
 * Original  tag: rewrite
 * Rewritten tag: updated
 */
static void flb_test_keep_true()
{
    struct flb_lib_out_cb cb_data;
    struct filter_test *ctx;
    int ret;
    int not_used = 0;
    int bytes;
    int got;
    char *p = "[0, {\"key\":\"rewrite\"}]";

    /* Prepare output callback with expected result */
    cb_data.cb = cb_count_msgpack;
    cb_data.data = &not_used;

    /* Create test context */
    ctx = filter_test_create((void *) &cb_data);
    if (!ctx) {
        exit(EXIT_FAILURE);
    }
    clear_output_num();
    /* Configure filter */
    ret = flb_filter_set(ctx->flb, ctx->f_ffd,
                         "Rule", "$key ^(rewrite)$ updated true",
                         NULL);
    TEST_CHECK(ret == 0);

    /* Configure output to count up all record */
    ret = flb_output_set(ctx->flb, ctx->o_ffd, "Match", "*", NULL);
    TEST_CHECK(ret == 0);

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* ingest record */
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, strlen(p));
    TEST_CHECK(bytes == strlen(p));

    flb_time_msleep(1500); /* waiting flush */
    got = get_output_num();

    /* original record(keep) + rewritten record */
    if (!TEST_CHECK(got == 2)) {
        TEST_MSG("expect: %d got: %d", 2, got);
    }

    filter_test_destroy(ctx);
}

/* https://github.com/fluent/fluent-bit/issues/4049
 * Emitter should pause if tons of input come.
 */
static void flb_test_heavy_input_pause_emitter()
{
    struct flb_lib_out_cb cb_data;
    struct filter_test *ctx;
    int ret;
    int not_used = 0;
    int bytes;
    int heavy_loop = 100000;
    int got;
    char p[256];
    int i;

    /* Prepare output callback with expected result */
    cb_data.cb = cb_count_msgpack;
    cb_data.data = &not_used;

    /* Create test context */
    ctx = filter_test_create((void *) &cb_data);
    if (!ctx) {
        exit(EXIT_FAILURE);
    }
    clear_output_num();
    /* Configure filter */
    ret = flb_filter_set(ctx->flb, ctx->f_ffd,
                         "Rule", "$key ^(rewrite)$ updated false",
                         "Emitter_Mem_Buf_Limit", "1kb",
                         NULL);
    TEST_CHECK(ret == 0);

    /* Configure output */
    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "Match", "updated",
                         NULL);
    TEST_CHECK(ret == 0);

    /* Suppress emitter log. error registering chunk with tag: updated */
    ret = flb_service_set(ctx->flb, "Log_Level", "Off", NULL);
    TEST_CHECK(ret == 0);

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    for (i = 0; i < heavy_loop; i++) {
        memset(p, '\0', sizeof(p));
        snprintf(p, sizeof(p), "[%d, {\"val\": \"%d\",\"key\": \"rewrite\"}]", i, i);
        bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, strlen(p));
        TEST_CHECK(bytes == strlen(p));
    }

    flb_time_msleep(1500); /* waiting flush */
    got = get_output_num();

    if (!TEST_CHECK(got != 0)) {
        TEST_MSG("callback is not invoked");
    }

    /* Input should be paused since Mem_Buf_Limit is small size.
     * So got is less than heavy_loop.
     */
    if(!TEST_CHECK(heavy_loop > got)) {
        TEST_MSG("expect: %d got: %d", heavy_loop, got);
    }

    filter_test_destroy(ctx);
}

static void flb_test_issue_4793()
{
    struct flb_lib_out_cb cb_data;
    struct filter_test *ctx;
    int ret;
    int not_used = 0;
    int loop_max = 4;
    int bytes;
    int got;
    char p[256];
    int i;

    /* Prepare output callback with expected result */
    cb_data.cb = cb_count_msgpack;
    cb_data.data = &not_used;

    /* Create test context */
    ctx = filter_test_create((void *) &cb_data);
    if (!ctx) {
        exit(EXIT_FAILURE);
    }
    clear_output_num();
    /* Configure filter */
    ret = flb_filter_set(ctx->flb, ctx->f_ffd,
                         "Rule", "$destination ^(server)$ updated false",
                         NULL);
    TEST_CHECK(ret == 0);

    /* Configure output */
    ret = flb_output_set(ctx->flb, ctx->o_ffd, "Match", "*", NULL);
    TEST_CHECK(ret == 0);

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);


    /* emit (loop_max * 2) records */
    for (i = 0; i < loop_max; i++) {
        /* "destination": "server" */
        memset(p, '\0', sizeof(p));
        snprintf(p, sizeof(p), "[%d, {\"val\": \"%d\",\"destination\": \"server\"}]", i, i);
        bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, strlen(p));
        TEST_CHECK(bytes == strlen(p));

        /* "destination": "other" */
        memset(p, '\0', sizeof(p));
        snprintf(p, sizeof(p), "[%d, {\"val\": \"%d\",\"destination\": \"other\"}]", i+1, i+1);
        bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, strlen(p));
        TEST_CHECK(bytes == strlen(p));
    }

    flb_time_msleep(1500); /* waiting flush */
    got = get_output_num();

    if (!TEST_CHECK(got != 0)) {
        TEST_MSG("callback is not invoked");
    }

    if(!TEST_CHECK(2*loop_max ==  got)) {
        TEST_MSG("expect: %d got: %d", 2 * loop_max, got);
    }

    filter_test_destroy(ctx);
}

static void flb_test_issue_4518()
{
    struct flb_lib_out_cb cb_data;
    struct filter_test *ctx;
    int ret;
    int not_used = 0;
    int loop_max = 2;
    int bytes;
    int got;
    char p[256];
    int i;
    int f_ffd;

    /* Prepare output callback with expected result */
    cb_data.cb = cb_count_msgpack;
    cb_data.data = &not_used;

    /* Create test context */
    ctx = filter_test_create((void *) &cb_data);
    if (!ctx) {
        exit(EXIT_FAILURE);
    }
    clear_output_num();

    /* Configure output */
    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "Match", "*",
                         NULL);

    /* create 2nd filter  */
    f_ffd = flb_filter(ctx->flb, (char *) "rewrite_tag", NULL);
    TEST_CHECK(f_ffd >= 0);
    flb_filter_set(ctx->flb, f_ffd, "match", "rewrite", NULL);
    /* Configure filter */
    ret = flb_filter_set(ctx->flb, f_ffd,
                         "Rule", "$test3 ^(true)$ updated true",
                         NULL);
    TEST_CHECK(ret == 0);

    /* Configure 1st filter */
    ret = flb_filter_set(ctx->flb, ctx->f_ffd,
                         "Rule", "$test2 ^(true)$ updated true",
                         NULL);
    TEST_CHECK(ret == 0);

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    for (i = 0; i < loop_max; i++) {
        memset(p, '\0', sizeof(p));
        /* 1st filter duplicates below record. */
        snprintf(p, sizeof(p), "[%d, {\"msg\":\"DEBUG\", \"val\": \"%d\",\"test2\": \"true\"}]", i, i);
        bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, strlen(p));
        TEST_CHECK(bytes == strlen(p));

        /* 2nd filter duplicates below record. */
        memset(p, '\0', sizeof(p));
        snprintf(p, sizeof(p), "[%d, {\"msg\":\"ERROR\", \"val\": \"%d\",\"test3\": \"true\"}]", i, i);
        bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, strlen(p));
        TEST_CHECK(bytes == strlen(p));
    }

    flb_time_msleep(1500); /* waiting flush */
    got = get_output_num();

    if (!TEST_CHECK(got != 0)) {
        TEST_MSG("callback is not invoked");
    }

    /* Output should be 4 * loop_max. 
       1st filter appends 1 record and 2nd filter also appends 1 record.
       Original 2 records + 1 record(1st filter) + 1 record(2nd filter) = 4 records.
     */
    if(!TEST_CHECK(4*loop_max ==  got)) {
        TEST_MSG("expect: %d got: %d", 4 * loop_max, got);
    }

    filter_test_destroy(ctx);
}

/* $TAG as a key of rule causes SIGSEGV */
static void flb_test_issue_5846()
{
    struct flb_lib_out_cb cb_data;
    struct filter_test *ctx;
    int ret;
    int not_used = 0;
    int bytes;
    char *p = "[0, {\"key\":\"rewrite\"}]";

    /* Prepare output callback with expected result */
    cb_data.cb = cb_count_msgpack;
    cb_data.data = &not_used;

    /* Create test context */
    ctx = filter_test_create((void *) &cb_data);
    if (!ctx) {
        exit(EXIT_FAILURE);
    }
    clear_output_num();
    /* Configure filter */
    ret = flb_filter_set(ctx->flb, ctx->f_ffd,
                         "Rule", "$TAG ^(rewrite)$ updated false",
                         NULL);
    TEST_CHECK(ret == 0);

    /* Configure output */
    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "Match", "updated",
                         NULL);
    TEST_CHECK(ret == 0);

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* ingest record */
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, strlen(p));
    TEST_CHECK(bytes == strlen(p));

    flb_time_msleep(1500); /* waiting flush */

    /* It is OK, if there is no SIGSEGV. */

    filter_test_destroy(ctx);
}

static void flb_test_recursion_action_drop()
{
    struct flb_lib_out_cb cb_data;
    struct filter_test *ctx;
    int ret;
    int not_used = 0;
    int bytes;
    char *p = "[0, {\"key\":\"rewrite\"}]";

    /* Prepare output callback with expected result */
    cb_data.cb = cb_count_msgpack;
    cb_data.data = &not_used;

    /* Create test context */
    ctx = filter_test_create((void *) &cb_data);
    if (!ctx) {
        exit(EXIT_FAILURE);
    }
    clear_output_num();

    /* Configure filter */
    ret = flb_filter_set(ctx->flb, ctx->f_ffd,
                         "Rule", "key ^(rewrite)$ rewrite false", /* recursion setting */
                         "recursion_action", "drop",
                         NULL);
    TEST_CHECK(ret == 0);

    /* Configure output */
    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "Match", "updated",
                         NULL);
    TEST_CHECK(ret == 0);

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* ingest record */
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, strlen(p));
    TEST_CHECK(bytes == strlen(p));

    flb_time_msleep(1500); /* waiting flush */

    /* It is OK, if there is no SIGSEGV. */

    filter_test_destroy(ctx);
}

#ifdef FLB_HAVE_REGEX
static void flb_test_recursion_action_drop_regex()
{
    struct flb_lib_out_cb cb_data;
    struct filter_test *ctx;
    int ret;
    int not_used = 0;
    int bytes;
    char *p = "[0, {\"key\":\"rewrite\"}]";

    /* Prepare output callback with expected result */
    cb_data.cb = cb_count_msgpack;
    cb_data.data = &not_used;

    /* Create test context */
    ctx = filter_test_create((void *) &cb_data);
    if (!ctx) {
        exit(EXIT_FAILURE);
    }
    clear_output_num();

    /* Configure filter */
    ret = flb_filter_set(ctx->flb, ctx->f_ffd,
                         "Rule", "key ^(rewrite)$ rewrite false", /* recursion setting */
                         "recursion_action", "drop_and_log",
                         NULL);
    TEST_CHECK(ret == 0);

    /* Configure output */
    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "Match_regex", "up*",
                         NULL);
    TEST_CHECK(ret == 0);

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* ingest record */
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, strlen(p));
    TEST_CHECK(bytes == strlen(p));

    flb_time_msleep(1000); /* waiting flush */

    /* It is OK, if there is no SIGSEGV. */

    filter_test_destroy(ctx);
}
#endif
TEST_LIST = {
    {"matched",          flb_test_matched},
    {"not_matched",      flb_test_not_matched},
    {"keep_true",        flb_test_keep_true},
    {"heavy_input_pause_emitter", flb_test_heavy_input_pause_emitter},
    {"issue_4518", flb_test_issue_4518},
    {"issue_4793", flb_test_issue_4793},
    {"sigsegv_issue_5846", flb_test_issue_5846},
    {"recursion_action_drop", flb_test_recursion_action_drop},
#ifdef FLB_HAVE_REGEX
    {"recursion_action_drop_regex", flb_test_recursion_action_drop_regex},
#endif
    {NULL, NULL}
};
