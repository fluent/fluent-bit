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
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "flb_tests_runtime.h"

#define TMP_CHECKLIST_PATH "checklist.txt"

struct test_ctx {
    flb_ctx_t *flb;    /* Fluent Bit library context */
    int i_ffd;         /* Input fd  */
    int f_ffd;         /* Filter fd (unused) */
    int o_ffd;         /* Output fd */
};

static struct test_ctx *test_ctx_create(struct flb_lib_out_cb *data)
{
    int i_ffd;
    int o_ffd;
    int f_ffd;
    struct test_ctx *ctx = NULL;

    ctx = flb_malloc(sizeof(struct test_ctx));
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("malloc failed");
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
    flb_input_set(ctx->flb, i_ffd, "tag", "test", NULL);
    ctx->i_ffd = i_ffd;

    /* Filter */
    f_ffd = flb_filter(ctx->flb, (char *) "checklist", NULL);
    TEST_CHECK(f_ffd >= 0);
    ctx->f_ffd = f_ffd;

    /* Output */
    o_ffd = flb_output(ctx->flb, (char *) "lib", (void *) data);
    ctx->o_ffd = o_ffd;
    TEST_CHECK(o_ffd >= 0);
    flb_output_set(ctx->flb, o_ffd,
                   "match", "test",
                   NULL);

    return ctx;
}

static void test_ctx_destroy(struct test_ctx *ctx)
{
    TEST_CHECK(ctx != NULL);

    sleep(1);
    flb_stop(ctx->flb);
    flb_destroy(ctx->flb);
    flb_free(ctx);
}

pthread_mutex_t result_mutex = PTHREAD_MUTEX_INITIALIZER;
char *output = NULL;

void set_output(char *val)
{
    pthread_mutex_lock(&result_mutex);
    output = val;
    pthread_mutex_unlock(&result_mutex);
}

char *get_output(void)
{
    char *val;

    pthread_mutex_lock(&result_mutex);
    val = output;
    pthread_mutex_unlock(&result_mutex);

    return val;
}

/* Callback to check expected results */
static int cb_check_result(void *record, size_t size, void *data)
{
    char *p;
    char *expected;
    char *result;

    expected = (char *) data;
    result = (char *) record;

    p = strstr(result, expected);
    TEST_CHECK(p != NULL);

    if (p==NULL) {
        flb_error("Expected to find: '%s' in result '%s'",
                  expected, result);
    }
    /*
     * If you want to debug your test
     *
     * printf("Expect: '%s' in result '%s'", expected, result);
     */
    flb_free(record);
    return 0;
}

void delete_checklist()
{
    unlink(TMP_CHECKLIST_PATH);
    flb_debug("remove checklist\n");
}


int create_checklist(char *checklist_body, size_t body_size)
{
    FILE *fp = NULL;
    fp = fopen(TMP_CHECKLIST_PATH, "w+");
    if (fp == NULL) {
        TEST_MSG("fopen error\n");
        return -1;
    }
    fwrite(checklist_body, body_size, 1, fp);
    fflush(fp);
    fclose(fp);
    return 0;
}

void flb_test_lookup_key(void)
{
    int ret;
    int bytes;
    struct test_ctx *ctx;
    struct flb_lib_out_cb cb_data;
    char *checklist_body = ""
        "malicious word\n";
    char *input = "[0, {\"secret\": \"malicious word\"}]";

    cb_data.cb = cb_check_result;
    cb_data.data = "\"secret\":\"----\"";

    ctx = test_ctx_create(&cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
        exit(EXIT_FAILURE);
    }

    ret = create_checklist(checklist_body, strlen(checklist_body));
    TEST_CHECK(ret == 0);
    /* Filter */
    ret = flb_filter_set(ctx->flb, ctx->f_ffd,
                         "Match", "*",
                         "file", TMP_CHECKLIST_PATH,
                         "lookup_key", "secret",
                         "record", "secret ----",
                         NULL);
    TEST_CHECK(ret==0);

    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "format", "json",
                         NULL);
    TEST_CHECK(ret==0);

    ret = flb_start(ctx->flb);
    TEST_CHECK(ret==0);

    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, input, strlen(input));
    TEST_CHECK(bytes == strlen(input));
    flb_time_msleep(1500); /* waiting flush */
    delete_checklist();

    test_ctx_destroy(ctx);
}

void flb_test_lookup_keys(void)
{
    int ret;
    int bytes;
    struct test_ctx *ctx;
    struct flb_lib_out_cb cb_data;
    char *checklist_body = ""
        "malicious word\n"
        "confidential\n";

    char *input = "[0, {\"secret\": \"malicious word\"}]";
    char *input2 = "[0, {\"secret\": \"confidential\"}]";

    cb_data.cb = cb_check_result;
    cb_data.data = "\"secret\":\"----\"";

    ctx = test_ctx_create(&cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
        exit(EXIT_FAILURE);
    }

    ret = create_checklist(checklist_body, strlen(checklist_body));
    TEST_CHECK(ret == 0);
    /* Filter */
    ret = flb_filter_set(ctx->flb, ctx->f_ffd,
                         "Match", "*",
                         "file", TMP_CHECKLIST_PATH,
                         "lookup_key", "secret",
                         "record", "secret ----",
                         NULL);
    TEST_CHECK(ret==0);

    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "format", "json",
                         NULL);
    TEST_CHECK(ret==0);

    ret = flb_start(ctx->flb);
    TEST_CHECK(ret==0);

    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, input, strlen(input));
    TEST_CHECK(bytes == strlen(input));
    flb_time_msleep(1500); /* waiting flush */
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, input2, strlen(input2));
    TEST_CHECK(bytes == strlen(input2));
    flb_time_msleep(1500); /* waiting flush */
    delete_checklist();

    test_ctx_destroy(ctx);
}

void flb_test_records(void)
{
    int ret;
    int bytes;
    struct test_ctx *ctx;
    struct flb_lib_out_cb cb_data;
    char *checklist_body = ""
        "malicious word\n";
    char *input = "[0, {\"secret\": \"malicious word\"}]";

    cb_data.cb = cb_check_result;
    cb_data.data = "\"secret\":\"----\",\"checklist\":true";

    ctx = test_ctx_create(&cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
        exit(EXIT_FAILURE);
    }

    ret = create_checklist(checklist_body, strlen(checklist_body));
    TEST_CHECK(ret == 0);
    /* Filter */
    ret = flb_filter_set(ctx->flb, ctx->f_ffd,
                         "Match", "*",
                         "file", TMP_CHECKLIST_PATH,
                         "lookup_key", "secret",
                         "record", "secret ----",
                         "record", "checklist true",
                         NULL);
    TEST_CHECK(ret==0);

    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "format", "json",
                         NULL);
    TEST_CHECK(ret==0);

    ret = flb_start(ctx->flb);
    TEST_CHECK(ret==0);

    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, input, strlen(input));
    TEST_CHECK(bytes == strlen(input));
    flb_time_msleep(1500); /* waiting flush */
    delete_checklist();

    test_ctx_destroy(ctx);
}

void flb_test_ignore_case(void)
{
    int ret;
    int bytes;
    struct test_ctx *ctx;
    struct flb_lib_out_cb cb_data;
    char *checklist_body = ""
        "MaliCioUs Word\n";
    char *input = "[0, {\"secret\": \"malicious word\"}]";

    cb_data.cb = cb_check_result;
    cb_data.data = "\"secret\":\"----\"";

    ctx = test_ctx_create(&cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
        exit(EXIT_FAILURE);
    }

    ret = create_checklist(checklist_body, strlen(checklist_body));
    TEST_CHECK(ret == 0);
    /* Filter */
    ret = flb_filter_set(ctx->flb, ctx->f_ffd,
                         "Match", "*",
                         "file", TMP_CHECKLIST_PATH,
                         "lookup_key", "secret",
                         "record", "secret ----",
                         "ignore_case", "true",
                         NULL);
    TEST_CHECK(ret==0);

    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "format", "json",
                         NULL);
    TEST_CHECK(ret==0);

    ret = flb_start(ctx->flb);
    TEST_CHECK(ret==0);

    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, input, strlen(input));
    TEST_CHECK(bytes == strlen(input));
    flb_time_msleep(1500); /* waiting flush */
    delete_checklist();

    test_ctx_destroy(ctx);
}

#ifdef FLB_HAVE_SQLDB
void flb_test_mode_partial(void)
{
    int ret;
    int bytes;
    struct test_ctx *ctx;
    struct flb_lib_out_cb cb_data;
    char *checklist_body = ""
        "malicious\n";
    char *input = "[0, {\"secret\": \"malicious word\"}]";

    cb_data.cb = cb_check_result;
    cb_data.data = "\"secret\":\"----\"";

    ctx = test_ctx_create(&cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
        exit(EXIT_FAILURE);
    }

    ret = create_checklist(checklist_body, strlen(checklist_body));
    TEST_CHECK(ret == 0);
    /* Filter */
    ret = flb_filter_set(ctx->flb, ctx->f_ffd,
                         "Match", "*",
                         "file", TMP_CHECKLIST_PATH,
                         "lookup_key", "secret",
                         "record", "secret ----",
                         "mode", "partial",
                         NULL);
    TEST_CHECK(ret==0);

    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "format", "json",
                         NULL);
    TEST_CHECK(ret==0);

    ret = flb_start(ctx->flb);
    TEST_CHECK(ret==0);

    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, input, strlen(input));
    TEST_CHECK(bytes == strlen(input));
    flb_time_msleep(1500); /* waiting flush */
    delete_checklist();

    test_ctx_destroy(ctx);
}
#endif

TEST_LIST = {
    {"lookup_key", flb_test_lookup_key},
    {"lookup_keys", flb_test_lookup_keys},
    {"records", flb_test_records},
    {"ignore_case", flb_test_ignore_case},
#ifdef FLB_HAVE_SQLDB
    {"mode_partial", flb_test_mode_partial},
#endif
    {NULL, NULL}
};
