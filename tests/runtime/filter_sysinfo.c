/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2023 The Fluent Bit Authors
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
#include "data/common/json_long.h"    /* JSON_LONG    */

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


/* Callback to check expected results */
static int cb_check_result(void *record, size_t size, void *data)
{
    char *p;
    char *result;
    struct expect_str *expected;

    expected = (struct expect_str*)data;
    result = (char *) record;

    if (!TEST_CHECK(expected != NULL)) {
        flb_error("expected is NULL");
    }
    if (!TEST_CHECK(result != NULL)) {
        flb_error("result is NULL");
    }

    while(expected != NULL && expected->str != NULL) {
        if (expected->found == FLB_TRUE) {
            p = strstr(result, expected->str);
            if(!TEST_CHECK(p != NULL)) {
                flb_error("Expected to find: '%s' in result '%s'",
                          expected->str, result);
            }
        }
        else {
            p = strstr(result, expected->str);
            if(!TEST_CHECK(p == NULL)) {
                flb_error("'%s' should be removed in result '%s'",
                          expected->str, result);
            }
        }

        /*
         * If you want to debug your test
         *
         * printf("Expect: '%s' in result '%s'", expected, result);
         */

        expected++;
    }

    flb_free(record);
    return 0;
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
    flb_input_set(ctx->flb, i_ffd, "tag", "test", NULL);
    ctx->i_ffd = i_ffd;

    /* Filter configuration */
    f_ffd = flb_filter(ctx->flb, (char *) "sysinfo", NULL);
    TEST_CHECK(f_ffd >= 0);
    flb_filter_set(ctx->flb, f_ffd, "match", "*", NULL);
    ctx->f_ffd = f_ffd;

    /* Output */
    o_ffd = flb_output(ctx->flb, (char *) "lib", (void *) data);
    TEST_CHECK(o_ffd >= 0);
    flb_output_set(ctx->flb, o_ffd,
                   "match", "test",
                   NULL);
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

static void flb_ver_key()
{
    int len;
    int ret;
    int bytes;
    char *p;
    struct flb_lib_out_cb cb_data;
    struct filter_test *ctx;
    struct expect_str expect[] = {
      {"\"flb_ver\"", FLB_TRUE},
      {FLB_VERSION_STR, FLB_TRUE},
      {"\"k\":\"sample\"", FLB_TRUE},
      {NULL, FLB_TRUE}
    };

    /* Create test context */
    ctx = filter_test_create((void *) &cb_data);
    if (!ctx) {
        exit(EXIT_FAILURE);
    }

    /* Configure filter */
    ret = flb_filter_set(ctx->flb, ctx->f_ffd,
                         "fluentbit_version_key", "flb_ver",
                         NULL);
    TEST_CHECK(ret == 0);

    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "format", "json",
                         NULL);
    TEST_CHECK(ret == 0);

    /* Prepare output callback with expected result */
    cb_data.cb = cb_check_result;
    cb_data.data = &expect;

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* Ingest data samples */
    p = "[0, {\"k\":\"sample\"}]";
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);

    filter_test_destroy(ctx);
}

static void hostname_key()
{
    int len;
    int ret;
    int bytes;
    char *p;
    struct flb_lib_out_cb cb_data;
    struct filter_test *ctx;
    struct expect_str expect[] = {
      {"\"h_key\"", FLB_TRUE},
      {NULL, FLB_TRUE}
    };

    /* Create test context */
    ctx = filter_test_create((void *) &cb_data);
    if (!ctx) {
        exit(EXIT_FAILURE);
    }

    /* Configure filter */
    ret = flb_filter_set(ctx->flb, ctx->f_ffd,
                         "hostname_key", "h_key",
                         NULL);
    TEST_CHECK(ret == 0);

    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "format", "json",
                         NULL);
    TEST_CHECK(ret == 0);

    /* Prepare output callback with expected result */
    cb_data.cb = cb_check_result;
    cb_data.data = &expect;

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* Ingest data samples */
    p = "[0, {\"k\":\"sample\"}]";
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);

    filter_test_destroy(ctx);
}

static void os_name_key()
{
    int len;
    int ret;
    int bytes;
    char *p;
    struct flb_lib_out_cb cb_data;
    struct filter_test *ctx;
    struct expect_str expect[] = {
      {"\"os_key\"", FLB_TRUE},
      {NULL, FLB_TRUE}
    };

    /* Create test context */
    ctx = filter_test_create((void *) &cb_data);
    if (!ctx) {
        exit(EXIT_FAILURE);
    }

    /* Configure filter */
    ret = flb_filter_set(ctx->flb, ctx->f_ffd,
                         "os_name_key", "os_key",
                         NULL);
    TEST_CHECK(ret == 0);

    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "format", "json",
                         NULL);
    TEST_CHECK(ret == 0);

    /* Prepare output callback with expected result */
    cb_data.cb = cb_check_result;
    cb_data.data = &expect;

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* Ingest data samples */
    p = "[0, {\"k\":\"sample\"}]";
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);

    filter_test_destroy(ctx);
}

/* test list */
TEST_LIST = {
    {"fluentbit_version_key"  , flb_ver_key },
    {"hostname_key" , hostname_key },
    {"os_name_key" , os_name_key },
    {NULL, NULL}
};
