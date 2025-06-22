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
#include "flb_tests_runtime.h"


#define SYSFS_TO_TEST FLB_TESTS_DATA_PATH "/data/node_exporter_metrics/sys"
#define PROCFS_TO_TEST FLB_TESTS_DATA_PATH "/data/node_exporter_metrics/proc"

struct test_ctx {
    flb_ctx_t *flb;    /* Fluent Bit library context */
    int i_ffd;         /* Input fd  */
    int f_ffd;         /* Filter fd (unused) */
    int o_ffd;         /* Output fd */
    struct http_client_ctx *httpc;
};

static struct test_ctx *test_ctx_create(struct flb_lib_out_cb *data)
{
    int i_ffd;
    int o_ffd;
    struct test_ctx *ctx = NULL;
    int ret;

    ctx = flb_calloc(1, sizeof(struct test_ctx));
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("flb_calloc failed");
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
    i_ffd = flb_input(ctx->flb, (char *) "node_exporter_metrics", NULL);
    TEST_CHECK(i_ffd >= 0);
    ctx->i_ffd = i_ffd;

    ret = flb_input_set(ctx->flb, i_ffd,
                        "scrape_interval", "1",
                        "path.sysfs", SYSFS_TO_TEST,
                        "path.procfs", PROCFS_TO_TEST,
                         NULL);
    TEST_CHECK(ret == 0);

    /* Output */
    o_ffd = flb_output(ctx->flb, (char *) "lib", (void *) data);
    ctx->o_ffd = o_ffd;

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


/* Callback to check expected results */
static int cb_check_result_json(void *record, size_t size, void *data)
{
    char *p;
    char *expected;
    char *result;
    int num = get_output_num();

    set_output_num(num+1);

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

void ne_uname()
{
    struct flb_lib_out_cb cb_data;
    struct test_ctx *ctx;
    int ret;
    int num;

    clear_output_num();

    cb_data.cb = cb_check_result_json;
    cb_data.data = "\"Linux\"";

    ctx = test_ctx_create(&cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
    }
    ret = flb_input_set(ctx->flb, ctx->i_ffd,
                         "metrics", "uname",
                         NULL);
    TEST_CHECK(ret == 0);


    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "format", "json",
                         NULL);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    flb_time_msleep(1500);

    num = get_output_num();
    if (!TEST_CHECK(num > 0))  {
        TEST_MSG("no outputs");
    }

    test_ctx_destroy(ctx);
}

void ne_cpu()
{
    struct flb_lib_out_cb cb_data;
    struct test_ctx *ctx;
    int ret;
    int num;
    char *expect_strs[] = {"iowait", "idle", "irq", "nice", "softirq", "steal", "system", "user",
        "core_throttles_total", "package_throttles_total"};
    struct str_list expected = {
        .size = sizeof(expect_strs)/sizeof(char*),
        .lists = &expect_strs[0],
    };

    clear_output_num();

    cb_data.cb = cb_check_json_str_list;
    cb_data.data = &expected;

    ctx = test_ctx_create(&cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
    }
    ret = flb_input_set(ctx->flb, ctx->i_ffd,
                         "metrics", "cpu",
                         NULL);
    TEST_CHECK(ret == 0);


    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "format", "json",
                         NULL);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    flb_time_msleep(1500);

    num = get_output_num();
    if (!TEST_CHECK(num > 0))  {
        TEST_MSG("no outputs");
    }

    test_ctx_destroy(ctx);
}

void ne_meminfo()
{
    struct flb_lib_out_cb cb_data;
    struct test_ctx *ctx;
    int ret;
    int num;
    char *expect_strs[] = {"MemTotal_bytes", "MemFree_bytes", "MemAvailable_bytes"};
    struct str_list expected = {
        .size = sizeof(expect_strs)/sizeof(char*),
        .lists = &expect_strs[0],
    };

    clear_output_num();

    cb_data.cb = cb_check_json_str_list;
    cb_data.data = &expected;

    ctx = test_ctx_create(&cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
    }
    ret = flb_input_set(ctx->flb, ctx->i_ffd,
                         "metrics", "meminfo",
                         NULL);
    TEST_CHECK(ret == 0);


    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "format", "json",
                         NULL);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    flb_time_msleep(1500);

    num = get_output_num();
    if (!TEST_CHECK(num > 0))  {
        TEST_MSG("no outputs");
    }

    test_ctx_destroy(ctx);
}

void ne_diskstats()
{
    struct flb_lib_out_cb cb_data;
    struct test_ctx *ctx;
    int ret;
    int num;
    char *expect_strs[] = {"reads_completed_total", "sr0", "sda", "sdb", "reads_merged_total"};
    struct str_list expected = {
        .size = sizeof(expect_strs)/sizeof(char*),
        .lists = &expect_strs[0],
    };

    clear_output_num();

    cb_data.cb = cb_check_json_str_list;
    cb_data.data = &expected;

    ctx = test_ctx_create(&cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
    }
    ret = flb_input_set(ctx->flb, ctx->i_ffd,
                         "metrics", "diskstats",
                         NULL);
    TEST_CHECK(ret == 0);


    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "format", "json",
                         NULL);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    flb_time_msleep(1500);

    num = get_output_num();
    if (!TEST_CHECK(num > 0))  {
        TEST_MSG("no outputs");
    }

    test_ctx_destroy(ctx);
}

void ne_time()
{
    struct flb_lib_out_cb cb_data;
    struct test_ctx *ctx;
    int ret;
    int num;
    char *expect_strs[] = {"time_seconds"};
    struct str_list expected = {
        .size = sizeof(expect_strs)/sizeof(char*),
        .lists = &expect_strs[0],
    };

    clear_output_num();

    cb_data.cb = cb_check_json_str_list;
    cb_data.data = &expected;

    ctx = test_ctx_create(&cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
    }
    ret = flb_input_set(ctx->flb, ctx->i_ffd,
                         "metrics", "time",
                         NULL);
    TEST_CHECK(ret == 0);


    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "format", "json",
                         NULL);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    flb_time_msleep(1500);

    num = get_output_num();
    if (!TEST_CHECK(num > 0))  {
        TEST_MSG("no outputs");
    }

    test_ctx_destroy(ctx);
}


void ne_loadavg()
{
    struct flb_lib_out_cb cb_data;
    struct test_ctx *ctx;
    int ret;
    int num;
    char *expect_strs[] = {"load1", "load5", "load15"};
    struct str_list expected = {
        .size = sizeof(expect_strs)/sizeof(char*),
        .lists = &expect_strs[0],
    };

    clear_output_num();

    cb_data.cb = cb_check_json_str_list;
    cb_data.data = &expected;

    ctx = test_ctx_create(&cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
    }
    ret = flb_input_set(ctx->flb, ctx->i_ffd,
                         "metrics", "loadavg",
                         NULL);
    TEST_CHECK(ret == 0);


    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "format", "json",
                         NULL);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    flb_time_msleep(1500);

    num = get_output_num();
    if (!TEST_CHECK(num > 0))  {
        TEST_MSG("no outputs");
    }

    test_ctx_destroy(ctx);
}

void ne_vmstat()
{
    struct flb_lib_out_cb cb_data;
    struct test_ctx *ctx;
    int ret;
    int num;
    char *expect_strs[] = {"pgpgin", "pgpgout", "pswpin", "pswpout"};
    struct str_list expected = {
        .size = sizeof(expect_strs)/sizeof(char*),
        .lists = &expect_strs[0],
    };

    clear_output_num();

    cb_data.cb = cb_check_json_str_list;
    cb_data.data = &expected;

    ctx = test_ctx_create(&cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
    }
    ret = flb_input_set(ctx->flb, ctx->i_ffd,
                         "metrics", "vmstat",
                         NULL);
    TEST_CHECK(ret == 0);


    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "format", "json",
                         NULL);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    flb_time_msleep(1500);

    num = get_output_num();
    if (!TEST_CHECK(num > 0))  {
        TEST_MSG("no outputs");
    }

    test_ctx_destroy(ctx);
}

void ne_netdev()
{
    struct flb_lib_out_cb cb_data;
    struct test_ctx *ctx;
    int ret;
    int num;
    char *expect_strs[] = {"receive_bytes_total", "receive_packets_total",  "receive_errs_total",
        "receive_drop_total", "receive_fifo_total"};
    struct str_list expected = {
        .size = sizeof(expect_strs)/sizeof(char*),
        .lists = &expect_strs[0],
    };

    clear_output_num();

    cb_data.cb = cb_check_json_str_list;
    cb_data.data = &expected;

    ctx = test_ctx_create(&cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
    }
    ret = flb_input_set(ctx->flb, ctx->i_ffd,
                         "metrics", "netdev",
                         NULL);
    TEST_CHECK(ret == 0);


    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "format", "json",
                         NULL);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    flb_time_msleep(1800);

    num = get_output_num();
    if (!TEST_CHECK(num > 0))  {
        TEST_MSG("no outputs");
    }

    test_ctx_destroy(ctx);
}

void ne_stat()
{
    struct flb_lib_out_cb cb_data;
    struct test_ctx *ctx;
    int ret;
    int num;
    char *expect_strs[] = {"intr_total", "context_switches_total", "forks_total",
        "boot_time_seconds"};
    struct str_list expected = {
        .size = sizeof(expect_strs)/sizeof(char*),
        .lists = &expect_strs[0],
    };

    clear_output_num();

    cb_data.cb = cb_check_json_str_list;
    cb_data.data = &expected;

    ctx = test_ctx_create(&cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
    }
    ret = flb_input_set(ctx->flb, ctx->i_ffd,
                         "metrics", "stat",
                         NULL);
    TEST_CHECK(ret == 0);


    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "format", "json",
                         NULL);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    flb_time_msleep(1500);

    num = get_output_num();
    if (!TEST_CHECK(num > 0))  {
        TEST_MSG("no outputs");
    }

    test_ctx_destroy(ctx);
}

void ne_filefd()
{
    struct flb_lib_out_cb cb_data;
    struct test_ctx *ctx;
    int ret;
    int num;
    char *expect_strs[] = {"allocated", "maximum"};
    struct str_list expected = {
        .size = sizeof(expect_strs)/sizeof(char*),
        .lists = &expect_strs[0],
    };

    clear_output_num();

    cb_data.cb = cb_check_json_str_list;
    cb_data.data = &expected;

    ctx = test_ctx_create(&cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
    }
    ret = flb_input_set(ctx->flb, ctx->i_ffd,
                         "metrics", "filefd",
                         NULL);
    TEST_CHECK(ret == 0);


    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "format", "json",
                         NULL);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    flb_time_msleep(1500);

    num = get_output_num();
    if (!TEST_CHECK(num > 0))  {
        TEST_MSG("no outputs");
    }

    test_ctx_destroy(ctx);
}

/* Test list */
TEST_LIST = {
    {"cpu",  ne_cpu},
    {"meminfo",  ne_meminfo},
    {"diskstats",  ne_diskstats},
    {"uname",  ne_uname},
    {"stat",  ne_stat},
    {"time",  ne_time},
    {"loadavg",  ne_loadavg},
    {"vmstat",  ne_vmstat},
    {"netdev",  ne_netdev},
    {"filefd",  ne_filefd},
    {NULL, NULL}
};
