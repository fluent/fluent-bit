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
#include <fluent-bit/flb_compat.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "flb_tests_runtime.h"

struct test_ctx {
    flb_ctx_t *flb;    /* Fluent Bit library context */
    int i_ffd;         /* Input fd  */
    int f_ffd;         /* Filter fd (unused) */
    int o_ffd;         /* Output fd */
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
        flb_error("Data is NULL");
        flb_free(record);
        return 0;
    }


    set_output_num(num+1);

    result = (char *) record;

    for (i=0; i<l->size; i++) {
        p = strstr(result, l->lists[i]);
        if(!TEST_CHECK(p != NULL)) {
            flb_error("Expected to find: '%s' in result '%s'",
                      l->lists[i], result);
        }
    }

    /*
     * If you want to debug your test
     *
     * printf("Expect: '%s' in result '%s'", expected, result);
     */
    flb_free(record);
    return 0;
}

static struct test_ctx *test_ctx_create(struct flb_lib_out_cb *data)
{
    int i_ffd;
    int o_ffd;
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
    i_ffd = flb_input(ctx->flb, (char *) "statsd", NULL);
    TEST_CHECK(i_ffd >= 0);
    ctx->i_ffd = i_ffd;

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

#define DEFAULT_HOST "127.0.0.1"
#define DEFAULT_PORT 8125
static int init_udp(char *in_host, int in_port, struct sockaddr_in *addr)
{
    int port = in_port;
    char *host = in_host;
    flb_sockfd_t fd;

    if (host == NULL) {
        host = DEFAULT_HOST;
    }
    if (port < 0) {
        port = DEFAULT_PORT;
    }

    memset(addr, 0, sizeof(struct sockaddr_in));
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (!TEST_CHECK(fd >= 0)) {
        TEST_MSG("failed to socket. host=%s port=%d errno=%d", host, port, errno);
        return -1;
    }

    addr->sin_family = AF_INET;
    addr->sin_addr.s_addr = inet_addr(host);
    addr->sin_port = htons(port);

    return fd;
}

static int test_normal(char *payload, struct str_list *expected)
{
    struct flb_lib_out_cb cb_data;
    struct test_ctx *ctx;
    struct sockaddr_in addr;
    int fd;
    int ret;
    int num;
    ssize_t w_size;

    size_t size;

    if (!TEST_CHECK(payload != NULL && expected != NULL)) {
        TEST_MSG("input is NULL");
        return -1;
    }
    size = strlen(payload);

    clear_output_num();

    cb_data.cb = cb_check_json_str_list;
    cb_data.data = expected;

    ctx = test_ctx_create(&cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
        exit(EXIT_FAILURE);
    }

    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "format", "json",
                         NULL);
    TEST_CHECK(ret == 0);

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* use default host/port */
    fd = init_udp(NULL, -1, &addr);
    if (!TEST_CHECK(fd >= 0)) {
        exit(EXIT_FAILURE);
    }

    w_size = sendto(fd, payload, size, 0, (const struct sockaddr *)&addr, sizeof(addr));
    if (!TEST_CHECK(w_size == size)) {
        TEST_MSG("failed to send, errno=%d", errno);
        flb_socket_close(fd);
        exit(EXIT_FAILURE);
    }

    /* waiting to flush */
    flb_time_msleep(500);

    num = get_output_num();
    if (!TEST_CHECK(num > 0))  {
        TEST_MSG("no outputs");
    }

    flb_socket_close(fd);
    test_ctx_destroy(ctx);

    return 0;
}

void flb_test_statsd_count()
{
    char *expected_strs[] = {"\"bucket\":\"gorets\"", "\"type\":\"counter\"", "\"value\":1"};
    struct str_list expected = {
                                .size = sizeof(expected_strs)/sizeof(char*),
                                .lists = &expected_strs[0],
    };

    char *buf = "gorets:1|c";
    int ret;

    ret = test_normal(buf, &expected);
    if (!TEST_CHECK(ret == 0))  {
        TEST_MSG("test failed");
        exit(EXIT_FAILURE);
    }

}

void flb_test_statsd_sample()
{
    char *expected_strs[] = {"\"bucket\":\"gorets\"", "\"type\":\"counter\"", 
                             "\"value\":1", "\"sample_rate\":0.1"};
    struct str_list expected = {
                                .size = sizeof(expected_strs)/sizeof(char*),
                                .lists = &expected_strs[0],
    };

    char *buf = "gorets:1|c|@0.1";
    int ret;

    ret = test_normal(buf, &expected);
    if (!TEST_CHECK(ret == 0))  {
        TEST_MSG("test failed");
        exit(EXIT_FAILURE);
    }
}

void flb_test_statsd_gauge()
{
    char *expected_strs[] = {"\"type\":\"gauge\"","\"bucket\":\"gaugor\"",
                             "\"value\":333"};
    struct str_list expected = {
                                .size = sizeof(expected_strs)/sizeof(char*),
                                .lists = &expected_strs[0],
    };

    char *buf = "gaugor:333|g";
    int ret;

    ret = test_normal(buf, &expected);
    if (!TEST_CHECK(ret == 0))  {
        TEST_MSG("test failed");
        exit(EXIT_FAILURE);
    }
}

void flb_test_statsd_set()
{
    char *expected_strs[] = {"\"bucket\":\"uniques\"", "\"type\":\"set\"", 
                             "\"value\":\"765\""};
    struct str_list expected = {
                                .size = sizeof(expected_strs)/sizeof(char*),
                                .lists = &expected_strs[0],
    };

    char *buf = "uniques:765|s";
    int ret;

    ret = test_normal(buf, &expected);
    if (!TEST_CHECK(ret == 0))  {
        TEST_MSG("test failed");
        exit(EXIT_FAILURE);
    }
}

TEST_LIST = {
    {"count", flb_test_statsd_count},
    {"sample", flb_test_statsd_sample},
    {"gauge", flb_test_statsd_gauge},
    {"set", flb_test_statsd_set},
    {NULL, NULL}
};

