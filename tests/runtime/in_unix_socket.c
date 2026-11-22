/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2026 The Fluent Bit Authors
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
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include "flb_tests_runtime.h"

struct test_ctx {
    flb_ctx_t *flb;    /* Fluent Bit library context */
    int i_ffd;         /* Input fd  */
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

/* Callback to check expected results */
static int cb_check_result_json(void *record, size_t size, void *data)
{
    char *p;
    char *expected;
    char *result;
    int num = get_output_num();

    set_output_num(num + 1);

    expected = (char *) data;
    result = (char *) record;

    p = strstr(result, expected);
    TEST_CHECK(p != NULL);

    if (p == NULL) {
        flb_error("Expected to find: '%s' in result '%s'",
                  expected, result);
    }

    flb_free(record);
    return 0;
}

static struct test_ctx *test_ctx_create(struct flb_lib_out_cb *data,
                                        char *socket_path, char *socket_mode)
{
    int ret;
    struct test_ctx *ctx;

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
    ctx->i_ffd = flb_input(ctx->flb, (char *) "unix_socket", NULL);
    TEST_CHECK(ctx->i_ffd >= 0);

    ret = flb_input_set(ctx->flb, ctx->i_ffd,
                        "socket_path", socket_path,
                        "socket_mode", socket_mode,
                        "format", "json",
                        NULL);
    TEST_CHECK(ret == 0);

    /* Output */
    ctx->o_ffd = flb_output(ctx->flb, (char *) "lib", (void *) data);
    TEST_CHECK(ctx->o_ffd >= 0);

    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "match", "*",
                         "format", "json",
                         NULL);
    TEST_CHECK(ret == 0);

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

/* Send one JSON map to the input and wait until the output receives it */
static void send_and_check(int socket_type, char *socket_mode)
{
    int i;
    int ret;
    int num;
    int fd;
    ssize_t w_size;
    char socket_path[64];
    struct sockaddr_un addr;
    struct flb_lib_out_cb cb_data;
    struct test_ctx *ctx;
    char *buf = "{\"test\":\"msg\"}";
    size_t size = strlen(buf);

    snprintf(socket_path, sizeof(socket_path),
             "/tmp/flb-rt-in-unix-socket-%s-%d.sock",
             socket_mode, (int) getpid());
    unlink(socket_path);

    clear_output_num();

    cb_data.cb = cb_check_result_json;
    cb_data.data = "\"test\":\"msg\"";

    ctx = test_ctx_create(&cb_data, socket_path, socket_mode);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
        exit(EXIT_FAILURE);
    }

    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    fd = socket(AF_UNIX, socket_type, 0);
    if (!TEST_CHECK(fd >= 0)) {
        TEST_MSG("failed to create socket, errno=%d", errno);
        test_ctx_destroy(ctx);
        exit(EXIT_FAILURE);
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path) - 1);

    if (socket_type == SOCK_STREAM) {
        ret = connect(fd, (struct sockaddr *) &addr, sizeof(addr));
        if (!TEST_CHECK(ret == 0)) {
            TEST_MSG("failed to connect, errno=%d", errno);
            close(fd);
            test_ctx_destroy(ctx);
            exit(EXIT_FAILURE);
        }
        w_size = send(fd, buf, size, 0);
    }
    else {
        w_size = sendto(fd, buf, size, 0,
                        (struct sockaddr *) &addr, sizeof(addr));
    }

    if (!TEST_CHECK(w_size == size)) {
        TEST_MSG("failed to send, errno=%d", errno);
        close(fd);
        test_ctx_destroy(ctx);
        exit(EXIT_FAILURE);
    }

    /* waiting to flush */
    for (i = 0; i < 30 && get_output_num() == 0; i++) {
        flb_time_msleep(100);
    }

    num = get_output_num();
    if (!TEST_CHECK(num > 0)) {
        TEST_MSG("no outputs");
    }

    close(fd);
    test_ctx_destroy(ctx);
    unlink(socket_path);
}

void flb_test_unix_socket_dgram()
{
    send_and_check(SOCK_DGRAM, "DGRAM");
}

void flb_test_unix_socket_stream()
{
    send_and_check(SOCK_STREAM, "STREAM");
}

TEST_LIST = {
    {"unix_socket_dgram", flb_test_unix_socket_dgram},
    {"unix_socket_stream", flb_test_unix_socket_stream},
    {NULL, NULL}
};
