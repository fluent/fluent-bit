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
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_socket.h>
#include <fluent-bit/flb_gzip.h>
#include <fluent-bit/flb_pack.h>
#include <sys/types.h>
#include <sys/stat.h>
#ifdef FLB_HAVE_UNIX_SOCKET
#include <sys/socket.h>
#include <sys/un.h>
#endif
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

static int create_simple_json(char **out_buf, size_t *size)
{
    int root_type;
    int ret;
    char json[] = "[\"test\", 1234567890,{\"test\":\"msg\"} ]";

    ret = flb_pack_json(&json[0], strlen(json), out_buf, size, &root_type, NULL);
    TEST_CHECK(ret==0);

    return ret;
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
    i_ffd = flb_input(ctx->flb, (char *) "forward", NULL);
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
#define DEFAULT_PORT 24224
static flb_sockfd_t connect_tcp(char *in_host, int in_port)
{
    int port = in_port;
    char *host = in_host;
    flb_sockfd_t fd;
    int ret;
    struct sockaddr_in addr;

    if (host == NULL) {
        host = DEFAULT_HOST;
    }
    if (port < 0) {
        port = DEFAULT_PORT;
    }

    memset(&addr, 0, sizeof(addr));
    fd = socket(PF_INET, SOCK_STREAM, 0);
    if (!TEST_CHECK(fd >= 0)) {
        TEST_MSG("failed to socket. host=%s port=%d errno=%d", host, port, errno);
        return -1;
    }

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(host);
    addr.sin_port = htons(port);

    ret = connect(fd, (const struct sockaddr *)&addr, sizeof(addr));
    if (!TEST_CHECK(ret >= 0)) {
        TEST_MSG("failed to connect. host=%s port=%d errno=%d", host, port, errno);
        flb_socket_close(fd);
        return -1;
    }
    return fd;
}

void flb_test_forward()
{
    struct flb_lib_out_cb cb_data;
    struct test_ctx *ctx;
    flb_sockfd_t fd;
    int ret;
    int num;
    ssize_t w_size;

    char *buf;
    size_t size;

    clear_output_num();

    cb_data.cb = cb_check_result_json;
    cb_data.data = "\"test\":\"msg\"";

    ctx = test_ctx_create(&cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
        exit(EXIT_FAILURE);
    }

    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "match", "test",
                         "format", "json",
                         NULL);
    TEST_CHECK(ret == 0);

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* use default host/port */
    fd = connect_tcp(NULL, -1);
    if (!TEST_CHECK(fd >= 0)) {
        exit(EXIT_FAILURE);
    }
    create_simple_json(&buf, &size);
    w_size = send(fd, buf, size, 0);
    flb_free(buf);
    if (!TEST_CHECK(w_size == size)) {
        TEST_MSG("failed to send, errno=%d", errno);
        flb_socket_close(fd);
        exit(EXIT_FAILURE);
    }

    /* waiting to flush */
    flb_time_msleep(1500);

    num = get_output_num();
    if (!TEST_CHECK(num > 0))  {
        TEST_MSG("no outputs");
    }

    flb_socket_close(fd);
    test_ctx_destroy(ctx);
}

void flb_test_forward_port()
{
    struct flb_lib_out_cb cb_data;
    struct test_ctx *ctx;

    flb_sockfd_t fd;
    int ret;
    int num;
    ssize_t w_size;
    char *port = "24000";

    char *buf;
    size_t size;

    clear_output_num();

    cb_data.cb = cb_check_result_json;
    cb_data.data = "\"test\":\"msg\"";

    ctx = test_ctx_create(&cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
        exit(EXIT_FAILURE);
    }

    ret = flb_input_set(ctx->flb, ctx->i_ffd,
                        "port", port,
                        NULL);
    TEST_CHECK(ret == 0);

    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "match", "test",
                         "format", "json",
                         NULL);
    TEST_CHECK(ret == 0);

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* use default host */
    fd = connect_tcp(NULL, atoi(port));
    if (!TEST_CHECK(fd >= 0)) {
        exit(EXIT_FAILURE);
    }

    create_simple_json(&buf, &size);
    w_size = send(fd, buf, size, 0);
    flb_free(buf);
    if (!TEST_CHECK(w_size == size)) {
        TEST_MSG("failed to send, errno=%d", errno);
        flb_socket_close(fd);
        exit(EXIT_FAILURE);
    }

    /* waiting to flush */
    flb_time_msleep(1500);

    num = get_output_num();
    if (!TEST_CHECK(num > 0))  {
        TEST_MSG("no outputs");
    }

    flb_socket_close(fd);
    test_ctx_destroy(ctx);
}

void flb_test_tag_prefix()
{
    struct flb_lib_out_cb cb_data;
    struct test_ctx *ctx;
    char *tag_prefix = "tag_";
    flb_sockfd_t fd;
    int ret;
    int num;
    ssize_t w_size;

    char *buf;
    size_t size;

    clear_output_num();

    cb_data.cb = cb_check_result_json;
    cb_data.data = "\"test\":\"msg\"";

    ctx = test_ctx_create(&cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
        exit(EXIT_FAILURE);
    }
    ret = flb_input_set(ctx->flb, ctx->i_ffd,
                        "tag_prefix", tag_prefix,
                        NULL);
    TEST_CHECK(ret == 0);

    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "match", "tag_test", /*tag_prefix + "test"*/
                         "format", "json",
                         NULL);
    TEST_CHECK(ret == 0);

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* use default host/port */
    fd = connect_tcp(NULL, -1);
    if (!TEST_CHECK(fd >= 0)) {
        exit(EXIT_FAILURE);
    }

    create_simple_json(&buf, &size);
    w_size = send(fd, buf, size, 0);
    flb_free(buf);
    if (!TEST_CHECK(w_size == size)) {
        TEST_MSG("failed to send, errno=%d", errno);
        flb_socket_close(fd);
        exit(EXIT_FAILURE);
    }

    /* waiting to flush */
    flb_time_msleep(1500);

    num = get_output_num();
    if (!TEST_CHECK(num > 0))  {
        TEST_MSG("no outputs");
    }

    flb_socket_close(fd);
    test_ctx_destroy(ctx);
}

#ifdef FLB_HAVE_UNIX_SOCKET
void flb_test_unix_path()
{
    struct flb_lib_out_cb cb_data;
    struct test_ctx *ctx;
    struct sockaddr_un sun;
    flb_sockfd_t fd;
    int ret;
    int num;
    ssize_t w_size;
    char *unix_path = "in_forward_unix";

    char *buf;
    size_t size;

    clear_output_num();

    cb_data.cb = cb_check_result_json;
    cb_data.data = "\"test\":\"msg\"";

    ctx = test_ctx_create(&cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
        exit(EXIT_FAILURE);
    }

    ret = flb_input_set(ctx->flb, ctx->i_ffd,
                        "unix_path", unix_path,
                        NULL);
    TEST_CHECK(ret == 0);

    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "match", "test",
                         "format", "json",
                         NULL);
    TEST_CHECK(ret == 0);

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* waiting to create socket */
    flb_time_msleep(200); 

    memset(&sun, 0, sizeof(sun));
    fd = socket(AF_LOCAL, SOCK_STREAM, 0);
    if (!TEST_CHECK(fd >= 0)) {
        TEST_MSG("failed to socket %s, errno=%d", unix_path, errno);
        unlink(unix_path);
        exit(EXIT_FAILURE);
    }

    sun.sun_family = AF_LOCAL;
    strcpy(sun.sun_path, unix_path);
    ret = connect(fd, (const struct sockaddr *)&sun, sizeof(sun));
    if (!TEST_CHECK(ret >= 0)) {
        TEST_MSG("failed to connect, errno=%d", errno);
        flb_socket_close(fd);
        unlink(unix_path);
        exit(EXIT_FAILURE);
    }
    create_simple_json(&buf, &size);
    w_size = send(fd, buf, size, 0);
    flb_free(buf);
    if (!TEST_CHECK(w_size == size)) {
        TEST_MSG("failed to write to %s", unix_path);
        flb_socket_close(fd);
        unlink(unix_path);
        exit(EXIT_FAILURE);
    }

    /* waiting to flush */
    flb_time_msleep(1500);

    num = get_output_num();
    if (!TEST_CHECK(num > 0))  {
        TEST_MSG("no outputs");
    }

    flb_socket_close(fd);
    test_ctx_destroy(ctx);
}


void flb_test_unix_perm()
{
    struct flb_lib_out_cb cb_data;
    struct test_ctx *ctx;
    struct sockaddr_un sun;
    flb_sockfd_t fd;
    int ret;
    int num;
    ssize_t w_size;
    char *unix_path = "in_forward_unix";
    struct stat sb;

    char *buf;
    size_t size;

    clear_output_num();

    cb_data.cb = cb_check_result_json;
    cb_data.data = "\"test\":\"msg\"";

    ctx = test_ctx_create(&cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
        exit(EXIT_FAILURE);
    }

    ret = flb_input_set(ctx->flb, ctx->i_ffd,
                        "unix_path", unix_path,
                        "unix_perm", "0600",
                        NULL);
    TEST_CHECK(ret == 0);

    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "match", "test",
                         "format", "json",
                         NULL);
    TEST_CHECK(ret == 0);

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* waiting to create socket */
    flb_time_msleep(200); 

    memset(&sun, 0, sizeof(sun));
    fd = socket(AF_LOCAL, SOCK_STREAM, 0);
    if (!TEST_CHECK(fd >= 0)) {
        TEST_MSG("failed to socket %s, errno=%d", unix_path, errno);
        unlink(unix_path);
        exit(EXIT_FAILURE);
    }

    sun.sun_family = AF_LOCAL;
    strcpy(sun.sun_path, unix_path);
    ret = connect(fd, (const struct sockaddr *)&sun, sizeof(sun));
    if (!TEST_CHECK(ret >= 0)) {
        TEST_MSG("failed to connect, errno=%d", errno);
        flb_socket_close(fd);
        unlink(unix_path);
        exit(EXIT_FAILURE);
    }
    create_simple_json(&buf, &size);
    w_size = send(fd, buf, size, 0);
    flb_free(buf);
    if (!TEST_CHECK(w_size == size)) {
        TEST_MSG("failed to write to %s", unix_path);
        flb_socket_close(fd);
        unlink(unix_path);
        exit(EXIT_FAILURE);
    }

    /* waiting to flush */
    flb_time_msleep(1500);

    num = get_output_num();
    if (!TEST_CHECK(num > 0))  {
        TEST_MSG("no outputs");
    }


    /* File permission */
    ret = stat(unix_path, &sb);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("stat failed. errno=%d", errno);
                test_ctx_destroy(ctx);
        exit(EXIT_FAILURE);
    }

    if (!TEST_CHECK((sb.st_mode & S_IRWXO) == 0)) {
        TEST_MSG("Permssion(others) error. val=0x%x",sb.st_mode & S_IRWXO);
    }
    if (!TEST_CHECK((sb.st_mode & S_IRWXG) == 0)) {
        TEST_MSG("Permssion(group) error. val=0x%x",sb.st_mode & S_IRWXG);
    }
    if (!TEST_CHECK((sb.st_mode & S_IRWXU) == (S_IRUSR | S_IWUSR))) {
        TEST_MSG("Permssion(user) error. val=0x%x",sb.st_mode & S_IRWXU);
    }

    flb_socket_close(fd);
    test_ctx_destroy(ctx);
}
#endif /* FLB_HAVE_UNIX_SOCKET */

/*
 * Creates a forward-protocol-compliant, Gzip-compressed MessagePack payload.
 * The final structure is: [tag, compressed_events, {options}]
 */
static int create_simple_json_gzip(msgpack_sbuffer *sbuf)
{
    int ret;
    char *event_buf;
    size_t event_size;
    char *compressed_buf;
    size_t compressed_size;
    int root_type;
    msgpack_packer pck;

    char *tag = "test";
    char event_json[] = "[1234567890,{\"test\":\"msg\"}]";

    ret = flb_pack_json(event_json, strlen(event_json),
                        &event_buf, &event_size, &root_type, NULL);
    if (!TEST_CHECK(ret == 0)) {
        return -1;
    }

    ret = flb_gzip_compress(event_buf, event_size,
                            (void **)&compressed_buf, &compressed_size);
    if (!TEST_CHECK(ret == 0)) {
        flb_free(event_buf);
        return -1;
    }
    flb_free(event_buf);

    /* Create temporary msgpack buffer */
    msgpack_packer_init(&pck, sbuf, msgpack_sbuffer_write);

    msgpack_pack_array(&pck, 3);
    msgpack_pack_str_with_body(&pck, tag, strlen(tag));
    msgpack_pack_bin_with_body(&pck, compressed_buf, compressed_size);
    msgpack_pack_map(&pck, 2);
    msgpack_pack_str_with_body(&pck, "compressed", 10);
    msgpack_pack_str_with_body(&pck, "gzip", 4);
    msgpack_pack_str_with_body(&pck, "size", 4);
    msgpack_pack_uint64(&pck, event_size);

    flb_free(compressed_buf);

    return 0;
}

void flb_test_forward_gzip()
{
    struct flb_lib_out_cb cb_data;
    struct test_ctx *ctx;
    flb_sockfd_t fd;
    int ret;
    int num;
    ssize_t w_size;

    char *buf;
    size_t size;

    msgpack_sbuffer sbuf;

    clear_output_num();

    cb_data.cb = cb_check_result_json;
    cb_data.data = "\"test\":\"msg\"";

    ctx = test_ctx_create(&cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
        exit(EXIT_FAILURE);
    }

    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "match", "test",
                         "format", "json",
                         NULL);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    fd = connect_tcp(NULL, -1);
    if (!TEST_CHECK(fd >= 0)) {
        exit(EXIT_FAILURE);
    }

    msgpack_sbuffer_init(&sbuf);
    create_simple_json_gzip(&sbuf);

    w_size = send(fd, sbuf.data, sbuf.size, 0);
    if (!TEST_CHECK(w_size == sbuf.size)) {
        TEST_MSG("failed to send, errno=%d", errno);
        flb_socket_close(fd);
        msgpack_sbuffer_destroy(&sbuf);
        exit(EXIT_FAILURE);
    }

    msgpack_sbuffer_destroy(&sbuf);

    flb_time_msleep(1500);

    num = get_output_num();
    if (!TEST_CHECK(num > 0))  {
        TEST_MSG("no outputs");
    }

    flb_socket_close(fd);
    test_ctx_destroy(ctx);
}


TEST_LIST = {
    {"forward", flb_test_forward},
    {"forward_port", flb_test_forward_port},
    {"tag_prefix", flb_test_tag_prefix},
#ifdef FLB_HAVE_UNIX_SOCKET
    {"unix_path", flb_test_unix_path},
    {"unix_perm", flb_test_unix_perm},
#endif
    {"forward_gzip", flb_test_forward_gzip},
    {NULL, NULL}
};
