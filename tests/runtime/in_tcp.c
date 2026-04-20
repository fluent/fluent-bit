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
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "flb_tests_runtime.h"

#define DEFAULT_IO_TIMEOUT 10
#define DEFAULT_HOST       "127.0.0.1"
#define DEFAULT_PORT       5170

#define TLS_CERTIFICATE_HOSTNAME "leo.vcap.me"
#define TLS_CERTIFICATE_FILENAME FLB_TESTS_DATA_PATH "/data/tls/certificate.pem"
#define TLS_PRIVATE_KEY_FILENAME FLB_TESTS_DATA_PATH "/data/tls/private_key.pem"

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

struct test_log_verifier {
    const char *expected;
    size_t expected_len;
    int records;
    int valid_matches;
};

static void reset_log_verifier(struct test_log_verifier *verifier,
                               const char *expected,
                               size_t expected_len)
{
    pthread_mutex_lock(&result_mutex);
    verifier->expected = expected;
    verifier->expected_len = expected_len;
    verifier->records = 0;
    verifier->valid_matches = 0;
    pthread_mutex_unlock(&result_mutex);
}

static void get_log_verifier(struct test_log_verifier *verifier,
                             int *records,
                             int *valid_matches)
{
    pthread_mutex_lock(&result_mutex);
    *records = verifier->records;
    *valid_matches = verifier->valid_matches;
    pthread_mutex_unlock(&result_mutex);
}

static int cb_count_msgpack(void *record, size_t size, void *data)
{
    msgpack_unpacked result;
    size_t off = 0;

    if (!TEST_CHECK(data != NULL)) {
        flb_error("data is NULL");
    }

    if (!TEST_CHECK(record != NULL)) {
        flb_error("record is NULL");
        return -1;
    }

    if (!TEST_CHECK(size > 0)) {
        flb_error("record size is zero");
        flb_free(record);
        return -1;
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

static int cb_check_large_record_msgpack(void *record, size_t size, void *data)
{
    msgpack_unpacked result;
    msgpack_object root;
    msgpack_object *map;
    msgpack_object_kv *kv;
    size_t off = 0;
    int i;
    struct test_log_verifier *verifier = data;

    if (!TEST_CHECK(verifier != NULL)) {
        flb_error("verifier is NULL");
        if (record != NULL) {
            flb_free(record);
        }
        return -1;
    }

    if (!TEST_CHECK(record != NULL)) {
        flb_error("record is NULL");
        return -1;
    }

    if (!TEST_CHECK(size > 0)) {
        flb_error("record size is zero");
        flb_free(record);
        return -1;
    }

    msgpack_unpacked_init(&result);

    while (msgpack_unpack_next(&result, record, size, &off) == MSGPACK_UNPACK_SUCCESS) {
        root = result.data;
        map = NULL;

        if (root.type == MSGPACK_OBJECT_ARRAY && root.via.array.size == 2) {
            if (root.via.array.ptr[1].type == MSGPACK_OBJECT_MAP) {
                map = &root.via.array.ptr[1];
            }
        }
        else if (root.type == MSGPACK_OBJECT_MAP) {
            map = &root;
        }

        pthread_mutex_lock(&result_mutex);
        verifier->records++;
        pthread_mutex_unlock(&result_mutex);

        if (map == NULL) {
            continue;
        }

        for (i = 0; i < map->via.map.size; i++) {
            kv = &map->via.map.ptr[i];

            if (kv->key.type != MSGPACK_OBJECT_STR) {
                continue;
            }

            if (kv->key.via.str.size != 3 ||
                strncmp(kv->key.via.str.ptr, "log", 3) != 0) {
                continue;
            }

            if (kv->val.type != MSGPACK_OBJECT_STR) {
                continue;
            }

            if (kv->val.via.str.size == verifier->expected_len &&
                memcmp(kv->val.via.str.ptr,
                       verifier->expected,
                       verifier->expected_len) == 0) {
                pthread_mutex_lock(&result_mutex);
                verifier->valid_matches++;
                pthread_mutex_unlock(&result_mutex);
            }
        }
    }

    msgpack_unpacked_destroy(&result);
    flb_free(record);

    return 0;
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
    i_ffd = flb_input(ctx->flb, (char *) "tcp", NULL);
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

void flb_test_tcp()
{
    struct flb_lib_out_cb cb_data;
    struct test_ctx *ctx;
    flb_sockfd_t fd;
    int ret;
    int num;
    ssize_t w_size;

    char *buf = "{\"test\":\"msg\"}";
    size_t size = strlen(buf);

    clear_output_num();

    cb_data.cb = cb_check_result_json;
    cb_data.data = "\"test\":\"msg\"";

    ctx = test_ctx_create(&cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
        exit(EXIT_FAILURE);
    }

    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "match", "*",
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

    w_size = send(fd, buf, size, 0);
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

void flb_test_tcp_with_source_address()
{
    struct flb_lib_out_cb cb_data;
    struct test_ctx *ctx;
    flb_sockfd_t fd;
    int ret;
    int num;
    ssize_t w_size;

    char *buf = "{\"test\":\"msg\"}";
    size_t size = strlen(buf);

    clear_output_num();

    cb_data.cb = cb_check_result_json;
    cb_data.data = "\"test\":\"msg\",\"source_host\":\"tcp://";

    ctx = test_ctx_create(&cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
        exit(EXIT_FAILURE);
    }

    ret = flb_input_set(ctx->flb, ctx->i_ffd,
                        "source_address_key", "source_host",
                        NULL);
    TEST_CHECK(ret == 0);

    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "match", "*",
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

    w_size = send(fd, buf, size, 0);
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

void flb_test_tcp_with_tls()
{
    struct flb_connection *client_connection;
    struct flb_upstream   *upstream;
    struct flb_lib_out_cb  cb_data;
    size_t                 sent;
    struct test_ctx       *ctx;
    int                    ret;
    int                    num;
    struct flb_tls        *tls;

    char *buf = "{\"test\":\"msg\"}";
    size_t size = strlen(buf);

    clear_output_num();

    cb_data.cb = cb_check_result_json;
    cb_data.data = "\"test\":\"msg\"";

    ctx = test_ctx_create(&cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
        exit(EXIT_FAILURE);
    }

    ret = flb_input_set(ctx->flb, ctx->i_ffd,
                        "tls",          "on",
                        "tls.verify",   "no",
                        "tls.vhost",    TLS_CERTIFICATE_HOSTNAME,
                        "tls.crt_file", TLS_CERTIFICATE_FILENAME,
                        "tls.key_file", TLS_PRIVATE_KEY_FILENAME,
                        NULL);
    TEST_CHECK(ret == 0);

    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "match", "*",
                         "format", "json",
                         NULL);
    TEST_CHECK(ret == 0);

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    ret = flb_tls_init();
    TEST_CHECK(ret == 0);

    tls = flb_tls_create(FLB_TLS_CLIENT_MODE,
                         FLB_FALSE,
                         FLB_TRUE,
                         TLS_CERTIFICATE_HOSTNAME,
                         NULL,
                         NULL,
                         NULL,
                         NULL,
                         NULL);

    TEST_CHECK(tls != NULL);

    upstream = flb_upstream_create(ctx->flb->config,
                                   DEFAULT_HOST,
                                   DEFAULT_PORT,
                                   FLB_IO_TCP | FLB_IO_TLS,
                                   tls);

    TEST_CHECK(upstream != NULL);

    flb_stream_disable_async_mode(&upstream->base);

    upstream->base.net.io_timeout = DEFAULT_IO_TIMEOUT;

    client_connection = flb_upstream_conn_get(upstream);

    TEST_CHECK(client_connection != NULL);

    if (client_connection != NULL) {
        ret = flb_io_net_write(client_connection,
                               (void *) buf,
                                size,
                                &sent);

        TEST_CHECK(ret > 0);

        /* waiting to flush */
        flb_time_msleep(1500);
    }

    num = get_output_num();

    if (!TEST_CHECK(num > 0))  {
        TEST_MSG("no outputs");
    }

    sleep(1);

    flb_stop(ctx->flb);
    flb_upstream_destroy(upstream);
    flb_tls_destroy(tls);
    flb_destroy(ctx->flb);
    flb_free(ctx);
}

void flb_test_format_none()
{
    struct flb_lib_out_cb cb_data;
    struct test_ctx *ctx;
    flb_sockfd_t fd;
    int ret;
    int num;
    ssize_t w_size;

    char *buf = "message\n";
    size_t size = strlen(buf);

    clear_output_num();

    cb_data.cb = cb_check_result_json;
    cb_data.data = "\"log\":\"message\"";

    ctx = test_ctx_create(&cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
        exit(EXIT_FAILURE);
    }

    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "match", "*",
                         "format", "json",
                         NULL);
    TEST_CHECK(ret == 0);

    ret = flb_input_set(ctx->flb, ctx->i_ffd,
                        "format", "none",
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

    w_size = send(fd, buf, size, 0);
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

void flb_test_format_none_separator()
{
    struct flb_lib_out_cb cb_data;
    struct test_ctx *ctx;
    flb_sockfd_t fd;
    int ret;
    int num;
    ssize_t w_size;

    char *buf = "message:message:";
    size_t size = strlen(buf);

    clear_output_num();

    cb_data.cb = cb_check_result_json;
    cb_data.data = "\"log\":\"message\"";

    ctx = test_ctx_create(&cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
        exit(EXIT_FAILURE);
    }

    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "match", "*",
                         "format", "json",
                         NULL);
    TEST_CHECK(ret == 0);

    ret = flb_input_set(ctx->flb, ctx->i_ffd,
                        "format", "none",
                        "separator", ":",
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

    w_size = send(fd, buf, size, 0);
    if (!TEST_CHECK(w_size == size)) {
        TEST_MSG("failed to send, errno=%d", errno);
        flb_socket_close(fd);
        exit(EXIT_FAILURE);
    }

    /* waiting to flush */
    flb_time_msleep(1500);

    num = get_output_num();
    if (!TEST_CHECK(num == 2))  {
        TEST_MSG("no outputs");
    }

    flb_socket_close(fd);
    test_ctx_destroy(ctx);
}

void flb_test_format_none_with_source_address()
{
    struct flb_lib_out_cb cb_data;
    struct test_ctx *ctx;
    flb_sockfd_t fd;
    int ret;
    int num;
    ssize_t w_size;
    char *buf = "message\n";
    size_t size = strlen(buf);
    clear_output_num();
    cb_data.cb = cb_check_result_json;
    cb_data.data = "\"log\":\"message\",\"source_host\":\"tcp://";
    ctx = test_ctx_create(&cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
        exit(EXIT_FAILURE);
    }
    ret = flb_input_set(ctx->flb, ctx->i_ffd,
                        "source_address_key", "source_host",
                        NULL);
    TEST_CHECK(ret == 0);
    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "match", "*",
                         "format", "json",
                         NULL);
    TEST_CHECK(ret == 0);
    ret = flb_input_set(ctx->flb, ctx->i_ffd,
                        "format", "none",
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
    w_size = send(fd, buf, size, 0);
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

/*
 * Ingest 64k records.
 * https://github.com/fluent/fluent-bit/issues/5336
 */
void flb_test_issue_5336()
{
    struct flb_lib_out_cb cb_data;
    struct test_ctx *ctx;
    flb_sockfd_t fd;
    int ret;
    int num;
    ssize_t w_size;
    int not_used;
    int i;
    int count = 65535;

    char *buf = "{\"test\":\"msg\"}";
    size_t size = strlen(buf);

    clear_output_num();

    cb_data.cb = cb_count_msgpack;
    cb_data.data = &not_used;

    ctx = test_ctx_create(&cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
        exit(EXIT_FAILURE);
    }

    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "match", "*",
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

    for (i=0; i<count; i++) {
        w_size = send(fd, buf, size, 0);
        if (!TEST_CHECK(w_size == size)) {
            TEST_MSG("failed to send, count=%d errno=%d",i, errno);
            flb_socket_close(fd);
            exit(EXIT_FAILURE);
        }
    }

    /* waiting to flush */
    flb_time_msleep(2500);

    num = get_output_num();
    if (!TEST_CHECK(num == count))  {
        TEST_MSG("got %d, expected: %d", num, count);
    }

    flb_socket_close(fd);
    test_ctx_destroy(ctx);
}


void flb_test_format_none_large_record()
{
    struct flb_lib_out_cb cb_data;
    struct test_ctx *ctx;
    flb_sockfd_t fd;
    int ret;
    int records;
    int valid_matches;
    ssize_t w_size;
    struct test_log_verifier verifier;
    size_t payload_size = 131072;
    char *buf;

    clear_output_num();

    buf = flb_malloc(payload_size + 3);
    if (!TEST_CHECK(buf != NULL)) {
        TEST_MSG("failed to allocate test payload");
        exit(EXIT_FAILURE);
    }

    memset(buf, 'a', payload_size);
    buf[payload_size] = ':';
    buf[payload_size + 1] = ';';
    buf[payload_size + 2] = '\0';

    reset_log_verifier(&verifier, buf, payload_size + 1);

    cb_data.cb = cb_check_large_record_msgpack;
    cb_data.data = &verifier;

    ctx = test_ctx_create(&cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
        flb_free(buf);
        exit(EXIT_FAILURE);
    }

    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "match", "*",
                         NULL);
    TEST_CHECK(ret == 0);

    ret = flb_input_set(ctx->flb, ctx->i_ffd,
                        "format", "none",
                        "separator", ";",
                        "chunk_size", "64KB",
                        "buffer_size", "256KB",
                        NULL);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    fd = connect_tcp(NULL, -1);
    if (!TEST_CHECK(fd >= 0)) {
        flb_free(buf);
        exit(EXIT_FAILURE);
    }

    w_size = 0;
    while ((size_t) w_size < payload_size + 2) {
        ret = send(fd,
                   buf + w_size,
                   (payload_size + 2) - (size_t) w_size,
                   0);

        if (!TEST_CHECK(ret > 0)) {
            TEST_MSG("failed to send large payload, errno=%d", errno);
            flb_socket_close(fd);
            flb_free(buf);
            exit(EXIT_FAILURE);
        }

        w_size += ret;
    }

    TEST_CHECK(w_size == (ssize_t) (payload_size + 2));

    flb_time_msleep(1500);

    get_log_verifier(&verifier, &records, &valid_matches);

    if (!TEST_CHECK(records == 1)) {
        TEST_MSG("got %d outputs, expected 1", records);
    }

    if (!TEST_CHECK(valid_matches == 1)) {
        TEST_MSG("matched payload count=%d, expected 1", valid_matches);
    }

    flb_socket_close(fd);
    test_ctx_destroy(ctx);
    flb_free(buf);
}

TEST_LIST = {
    {"tcp", flb_test_tcp},
    {"tcp_with_source_address", flb_test_tcp_with_source_address},
    {"tcp_with_tls", flb_test_tcp_with_tls},
    {"format_none", flb_test_format_none},
    {"format_none_separator", flb_test_format_none_separator},
    {"format_none_with_source_address", flb_test_format_none_with_source_address},
    {"format_none_large_record", flb_test_format_none_large_record},
    {"65535_records_issue_5336", flb_test_issue_5336},
    {NULL, NULL}
};

