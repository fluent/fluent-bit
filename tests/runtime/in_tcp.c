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
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_input_ingest.h>
#include <fluent-bit/flb_sds.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "flb_tests_runtime.h"

#define DPATH            FLB_TESTS_DATA_PATH "/data/common"
#define DEFAULT_IO_TIMEOUT 10
#define DEFAULT_HOST       "127.0.0.1"
#define DEFAULT_PORT       5170

#define TLS_CERTIFICATE_HOSTNAME "leo.vcap.me"
#define TLS_CERTIFICATE_FILENAME FLB_TESTS_DATA_PATH "/data/tls/certificate.pem"
#define TLS_PRIVATE_KEY_FILENAME FLB_TESTS_DATA_PATH "/data/tls/private_key.pem"

#define TLS_CA_FILE                  FLB_TESTS_DATA_PATH "/data/tls/ca_certificate.pem"
#define TLS_CLIENT_CERT_FILE         FLB_TESTS_DATA_PATH "/data/tls/client_certificate.pem"
#define TLS_CLIENT_KEY_FILE          FLB_TESTS_DATA_PATH "/data/tls/client_private_key.pem"
#define TLS_CLIENT_CERT_REVOKED_FILE FLB_TESTS_DATA_PATH "/data/tls/client_certificate_revoked.pem"
#define TLS_CLIENT_KEY_REVOKED_FILE  FLB_TESTS_DATA_PATH "/data/tls/client_private_key_revoked.pem"
#define TLS_CRL_FILE                 FLB_TESTS_DATA_PATH "/data/tls/crl.pem"

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
                    "Parsers_File", DPATH "/parsers.conf",
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

/*
 * The tcp input acts as a TLS server that verifies the client certificate
 * against a CRL (tls.crl_file). A valid client must be accepted (records
 * ingested); a revoked client must be rejected (no records).
 */
static void run_tls_crl_client(const char *client_cert, const char *client_key,
                               int expect_output)
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
                        "tls.verify",   "on",
                        "tls.vhost",    TLS_CERTIFICATE_HOSTNAME,
                        "tls.crt_file", TLS_CERTIFICATE_FILENAME,
                        "tls.key_file", TLS_PRIVATE_KEY_FILENAME,
                        "tls.ca_file",  TLS_CA_FILE,
                        "tls.crl_file", TLS_CRL_FILE,
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

    /* Client presents the certificate under test */
    tls = flb_tls_create(FLB_TLS_CLIENT_MODE,
                         FLB_FALSE,
                         FLB_TRUE,
                         TLS_CERTIFICATE_HOSTNAME,
                         NULL,
                         TLS_CA_FILE,
                         client_cert,
                         client_key,
                         NULL);

    TEST_CHECK(tls != NULL);

    /*
     * Force TLS 1.2 so the client certificate is verified during the
     * handshake. Under TLS 1.3 the client is authenticated after the
     * handshake completes (post-handshake auth).
     */
    ret = flb_tls_set_minmax_proto(tls, "TLSv1.2", "TLSv1.2");
    TEST_CHECK(ret == 0);

    upstream = flb_upstream_create(ctx->flb->config,
                                   DEFAULT_HOST,
                                   DEFAULT_PORT,
                                   FLB_IO_TCP | FLB_IO_TLS,
                                   tls);

    TEST_CHECK(upstream != NULL);

    flb_stream_disable_async_mode(&upstream->base);

    upstream->base.net.io_timeout = DEFAULT_IO_TIMEOUT;

    /* Connecting performs the TLS handshake (and client-cert verification) */
    client_connection = flb_upstream_conn_get(upstream);

    if (client_connection != NULL) {
        ret = flb_io_net_write(client_connection,
                               (void *) buf,
                                size,
                                &sent);
        (void) ret;

        /* waiting to flush */
        flb_time_msleep(1500);
    }

    num = get_output_num();

    if (expect_output) {
        if (!TEST_CHECK(num > 0)) {
            TEST_MSG("valid client: expected ingested records, got %d", num);
        }
    }
    else {
        if (!TEST_CHECK(num == 0)) {
            TEST_MSG("revoked client: expected rejection, but %d records ingested",
                     num);
        }
    }

    sleep(1);

    flb_stop(ctx->flb);
    flb_upstream_destroy(upstream);
    flb_tls_destroy(tls);
    flb_destroy(ctx->flb);
    flb_free(ctx);
}

void flb_test_tcp_tls_crl_valid_client()
{
    run_tls_crl_client(TLS_CLIENT_CERT_FILE, TLS_CLIENT_KEY_FILE, FLB_TRUE);
}

void flb_test_tcp_tls_crl_revoked_client()
{
    run_tls_crl_client(TLS_CLIENT_CERT_REVOKED_FILE, TLS_CLIENT_KEY_REVOKED_FILE,
                       FLB_FALSE);
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

#ifdef FLB_HAVE_PARSER
void flb_test_format_none_with_parser()
{
    struct flb_lib_out_cb cb_data;
    struct test_ctx *ctx;
    flb_sockfd_t fd;
    int ret;
    int num;
    ssize_t w_size;
    char *buf = "{\"test\":\"msg\"}\n";
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

    ret = flb_input_set(ctx->flb, ctx->i_ffd,
                        "format", "none",
                        "parser", "json",
                        NULL);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

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

    flb_time_msleep(1500);

    num = get_output_num();
    if (!TEST_CHECK(num > 0)) {
        TEST_MSG("no outputs");
    }

    flb_socket_close(fd);
    test_ctx_destroy(ctx);
}

void flb_test_format_none_with_unknown_parser()
{
    struct flb_lib_out_cb cb_data;
    struct test_ctx *ctx;
    int ret;

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

    ret = flb_input_set(ctx->flb, ctx->i_ffd,
                        "format", "none",
                        "parser", "nonexistent_parser",
                        NULL);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx->flb);
    if (!TEST_CHECK(ret != 0)) {
        TEST_MSG("flb_start unexpectedly succeeded with unknown parser");
    }

    /* flb_start failed, so there is no running engine to stop. */
    flb_destroy(ctx->flb);
    flb_free(ctx);
}
#endif

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

/*
 * External source mode
 * ====================
 * The host program submits the bytes a socket would deliver. The scenarios
 * below run the same chunks through a socket and through the external entry
 * point and compare the records.
 */
static flb_sds_t collected_records = NULL;
static int collected_count = 0;

static void collected_release()
{
    pthread_mutex_lock(&result_mutex);
    if (collected_records != NULL) {
        flb_sds_destroy(collected_records);
        collected_records = NULL;
    }
    pthread_mutex_unlock(&result_mutex);
}

static void collected_reset()
{
    pthread_mutex_lock(&result_mutex);
    if (collected_records != NULL) {
        flb_sds_destroy(collected_records);
    }
    collected_records = flb_sds_create_size(256);
    collected_count = 0;
    pthread_mutex_unlock(&result_mutex);
}

static int collected_wait(int expected)
{
    int i;
    int count;

    for (i = 0; i < 400; i++) {
        pthread_mutex_lock(&result_mutex);
        count = collected_count;
        pthread_mutex_unlock(&result_mutex);

        if (count >= expected) {
            return count;
        }
        flb_time_msleep(10);
    }

    return count;
}

/* Keep the body of every record, one JSON document per line */
static int cb_collect_records(void *record, size_t size, void *data)
{
    char *json;
    size_t off = 0;
    msgpack_unpacked result;
    msgpack_object root;

    (void) data;

    msgpack_unpacked_init(&result);
    while (msgpack_unpack_next(&result, record, size, &off) == MSGPACK_UNPACK_SUCCESS) {
        root = result.data;
        if (root.type != MSGPACK_OBJECT_ARRAY || root.via.array.size != 2) {
            continue;
        }

        json = flb_msgpack_to_json_str(256, &root.via.array.ptr[1], FLB_TRUE);
        if (json == NULL) {
            continue;
        }

        pthread_mutex_lock(&result_mutex);
        flb_sds_cat_safe(&collected_records, json, strlen(json));
        flb_sds_cat_safe(&collected_records, "\n", 1);
        collected_count++;
        pthread_mutex_unlock(&result_mutex);

        flb_free(json);
    }
    msgpack_unpacked_destroy(&result);

    flb_free(record);

    return 0;
}

static struct flb_input_instance *external_instance_get(struct test_ctx *ctx)
{
    struct mk_list *head;
    struct flb_input_instance *ins;

    mk_list_foreach(head, &ctx->flb->config->inputs) {
        ins = mk_list_entry(head, struct flb_input_instance, _head);
        if (ins->id == ctx->i_ffd) {
            return ins;
        }
    }

    return NULL;
}

static int external_wait_drained(struct flb_input_instance *ins)
{
    int i;
    size_t pending;

    for (i = 0; i < 400; i++) {
        pthread_mutex_lock(&ins->ingress_queue_lock);
        pending = ins->ingress_queue_pending_events;
        pthread_mutex_unlock(&ins->ingress_queue_lock);

        if (pending == 0) {
            return 0;
        }
        flb_time_msleep(5);
    }

    return -1;
}

/* Submit and wait: every submission is seen by the plugin on its own */
static int external_submit(struct flb_input_instance *ins,
                           const char *data, size_t size)
{
    int i;
    int ret;

    ret = FLB_INPUT_INGEST_BUSY;
    for (i = 0; i < 200 && ret == FLB_INPUT_INGEST_BUSY; i++) {
        ret = flb_input_ingest_submit(ins, FLB_INPUT_INGEST_STREAM_BYTES,
                                      data, size, NULL, NULL, NULL);
        if (ret == FLB_INPUT_INGEST_BUSY) {
            flb_time_msleep(5);
        }
    }

    if (ret == FLB_INPUT_INGEST_OK) {
        external_wait_drained(ins);
    }

    return ret;
}

struct stream_scenario {
    const char *format;
    const char *separator;
    const char **chunks;       /* NULL terminated */
    int expected_records;
};

#define SCENARIO_NATIVE         0   /* socket, one send per chunk          */
#define SCENARIO_EXTERNAL       1   /* one submission per chunk            */
#define SCENARIO_EXTERNAL_BYTES 2   /* one submission per byte             */
#define SCENARIO_EXTERNAL_WHOLE 3   /* every chunk in a single submission  */

/* Run a scenario and return the collected records; the caller owns them */
static flb_sds_t scenario_run(struct stream_scenario *scenario, int mode)
{
    int i;
    int ret;
    size_t j;
    size_t length;
    flb_sockfd_t fd;
    flb_sds_t whole;
    flb_sds_t output;
    struct flb_lib_out_cb cb_data;
    struct test_ctx *ctx;
    struct flb_input_instance *ins;

    collected_reset();

    cb_data.cb = cb_collect_records;
    cb_data.data = NULL;

    ctx = test_ctx_create(&cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        return NULL;
    }

    ret = flb_output_set(ctx->flb, ctx->o_ffd, "match", "*", NULL);
    TEST_CHECK(ret == 0);

    ret = flb_input_set(ctx->flb, ctx->i_ffd, "format", scenario->format, NULL);
    TEST_CHECK(ret == 0);

    if (scenario->separator != NULL) {
        ret = flb_input_set(ctx->flb, ctx->i_ffd,
                            "separator", scenario->separator, NULL);
        TEST_CHECK(ret == 0);
    }

    if (mode != SCENARIO_NATIVE) {
        ret = flb_input_set(ctx->flb, ctx->i_ffd, "source.mode", "external", NULL);
        TEST_CHECK(ret == 0);
    }

    ret = flb_start(ctx->flb);
    if (!TEST_CHECK(ret == 0)) {
        flb_destroy(ctx->flb);
        flb_free(ctx);
        return NULL;
    }

    ins = external_instance_get(ctx);
    TEST_CHECK(ins != NULL);

    if (mode == SCENARIO_NATIVE) {
        fd = connect_tcp(NULL, -1);
        if (TEST_CHECK(fd >= 0)) {
            for (i = 0; scenario->chunks[i] != NULL; i++) {
                length = strlen(scenario->chunks[i]);
                ret = send(fd, scenario->chunks[i], length, 0);
                TEST_CHECK(ret == (int) length);
                /* keep the read boundaries: one chunk per read */
                flb_time_msleep(150);
            }
        }
    }
    else if (mode == SCENARIO_EXTERNAL_WHOLE) {
        fd = -1;
        whole = flb_sds_create_size(256);
        for (i = 0; scenario->chunks[i] != NULL; i++) {
            flb_sds_cat_safe(&whole, scenario->chunks[i], strlen(scenario->chunks[i]));
        }
        ret = external_submit(ins, whole, flb_sds_len(whole));
        TEST_CHECK(ret == FLB_INPUT_INGEST_OK);
        flb_sds_destroy(whole);
    }
    else {
        fd = -1;
        for (i = 0; scenario->chunks[i] != NULL; i++) {
            length = strlen(scenario->chunks[i]);
            if (mode == SCENARIO_EXTERNAL_BYTES) {
                for (j = 0; j < length; j++) {
                    ret = external_submit(ins, scenario->chunks[i] + j, 1);
                    TEST_CHECK(ret == FLB_INPUT_INGEST_OK);
                }
            }
            else {
                ret = external_submit(ins, scenario->chunks[i], length);
                TEST_CHECK(ret == FLB_INPUT_INGEST_OK);
            }
        }
    }

    ret = collected_wait(scenario->expected_records);
    if (!TEST_CHECK(ret == scenario->expected_records)) {
        TEST_MSG("mode=%d records=%d expected=%d", mode, ret,
                 scenario->expected_records);
    }

    /* Nothing else may show up after the expected records */
    flb_time_msleep(300);

    if (fd >= 0) {
        flb_socket_close(fd);
    }

    flb_stop(ctx->flb);
    flb_destroy(ctx->flb);
    flb_free(ctx);

    pthread_mutex_lock(&result_mutex);
    output = collected_records;
    collected_records = NULL;
    if (!TEST_CHECK(collected_count == scenario->expected_records)) {
        TEST_MSG("mode=%d final records=%d expected=%d", mode, collected_count,
                 scenario->expected_records);
    }
    pthread_mutex_unlock(&result_mutex);

    return output;
}

/* The socket path is the reference for every way of submitting the chunks */
static void scenario_compare(struct stream_scenario *scenario, int whole_is_equal)
{
    int mode;
    flb_sds_t native;
    flb_sds_t external;

    native = scenario_run(scenario, SCENARIO_NATIVE);
    if (!TEST_CHECK(native != NULL)) {
        return;
    }

    for (mode = SCENARIO_EXTERNAL; mode <= SCENARIO_EXTERNAL_WHOLE; mode++) {
        if (mode != SCENARIO_EXTERNAL && whole_is_equal == FLB_FALSE) {
            continue;
        }

        external = scenario_run(scenario, mode);
        if (!TEST_CHECK(external != NULL)) {
            continue;
        }

        if (!TEST_CHECK(strcmp(native, external) == 0)) {
            TEST_MSG("mode=%d\nnative:\n%s\nexternal:\n%s", mode, native, external);
        }
        flb_sds_destroy(external);
    }

    flb_sds_destroy(native);
}

void flb_test_external_json_parity()
{
    const char *chunks[] = {
        "{\"key\":\"value\",\"n\":1}",
        "{\"text\":\"h\xc3\xa9llo w\xc3\xb6rld \xe2\x82\xac\"}\n{\"nested\":{\"a\":[1,2,3]}}",
        "\r\n{\"last\":true}",
        NULL
    };
    struct stream_scenario scenario = { "json", NULL, chunks, 4 };

    scenario_compare(&scenario, FLB_TRUE);
}

void flb_test_external_none_parity()
{
    const char *chunks[] = {
        "first line\nsecond l",
        "ine with \xe2\x82\xac and \xc3\xa9\n",
        "third\nfourth\n",
        NULL
    };
    struct stream_scenario scenario = { "none", NULL, chunks, 4 };

    scenario_compare(&scenario, FLB_TRUE);
}

void flb_test_external_none_separator_parity()
{
    const char *chunks[] = {
        "alpha;;beta;;gam",
        "ma;;delta;;",
        NULL
    };
    struct stream_scenario scenario = { "none", ";;", chunks, 4 };

    scenario_compare(&scenario, FLB_TRUE);
}

/*
 * Invalid JSON resets the buffer and the parser and the stream stays usable.
 * What is dropped depends on the read boundaries, so only the submission
 * that keeps them is compared with the socket.
 */
void flb_test_external_invalid_json_parity()
{
    const char *chunks[] = {
        "{\"before\":1}",
        "{\"broken\": ]]]}",
        "{\"after\":2}",
        NULL
    };
    struct stream_scenario scenario = { "json", NULL, chunks, 2 };

    scenario_compare(&scenario, FLB_FALSE);
}

void flb_test_external_buffer_limits()
{
    int i;
    int ret;
    int count;
    size_t length;
    char *buf;
    char line[64];
    flb_sds_t payload;
    struct flb_lib_out_cb cb_data;
    struct test_ctx *ctx;
    struct flb_input_instance *ins;

    collected_reset();

    cb_data.cb = cb_collect_records;
    cb_data.data = NULL;

    ctx = test_ctx_create(&cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        exit(EXIT_FAILURE);
    }

    ret = flb_output_set(ctx->flb, ctx->o_ffd, "match", "*", NULL);
    TEST_CHECK(ret == 0);

    ret = flb_input_set(ctx->flb, ctx->i_ffd,
                        "source.mode", "external",
                        "format", "none",
                        "chunk_size", "1",
                        "buffer_size", "4",
                        NULL);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    ins = external_instance_get(ctx);
    TEST_CHECK(ins != NULL);

    /* One submission far larger than Buffer_Size, made of small records */
    payload = flb_sds_create_size(128 * 1024);
    for (i = 0; i < 4000; i++) {
        length = snprintf(line, sizeof(line), "record number %d\n", i);
        flb_sds_cat_safe(&payload, line, length);
    }
    TEST_CHECK(flb_sds_len(payload) > 4096 * 10);

    ret = external_submit(ins, payload, flb_sds_len(payload));
    TEST_CHECK(ret == FLB_INPUT_INGEST_OK);
    flb_sds_destroy(payload);

    count = collected_wait(4000);
    if (!TEST_CHECK(count == 4000)) {
        TEST_MSG("records=%d expected=4000", count);
    }

    /* A partial record stays buffered across submissions */
    ret = external_submit(ins, "partial ", 8);
    TEST_CHECK(ret == FLB_INPUT_INGEST_OK);
    ret = external_submit(ins, "record\n", 7);
    TEST_CHECK(ret == FLB_INPUT_INGEST_OK);
    count = collected_wait(4001);
    TEST_CHECK(count == 4001);
    pthread_mutex_lock(&result_mutex);
    TEST_CHECK(strstr(collected_records, "{\"log\":\"partial record\"}") != NULL);
    pthread_mutex_unlock(&result_mutex);

    /* A single record larger than Buffer_Size ends the stream */
    buf = flb_malloc(8192);
    TEST_CHECK(buf != NULL);
    memset(buf, 'z', 8192);

    ret = flb_input_ingest_submit(ins, FLB_INPUT_INGEST_STREAM_BYTES,
                                  buf, 8192, NULL, NULL, NULL);
    TEST_CHECK(ret == FLB_INPUT_INGEST_OK);
    flb_free(buf);

    ret = FLB_INPUT_INGEST_OK;
    for (i = 0; i < 200 && ret != FLB_INPUT_INGEST_FAILED; i++) {
        ret = flb_input_ingest_submit(ins, FLB_INPUT_INGEST_STREAM_BYTES,
                                      "later\n", 6, NULL, NULL, NULL);
        if (ret != FLB_INPUT_INGEST_FAILED) {
            flb_time_msleep(10);
        }
    }
    TEST_CHECK(ret == FLB_INPUT_INGEST_FAILED);

    flb_time_msleep(300);
    pthread_mutex_lock(&result_mutex);
    TEST_CHECK(strstr(collected_records, "later") == NULL);
    TEST_CHECK(strstr(collected_records, "zzzz") == NULL);
    pthread_mutex_unlock(&result_mutex);

    flb_stop(ctx->flb);
    flb_destroy(ctx->flb);
    flb_free(ctx);    collected_release();
}

/* Partial data retained when the engine stops is discarded */
void flb_test_external_stop_with_partial_data()
{
    int ret;
    struct flb_lib_out_cb cb_data;
    struct test_ctx *ctx;
    struct flb_input_instance *ins;

    collected_reset();

    cb_data.cb = cb_collect_records;
    cb_data.data = NULL;

    ctx = test_ctx_create(&cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        exit(EXIT_FAILURE);
    }

    flb_output_set(ctx->flb, ctx->o_ffd, "match", "*", NULL);
    ret = flb_input_set(ctx->flb, ctx->i_ffd, "source.mode", "external", NULL);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    ins = external_instance_get(ctx);
    TEST_CHECK(ins != NULL);

    ret = external_submit(ins, "{\"complete\":1}{\"partial\":", 25);
    TEST_CHECK(ret == FLB_INPUT_INGEST_OK);
    TEST_CHECK(collected_wait(1) == 1);

    flb_stop(ctx->flb);
    flb_destroy(ctx->flb);
    flb_free(ctx);

    TEST_CHECK(collected_count == 1);    collected_release();
}

static void external_expect_start_failure(const char *key, const char *value)
{
    int ret;
    struct flb_lib_out_cb cb_data;
    struct test_ctx *ctx;

    cb_data.cb = cb_collect_records;
    cb_data.data = NULL;

    ctx = test_ctx_create(&cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        exit(EXIT_FAILURE);
    }

    flb_service_set(ctx->flb, "Log_Level", "off", NULL);
    flb_output_set(ctx->flb, ctx->o_ffd, "match", "*", NULL);
    ret = flb_input_set(ctx->flb, ctx->i_ffd,
                        "source.mode", "external",
                        key, value,
                        NULL);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx->flb);
    if (!TEST_CHECK(ret != 0)) {
        TEST_MSG("'%s' was accepted in external mode", key);
        flb_stop(ctx->flb);
    }

    flb_destroy(ctx->flb);
    flb_free(ctx);
}

void flb_test_external_rejected_options()
{
    external_expect_start_failure("workers", "2");
    external_expect_start_failure("source_address_key", "source");
    external_expect_start_failure("port", "5171");
    external_expect_start_failure("listen", "127.0.0.1");
    external_expect_start_failure("threaded", "true");
#ifdef FLB_HAVE_TLS
    external_expect_start_failure("tls", "on");
#endif
}

/* A regular instance does not take submissions */
void flb_test_external_native_mode_refuses()
{
    int ret;
    struct flb_lib_out_cb cb_data;
    struct test_ctx *ctx;
    struct flb_input_instance *ins;

    cb_data.cb = cb_collect_records;
    cb_data.data = NULL;

    ctx = test_ctx_create(&cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        exit(EXIT_FAILURE);
    }

    flb_output_set(ctx->flb, ctx->o_ffd, "match", "*", NULL);
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    ins = external_instance_get(ctx);
    TEST_CHECK(ins != NULL);

    ret = flb_input_ingest_submit(ins, FLB_INPUT_INGEST_STREAM_BYTES,
                                  "{}", 2, NULL, NULL, NULL);
    TEST_CHECK(ret == FLB_INPUT_INGEST_NOT_SUPPORTED);

    flb_stop(ctx->flb);
    flb_destroy(ctx->flb);
    flb_free(ctx);
}

TEST_LIST = {
    {"tcp", flb_test_tcp},
    {"tcp_with_source_address", flb_test_tcp_with_source_address},
    {"tcp_with_tls", flb_test_tcp_with_tls},
    {"tcp_with_tls_crl_valid_client", flb_test_tcp_tls_crl_valid_client},
    {"tcp_with_tls_crl_revoked_client", flb_test_tcp_tls_crl_revoked_client},
    {"format_none", flb_test_format_none},
    {"format_none_separator", flb_test_format_none_separator},
#ifdef FLB_HAVE_PARSER
    {"format_none_with_parser", flb_test_format_none_with_parser},
    {"format_none_with_unknown_parser", flb_test_format_none_with_unknown_parser},
#endif
    {"format_none_large_record", flb_test_format_none_large_record},
    {"65535_records_issue_5336", flb_test_issue_5336},
    {"external_json_parity", flb_test_external_json_parity},
    {"external_none_parity", flb_test_external_none_parity},
    {"external_none_separator_parity", flb_test_external_none_separator_parity},
    {"external_invalid_json_parity", flb_test_external_invalid_json_parity},
    {"external_buffer_limits", flb_test_external_buffer_limits},
    {"external_stop_with_partial_data", flb_test_external_stop_with_partial_data},
    {"external_rejected_options", flb_test_external_rejected_options},
    {"external_native_mode_refuses", flb_test_external_native_mode_refuses},
    {NULL, NULL}
};
