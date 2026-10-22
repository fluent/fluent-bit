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
#include <fluent-bit/flb_compat.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_socket.h>
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
    flb_free(record);
    return 0;
}

static struct test_ctx *test_ctx_create(struct flb_lib_out_cb *data)
{
    int i_ffd;
    int o_ffd;
    int ret;
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
    i_ffd = flb_input(ctx->flb, (char *) "mqtt", NULL);
    TEST_CHECK(i_ffd >= 0);
    ctx->i_ffd = i_ffd;

    /* Output */
    o_ffd = flb_output(ctx->flb, (char *) "lib", (void *) data);
    ctx->o_ffd = o_ffd;
    ret = flb_output_set(ctx->flb, ctx->o_ffd,
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

#define DEFAULT_HOST "127.0.0.1"
#define DEFAULT_PORT 1883
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

/* http://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.html#_Toc398718028 */
int send_CONNECT(flb_sockfd_t fd)
{
    ssize_t w_size;
    char buf[] = {0x10, 0xa,
        0x0,0x4, 'M', 'Q', 'T', 'T', 0x4, 0xce, 0x0, 0xa
    };

    w_size = send(fd, buf, sizeof(buf), 0);
    if (!TEST_CHECK(w_size == sizeof(buf))) {
        TEST_MSG("failed to send CONNECT, errno=%d", errno);
        return -1;
    }
    return 0;
}

/* http://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.html#_Toc398718033 */
int recv_CONNACK(flb_sockfd_t fd)
{
    ssize_t r_size;
    char buf[1024] = {0};

    r_size = recv(fd, &buf[0], sizeof(buf), 0);
    if (!TEST_CHECK(r_size != -1)) {
        TEST_MSG("failed to recv CONNACK, errno=%d", errno);
        return -1;
    }
    return 0;
}

/* http://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.html#_Toc398718037 */
int send_PUBLISH(flb_sockfd_t fd, const char *payload, size_t payload_size)
{
    ssize_t w_size;
    char buf[1024] = {0};

    buf[0] = 0x30;

    buf[2] = 0x0;
    buf[3] = 0x3;
    buf[4] = 'a';
    buf[5] = '/';
    buf[6] = 'b';
    /* No packet id since QoS Level is 0 */
    buf[1] = 5 + (char)payload_size;

    if (!TEST_CHECK(sizeof(buf) >= buf[1])) {
        TEST_MSG("payload is too long");
        return -1;
    }

    strncpy(&buf[7], payload, payload_size);

    w_size = send(fd, buf, sizeof(buf), 0);
    if (!TEST_CHECK(w_size == sizeof(buf))) {
        TEST_MSG("failed to send PUBLISH, errno=%d", errno);
        return -1;
    }
    return 0;
}

void flb_test_mqtt()
{
    struct flb_lib_out_cb cb_data;
    struct test_ctx *ctx;
    flb_sockfd_t fd;
    int ret;
    int num;

    char *expected_strs[] = {"\"key\":\"val\""};
    struct str_list expected = {
                                .size = sizeof(expected_strs)/sizeof(char*),
                                .lists = &expected_strs[0],
    };
    const char *payload = "{\"key\":\"val\"}";
    size_t payload_size = strlen(payload);

    clear_output_num();

    cb_data.cb = cb_check_json_str_list;
    cb_data.data = &expected;

    ctx = test_ctx_create(&cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
        exit(EXIT_FAILURE);
    }

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* use default host/port */
    fd = connect_tcp(NULL, -1);
    if (!TEST_CHECK(fd >= 0)) {
        test_ctx_destroy(ctx);
        exit(EXIT_FAILURE);
    }

    ret = send_CONNECT(fd);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("failed to send, errno=%d", errno);
        flb_socket_close(fd);
        test_ctx_destroy(ctx);
        exit(EXIT_FAILURE);
    }

    ret = recv_CONNACK(fd);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("failed to recv, errno=%d", errno);
        flb_socket_close(fd);
        test_ctx_destroy(ctx);
        exit(EXIT_FAILURE);
    }

    ret = send_PUBLISH(fd, payload, payload_size);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("failed to send, errno=%d", errno);
        flb_socket_close(fd);
        test_ctx_destroy(ctx);
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
}

void flb_test_payload_key()
{
    struct flb_lib_out_cb cb_data;
    struct test_ctx *ctx;
    flb_sockfd_t fd;
    int ret;
    int num;

    char *expected_strs[] = {"\"payload_k\":{\"key\":\"val\"}"};
    struct str_list expected = {
                                .size = sizeof(expected_strs)/sizeof(char*),
                                .lists = &expected_strs[0],
    };
    const char *payload = "{\"key\":\"val\"}";
    size_t payload_size = strlen(payload);

    clear_output_num();

    cb_data.cb = cb_check_json_str_list;
    cb_data.data = &expected;

    ctx = test_ctx_create(&cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
        exit(EXIT_FAILURE);
    }

    ret = flb_input_set(ctx->flb, ctx->i_ffd,
                        "payload_key", "payload_k",
                         NULL);
    TEST_CHECK(ret == 0);

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* use default host/port */
    fd = connect_tcp(NULL, -1);
    if (!TEST_CHECK(fd >= 0)) {
        test_ctx_destroy(ctx);
        exit(EXIT_FAILURE);
    }

    ret = send_CONNECT(fd);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("failed to send, errno=%d", errno);
        flb_socket_close(fd);
        test_ctx_destroy(ctx);
        exit(EXIT_FAILURE);
    }

    ret = recv_CONNACK(fd);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("failed to recv, errno=%d", errno);
        flb_socket_close(fd);
        test_ctx_destroy(ctx);
        exit(EXIT_FAILURE);
    }

    ret = send_PUBLISH(fd, payload, payload_size);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("failed to send, errno=%d", errno);
        flb_socket_close(fd);
        test_ctx_destroy(ctx);
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
}

/* Send raw bytes and check that all of them were written */
static int send_raw(flb_sockfd_t fd, const unsigned char *buf, size_t size)
{
    ssize_t w_size;

    w_size = send(fd, (const char *) buf, size, 0);
    if (!TEST_CHECK(w_size == (ssize_t) size)) {
        TEST_MSG("failed to send, errno=%d", errno);
        return -1;
    }
    return 0;
}

/*
 * Receive exactly 'size' bytes with a timeout. Returns the number of bytes
 * received, 0 if the peer closed the connection and -1 on error or timeout.
 */
static int recv_exact(flb_sockfd_t fd, unsigned char *buf, size_t size)
{
    int ret;
    size_t total = 0;
    ssize_t r_size;
    fd_set rfds;
    struct timeval tv;

    while (total < size) {
        FD_ZERO(&rfds);
        FD_SET(fd, &rfds);
        tv.tv_sec = 2;
        tv.tv_usec = 0;

        ret = select(fd + 1, &rfds, NULL, NULL, &tv);
        if (ret <= 0) {
            return -1;
        }

        r_size = recv(fd, (char *) buf + total, size - total, 0);
        if (r_size == 0) {
            return 0;
        }
        else if (r_size < 0) {
            return -1;
        }
        total += r_size;
    }

    return (int) total;
}

/* Connect, send a CONNECT with CleanSession=1 and return the CONNACK flags */
static flb_sockfd_t mqtt_session_start(int *session_present)
{
    flb_sockfd_t fd;
    unsigned char connack[4] = {0};
    const unsigned char connect[] = {
        0x10, 0x0d, 0x00, 0x04, 'M', 'Q', 'T', 'T', 0x04, 0x02, 0x00, 0x3c,
        0x00, 0x01, 'c'
    };

    fd = connect_tcp(NULL, -1);
    if (!TEST_CHECK(fd >= 0)) {
        return -1;
    }

    if (!TEST_CHECK(send_raw(fd, connect, sizeof(connect)) == 0) ||
        !TEST_CHECK(recv_exact(fd, connack, sizeof(connack)) == 4)) {
        flb_socket_close(fd);
        return -1;
    }

    TEST_CHECK(connack[0] == 0x20 && connack[1] == 0x02 && connack[3] == 0x00);
    *session_present = connack[2];

    return fd;
}

/* CONNACK must not claim a resumed session */
void flb_test_connack_session_present()
{
    struct flb_lib_out_cb cb_data = {0};
    struct test_ctx *ctx;
    flb_sockfd_t fd;
    int session_present = -1;

    ctx = test_ctx_create(&cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        exit(EXIT_FAILURE);
    }
    TEST_CHECK(flb_start(ctx->flb) == 0);

    fd = mqtt_session_start(&session_present);
    if (!TEST_CHECK(fd >= 0)) {
        test_ctx_destroy(ctx);
        exit(EXIT_FAILURE);
    }
    TEST_CHECK(session_present == 0);

    flb_socket_close(fd);
    test_ctx_destroy(ctx);
}

/* A QoS 2 PUBLISH must be completed with PUBCOMP after the PUBREL */
void flb_test_qos2_pubcomp()
{
    struct flb_lib_out_cb cb_data = {0};
    char *expected_strs[] = {"\"a\":1"};
    struct str_list expected = {
                                .size = sizeof(expected_strs)/sizeof(char*),
                                .lists = &expected_strs[0],
    };
    struct test_ctx *ctx;
    flb_sockfd_t fd;
    int session_present;
    unsigned char reply[4] = {0};
    const unsigned char publish[] = {
        0x34, 0x0e, 0x00, 0x03, 'a', '/', 'b', 0x00, 0x07,
        '{', '"', 'a', '"', ':', '1', '}'
    };
    /* the same PUBLISH retransmitted with the DUP flag set */
    const unsigned char publish_dup[] = {
        0x3c, 0x0e, 0x00, 0x03, 'a', '/', 'b', 0x00, 0x07,
        '{', '"', 'a', '"', ':', '1', '}'
    };
    const unsigned char pubrel[] = {0x62, 0x02, 0x00, 0x07};
    const unsigned char pubrec[] = {0x50, 0x02, 0x00, 0x07};
    const unsigned char pubcomp[] = {0x70, 0x02, 0x00, 0x07};

    clear_output_num();
    cb_data.cb = cb_check_json_str_list;
    cb_data.data = &expected;

    ctx = test_ctx_create(&cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        exit(EXIT_FAILURE);
    }
    TEST_CHECK(flb_start(ctx->flb) == 0);

    fd = mqtt_session_start(&session_present);
    if (!TEST_CHECK(fd >= 0)) {
        test_ctx_destroy(ctx);
        exit(EXIT_FAILURE);
    }

    TEST_CHECK(send_raw(fd, publish, sizeof(publish)) == 0);
    TEST_CHECK(recv_exact(fd, reply, 4) == 4);
    TEST_CHECK(memcmp(reply, pubrec, 4) == 0);

    /* a retransmission is acknowledged again but must not be ingested again */
    TEST_CHECK(send_raw(fd, publish_dup, sizeof(publish_dup)) == 0);
    memset(reply, 0, sizeof(reply));
    TEST_CHECK(recv_exact(fd, reply, 4) == 4);
    TEST_CHECK(memcmp(reply, pubrec, 4) == 0);

    TEST_CHECK(send_raw(fd, pubrel, sizeof(pubrel)) == 0);
    memset(reply, 0, sizeof(reply));
    TEST_CHECK(recv_exact(fd, reply, 4) == 4);
    TEST_CHECK(memcmp(reply, pubcomp, 4) == 0);

    /* the message is still ingested exactly once */
    flb_time_msleep(500);
    TEST_CHECK(get_output_num() == 1);

    flb_socket_close(fd);
    test_ctx_destroy(ctx);
}

/* SUBSCRIBE and UNSUBSCRIBE must be answered */
void flb_test_subscribe_suback()
{
    struct flb_lib_out_cb cb_data = {0};
    struct test_ctx *ctx;
    flb_sockfd_t fd;
    int session_present;
    unsigned char reply[4] = {0};
    const unsigned char subscribe[] = {
        0x82, 0x0a, 0x00, 0x01, 0x00, 0x01, 't', 0x00,
        0x00, 0x01, 'u', 0x01
    };
    const unsigned char suback[] = {0x90, 0x04, 0x00, 0x01, 0x80, 0x80};
    const unsigned char unsubscribe[] = {0xa2, 0x05, 0x00, 0x02, 0x00, 0x01, 't'};
    const unsigned char unsuback[] = {0xb0, 0x02, 0x00, 0x02};

    ctx = test_ctx_create(&cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        exit(EXIT_FAILURE);
    }
    TEST_CHECK(flb_start(ctx->flb) == 0);

    fd = mqtt_session_start(&session_present);
    if (!TEST_CHECK(fd >= 0)) {
        test_ctx_destroy(ctx);
        exit(EXIT_FAILURE);
    }

    TEST_CHECK(send_raw(fd, subscribe, sizeof(subscribe)) == 0);
    {
        unsigned char sub_reply[6] = {0};

        TEST_CHECK(recv_exact(fd, sub_reply, sizeof(sub_reply)) == 6);
        TEST_CHECK(memcmp(sub_reply, suback, sizeof(suback)) == 0);
    }

    TEST_CHECK(send_raw(fd, unsubscribe, sizeof(unsubscribe)) == 0);
    TEST_CHECK(recv_exact(fd, reply, 4) == 4);
    TEST_CHECK(memcmp(reply, unsuback, sizeof(unsuback)) == 0);

    /* more filters than any fixed reply buffer: one return code for each */
    {
        int i;
        int pos = 0;
        unsigned char many[3 + 2 + 33 * 4] = {0};
        unsigned char many_reply[2 + 2 + 33] = {0};

        many[pos++] = 0x82;
        many[pos++] = 0x80 | ((2 + 33 * 4) & 0x7f);
        many[pos++] = (2 + 33 * 4) >> 7;
        many[pos++] = 0x00;
        many[pos++] = 0x03;
        for (i = 0; i < 33; i++) {
            many[pos++] = 0x00;
            many[pos++] = 0x01;
            many[pos++] = 'f';
            many[pos++] = 0x00;
        }
        TEST_CHECK(send_raw(fd, many, pos) == 0);
        TEST_CHECK(recv_exact(fd, many_reply, sizeof(many_reply)) ==
                   (int) sizeof(many_reply));
        TEST_CHECK(many_reply[0] == 0x90 && many_reply[1] == 2 + 33);
        TEST_CHECK(many_reply[2] == 0x00 && many_reply[3] == 0x03);
        for (i = 0; i < 33; i++) {
            TEST_CHECK(many_reply[4 + i] == 0x80);
        }
    }

    flb_socket_close(fd);

    /* an UNSUBSCRIBE with an empty topic filter closes the connection */
    fd = mqtt_session_start(&session_present);
    if (!TEST_CHECK(fd >= 0)) {
        test_ctx_destroy(ctx);
        exit(EXIT_FAILURE);
    }
    {
        const unsigned char bad_unsubscribe[] = {0xa2, 0x04, 0x00, 0x03, 0x00, 0x00};

        TEST_CHECK(send_raw(fd, bad_unsubscribe, sizeof(bad_unsubscribe)) == 0);
        TEST_CHECK(recv_exact(fd, reply, 4) == 0);
    }

    flb_socket_close(fd);
    test_ctx_destroy(ctx);
}

/* A second CONNECT on the same connection closes the connection */
void flb_test_duplicated_connect()
{
    struct flb_lib_out_cb cb_data = {0};
    struct test_ctx *ctx;
    flb_sockfd_t fd;
    int session_present;
    unsigned char reply[4] = {0};
    const unsigned char connect[] = {
        0x10, 0x0d, 0x00, 0x04, 'M', 'Q', 'T', 'T', 0x04, 0x02, 0x00, 0x3c,
        0x00, 0x01, 'c'
    };

    ctx = test_ctx_create(&cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        exit(EXIT_FAILURE);
    }
    TEST_CHECK(flb_start(ctx->flb) == 0);

    fd = mqtt_session_start(&session_present);
    if (!TEST_CHECK(fd >= 0)) {
        test_ctx_destroy(ctx);
        exit(EXIT_FAILURE);
    }

    TEST_CHECK(send_raw(fd, connect, sizeof(connect)) == 0);
    /* the server closes the connection instead of sending another CONNACK */
    TEST_CHECK(recv_exact(fd, reply, 4) == 0);

    flb_socket_close(fd);
    test_ctx_destroy(ctx);
}

TEST_LIST = {
    {"mqtt", flb_test_mqtt},
    {"payload_key", flb_test_payload_key},
    {"connack_session_present", flb_test_connack_session_present},
    {"qos2_pubcomp", flb_test_qos2_pubcomp},
    {"subscribe_suback", flb_test_subscribe_suback},
    {"duplicated_connect", flb_test_duplicated_connect},
    {NULL, NULL}
};

