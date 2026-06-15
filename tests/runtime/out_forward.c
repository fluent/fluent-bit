/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2022 The Fluent Bit Authors
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
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_record_accessor.h>

#ifndef FLB_SYSTEM_WINDOWS
#include <errno.h>
#include <pthread.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#endif

#include "flb_tests_runtime.h"

/* Include plugin header to get the flush_ctx structure definition */
#include "../../plugins/out_forward/forward.h"

#ifndef FLB_SYSTEM_WINDOWS
struct secure_forward_server {
    int listen_fd;
    int port;
    int got_ping;
    pthread_t thread;
};

static int forward_socket_write_all(int fd, const char *buffer, size_t length)
{
    ssize_t bytes;
    size_t offset;

    offset = 0;

    while (offset < length) {
        bytes = write(fd, buffer + offset, length - offset);
        if (bytes == -1) {
            if (errno == EINTR) {
                continue;
            }

            return -1;
        }

        if (bytes == 0) {
            return -1;
        }

        offset += bytes;
    }

    return 0;
}

static int forward_create_listen_socket(int *out_port)
{
    int fd;
    int ret;
    int enable;
    socklen_t length;
    struct sockaddr_in address;

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd == -1) {
        return -1;
    }

    enable = 1;
    ret = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable));
    if (ret == -1) {
        close(fd);
        return -1;
    }

    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = htons(0);

    if (bind(fd, (struct sockaddr *) &address, sizeof(address)) == -1) {
        close(fd);
        return -1;
    }

    if (listen(fd, 4) == -1) {
        close(fd);
        return -1;
    }

    length = sizeof(address);
    if (getsockname(fd, (struct sockaddr *) &address, &length) == -1) {
        close(fd);
        return -1;
    }

    *out_port = ntohs(address.sin_port);

    return fd;
}

static int forward_pack_secure_helo(msgpack_sbuffer *mp_sbuf)
{
    msgpack_packer mp_pck;

    msgpack_sbuffer_init(mp_sbuf);
    msgpack_packer_init(&mp_pck, mp_sbuf, msgpack_sbuffer_write);

    msgpack_pack_array(&mp_pck, 2);
    msgpack_pack_str(&mp_pck, 4);
    msgpack_pack_str_body(&mp_pck, "HELO", 4);
    msgpack_pack_map(&mp_pck, 1);
    msgpack_pack_str(&mp_pck, 5);
    msgpack_pack_str_body(&mp_pck, "nonce", 5);
    msgpack_pack_str(&mp_pck, 16);
    msgpack_pack_str_body(&mp_pck, "0123456789abcdef", 16);

    return 0;
}

static int forward_pack_oversized_pong(msgpack_sbuffer *mp_sbuf)
{
    char reason[900];
    msgpack_packer mp_pck;

    memset(reason, 'A', sizeof(reason));

    msgpack_sbuffer_init(mp_sbuf);
    msgpack_packer_init(&mp_pck, mp_sbuf, msgpack_sbuffer_write);

    msgpack_pack_array(&mp_pck, 5);
    msgpack_pack_str(&mp_pck, 4);
    msgpack_pack_str_body(&mp_pck, "PONG", 4);
    msgpack_pack_false(&mp_pck);
    msgpack_pack_str(&mp_pck, sizeof(reason));
    msgpack_pack_str_body(&mp_pck, reason, sizeof(reason));
    msgpack_pack_str(&mp_pck, 4);
    msgpack_pack_str_body(&mp_pck, "host", 4);
    msgpack_pack_str(&mp_pck, 4);
    msgpack_pack_str_body(&mp_pck, "desc", 4);

    return 0;
}

static int forward_read_msgpack(int fd, char *buf, size_t size)
{
    int ret;
    ssize_t bytes;
    size_t off;
    size_t buf_off;
    msgpack_unpacked result;

    buf_off = 0;
    msgpack_unpacked_init(&result);

    while (buf_off < size) {
        bytes = read(fd, buf + buf_off, size - buf_off);
        if (bytes <= 0) {
            msgpack_unpacked_destroy(&result);
            return -1;
        }

        buf_off += bytes;
        off = 0;
        ret = msgpack_unpack_next(&result, buf, buf_off, &off);
        if (ret == MSGPACK_UNPACK_SUCCESS) {
            msgpack_unpacked_destroy(&result);
            return 0;
        }

        if (ret != MSGPACK_UNPACK_CONTINUE) {
            msgpack_unpacked_destroy(&result);
            return -1;
        }
    }

    msgpack_unpacked_destroy(&result);
    return -1;
}

static void *secure_forward_oversized_pong_server_thread(void *data)
{
    int ret;
    int conn_fd;
    fd_set read_fds;
    struct timeval timeout;
    char buf[1024];
    msgpack_sbuffer helo;
    msgpack_sbuffer pong;
    struct secure_forward_server *server;

    server = data;
    conn_fd = -1;

    FD_ZERO(&read_fds);
    FD_SET(server->listen_fd, &read_fds);
    timeout.tv_sec = 5;
    timeout.tv_usec = 0;

    ret = select(server->listen_fd + 1, &read_fds, NULL, NULL, &timeout);
    if (ret <= 0) {
        return NULL;
    }

    conn_fd = accept(server->listen_fd, NULL, NULL);
    if (conn_fd == -1) {
        return NULL;
    }

    if (forward_pack_secure_helo(&helo) != 0) {
        close(conn_fd);
        return NULL;
    }

    if (forward_socket_write_all(conn_fd, helo.data, helo.size) != 0) {
        msgpack_sbuffer_destroy(&helo);
        close(conn_fd);
        return NULL;
    }
    msgpack_sbuffer_destroy(&helo);

    if (forward_read_msgpack(conn_fd, buf, sizeof(buf)) != 0) {
        close(conn_fd);
        return NULL;
    }
    server->got_ping = FLB_TRUE;

    if (forward_pack_oversized_pong(&pong) != 0) {
        close(conn_fd);
        return NULL;
    }

    forward_socket_write_all(conn_fd, pong.data, pong.size);
    msgpack_sbuffer_destroy(&pong);
    close(conn_fd);

    return NULL;
}
#endif

static void cb_check_message_mode(void *ctx, int ffd,
                                  int res_ret, void *res_data, size_t res_size,
                                  void *data)
{
    int ret;
    size_t off = 0;
    msgpack_object tag;
    msgpack_object ts;
    msgpack_object record;
    msgpack_object root;
    msgpack_unpacked result;
    struct flb_time time = {0};

    msgpack_unpacked_init(&result);
    ret = msgpack_unpack_next(&result, res_data, res_size, &off);
    root = result.data;

    TEST_CHECK(ret == MSGPACK_UNPACK_SUCCESS);
    TEST_CHECK(root.type == MSGPACK_OBJECT_ARRAY);
    TEST_CHECK(root.via.array.size == 4);

    /* Tag */
    tag = root.via.array.ptr[0];
    TEST_CHECK(tag.type == MSGPACK_OBJECT_STR);
    ret = strncmp(tag.via.str.ptr, "new.tag.fluent", tag.via.str.size);
    TEST_CHECK(ret == 0);

    /* Timestamp */
    ts = root.via.array.ptr[1];
    TEST_CHECK(ts.type == MSGPACK_OBJECT_EXT);

    ret = flb_time_msgpack_to_time(&time, &ts);
    TEST_CHECK(ret == 0);
    TEST_CHECK(time.tm.tv_nsec != 0);

    /* Record */
    record = root.via.array.ptr[2];
    TEST_CHECK(record.type == MSGPACK_OBJECT_MAP);
    TEST_CHECK(record.via.map.size == 2);

    msgpack_unpacked_destroy(&result);
    flb_free(res_data);
}

static void cb_check_message_compat_mode(void *ctx, int ffd,
                                         int res_ret, void *res_data, size_t res_size,
                                         void *data)
{
    int ret;
    size_t off = 0;
    msgpack_object tag;
    msgpack_object ts;
    msgpack_object record;
    msgpack_object root;
    msgpack_unpacked result;
    struct flb_time time = {0};

    msgpack_unpacked_init(&result);
    ret = msgpack_unpack_next(&result, res_data, res_size, &off);
    root = result.data;

    TEST_CHECK(ret == MSGPACK_UNPACK_SUCCESS);
    TEST_CHECK(root.type == MSGPACK_OBJECT_ARRAY);
    TEST_CHECK(root.via.array.size == 4);

    /* Tag */
    tag = root.via.array.ptr[0];
    TEST_CHECK(tag.type == MSGPACK_OBJECT_STR);
    ret = strncmp(tag.via.str.ptr, "new.tag.fluent", tag.via.str.size);
    TEST_CHECK(ret == 0);

    /* Timestamp */
    ts = root.via.array.ptr[1];
    TEST_CHECK(ts.type == MSGPACK_OBJECT_POSITIVE_INTEGER);

    ret = flb_time_msgpack_to_time(&time, &ts);
    TEST_CHECK(ret == 0);
    TEST_CHECK(time.tm.tv_nsec == 0);

    /* Record */
    record = root.via.array.ptr[2];
    TEST_CHECK(record.type == MSGPACK_OBJECT_MAP);
    TEST_CHECK(record.via.map.size == 2);

    msgpack_unpacked_destroy(&result);
    flb_free(res_data);
}

static void cb_check_forward_mode(void *ctx, int ffd,
                                  int res_ret, void *res_data, size_t res_size,
                                  void *data)
{
    int ret;
    size_t off = 0;
    msgpack_object key;
    msgpack_object val;
    msgpack_object root;
    msgpack_unpacked result;

    /*
     * the check for forward mode is a bit special, since no data is formatted, instead the formatter callback
     * will return the "options" map that will be send after the records chunk. The options are set because the
     * caller specified 'send_options true'.
     */
    TEST_CHECK(res_ret == MODE_FORWARD);

    msgpack_unpacked_init(&result);
    ret = msgpack_unpack_next(&result, res_data, res_size, &off);
    root = result.data;

    TEST_CHECK(ret == MSGPACK_UNPACK_SUCCESS);
    TEST_CHECK(root.type == MSGPACK_OBJECT_MAP);

    /* fluent_signal and size */
    TEST_CHECK(root.via.map.size == 2);

    /* Record */
    key = root.via.map.ptr[1].key;
    val = root.via.map.ptr[1].val;

    ret = strncmp(key.via.str.ptr, "fluent_signal", 13);
    TEST_CHECK(ret == 0);
    TEST_CHECK(val.type == MSGPACK_OBJECT_POSITIVE_INTEGER);
    TEST_CHECK(val.via.u64 == 0);

    msgpack_unpacked_destroy(&result);
    flb_free(res_data);
}

static void cb_check_forward_compat_mode(void *ctx, int ffd,
                                         int res_ret, void *res_data, size_t res_size,
                                         void *data)
{
    int ret;
    size_t off = 0;
    msgpack_object root;
    msgpack_object records;
    msgpack_object entry;
    msgpack_unpacked result;

    TEST_CHECK(res_ret == MODE_FORWARD_COMPAT);

    msgpack_unpacked_init(&result);
    ret = msgpack_unpack_next(&result, res_data, res_size, &off);
    root = result.data;
    records = root.via.array.ptr[1];

    TEST_CHECK(ret == MSGPACK_UNPACK_SUCCESS);
    TEST_CHECK(root.type == MSGPACK_OBJECT_ARRAY);

    /* Record */
    entry = records.via.array.ptr[0];
    TEST_CHECK(entry.type == MSGPACK_OBJECT_ARRAY);
    TEST_CHECK(entry.via.array.ptr[0].type == MSGPACK_OBJECT_POSITIVE_INTEGER);

    msgpack_unpacked_destroy(&result);
    flb_free(res_data);
}

void flb_test_message_mode()
{
    int ret;
    int in_ffd;
    int out_ffd;
    flb_ctx_t *ctx;

    /* Create context, flush every second (some checks omitted here) */
    ctx = flb_create();
    flb_service_set(ctx, "flush", "2", "grace", "1", NULL);

    /* Lib input mode */
    in_ffd = flb_input(ctx, (char *) "dummy", NULL);
    flb_input_set(ctx, in_ffd,
                  "tag", "test",
                  "samples", "1",
                  "dummy", "{\"key1\": 123, \"key2\": {\"s1\": \"fluent\"}}",
                  NULL);


    /* Forward output */
    out_ffd = flb_output(ctx, (char *) "forward", NULL);
    flb_output_set(ctx, out_ffd,
                   "match", "test",
                   "tag", "new.tag.$key2['s1']",
                   NULL);

    /* Enable test mode */
    ret = flb_output_set_test(ctx, out_ffd, "formatter",
                              cb_check_message_mode,
                              NULL, NULL);

    /* Start */
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_message_compat_mode()
{
    int ret;
    int in_ffd;
    int out_ffd;
    flb_ctx_t *ctx;

    /* Create context, flush every second (some checks omitted here) */
    ctx = flb_create();
    flb_service_set(ctx, "flush", "2", "grace", "1", NULL);

    /* Lib input mode */
    in_ffd = flb_input(ctx, (char *) "dummy", NULL);
    flb_input_set(ctx, in_ffd,
                  "tag", "test",
                  "samples", "1",
                  "dummy", "{\"key1\": 123, \"key2\": {\"s1\": \"fluent\"}}",
                  NULL);


    /* Forward output with timestamp in integer mode (compat) */
    out_ffd = flb_output(ctx, (char *) "forward", NULL);
    flb_output_set(ctx, out_ffd,
                   "match", "test",
                   "time_as_integer", "true",
                   "tag", "new.tag.$key2['s1']",
                   NULL);

    /* Enable test mode */
    ret = flb_output_set_test(ctx, out_ffd, "formatter",
                              cb_check_message_compat_mode,
                              NULL, NULL);

    /* Start */
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_forward_mode()
{
    int ret;
    int in_ffd;
    int out_ffd;
    flb_ctx_t *ctx;

    /* Create context, flush every second (some checks omitted here) */
    ctx = flb_create();
    flb_service_set(ctx, "flush", "2", "grace", "1", NULL);

    /* Lib input mode */
    in_ffd = flb_input(ctx, (char *) "dummy", NULL);
    flb_input_set(ctx, in_ffd,
                  "tag", "test",
                  "samples", "1",
                  "dummy", "{\"key1\": 123, \"key2\": {\"s1\": \"fluent\"}}",
                  NULL);


    /* Forward output: without a tag key access, forward mode is used */
    out_ffd = flb_output(ctx, (char *) "forward", NULL);
    flb_output_set(ctx, out_ffd,
                   "match", "test",
                   "tag", "new.tag",
                   "send_options", "true",
                   NULL);

    /* Enable test mode */
    ret = flb_output_set_test(ctx, out_ffd, "formatter",
                              cb_check_forward_mode,
                              NULL, NULL);

    /* Start */
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_forward_compat_mode()
{
    int ret;
    int in_ffd;
    int out_ffd;
    flb_ctx_t *ctx;

    /* Create context, flush every second (some checks omitted here) */
    ctx = flb_create();
    flb_service_set(ctx, "flush", "3", "grace", "1", NULL);

    /* Lib input mode */
    in_ffd = flb_input(ctx, (char *) "dummy", NULL);
    flb_input_set(ctx, in_ffd,
                  "tag", "test",
                  "samples", "2",
                  "dummy", "{\"key1\": 123, \"key2\": {\"s1\": \"fluent\"}}",
                  NULL);


    /* Forward output: without a tag key access, forward mode is used */
    out_ffd = flb_output(ctx, (char *) "forward", NULL);
    flb_output_set(ctx, out_ffd,
                   "match", "test",
                   "tag", "new.tag",
                   "time_as_integer", "true",
                   NULL);

    /* Enable test mode */
    ret = flb_output_set_test(ctx, out_ffd, "formatter",
                              cb_check_forward_compat_mode,
                              NULL, NULL);

    /* Start */
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}

#ifndef FLB_SYSTEM_WINDOWS
void flb_test_secure_forward_oversized_pong_reason()
{
    int ret;
    int in_ffd;
    int out_ffd;
    char port[16];
    flb_ctx_t *ctx;
    struct secure_forward_server server;

    memset(&server, 0, sizeof(server));
    server.listen_fd = -1;

    server.listen_fd = forward_create_listen_socket(&server.port);
    TEST_CHECK(server.listen_fd != -1);
    if (server.listen_fd == -1) {
        return;
    }

    ret = pthread_create(&server.thread, NULL,
                         secure_forward_oversized_pong_server_thread,
                         &server);
    TEST_CHECK(ret == 0);
    if (ret != 0) {
        close(server.listen_fd);
        return;
    }

    snprintf(port, sizeof(port), "%i", server.port);

    ctx = flb_create();
    flb_service_set(ctx, "flush", "0.2", "grace", "1", NULL);

    in_ffd = flb_input(ctx, (char *) "dummy", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd,
                  "tag", "test",
                  "samples", "1",
                  "dummy", "{\"key\":\"value\"}",
                  NULL);

    out_ffd = flb_output(ctx, (char *) "forward", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd,
                   "match", "test",
                   "host", "127.0.0.1",
                   "port", port,
                   "shared_key", "secret",
                   NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    flb_time_msleep(1500);
    flb_stop(ctx);
    flb_destroy(ctx);

    close(server.listen_fd);
    pthread_join(server.thread, NULL);

    TEST_CHECK(server.got_ping == FLB_TRUE);
}
#endif

/* Test list */
TEST_LIST = {
#ifdef FLB_HAVE_RECORD_ACCESSOR
    {"message_mode"       , flb_test_message_mode },
    {"message_compat_mode", flb_test_message_compat_mode },
#endif
    {"forward_mode"       , flb_test_forward_mode },
    {"forward_compat_mode", flb_test_forward_compat_mode },
#ifndef FLB_SYSTEM_WINDOWS
    {"secure_forward_oversized_pong_reason",
     flb_test_secure_forward_oversized_pong_reason },
#endif
    {NULL, NULL}
};
