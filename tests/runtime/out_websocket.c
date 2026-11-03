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
#include <fluent-bit/flb_socket.h>

#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>

#ifndef _WIN32
#include <signal.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#else
#include <winsock2.h>
#include <ws2tcpip.h>
#endif

#include "flb_tests_runtime.h"

/*
 * net.keepalive_max_recycle 1 destroys a connection after two releases
 * (ka_count is incremented on release and the connection is dropped when
 * ka_count exceeds the limit). Six separate flushes therefore open three
 * TCP connections. Each one must start with the HTTP Upgrade request.
 */
#define WS_EXPECT_CONNS  3

static const char ws_switch_response[] =
    "HTTP/1.1 101 Switching Protocols\r\n"
    "Upgrade: websocket\r\n"
    "Connection: Upgrade\r\n"
    "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n"
    "Content-Length: 0\r\n"
    "\r\n";

struct ws_server {
    int listen_fd;
    int port;
    int stop;
    int connections;
    int upgrades;
    int missing_upgrade;
    int bad_len;
    unsigned char bad_prefix[12];
    pthread_t thread;
    pthread_mutex_t lock;
};

static int send_all(int fd, const char *data, size_t len)
{
    size_t off;
    ssize_t n;

    off = 0;
    while (off < len) {
        n = send(fd, data + off, len - off, 0);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if (n == 0) {
            return -1;
        }
        off += (size_t) n;
    }

    return 0;
}

static int create_listen_socket(int *out_port)
{
    int fd;
    int on;
    socklen_t length;
    struct sockaddr_in address;

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }

    on = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const char *) &on, sizeof(on));

    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = htons(0);

    if (bind(fd, (struct sockaddr *) &address, sizeof(address)) != 0) {
        flb_socket_close(fd);
        return -1;
    }

    if (listen(fd, 16) != 0) {
        flb_socket_close(fd);
        return -1;
    }

    length = sizeof(address);
    if (getsockname(fd, (struct sockaddr *) &address, &length) != 0) {
        flb_socket_close(fd);
        return -1;
    }

    *out_port = ntohs(address.sin_port);
    return fd;
}

static int wait_readable(int fd, int timeout_ms)
{
    int ret;
    fd_set rfds;
    struct timeval tv;

    FD_ZERO(&rfds);
    FD_SET(fd, &rfds);
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;

    ret = select(fd + 1, &rfds, NULL, NULL, &tv);
    if (ret < 0 && errno == EINTR) {
        return 0;
    }

    return ret;
}

static int read_prefix(int fd, char *buf, int cap)
{
    int total;
    int ready;
    ssize_t n;

    total = 0;
    buf[0] = '\0';

    while (total < cap - 1) {
        ready = wait_readable(fd, 2000);
        if (ready <= 0) {
            break;
        }

        n = recv(fd, buf + total, cap - 1 - total, 0);
        if (n <= 0) {
            break;
        }

        total += (int) n;
        buf[total] = '\0';

        if (total >= 4 && memcmp(buf, "GET ", 4) != 0) {
            break;
        }
        if (strstr(buf, "\r\n\r\n") != NULL) {
            break;
        }
    }

    return total;
}

static void record_connection(struct ws_server *srv, const char *buf, int len)
{
    int copy_len;

    pthread_mutex_lock(&srv->lock);
    srv->connections++;
    if (len >= 4 && memcmp(buf, "GET ", 4) == 0) {
        srv->upgrades++;
    }
    else {
        srv->missing_upgrade++;
        if (srv->bad_len == 0 && len > 0) {
            copy_len = len;
            if (copy_len > (int) sizeof(srv->bad_prefix)) {
                copy_len = (int) sizeof(srv->bad_prefix);
            }
            memcpy(srv->bad_prefix, buf, copy_len);
            srv->bad_len = copy_len;
        }
    }
    pthread_mutex_unlock(&srv->lock);
}

static void drain_until_close(struct ws_server *srv, int fd)
{
    int stop;
    int ready;
    ssize_t n;
    char buf[1024];

    for (;;) {
        pthread_mutex_lock(&srv->lock);
        stop = srv->stop;
        pthread_mutex_unlock(&srv->lock);
        if (stop) {
            break;
        }

        ready = wait_readable(fd, 100);
        if (ready < 0) {
            break;
        }
        if (ready == 0) {
            continue;
        }

        n = recv(fd, buf, sizeof(buf), 0);
        if (n <= 0) {
            break;
        }
    }
}

static void *ws_server_thread(void *data)
{
    int conn_fd;
    int ready;
    int len;
    int stop;
    char buf[2048];
    struct ws_server *srv;

    srv = data;

    for (;;) {
        pthread_mutex_lock(&srv->lock);
        stop = srv->stop;
        pthread_mutex_unlock(&srv->lock);
        if (stop) {
            break;
        }

        ready = wait_readable(srv->listen_fd, 100);
        if (ready <= 0) {
            continue;
        }

        conn_fd = accept(srv->listen_fd, NULL, NULL);
        if (conn_fd < 0) {
            if (errno == EINTR) {
                continue;
            }
            break;
        }

        len = read_prefix(conn_fd, buf, (int) sizeof(buf));
        record_connection(srv, buf, len);

        if (len >= 4 && memcmp(buf, "GET ", 4) == 0) {
            send_all(conn_fd, ws_switch_response, sizeof(ws_switch_response) - 1);
        }

        drain_until_close(srv, conn_fd);
        flb_socket_close(conn_fd);
    }

    return NULL;
}

static int snapshot_counts(struct ws_server *srv, int *connections,
                           int *upgrades, int *missing)
{
    pthread_mutex_lock(&srv->lock);
    *connections = srv->connections;
    *upgrades = srv->upgrades;
    *missing = srv->missing_upgrade;
    pthread_mutex_unlock(&srv->lock);

    if (*missing > 0) {
        return -1;
    }
    if (*connections >= WS_EXPECT_CONNS && *upgrades >= WS_EXPECT_CONNS) {
        return 0;
    }

    return 1;
}

void flb_test_websocket_handshake_on_new_connection(void)
{
    int ret;
    int in_ffd;
    int out_ffd;
    int thread_started;
    int connections;
    int upgrades;
    int missing;
    int elapsed;
    int bad_len;
    int bi;
    int started;
    char port[8];
    char bad_hex[40];
    flb_ctx_t *ctx;
    struct ws_server srv;
#ifdef _WIN32
    WSADATA wsa_data;
#endif

    memset(&srv, 0, sizeof(srv));
    srv.listen_fd = -1;
    thread_started = 0;
    connections = 0;
    upgrades = 0;
    missing = 0;
    started = 0;
    ctx = NULL;

#ifdef _WIN32
    WSAStartup(MAKEWORD(2, 1), &wsa_data);
#else
    signal(SIGPIPE, SIG_IGN);
#endif

    pthread_mutex_init(&srv.lock, NULL);
    srv.listen_fd = create_listen_socket(&srv.port);
    if (!TEST_CHECK(srv.listen_fd >= 0)) {
        TEST_MSG("could not bind local websocket sink");
        pthread_mutex_destroy(&srv.lock);
        return;
    }

    ret = pthread_create(&srv.thread, NULL, ws_server_thread, &srv);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("pthread_create failed: %d", ret);
        flb_socket_close(srv.listen_fd);
        pthread_mutex_destroy(&srv.lock);
        return;
    }
    thread_started = 1;

    snprintf(port, sizeof(port), "%d", srv.port);

    ctx = flb_create();
    if (!TEST_CHECK(ctx != NULL)) {
        goto cleanup;
    }

    ret = flb_service_set(ctx,
                          "Flush", "0.2",
                          "Grace", "1",
                          "Log_Level", "error",
                          NULL);
    TEST_CHECK(ret == 0);

    in_ffd = flb_input(ctx, (char *) "dummy", NULL);
    TEST_CHECK(in_ffd >= 0);
    ret = flb_input_set(ctx, in_ffd,
                        "tag", "test",
                        "samples", "6",
                        "rate", "1",
                        "interval_sec", "0",
                        "interval_nsec", "500000000",
                        NULL);
    TEST_CHECK(ret == 0);

    out_ffd = flb_output(ctx, (char *) "websocket", NULL);
    TEST_CHECK(out_ffd >= 0);
    ret = flb_output_set(ctx, out_ffd,
                         "match", "*",
                         "host", "127.0.0.1",
                         "port", port,
                         "uri", "/ws",
                         "format", "json_lines",
                         "net.keepalive", "on",
                         "net.keepalive_idle_timeout", "300",
                         "net.keepalive_max_recycle", "1",
                         "net.io_timeout", "10s",
                         NULL);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("flb_start failed");
        goto cleanup;
    }
    started = 1;

    /*
     * Dummy emits one record every 500ms. Flush is 200ms, so each record
     * is sealed before the next one arrives and borrows its own connection.
     */
    elapsed = 0;
    while (elapsed < 8000) {
        ret = snapshot_counts(&srv, &connections, &upgrades, &missing);
        if (ret <= 0) {
            break;
        }
        flb_time_msleep(50);
        elapsed += 50;
    }

cleanup:
    if (ctx != NULL) {
        if (started) {
            flb_stop(ctx);
        }
        flb_destroy(ctx);
    }

    if (thread_started) {
        pthread_mutex_lock(&srv.lock);
        srv.stop = 1;
        pthread_mutex_unlock(&srv.lock);
        pthread_join(srv.thread, NULL);
    }

    pthread_mutex_lock(&srv.lock);
    connections = srv.connections;
    upgrades = srv.upgrades;
    missing = srv.missing_upgrade;
    bad_len = srv.bad_len;
    bad_hex[0] = '\0';
    if (bad_len > 0) {
        for (bi = 0; bi < bad_len && bi < 12; bi++) {
            snprintf(bad_hex + (bi * 3), sizeof(bad_hex) - (bi * 3),
                     "%02x ", srv.bad_prefix[bi]);
        }
    }
    pthread_mutex_unlock(&srv.lock);

    if (srv.listen_fd >= 0) {
        flb_socket_close(srv.listen_fd);
    }
    pthread_mutex_destroy(&srv.lock);

    if (!TEST_CHECK(missing == 0)) {
        TEST_MSG("connection started without HTTP upgrade, first bytes: %s",
                 bad_hex);
    }
    if (!TEST_CHECK(connections >= WS_EXPECT_CONNS)) {
        TEST_MSG("expected at least %d TCP connections, got %d (upgrades %d)",
                 WS_EXPECT_CONNS, connections, upgrades);
    }
    if (!TEST_CHECK(upgrades == connections)) {
        TEST_MSG("upgrades=%d connections=%d", upgrades, connections);
    }
}

TEST_LIST = {
    {"handshake_on_new_connection", flb_test_websocket_handshake_on_new_connection},
    {NULL, NULL}
};
