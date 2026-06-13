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
#include <fluent-bit/flb_pthread.h>
#include <fluent-bit/flb_socket.h>
#include <fluent-bit/flb_network.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_time.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef _WIN32
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#else
#include <winsock2.h>
#include <ws2tcpip.h>
#include <fluent-bit/flb_compat.h>
#endif

#include "flb_tests_runtime.h"

void flb_test_otel_default_config(void);
void flb_test_otel_oauth2_metadata_smoke(void);

TEST_LIST = {
    {"default_config",         flb_test_otel_default_config},
    {"oauth2_metadata_smoke",  flb_test_otel_oauth2_metadata_smoke},
    {NULL, NULL}
};

void flb_test_otel_default_config(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    ctx = flb_create();
    TEST_CHECK(ctx != NULL);

    flb_service_set(ctx,
                    "Flush", "1",
                    "Grace", "1",
                    "Log_Level", "error",
                    NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "opentelemetry", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd,
                   "match", "test",
                   "host",  "127.0.0.1",
                   "port",  "14317",
                   NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    flb_stop(ctx);
    flb_destroy(ctx);
}

#define SMOKE_BUF_SIZE          16384
#define SMOKE_TOKEN_VALUE       "smoke-token"
#define SMOKE_METADATA_PATH     "/token"
#define SMOKE_METADATA_HEADER   "Metadata-Flavor: Google"
#define SMOKE_METADATA_HDR_NAME "Metadata-Flavor"
#define SMOKE_METADATA_HDR_VAL  "Google"

struct smoke_mock_server {
    flb_sockfd_t    listen_fd;
    int             port;
    int             stop;
    int             metadata_get_count;
    int             collector_post_count;
    int             metadata_header_seen;
    int             authorization_seen;
    char            last_authorization[256];
    pthread_mutex_t state_lock;
    int             active_clients;
    pthread_cond_t  clients_idle;
    pthread_t       thread;
#ifdef _WIN32
    int             wsa_initialized;
#endif
};

struct smoke_client_args {
    struct smoke_mock_server *server;
    flb_sockfd_t              client_fd;
};

static void smoke_send_response(flb_sockfd_t fd, int status, const char *body)
{
    char buffer[SMOKE_BUF_SIZE];
    int  body_len = 0;
    ssize_t sent = 0;
    ssize_t total = 0;
    ssize_t len;

    if (body != NULL) {
        body_len = (int) strlen(body);
    }

    snprintf(buffer, sizeof(buffer),
             "HTTP/1.1 %d OK\r\n"
             "Content-Length: %d\r\n"
             "Content-Type: application/json\r\n"
             "Connection: close\r\n\r\n"
             "%s",
             status, body_len, body ? body : "");

    len = (ssize_t) strlen(buffer);
    while (total < len) {
        sent = send(fd, buffer + total, (int)(len - total), 0);
        if (sent <= 0) {
            break;
        }
        total += sent;
    }
}

static int smoke_request_content_length(const char *request)
{
    int len;
    const char *p;

    p = strstr(request, "Content-Length:");
    if (!p) {
        return 0;
    }

    p += sizeof("Content-Length:") - 1;
    while (*p == ' ') {
        p++;
    }

    len = atoi(p);
    if (len < 0) {
        len = 0;
    }

    return len;
}

static void smoke_capture_authorization(struct smoke_mock_server *server,
                                        const char *request)
{
    const char *line;
    const char *eol;
    const char *value;
    size_t      copy_len;

    line = strcasestr(request, "Authorization:");
    if (line == NULL) {
        return;
    }

    value = line + sizeof("Authorization:") - 1;
    while (*value == ' ' || *value == '\t') {
        value++;
    }

    eol = strstr(value, "\r\n");
    if (eol == NULL) {
        return;
    }

    copy_len = (size_t)(eol - value);
    if (copy_len >= sizeof(server->last_authorization)) {
        copy_len = sizeof(server->last_authorization) - 1;
    }
    memcpy(server->last_authorization, value, copy_len);
    server->last_authorization[copy_len] = '\0';
    server->authorization_seen = 1;
}

static void *smoke_mock_client_thread(void *data)
{
    struct smoke_client_args *args = (struct smoke_client_args *) data;
    struct smoke_mock_server *server = args->server;
    flb_sockfd_t              client_fd = args->client_fd;
    char                      buffer[SMOKE_BUF_SIZE];
    ssize_t                   total = 0;
    ssize_t                   n;
    int                       content_len;
    const char               *headers_end;
    const char               *body =
        "{\"access_token\":\"" SMOKE_TOKEN_VALUE "\","
        "\"expires_in\":3600,\"token_type\":\"Bearer\"}";

    flb_free(args);

    memset(buffer, 0, sizeof(buffer));
    flb_net_socket_blocking(client_fd);

    while (total < (ssize_t) sizeof(buffer) - 1) {
        n = recv(client_fd, buffer + total,
                 (int)(sizeof(buffer) - 1 - total), 0);
        if (n <= 0) {
            break;
        }
        total += n;
        if (strstr(buffer, "\r\n\r\n") != NULL) {
            break;
        }
    }

    headers_end = strstr(buffer, "\r\n\r\n");
    if (headers_end != NULL) {
        content_len = smoke_request_content_length(buffer);
        while (content_len > 0 && total < (ssize_t) sizeof(buffer) - 1) {
            if (total >= ((headers_end - buffer) + 4 + content_len)) {
                break;
            }
            n = recv(client_fd, buffer + total,
                     (int)(sizeof(buffer) - 1 - total), 0);
            if (n <= 0) {
                break;
            }
            total += n;
        }
        buffer[total] = '\0';
    }

    pthread_mutex_lock(&server->state_lock);

    if (strncmp(buffer, "GET ", 4) == 0 &&
        strstr(buffer, SMOKE_METADATA_PATH) != NULL) {
        server->metadata_get_count++;
        if (strstr(buffer, SMOKE_METADATA_HDR_NAME ":") != NULL &&
            strstr(buffer, SMOKE_METADATA_HDR_VAL) != NULL) {
            server->metadata_header_seen = 1;
        }
        pthread_mutex_unlock(&server->state_lock);
        smoke_send_response(client_fd, 200, body);
    }
    else if (strncmp(buffer, "POST ", 5) == 0) {
        server->collector_post_count++;
        smoke_capture_authorization(server, buffer);
        pthread_mutex_unlock(&server->state_lock);
        smoke_send_response(client_fd, 200, "{}");
    }
    else {
        pthread_mutex_unlock(&server->state_lock);
        smoke_send_response(client_fd, 200, "{}");
    }

    flb_socket_close(client_fd);

    pthread_mutex_lock(&server->state_lock);
    server->active_clients--;
    if (server->active_clients == 0) {
        pthread_cond_broadcast(&server->clients_idle);
    }
    pthread_mutex_unlock(&server->state_lock);

    return NULL;
}

static void *smoke_mock_server_thread(void *data)
{
    struct smoke_mock_server *server = (struct smoke_mock_server *) data;
    flb_sockfd_t              client_fd;
    fd_set                    rfds;
    struct timeval            tv;
    pthread_t                 client_thread;
    struct smoke_client_args *args;

    while (!server->stop) {
        FD_ZERO(&rfds);
        FD_SET(server->listen_fd, &rfds);
        tv.tv_sec = 0;
        tv.tv_usec = 200000;

        if (select((int)(server->listen_fd + 1), &rfds, NULL, NULL, &tv) <= 0) {
            continue;
        }

        client_fd = accept(server->listen_fd, NULL, NULL);
        if (client_fd == FLB_INVALID_SOCKET) {
            continue;
        }

        args = flb_malloc(sizeof(*args));
        if (args == NULL) {
            flb_socket_close(client_fd);
            continue;
        }
        args->server    = server;
        args->client_fd = client_fd;

        pthread_mutex_lock(&server->state_lock);
        server->active_clients++;
        pthread_mutex_unlock(&server->state_lock);

        if (pthread_create(&client_thread, NULL,
                           smoke_mock_client_thread, args) != 0) {
            pthread_mutex_lock(&server->state_lock);
            server->active_clients--;
            if (server->active_clients == 0) {
                pthread_cond_broadcast(&server->clients_idle);
            }
            pthread_mutex_unlock(&server->state_lock);
            flb_free(args);
            flb_socket_close(client_fd);
            continue;
        }
        pthread_detach(client_thread);
    }

    return NULL;
}

static int smoke_mock_server_start(struct smoke_mock_server *server)
{
    int                on = 1;
    struct sockaddr_in addr;
    socklen_t          len;
#ifdef _WIN32
    WSADATA wsa_data;
    int     wsa_result;
#endif

    server->stop                 = 0;
    server->metadata_get_count   = 0;
    server->collector_post_count = 0;
    server->metadata_header_seen = 0;
    server->authorization_seen   = 0;
    server->last_authorization[0] = '\0';
    server->active_clients       = 0;
    pthread_mutex_init(&server->state_lock, NULL);
    pthread_cond_init(&server->clients_idle, NULL);

#ifdef _WIN32
    wsa_result = WSAStartup(MAKEWORD(2, 2), &wsa_data);
    if (wsa_result != 0) {
        return -1;
    }
    server->wsa_initialized = 1;
#endif

    server->listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server->listen_fd == FLB_INVALID_SOCKET) {
        return -1;
    }

    setsockopt(server->listen_fd, SOL_SOCKET, SO_REUSEADDR,
               (const char *) &on, sizeof(on));

    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port        = 0;

    if (bind(server->listen_fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
        flb_socket_close(server->listen_fd);
        return -1;
    }

    if (listen(server->listen_fd, 4) < 0) {
        flb_socket_close(server->listen_fd);
        return -1;
    }

    len = sizeof(addr);
    memset(&addr, 0, sizeof(addr));
    if (getsockname(server->listen_fd, (struct sockaddr *) &addr, &len) < 0) {
        flb_socket_close(server->listen_fd);
        return -1;
    }

    server->port = ntohs(addr.sin_port);
    flb_net_socket_nonblocking(server->listen_fd);

    if (pthread_create(&server->thread, NULL,
                       smoke_mock_server_thread, server) != 0) {
        flb_socket_close(server->listen_fd);
        return -1;
    }

    return 0;
}

static void smoke_mock_server_stop(struct smoke_mock_server *server)
{
    if (server->listen_fd != FLB_INVALID_SOCKET) {
        server->stop = 1;
        shutdown(server->listen_fd, SHUT_RDWR);
        pthread_join(server->thread, NULL);
        flb_socket_close(server->listen_fd);
        server->listen_fd = FLB_INVALID_SOCKET;

        /* Drain detached client threads before returning: server is
         * stack-allocated and racing threads would use-after-scope it. */
        pthread_mutex_lock(&server->state_lock);
        while (server->active_clients > 0) {
            pthread_cond_wait(&server->clients_idle, &server->state_lock);
        }
        pthread_mutex_unlock(&server->state_lock);

        pthread_cond_destroy(&server->clients_idle);
        pthread_mutex_destroy(&server->state_lock);
    }
#ifdef _WIN32
    if (server->wsa_initialized) {
        WSACleanup();
        server->wsa_initialized = 0;
    }
#endif
}

static int smoke_mock_metadata_seen(struct smoke_mock_server *server)
{
    int v;
    pthread_mutex_lock(&server->state_lock);
    v = server->metadata_get_count;
    pthread_mutex_unlock(&server->state_lock);
    return v;
}

static int smoke_mock_collector_seen(struct smoke_mock_server *server)
{
    int v;
    pthread_mutex_lock(&server->state_lock);
    v = server->collector_post_count;
    pthread_mutex_unlock(&server->state_lock);
    return v;
}

/* Negative paths are covered in tests/internal/oauth2_metadata.c. */
void flb_test_otel_oauth2_metadata_smoke(void)
{
    int                       ret;
    int                       attempts;
    flb_ctx_t                *ctx;
    int                       in_ffd;
    int                       out_ffd;
    char                      port_str[16];
    char                      metadata_url[128];
    const char               *record =
        "[1717000000, {\"msg\":\"otel-smoke\"}]";
    struct smoke_mock_server  server;

    memset(&server, 0, sizeof(server));
    server.listen_fd = FLB_INVALID_SOCKET;

    ret = smoke_mock_server_start(&server);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("failed to start mock server");
        return;
    }

    snprintf(port_str, sizeof(port_str), "%d", server.port);
    snprintf(metadata_url, sizeof(metadata_url),
             "http://127.0.0.1:%d%s", server.port, SMOKE_METADATA_PATH);

    ctx = flb_create();
    TEST_CHECK(ctx != NULL);

    flb_service_set(ctx,
                    "Flush",     "1",
                    "Grace",     "1",
                    "Log_Level", "error",
                    NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "opentelemetry", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd,
                   "match",                  "test",
                   "host",                   "127.0.0.1",
                   "port",                   port_str,
                   "tls",                    "off",
                   "logs_uri",               "/v1/logs",
                   "oauth2.enable",          "true",
                   "oauth2.token_source",    "metadata",
                   "oauth2.metadata_url",    metadata_url,
                   "oauth2.metadata_header", SMOKE_METADATA_HEADER,
                   NULL);

    ret = flb_start(ctx);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("flb_start failed");
        flb_destroy(ctx);
        smoke_mock_server_stop(&server);
        return;
    }

    ret = flb_lib_push(ctx, in_ffd, (char *) record, strlen(record));
    TEST_CHECK(ret >= 0);

    for (attempts = 0; attempts < 50; attempts++) {
        if (smoke_mock_metadata_seen(&server) > 0 &&
            smoke_mock_collector_seen(&server) > 0) {
            break;
        }
        flb_time_msleep(100);
    }

    /* Lock before asserts: shutdown still races with detached client threads. */
    pthread_mutex_lock(&server.state_lock);
    TEST_CHECK(server.metadata_get_count >= 1);
    TEST_MSG("metadata_get_count=%d", server.metadata_get_count);
    TEST_CHECK(server.metadata_header_seen == 1);
    TEST_MSG("metadata header '%s' not observed on GET",
             SMOKE_METADATA_HEADER);
    TEST_CHECK(server.collector_post_count >= 1);
    TEST_MSG("collector_post_count=%d", server.collector_post_count);
    TEST_CHECK(server.authorization_seen == 1);
    TEST_MSG("Authorization header missing from collector POST");
    if (server.authorization_seen) {
        TEST_CHECK(strcmp(server.last_authorization,
                          "Bearer " SMOKE_TOKEN_VALUE) == 0);
        TEST_MSG("Authorization header value: '%s'",
                 server.last_authorization);
    }
    pthread_mutex_unlock(&server.state_lock);

    flb_stop(ctx);
    flb_destroy(ctx);

    smoke_mock_server_stop(&server);
}
