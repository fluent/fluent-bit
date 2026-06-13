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

#include <fluent-bit/flb_pthread.h>
#include <fluent-bit/flb_socket.h>
#include <fluent-bit/flb_network.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_http_client.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_oauth2.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_upstream.h>

#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

#ifndef _WIN32
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <unistd.h>
#else
#include <winsock2.h>
#include <ws2tcpip.h>
#include <fluent-bit/flb_compat.h>
#endif

#include "flb_tests_internal.h"
#include "flb_oauth2_test_internal.h"

#define MOCK_BODY_SIZE 16384

/* Fragmentation modes simulate metadata responses split across TCP segments. */
enum oauth2_metadata_fragment_mode {
    FLB_OAUTH2_FRAGMENT_NONE = 0,
    FLB_OAUTH2_FRAGMENT_AFTER_STATUS_LINE,
    FLB_OAUTH2_FRAGMENT_AFTER_HEADERS,
    FLB_OAUTH2_FRAGMENT_MID_BODY
};

struct oauth2_metadata_mock_server {
    flb_sockfd_t listen_fd;
    int port;
    int stop;
    int token_post_requests;
    int metadata_get_requests;
    int response_status;
    int expires_in;
    /* Response fragmentation knobs (see enum above). */
    int fragment_mode;
    int fragment_delay_us;
    char metadata_path[128];
    char response_body[MOCK_BODY_SIZE];
    char latest_request[MOCK_BODY_SIZE];
    pthread_t thread;
#ifdef _WIN32
    int wsa_initialized;
#endif
};

static int compose_http_response_buffer(char *buffer, size_t buffer_size,
                                        int status, const char *body,
                                        int *body_offset)
{
    int body_len = 0;
    int header_len;
    int response_len;

    if (body != NULL) {
        body_len = (int) strlen(body);
    }

    header_len = snprintf(buffer, buffer_size,
                          "HTTP/1.1 %d\r\n"
                          "Content-Length: %d\r\n"
                          "Content-Type: application/json\r\n"
                          "Connection: close\r\n\r\n",
                          status, body_len);
    if (header_len < 0 || (size_t) header_len >= buffer_size) {
        return -1;
    }

    response_len = header_len + body_len;
    if ((size_t) response_len >= buffer_size) {
        return -1;
    }

    if (body_len > 0) {
        memcpy(buffer + header_len, body, body_len);
    }
    buffer[response_len] = '\0';

    if (body_offset != NULL) {
        *body_offset = header_len;
    }
    return response_len;
}

static int send_all(flb_sockfd_t fd, const char *buf, int len)
{
    int total = 0;
    ssize_t sent;

    while (total < len) {
        sent = send(fd, buf + total, len - total, 0);
        if (sent <= 0) {
            return -1;
        }
        total += (int) sent;
    }
    return 0;
}

static void mock_segment_delay(int delay_us)
{
    if (delay_us <= 0) {
        return;
    }
#ifdef _WIN32
    Sleep((delay_us + 999) / 1000);
#else
    usleep(delay_us);
#endif
}

static void compose_http_response(flb_sockfd_t fd, int status, const char *body)
{
    char buffer[MOCK_BODY_SIZE];
    int response_len;

    response_len = compose_http_response_buffer(buffer, sizeof(buffer),
                                                status, body, NULL);
    if (response_len < 0) {
        return;
    }

    send_all(fd, buffer, response_len);
}

static void compose_http_response_fragmented(flb_sockfd_t fd, int status,
                                             const char *body,
                                             int mode, int delay_us)
{
    char buffer[MOCK_BODY_SIZE];
    int response_len;
    int body_offset = 0;
    int body_len;
    int split = -1;
    const char *crlf;
    int on = 1;

    response_len = compose_http_response_buffer(buffer, sizeof(buffer),
                                                status, body, &body_offset);
    if (response_len < 0) {
        return;
    }

    body_len = response_len - body_offset;

    /* Reduce Nagle-induced merging so the kernel ships our writes promptly. */
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (const char *) &on, sizeof(on));

    switch (mode) {
    case FLB_OAUTH2_FRAGMENT_AFTER_STATUS_LINE:
        crlf = strstr(buffer, "\r\n");
        if (crlf != NULL) {
            split = (int) (crlf - buffer) + 2;
        }
        break;
    case FLB_OAUTH2_FRAGMENT_AFTER_HEADERS:
        if (body_offset > 0 && body_offset < response_len) {
            split = body_offset;
        }
        break;
    case FLB_OAUTH2_FRAGMENT_MID_BODY:
        if (body_len > 1) {
            split = body_offset + body_len / 2;
        }
        break;
    case FLB_OAUTH2_FRAGMENT_NONE:
    default:
        break;
    }

    if (split <= 0 || split >= response_len) {
        send_all(fd, buffer, response_len);
        return;
    }

    if (send_all(fd, buffer, split) != 0) {
        return;
    }
    mock_segment_delay(delay_us);
    send_all(fd, buffer + split, response_len - split);
}

static int request_content_length(const char *request)
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

static void *oauth2_metadata_mock_server_thread(void *data)
{
    int content_len;
    struct oauth2_metadata_mock_server *server =
        (struct oauth2_metadata_mock_server *) data;
    const char *headers_end;
    flb_sockfd_t client_fd;
    fd_set rfds;
    struct timeval tv;
    char buffer[MOCK_BODY_SIZE];
    ssize_t total;
    ssize_t n;
    size_t copy_len;

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

        memset(buffer, 0, sizeof(buffer));
        total = 0;

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
            content_len = request_content_length(buffer);
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

        copy_len = (size_t) total;
        if (copy_len >= sizeof(server->latest_request)) {
            copy_len = sizeof(server->latest_request) - 1;
        }
        memcpy(server->latest_request, buffer, copy_len);
        server->latest_request[copy_len] = '\0';

        if (strncmp(buffer, "POST ", 5) == 0) {
            server->token_post_requests++;
        }
        else if (strncmp(buffer, "GET ", 4) == 0 &&
                 server->metadata_path[0] != '\0' &&
                 strstr(buffer, server->metadata_path) != NULL) {
            server->metadata_get_requests++;
        }

        if (server->fragment_mode != FLB_OAUTH2_FRAGMENT_NONE) {
            compose_http_response_fragmented(client_fd,
                                             server->response_status,
                                             server->response_body,
                                             server->fragment_mode,
                                             server->fragment_delay_us);
        }
        else {
            compose_http_response(client_fd, server->response_status,
                                  server->response_body);
        }
        flb_socket_close(client_fd);
    }

    return NULL;
}

static int oauth2_metadata_mock_server_start(
        struct oauth2_metadata_mock_server *server)
{
    int on = 1;
    struct sockaddr_in addr;
    socklen_t len;
#ifdef _WIN32
    WSADATA wsa_data;
    int wsa_result;
#endif

    server->stop = 0;
    server->token_post_requests = 0;
    server->metadata_get_requests = 0;
    server->latest_request[0] = '\0';

#ifdef _WIN32
    wsa_result = WSAStartup(MAKEWORD(2, 2), &wsa_data);
    if (wsa_result != 0) {
        flb_errno();
        return -1;
    }
    server->wsa_initialized = 1;
#endif

    server->listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server->listen_fd == FLB_INVALID_SOCKET) {
        flb_errno();
        return -1;
    }

    setsockopt(server->listen_fd, SOL_SOCKET, SO_REUSEADDR,
               (const char *) &on, sizeof(on));

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;

    if (bind(server->listen_fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
        flb_errno();
        flb_socket_close(server->listen_fd);
        return -1;
    }

    if (listen(server->listen_fd, 4) < 0) {
        flb_errno();
        flb_socket_close(server->listen_fd);
        return -1;
    }

    len = sizeof(addr);
    memset(&addr, 0, sizeof(addr));
    if (getsockname(server->listen_fd, (struct sockaddr *) &addr, &len) < 0) {
        flb_errno();
        flb_socket_close(server->listen_fd);
        return -1;
    }

    server->port = ntohs(addr.sin_port);
    flb_net_socket_nonblocking(server->listen_fd);

    if (pthread_create(&server->thread, NULL,
                       oauth2_metadata_mock_server_thread, server) != 0) {
        flb_socket_close(server->listen_fd);
        return -1;
    }

    return 0;
}

static void oauth2_metadata_mock_server_stop(
        struct oauth2_metadata_mock_server *server)
{
    if (server->listen_fd != FLB_INVALID_SOCKET) {
        server->stop = 1;
        shutdown(server->listen_fd, SHUT_RDWR);
        pthread_join(server->thread, NULL);
        flb_socket_close(server->listen_fd);
        server->listen_fd = FLB_INVALID_SOCKET;
    }
#ifdef _WIN32
    if (server->wsa_initialized) {
        WSACleanup();
        server->wsa_initialized = 0;
    }
#endif
}

static int oauth2_metadata_mock_server_wait_ready(
        struct oauth2_metadata_mock_server *server)
{
    int retries = 50;
    int ret;
    flb_sockfd_t test_fd;
    struct sockaddr_in addr;

    while (retries-- > 0) {
        test_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (test_fd != FLB_INVALID_SOCKET) {
            memset(&addr, 0, sizeof(addr));
            addr.sin_family = AF_INET;
            addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            addr.sin_port = htons(server->port);

            flb_net_socket_nonblocking(test_fd);
            ret = connect(test_fd, (struct sockaddr *) &addr, sizeof(addr));
#ifdef _WIN32
            if (ret == 0 || (ret < 0 && WSAGetLastError() == WSAEWOULDBLOCK)) {
#else
            if (ret == 0 || (ret < 0 &&
                             (errno == EINPROGRESS || errno == EWOULDBLOCK))) {
#endif
                flb_socket_close(test_fd);
                flb_time_msleep(10);
                return 0;
            }
            flb_socket_close(test_fd);
        }
        flb_time_msleep(20);
    }

    return -1;
}

void test_token_source_parse_client_credentials(void)
{
    int out = -42;
    int ret;

    ret = oauth2_token_source_parse("client_credentials", &out);
    TEST_CHECK(ret == 0);
    TEST_CHECK(out == FLB_OAUTH2_TOKEN_SOURCE_CLIENT_CREDENTIALS);
}

void test_token_source_parse_metadata(void)
{
    int out = -42;
    int ret;

    ret = oauth2_token_source_parse("metadata", &out);
    TEST_CHECK(ret == 0);
    TEST_CHECK(out == FLB_OAUTH2_TOKEN_SOURCE_METADATA);
}

void test_token_source_parse_mixed_case(void)
{
    int out = -42;
    int ret;

    ret = oauth2_token_source_parse("Metadata", &out);
    TEST_CHECK(ret == 0);
    TEST_CHECK(out == FLB_OAUTH2_TOKEN_SOURCE_METADATA);

    out = -42;
    ret = oauth2_token_source_parse("CLIENT_credentials", &out);
    TEST_CHECK(ret == 0);
    TEST_CHECK(out == FLB_OAUTH2_TOKEN_SOURCE_CLIENT_CREDENTIALS);
}

void test_metadata_split_header_simple(void)
{
    int ret;
    flb_sds_t name = NULL;
    flb_sds_t value = NULL;

    ret = oauth2_metadata_split_header("X-Custom: value", &name, &value);
    TEST_CHECK(ret == 0);
    TEST_CHECK(name != NULL);
    TEST_CHECK(value != NULL);
    if (name && value) {
        TEST_CHECK(strcmp(name, "X-Custom") == 0);
        TEST_CHECK(strcmp(value, "value") == 0);
    }

    flb_sds_destroy(name);
    flb_sds_destroy(value);
}

void test_metadata_split_header_no_space_after_colon(void)
{
    int ret;
    flb_sds_t name = NULL;
    flb_sds_t value = NULL;

    ret = oauth2_metadata_split_header("X-Custom:value", &name, &value);
    TEST_CHECK(ret == 0);
    TEST_CHECK(name != NULL);
    TEST_CHECK(value != NULL);
    if (name && value) {
        TEST_CHECK(strcmp(name, "X-Custom") == 0);
        TEST_CHECK(strcmp(value, "value") == 0);
    }

    flb_sds_destroy(name);
    flb_sds_destroy(value);
}

void test_metadata_split_header_extra_whitespace(void)
{
    int ret;
    flb_sds_t name = NULL;
    flb_sds_t value = NULL;

    ret = oauth2_metadata_split_header(
            "  X-Custom :   value with spaces   ", &name, &value);
    TEST_CHECK(ret == 0);
    TEST_CHECK(name != NULL);
    TEST_CHECK(value != NULL);
    if (name && value) {
        TEST_CHECK(strcmp(name, "X-Custom") == 0);
        TEST_CHECK(strcmp(value, "value with spaces") == 0);
    }

    flb_sds_destroy(name);
    flb_sds_destroy(value);
}

void test_metadata_split_header_multiple_colons(void)
{
    int ret;
    flb_sds_t name = NULL;
    flb_sds_t value = NULL;

    ret = oauth2_metadata_split_header(
            "Authorization: Bearer abc:def", &name, &value);
    TEST_CHECK(ret == 0);
    TEST_CHECK(name != NULL);
    TEST_CHECK(value != NULL);
    if (name && value) {
        TEST_CHECK(strcmp(name, "Authorization") == 0);
        TEST_CHECK(strcmp(value, "Bearer abc:def") == 0);
    }

    flb_sds_destroy(name);
    flb_sds_destroy(value);
}

void test_metadata_split_header_missing_colon(void)
{
    int ret;
    flb_sds_t name = (flb_sds_t) 0xdeadbeef;
    flb_sds_t value = (flb_sds_t) 0xdeadbeef;

    ret = oauth2_metadata_split_header("NoColonHere", &name, &value);
    TEST_CHECK(ret == -1);
    TEST_CHECK(name == NULL);
    TEST_CHECK(value == NULL);
}

void test_metadata_split_header_empty_value(void)
{
    int ret;
    flb_sds_t name = (flb_sds_t) 0xdeadbeef;
    flb_sds_t value = (flb_sds_t) 0xdeadbeef;

    ret = oauth2_metadata_split_header("X-Custom:    ", &name, &value);
    TEST_CHECK(ret == -1);
    TEST_CHECK(name == NULL);
    TEST_CHECK(value == NULL);
}

void test_metadata_split_header_injection_rejected(void)
{
    int ret;
    flb_sds_t name = (flb_sds_t) 0xdeadbeef;
    flb_sds_t value = (flb_sds_t) 0xdeadbeef;

    /* Embedded CRLF in the value must be rejected as header injection. */
    ret = oauth2_metadata_split_header(
            "X-Custom: good\r\nEvil: payload", &name, &value);
    TEST_CHECK(ret == -1);
    TEST_CHECK(name == NULL);
    TEST_CHECK(value == NULL);

    /* Embedded LF in the name must also be rejected. */
    name = (flb_sds_t) 0xdeadbeef;
    value = (flb_sds_t) 0xdeadbeef;
    ret = oauth2_metadata_split_header("Bad\nName: value", &name, &value);
    TEST_CHECK(ret == -1);
    TEST_CHECK(name == NULL);
    TEST_CHECK(value == NULL);
}

static void build_url_set_strings(struct flb_oauth2 *ctx,
                                  const char *metadata_url,
                                  const char *scope,
                                  const char *audience)
{
    memset(ctx, 0, sizeof(*ctx));
    if (metadata_url) {
        ctx->cfg.metadata_url = flb_sds_create(metadata_url);
    }
    if (scope) {
        ctx->cfg.scope = flb_sds_create(scope);
    }
    if (audience) {
        ctx->cfg.audience = flb_sds_create(audience);
    }
}

static void build_url_destroy_strings(struct flb_oauth2 *ctx)
{
    if (ctx->cfg.metadata_url) {
        flb_sds_destroy(ctx->cfg.metadata_url);
        ctx->cfg.metadata_url = NULL;
    }
    if (ctx->cfg.scope) {
        flb_sds_destroy(ctx->cfg.scope);
        ctx->cfg.scope = NULL;
    }
    if (ctx->cfg.audience) {
        flb_sds_destroy(ctx->cfg.audience);
        ctx->cfg.audience = NULL;
    }
}

void test_metadata_build_url_bare(void)
{
    struct flb_oauth2 ctx;
    flb_sds_t url;

    build_url_set_strings(&ctx, "http://169.254.169.254/token", NULL, NULL);

    url = oauth2_metadata_build_url(&ctx);
    TEST_CHECK(url != NULL);
    if (url) {
        TEST_CHECK(strcmp(url, "http://169.254.169.254/token") == 0);
        flb_sds_destroy(url);
    }

    build_url_destroy_strings(&ctx);
}

void test_metadata_build_url_scope_only(void)
{
    struct flb_oauth2 ctx;
    flb_sds_t url;

    build_url_set_strings(&ctx, "http://example.com/token",
                          "monitoring", NULL);

    url = oauth2_metadata_build_url(&ctx);
    TEST_CHECK(url != NULL);
    if (url) {
        TEST_CHECK(strcmp(url,
                          "http://example.com/token?scope=monitoring") == 0);
        flb_sds_destroy(url);
    }

    build_url_destroy_strings(&ctx);
}

void test_metadata_build_url_audience_only(void)
{
    struct flb_oauth2 ctx;
    flb_sds_t url;

    build_url_set_strings(&ctx, "http://example.com/token",
                          NULL, "https://api.example.com");

    url = oauth2_metadata_build_url(&ctx);
    TEST_CHECK(url != NULL);
    if (url) {
        TEST_CHECK(strcmp(url,
                          "http://example.com/token"
                          "?audience=https%3A//api.example.com") == 0);
        flb_sds_destroy(url);
    }

    build_url_destroy_strings(&ctx);
}

void test_metadata_build_url_scope_and_audience(void)
{
    struct flb_oauth2 ctx;
    flb_sds_t url;

    build_url_set_strings(&ctx, "http://example.com/token",
                          "monitoring", "https://api.example.com");

    url = oauth2_metadata_build_url(&ctx);
    TEST_CHECK(url != NULL);
    if (url) {
        TEST_CHECK(strcmp(url,
                          "http://example.com/token"
                          "?scope=monitoring"
                          "&audience=https%3A//api.example.com") == 0);
        flb_sds_destroy(url);
    }

    build_url_destroy_strings(&ctx);
}

void test_metadata_build_url_scope_special_chars(void)
{
    struct flb_oauth2 ctx;
    flb_sds_t url;

    build_url_set_strings(&ctx, "http://example.com/token",
                          "monitoring write", NULL);

    url = oauth2_metadata_build_url(&ctx);
    TEST_CHECK(url != NULL);
    if (url) {
        TEST_CHECK(strcmp(url,
                          "http://example.com/token"
                          "?scope=monitoring%20write") == 0);
        flb_sds_destroy(url);
    }

    build_url_destroy_strings(&ctx);
}

void test_metadata_build_url_existing_query(void)
{
    struct flb_oauth2 ctx;
    flb_sds_t url;

    build_url_set_strings(&ctx,
                          "http://169.254.169.254/token?api-version=2018-02-01",
                          "monitoring", NULL);

    url = oauth2_metadata_build_url(&ctx);
    TEST_CHECK(url != NULL);
    if (url) {
        TEST_CHECK(strcmp(url,
                          "http://169.254.169.254/token"
                          "?api-version=2018-02-01"
                          "&scope=monitoring") == 0);
        flb_sds_destroy(url);
    }

    build_url_destroy_strings(&ctx);
}

void test_metadata_build_url_query_delimiter_injection(void)
{
    struct flb_oauth2 ctx;
    flb_sds_t url;

    /* scope/audience values that include the query delimiters '?', '&', '='
     * must be percent-encoded so they cannot inject extra parameters into the
     * metadata request URL. */
    build_url_set_strings(&ctx, "http://example.com/token",
                          "foo&injected=evil", "a=b?c");

    url = oauth2_metadata_build_url(&ctx);
    TEST_CHECK(url != NULL);
    if (url) {
        TEST_CHECK(strcmp(url,
                          "http://example.com/token"
                          "?scope=foo%26injected%3Devil"
                          "&audience=a%3Db%3Fc") == 0);
        flb_sds_destroy(url);
    }

    build_url_destroy_strings(&ctx);
}

/* Standalone mock self-tests, run before the oauth2 client tests below. */

#define FRAG_TEST_BODY \
    "{\"access_token\":\"frag-token-1\"," \
    "\"token_type\":\"Bearer\"," \
    "\"expires_in\":3600}"

static int frag_round_trip_get(int port, const char *path, char *out,
                               size_t out_size)
{
    flb_sockfd_t fd;
    struct sockaddr_in addr;
    char request[256];
    int request_len;
    int total = 0;
    int sent_total;
    ssize_t n;
    ssize_t sent;

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd == FLB_INVALID_SOCKET) {
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(port);

    if (connect(fd, (struct sockaddr *) &addr, sizeof(addr)) != 0) {
        flb_socket_close(fd);
        return -1;
    }

    request_len = snprintf(request, sizeof(request),
                           "GET %s HTTP/1.1\r\n"
                           "Host: 127.0.0.1\r\n"
                           "Connection: close\r\n\r\n",
                           path);
    if (request_len < 0) {
        flb_socket_close(fd);
        return -1;
    }

    sent_total = 0;
    while (sent_total < request_len) {
        sent = send(fd, request + sent_total,
                    request_len - sent_total, 0);
        if (sent <= 0) {
            flb_socket_close(fd);
            return -1;
        }
        sent_total += (int) sent;
    }

    /* The server uses Connection: close, so read until peer FIN. */
    while (total < (int) out_size - 1) {
        n = recv(fd, out + total, (int) (out_size - 1 - total), 0);
        if (n <= 0) {
            break;
        }
        total += (int) n;
    }
    out[total] = '\0';

    flb_socket_close(fd);
    return total;
}

static void frag_assert_full_response(const char *raw, int raw_len,
                                      int expected_status,
                                      const char *expected_body)
{
    char status_prefix[64];
    const char *eoh;
    const char *body;
    int header_len;
    int body_len;

    snprintf(status_prefix, sizeof(status_prefix),
             "HTTP/1.1 %d", expected_status);

    TEST_CHECK(raw_len > 0);
    TEST_CHECK(strncmp(raw, status_prefix, strlen(status_prefix)) == 0);

    eoh = strstr(raw, "\r\n\r\n");
    TEST_CHECK(eoh != NULL);
    if (eoh == NULL) {
        return;
    }

    body = eoh + 4;
    header_len = (int) (body - raw);
    body_len = raw_len - header_len;

    TEST_CHECK(body_len == (int) strlen(expected_body));
    TEST_CHECK(strncmp(body, expected_body, strlen(expected_body)) == 0);
}

static void frag_run_round_trip(struct oauth2_metadata_mock_server *server,
                                int mode)
{
    char raw[MOCK_BODY_SIZE];
    int raw_len;

    server->fragment_mode = mode;

    raw_len = frag_round_trip_get(server->port, server->metadata_path,
                                  raw, sizeof(raw));
    frag_assert_full_response(raw, raw_len, server->response_status,
                              server->response_body);
}

void test_metadata_mock_fragmented_round_trip(void)
{
    int ret;
    struct oauth2_metadata_mock_server server;

    memset(&server, 0, sizeof(server));
    snprintf(server.metadata_path, sizeof(server.metadata_path), "/token");
    server.response_status = 200;
    snprintf(server.response_body, sizeof(server.response_body),
             "%s", FRAG_TEST_BODY);
    /* 5 ms inter-segment delay -- enough to let the kernel ship the first
     * write before the second one is enqueued, while keeping the test fast. */
    server.fragment_delay_us = 5000;

    ret = oauth2_metadata_mock_server_start(&server);
    TEST_CHECK(ret == 0);

    ret = oauth2_metadata_mock_server_wait_ready(&server);
    TEST_CHECK(ret == 0);
    flb_time_msleep(50);

    frag_run_round_trip(&server, FLB_OAUTH2_FRAGMENT_NONE);
    frag_run_round_trip(&server, FLB_OAUTH2_FRAGMENT_AFTER_STATUS_LINE);
    frag_run_round_trip(&server, FLB_OAUTH2_FRAGMENT_AFTER_HEADERS);
    frag_run_round_trip(&server, FLB_OAUTH2_FRAGMENT_MID_BODY);

    oauth2_metadata_mock_server_stop(&server);
}

static struct flb_oauth2 *create_metadata_oauth_ctx(
        struct flb_config *config,
        struct oauth2_metadata_mock_server *server,
        const char *metadata_header)
{
    struct flb_oauth2 *ctx;
    struct flb_oauth2_config cfg;

    memset(&cfg, 0, sizeof(cfg));
    cfg.enabled = FLB_TRUE;
    cfg.auth_method = FLB_OAUTH2_AUTH_METHOD_BASIC;
    cfg.token_source = FLB_OAUTH2_TOKEN_SOURCE_METADATA;
    cfg.refresh_skew = 60;

    cfg.token_url = flb_sds_create_size(64);
    if (!cfg.token_url) {
        return NULL;
    }
    flb_sds_printf(&cfg.token_url, "http://127.0.0.1:%d%s",
                   server->port, server->metadata_path);

    cfg.metadata_url = flb_sds_create_size(64);
    if (!cfg.metadata_url) {
        flb_sds_destroy(cfg.token_url);
        return NULL;
    }
    flb_sds_printf(&cfg.metadata_url, "http://127.0.0.1:%d%s",
                   server->port, server->metadata_path);

    if (metadata_header) {
        cfg.metadata_header = flb_sds_create(metadata_header);
    }

    ctx = flb_oauth2_create_from_config(config, &cfg);
    flb_oauth2_config_destroy(&cfg);

    return ctx;
}

/*
 * Drive oauth2_metadata_refresh_locked against the fragmenting mock with each
 * fragmentation mode and assert ret == 0 and ctx->access_token matches the
 * served value.
 */

#define FRAG_REFRESH_BODY \
    "{\"access_token\":\"frag-meta-token\"," \
    "\"token_type\":\"Bearer\"," \
    "\"expires_in\":3600}"

static void run_metadata_refresh_with_fragmentation(int fragment_mode,
                                                    int fragment_delay_us)
{
    int ret;
    struct flb_config *config;
    struct flb_oauth2 *ctx;
    struct oauth2_metadata_mock_server server;

    memset(&server, 0, sizeof(server));
    snprintf(server.metadata_path, sizeof(server.metadata_path), "/token");
    server.response_status = 200;
    snprintf(server.response_body, sizeof(server.response_body),
             "%s", FRAG_REFRESH_BODY);
    server.fragment_mode = fragment_mode;
    server.fragment_delay_us = fragment_delay_us;

    config = flb_config_init();
    TEST_CHECK(config != NULL);

    ret = oauth2_metadata_mock_server_start(&server);
    TEST_CHECK(ret == 0);

    ctx = create_metadata_oauth_ctx(config, &server, NULL);
    TEST_ASSERT(ctx != NULL);

    ret = oauth2_metadata_mock_server_wait_ready(&server);
    TEST_CHECK(ret == 0);
    flb_time_msleep(50);

    /*
     * Post-fix invariant: every fragmentation mode the metadata endpoint
     * may legitimately produce on the wire must yield a successful refresh
     * with the JSON-decoded access token visible to the caller.
     */
    ret = oauth2_metadata_refresh_locked(ctx);
    TEST_CHECK(ret == 0);
    TEST_CHECK(ctx->access_token != NULL);
    if (ctx->access_token) {
        TEST_CHECK(strcmp(ctx->access_token, "frag-meta-token") == 0);
    }

    flb_oauth2_destroy(ctx);
    oauth2_metadata_mock_server_stop(&server);
    flb_config_exit(config);
}

void test_metadata_refresh_fragmented_after_status_line(void)
{
    run_metadata_refresh_with_fragmentation(
        FLB_OAUTH2_FRAGMENT_AFTER_STATUS_LINE, 5000);
}

void test_metadata_refresh_fragmented_after_headers(void)
{
    run_metadata_refresh_with_fragmentation(
        FLB_OAUTH2_FRAGMENT_AFTER_HEADERS, 5000);
}

void test_metadata_refresh_fragmented_mid_body(void)
{
    run_metadata_refresh_with_fragmentation(
        FLB_OAUTH2_FRAGMENT_MID_BODY, 5000);
}

void test_metadata_refresh_success(void)
{
    int ret;
    struct flb_config *config;
    struct flb_oauth2 *ctx;
    struct oauth2_metadata_mock_server server;

    memset(&server, 0, sizeof(server));
    snprintf(server.metadata_path, sizeof(server.metadata_path), "/token");
    server.response_status = 200;
    snprintf(server.response_body, sizeof(server.response_body),
             "{\"access_token\":\"meta-token-1\","
             "\"token_type\":\"Bearer\","
             "\"expires_in\":3600}");

    config = flb_config_init();
    TEST_CHECK(config != NULL);

    ret = oauth2_metadata_mock_server_start(&server);
    TEST_CHECK(ret == 0);

    ctx = create_metadata_oauth_ctx(config, &server,
                                    "Metadata-Flavor: Google");
    TEST_CHECK(ctx != NULL);

    ret = oauth2_metadata_mock_server_wait_ready(&server);
    TEST_CHECK(ret == 0);
    flb_time_msleep(50);

    ret = oauth2_metadata_refresh_locked(ctx);
    TEST_CHECK(ret == 0);
    TEST_CHECK(ctx->access_token != NULL);
    if (ctx->access_token) {
        TEST_CHECK(strcmp(ctx->access_token, "meta-token-1") == 0);
    }
    TEST_CHECK(ctx->token_type != NULL);
    if (ctx->token_type) {
        TEST_CHECK(strcmp(ctx->token_type, "Bearer") == 0);
    }
    TEST_CHECK(ctx->expires_in > 0);
    TEST_CHECK(server.metadata_get_requests >= 1);
    TEST_CHECK(strstr(server.latest_request, "GET ") != NULL);
    TEST_CHECK(strstr(server.latest_request, "Metadata-Flavor: Google")
               != NULL);

    flb_oauth2_destroy(ctx);
    oauth2_metadata_mock_server_stop(&server);
    flb_config_exit(config);
}

void test_metadata_refresh_4xx_response(void)
{
    int ret;
    struct flb_config *config;
    struct flb_oauth2 *ctx;
    struct oauth2_metadata_mock_server server;

    memset(&server, 0, sizeof(server));
    snprintf(server.metadata_path, sizeof(server.metadata_path), "/token");
    server.response_status = 200;
    snprintf(server.response_body, sizeof(server.response_body),
             "{\"access_token\":\"initial-token\","
             "\"token_type\":\"Bearer\","
             "\"expires_in\":3600}");

    config = flb_config_init();
    TEST_CHECK(config != NULL);

    ret = oauth2_metadata_mock_server_start(&server);
    TEST_CHECK(ret == 0);

    ctx = create_metadata_oauth_ctx(config, &server, NULL);
    TEST_ASSERT(ctx != NULL);

    ret = oauth2_metadata_mock_server_wait_ready(&server);
    TEST_CHECK(ret == 0);
    flb_time_msleep(50);

    /* First refresh succeeds via the production path: the token is set up
     * with all the invariants (access_token, token_type, expires_at). */
    ret = oauth2_metadata_refresh_locked(ctx);
    TEST_ASSERT(ret == 0);
    TEST_ASSERT(ctx->access_token != NULL);
    TEST_CHECK(strcmp(ctx->access_token, "initial-token") == 0);

    /* Reconfigure the server to fail with 4xx and refresh again: the cached
     * token must be preserved across the failure. */
    server.response_status = 403;
    snprintf(server.response_body, sizeof(server.response_body),
             "{\"error\":\"forbidden\"}");

    ret = oauth2_metadata_refresh_locked(ctx);
    TEST_CHECK(ret == -1);
    TEST_ASSERT(ctx->access_token != NULL);
    TEST_CHECK(strcmp(ctx->access_token, "initial-token") == 0);
    TEST_CHECK(ctx->token_type != NULL &&
               strcmp(ctx->token_type, "Bearer") == 0);
    TEST_CHECK(ctx->expires_at > time(NULL));

    flb_oauth2_destroy(ctx);
    oauth2_metadata_mock_server_stop(&server);
    flb_config_exit(config);
}

void test_metadata_refresh_5xx_response(void)
{
    int ret;
    struct flb_config *config;
    struct flb_oauth2 *ctx;
    struct oauth2_metadata_mock_server server;

    memset(&server, 0, sizeof(server));
    snprintf(server.metadata_path, sizeof(server.metadata_path), "/token");
    server.response_status = 200;
    snprintf(server.response_body, sizeof(server.response_body),
             "{\"access_token\":\"initial-token\","
             "\"token_type\":\"Bearer\","
             "\"expires_in\":3600}");

    config = flb_config_init();
    TEST_CHECK(config != NULL);

    ret = oauth2_metadata_mock_server_start(&server);
    TEST_CHECK(ret == 0);

    ctx = create_metadata_oauth_ctx(config, &server, NULL);
    TEST_ASSERT(ctx != NULL);

    ret = oauth2_metadata_mock_server_wait_ready(&server);
    TEST_CHECK(ret == 0);
    flb_time_msleep(50);

    ret = oauth2_metadata_refresh_locked(ctx);
    TEST_ASSERT(ret == 0);
    TEST_ASSERT(ctx->access_token != NULL);
    TEST_CHECK(strcmp(ctx->access_token, "initial-token") == 0);

    server.response_status = 503;
    snprintf(server.response_body, sizeof(server.response_body),
             "service unavailable");

    ret = oauth2_metadata_refresh_locked(ctx);
    TEST_CHECK(ret == -1);
    TEST_ASSERT(ctx->access_token != NULL);
    TEST_CHECK(strcmp(ctx->access_token, "initial-token") == 0);
    TEST_CHECK(ctx->token_type != NULL &&
               strcmp(ctx->token_type, "Bearer") == 0);
    TEST_CHECK(ctx->expires_at > time(NULL));

    flb_oauth2_destroy(ctx);
    oauth2_metadata_mock_server_stop(&server);
    flb_config_exit(config);
}

void test_metadata_refresh_malformed_json(void)
{
    int ret;
    struct flb_config *config;
    struct flb_oauth2 *ctx;
    struct oauth2_metadata_mock_server server;

    memset(&server, 0, sizeof(server));
    snprintf(server.metadata_path, sizeof(server.metadata_path), "/token");
    server.response_status = 200;
    snprintf(server.response_body, sizeof(server.response_body),
             "not a json {{{");

    config = flb_config_init();
    TEST_CHECK(config != NULL);

    ret = oauth2_metadata_mock_server_start(&server);
    TEST_CHECK(ret == 0);

    ctx = create_metadata_oauth_ctx(config, &server, NULL);
    TEST_CHECK(ctx != NULL);

    ret = oauth2_metadata_mock_server_wait_ready(&server);
    TEST_CHECK(ret == 0);
    flb_time_msleep(50);

    ret = oauth2_metadata_refresh_locked(ctx);
    TEST_CHECK(ret == -1);
    TEST_CHECK(ctx->access_token == NULL);

    flb_oauth2_destroy(ctx);
    oauth2_metadata_mock_server_stop(&server);
    flb_config_exit(config);
}

void test_metadata_refresh_invalid_metadata_header(void)
{
    int ret;
    struct flb_config *config;
    struct flb_oauth2 *ctx;
    struct oauth2_metadata_mock_server server;

    memset(&server, 0, sizeof(server));
    snprintf(server.metadata_path, sizeof(server.metadata_path), "/token");
    server.response_status = 200;
    snprintf(server.response_body, sizeof(server.response_body),
             "{\"access_token\":\"meta-token\","
             "\"token_type\":\"Bearer\","
             "\"expires_in\":3600}");

    config = flb_config_init();
    TEST_CHECK(config != NULL);

    ret = oauth2_metadata_mock_server_start(&server);
    TEST_CHECK(ret == 0);

    ctx = create_metadata_oauth_ctx(config, &server, "NoColon");
    TEST_ASSERT(ctx != NULL);

    ret = oauth2_metadata_mock_server_wait_ready(&server);
    TEST_CHECK(ret == 0);
    flb_time_msleep(50);

    ret = oauth2_metadata_refresh_locked(ctx);
    TEST_CHECK(ret == -1);
    TEST_CHECK(server.metadata_get_requests == 0);
    TEST_CHECK(ctx->access_token == NULL);

    flb_oauth2_destroy(ctx);
    oauth2_metadata_mock_server_stop(&server);
    flb_config_exit(config);
}

void test_metadata_refresh_url_wiring(void)
{
    int ret;
    const char *request_line_end;
    const char *space_after_method;
    char request_line[1024];
    size_t request_line_len;
    struct flb_config *config;
    struct flb_oauth2 *ctx;
    struct flb_oauth2_config cfg;
    struct oauth2_metadata_mock_server server;

    memset(&server, 0, sizeof(server));
    snprintf(server.metadata_path, sizeof(server.metadata_path), "/token");
    server.response_status = 200;
    snprintf(server.response_body, sizeof(server.response_body),
             "{\"access_token\":\"wired-token\","
             "\"token_type\":\"Bearer\","
             "\"expires_in\":3600}");

    config = flb_config_init();
    TEST_CHECK(config != NULL);

    ret = oauth2_metadata_mock_server_start(&server);
    TEST_CHECK(ret == 0);

    memset(&cfg, 0, sizeof(cfg));
    cfg.enabled = FLB_TRUE;
    cfg.auth_method = FLB_OAUTH2_AUTH_METHOD_BASIC;
    cfg.token_source = FLB_OAUTH2_TOKEN_SOURCE_METADATA;
    cfg.refresh_skew = 60;
    cfg.metadata_url = flb_sds_create_size(64);
    TEST_CHECK(cfg.metadata_url != NULL);
    flb_sds_printf(&cfg.metadata_url, "http://127.0.0.1:%d/token",
                   server.port);
    cfg.scope = flb_sds_create("monitoring write");
    cfg.audience = flb_sds_create("https://api.example.com");

    ctx = flb_oauth2_create_from_config(config, &cfg);
    flb_oauth2_config_destroy(&cfg);
    TEST_ASSERT(ctx != NULL);

    ret = oauth2_metadata_mock_server_wait_ready(&server);
    TEST_CHECK(ret == 0);
    flb_time_msleep(50);

    ret = oauth2_metadata_refresh_locked(ctx);
    TEST_CHECK(ret == 0);
    TEST_CHECK(server.metadata_get_requests >= 1);

    /* Extract the request line (everything up to the first CRLF) and assert
     * it is exactly "GET <path-with-encoded-query> HTTP/1.1". */
    request_line_end = strstr(server.latest_request, "\r\n");
    TEST_ASSERT(request_line_end != NULL);
    request_line_len = (size_t)(request_line_end - server.latest_request);
    TEST_ASSERT(request_line_len < sizeof(request_line));
    memcpy(request_line, server.latest_request, request_line_len);
    request_line[request_line_len] = '\0';

    TEST_CHECK(strncmp(request_line, "GET ", 4) == 0);
    space_after_method = request_line + 4;
    TEST_CHECK(strstr(space_after_method,
                      "/token?scope=monitoring%20write"
                      "&audience=https%3A//api.example.com") != NULL);

    flb_oauth2_destroy(ctx);
    oauth2_metadata_mock_server_stop(&server);
    flb_config_exit(config);
}

void test_metadata_refresh_header_wiring(void)
{
    int ret;
    const char *line;
    const char *line_end;
    int saw_metadata_flavor = 0;
    int saw_unexpected_metadata_header = 0;
    struct flb_config *config;
    struct flb_oauth2 *ctx;
    struct oauth2_metadata_mock_server server;

    memset(&server, 0, sizeof(server));
    snprintf(server.metadata_path, sizeof(server.metadata_path), "/token");
    server.response_status = 200;
    snprintf(server.response_body, sizeof(server.response_body),
             "{\"access_token\":\"hdr-token\","
             "\"token_type\":\"Bearer\","
             "\"expires_in\":3600}");

    config = flb_config_init();
    TEST_CHECK(config != NULL);

    ret = oauth2_metadata_mock_server_start(&server);
    TEST_CHECK(ret == 0);

    ctx = create_metadata_oauth_ctx(config, &server,
                                    "Metadata-Flavor: Google");
    TEST_ASSERT(ctx != NULL);

    ret = oauth2_metadata_mock_server_wait_ready(&server);
    TEST_CHECK(ret == 0);
    flb_time_msleep(50);

    ret = oauth2_metadata_refresh_locked(ctx);
    TEST_CHECK(ret == 0);
    TEST_CHECK(server.metadata_get_requests >= 1);

    /* Verify the split helper preserves header name and value end-to-end. */
    line = strstr(server.latest_request, "\r\n");
    if (line) {
        line += 2;
    }
    while (line && *line && strncmp(line, "\r\n", 2) != 0) {
        line_end = strstr(line, "\r\n");
        if (!line_end) {
            break;
        }
        if ((size_t)(line_end - line) == strlen("Metadata-Flavor: Google") &&
            strncmp(line, "Metadata-Flavor: Google",
                    strlen("Metadata-Flavor: Google")) == 0) {
            saw_metadata_flavor++;
        }
        else if ((size_t)(line_end - line) >=
                     strlen("Metadata-Flavor:") &&
                 strncmp(line, "Metadata-Flavor:",
                         strlen("Metadata-Flavor:")) == 0) {
            saw_unexpected_metadata_header++;
        }
        line = line_end + 2;
    }
    TEST_CHECK(saw_metadata_flavor == 1);
    TEST_CHECK(saw_unexpected_metadata_header == 0);

    flb_oauth2_destroy(ctx);
    oauth2_metadata_mock_server_stop(&server);
    flb_config_exit(config);
}

static struct flb_oauth2 *create_client_credentials_oauth_ctx(
        struct flb_config *config,
        struct oauth2_metadata_mock_server *server)
{
    struct flb_oauth2 *ctx;
    struct flb_oauth2_config cfg;

    memset(&cfg, 0, sizeof(cfg));
    cfg.enabled = FLB_TRUE;
    cfg.auth_method = FLB_OAUTH2_AUTH_METHOD_BASIC;
    cfg.token_source = FLB_OAUTH2_TOKEN_SOURCE_CLIENT_CREDENTIALS;
    cfg.refresh_skew = 60;
    cfg.client_id = flb_sds_create("id");
    cfg.client_secret = flb_sds_create("secret");

    cfg.token_url = flb_sds_create_size(64);
    if (!cfg.token_url) {
        return NULL;
    }
    flb_sds_printf(&cfg.token_url, "http://127.0.0.1:%d/token", server->port);

    ctx = flb_oauth2_create_from_config(config, &cfg);
    flb_oauth2_config_destroy(&cfg);

    return ctx;
}

void test_dispatch_routes_to_client_credentials(void)
{
    int ret;
    struct flb_config *config;
    struct flb_oauth2 *ctx;
    struct oauth2_metadata_mock_server server;

    memset(&server, 0, sizeof(server));
    server.metadata_path[0] = '\0';
    server.response_status = 200;
    snprintf(server.response_body, sizeof(server.response_body),
             "{\"access_token\":\"cc-token\","
             "\"token_type\":\"Bearer\","
             "\"expires_in\":3600}");

    config = flb_config_init();
    TEST_CHECK(config != NULL);

    ret = oauth2_metadata_mock_server_start(&server);
    TEST_CHECK(ret == 0);

    ctx = create_client_credentials_oauth_ctx(config, &server);
    TEST_CHECK(ctx != NULL);

    ret = oauth2_metadata_mock_server_wait_ready(&server);
    TEST_CHECK(ret == 0);
    flb_time_msleep(50);

    ret = oauth2_dispatch_refresh_locked(ctx);
    TEST_CHECK(ret == 0);
    TEST_CHECK(server.token_post_requests >= 1);
    TEST_CHECK(server.metadata_get_requests == 0);
    TEST_CHECK(strstr(server.latest_request, "POST ") != NULL);

    flb_oauth2_destroy(ctx);
    oauth2_metadata_mock_server_stop(&server);
    flb_config_exit(config);
}

void test_dispatch_routes_to_metadata(void)
{
    int ret;
    struct flb_config *config;
    struct flb_oauth2 *ctx;
    struct oauth2_metadata_mock_server server;

    memset(&server, 0, sizeof(server));
    snprintf(server.metadata_path, sizeof(server.metadata_path), "/token");
    server.response_status = 200;
    snprintf(server.response_body, sizeof(server.response_body),
             "{\"access_token\":\"meta-dispatch-token\","
             "\"token_type\":\"Bearer\","
             "\"expires_in\":3600}");

    config = flb_config_init();
    TEST_CHECK(config != NULL);

    ret = oauth2_metadata_mock_server_start(&server);
    TEST_CHECK(ret == 0);

    ctx = create_metadata_oauth_ctx(config, &server, NULL);
    TEST_CHECK(ctx != NULL);

    ret = oauth2_metadata_mock_server_wait_ready(&server);
    TEST_CHECK(ret == 0);
    flb_time_msleep(50);

    ret = oauth2_dispatch_refresh_locked(ctx);
    TEST_CHECK(ret == 0);
    TEST_CHECK(server.metadata_get_requests >= 1);
    TEST_CHECK(server.token_post_requests == 0);
    TEST_CHECK(strstr(server.latest_request, "GET ") != NULL);

    flb_oauth2_destroy(ctx);
    oauth2_metadata_mock_server_stop(&server);
    flb_config_exit(config);
}

void test_upstream_bound_to_metadata_url(void)
{
    int ret;
    char expected_port[16];
    struct flb_config *config;
    struct flb_oauth2 *ctx;
    struct flb_oauth2_config cfg;
    struct oauth2_metadata_mock_server server;

    memset(&server, 0, sizeof(server));
    snprintf(server.metadata_path, sizeof(server.metadata_path), "/token");
    server.response_status = 200;
    snprintf(server.response_body, sizeof(server.response_body),
             "{\"access_token\":\"bound-to-metadata\","
             "\"token_type\":\"Bearer\","
             "\"expires_in\":3600}");

    config = flb_config_init();
    TEST_CHECK(config != NULL);

    ret = oauth2_metadata_mock_server_start(&server);
    TEST_CHECK(ret == 0);

    /* token_url points at a guaranteed-unreachable port; if the upstream is
     * mistakenly bound to it the refresh will fail. metadata_url points at
     * the live mock server. */
    memset(&cfg, 0, sizeof(cfg));
    cfg.enabled = FLB_TRUE;
    cfg.auth_method = FLB_OAUTH2_AUTH_METHOD_BASIC;
    cfg.token_source = FLB_OAUTH2_TOKEN_SOURCE_METADATA;
    cfg.refresh_skew = 60;
    cfg.token_url = flb_sds_create("http://127.0.0.1:1/should-not-be-hit");
    cfg.metadata_url = flb_sds_create_size(64);
    TEST_CHECK(cfg.metadata_url != NULL);
    flb_sds_printf(&cfg.metadata_url, "http://127.0.0.1:%d/token",
                   server.port);

    ctx = flb_oauth2_create_from_config(config, &cfg);
    flb_oauth2_config_destroy(&cfg);
    TEST_CHECK(ctx != NULL);

    /* Confirm at the struct level that the upstream's host:port comes from
     * metadata_url, not token_url. */
    snprintf(expected_port, sizeof(expected_port), "%d", server.port);
    TEST_CHECK(ctx->host != NULL && strcmp(ctx->host, "127.0.0.1") == 0);
    TEST_CHECK(ctx->port != NULL && strcmp(ctx->port, expected_port) == 0);

    ret = oauth2_metadata_mock_server_wait_ready(&server);
    TEST_CHECK(ret == 0);
    flb_time_msleep(50);

    ret = oauth2_metadata_refresh_locked(ctx);
    TEST_CHECK(ret == 0);
    TEST_CHECK(ctx->access_token != NULL);
    if (ctx->access_token) {
        TEST_CHECK(strcmp(ctx->access_token, "bound-to-metadata") == 0);
    }
    TEST_CHECK(server.metadata_get_requests >= 1);

    flb_oauth2_destroy(ctx);
    oauth2_metadata_mock_server_stop(&server);
    flb_config_exit(config);
}

void test_create_from_config_metadata_missing_url(void)
{
    struct flb_config *config;
    struct flb_oauth2 *ctx;
    struct flb_oauth2_config cfg;

    config = flb_config_init();
    TEST_CHECK(config != NULL);

    memset(&cfg, 0, sizeof(cfg));
    cfg.enabled = FLB_TRUE;
    cfg.auth_method = FLB_OAUTH2_AUTH_METHOD_BASIC;
    cfg.token_source = FLB_OAUTH2_TOKEN_SOURCE_METADATA;
    cfg.refresh_skew = 60;
    /* metadata_url intentionally left NULL */

    ctx = flb_oauth2_create_from_config(config, &cfg);
    TEST_CHECK(ctx == NULL);

    flb_oauth2_config_destroy(&cfg);
    flb_config_exit(config);
}

void test_create_from_config_client_credentials_missing_token_url(void)
{
    struct flb_config *config;
    struct flb_oauth2 *ctx;
    struct flb_oauth2_config cfg;

    config = flb_config_init();
    TEST_CHECK(config != NULL);

    memset(&cfg, 0, sizeof(cfg));
    cfg.enabled = FLB_TRUE;
    cfg.auth_method = FLB_OAUTH2_AUTH_METHOD_BASIC;
    cfg.token_source = FLB_OAUTH2_TOKEN_SOURCE_CLIENT_CREDENTIALS;
    cfg.refresh_skew = 60;
    cfg.client_id = flb_sds_create("id");
    cfg.client_secret = flb_sds_create("secret");
    /* token_url intentionally left NULL */

    ctx = flb_oauth2_create_from_config(config, &cfg);
    TEST_CHECK(ctx == NULL);

    flb_oauth2_config_destroy(&cfg);
    flb_config_exit(config);
}

void test_create_from_config_invalid_token_source(void)
{
    struct flb_config *config;
    struct flb_oauth2 *ctx;
    struct flb_oauth2_config cfg;

    config = flb_config_init();
    TEST_CHECK(config != NULL);

    memset(&cfg, 0, sizeof(cfg));
    cfg.enabled = FLB_TRUE;
    cfg.auth_method = FLB_OAUTH2_AUTH_METHOD_BASIC;
    cfg.token_source = 99; /* outside the {0, 1} enum range */
    cfg.refresh_skew = 60;
    cfg.token_url = flb_sds_create("http://127.0.0.1:1/token");
    cfg.metadata_url = flb_sds_create("http://127.0.0.1:1/metadata");

    ctx = flb_oauth2_create_from_config(config, &cfg);
    TEST_CHECK(ctx == NULL);

    flb_oauth2_config_destroy(&cfg);
    flb_config_exit(config);
}

void test_create_from_config_token_source_str_metadata(void)
{
    struct flb_config *config;
    struct flb_oauth2 *ctx;
    struct flb_oauth2_config cfg;

    config = flb_config_init();
    TEST_CHECK(config != NULL);

    memset(&cfg, 0, sizeof(cfg));
    cfg.enabled = FLB_TRUE;
    cfg.auth_method = FLB_OAUTH2_AUTH_METHOD_BASIC;
    cfg.token_source = FLB_OAUTH2_TOKEN_SOURCE_CLIENT_CREDENTIALS;
    cfg.refresh_skew = 60;
    cfg.token_source_str = flb_sds_create("metadata");
    cfg.metadata_url = flb_sds_create("http://127.0.0.1:1/metadata");

    ctx = flb_oauth2_create_from_config(config, &cfg);
    TEST_CHECK(ctx != NULL);
    if (ctx) {
        TEST_CHECK(ctx->cfg.token_source ==
                   FLB_OAUTH2_TOKEN_SOURCE_METADATA);
        flb_oauth2_destroy(ctx);
    }

    flb_oauth2_config_destroy(&cfg);
    flb_config_exit(config);
}

/*
 * test_create_from_config_token_source_str_invalid asserts that an unknown
 * token_source string ('imds' is reserved for a future provider but not
 * recognised today) is rejected by flb_oauth2_create_from_config.
 */
void test_create_from_config_token_source_str_invalid(void)
{
    struct flb_config *config;
    struct flb_oauth2 *ctx;
    struct flb_oauth2_config cfg;

    config = flb_config_init();
    TEST_CHECK(config != NULL);

    memset(&cfg, 0, sizeof(cfg));
    cfg.enabled = FLB_TRUE;
    cfg.auth_method = FLB_OAUTH2_AUTH_METHOD_BASIC;
    cfg.token_source = FLB_OAUTH2_TOKEN_SOURCE_CLIENT_CREDENTIALS;
    cfg.refresh_skew = 60;
    cfg.token_source_str = flb_sds_create("imds");
    cfg.token_url = flb_sds_create("http://127.0.0.1:1/token");
    cfg.metadata_url = flb_sds_create("http://127.0.0.1:1/metadata");

    ctx = flb_oauth2_create_from_config(config, &cfg);
    TEST_CHECK(ctx == NULL);

    flb_oauth2_config_destroy(&cfg);
    flb_config_exit(config);
}

/*
 * test_resolve_token_source_metadata exercises the public helper with a
 * "metadata" string and asserts the enum is updated and 0 is returned.
 */
void test_resolve_token_source_metadata(void)
{
    int ret;
    struct flb_oauth2_config cfg;

    memset(&cfg, 0, sizeof(cfg));
    cfg.token_source = FLB_OAUTH2_TOKEN_SOURCE_CLIENT_CREDENTIALS;
    cfg.token_source_str = flb_sds_create("metadata");

    ret = flb_oauth2_config_resolve_token_source(&cfg);
    TEST_CHECK(ret == 0);
    TEST_CHECK(cfg.token_source == FLB_OAUTH2_TOKEN_SOURCE_METADATA);

    flb_sds_destroy(cfg.token_source_str);
}

/*
 * test_resolve_token_source_invalid feeds the helper an unknown identifier
 * and asserts it returns -1 and leaves cfg.token_source untouched.
 */
void test_resolve_token_source_invalid(void)
{
    int ret;
    struct flb_oauth2_config cfg;

    memset(&cfg, 0, sizeof(cfg));
    cfg.token_source = FLB_OAUTH2_TOKEN_SOURCE_CLIENT_CREDENTIALS;
    cfg.token_source_str = flb_sds_create("imds");

    ret = flb_oauth2_config_resolve_token_source(&cfg);
    TEST_CHECK(ret == -1);
    TEST_CHECK(cfg.token_source == FLB_OAUTH2_TOKEN_SOURCE_CLIENT_CREDENTIALS);

    flb_sds_destroy(cfg.token_source_str);
}

/*
 * test_resolve_token_source_noop exercises the legacy path in which the
 * caller never set token_source_str: the helper must return 0 and leave the
 * enum field at its existing value.
 */
void test_resolve_token_source_noop(void)
{
    int ret;
    struct flb_oauth2_config cfg;

    memset(&cfg, 0, sizeof(cfg));
    cfg.token_source = FLB_OAUTH2_TOKEN_SOURCE_CLIENT_CREDENTIALS;
    cfg.token_source_str = NULL;

    ret = flb_oauth2_config_resolve_token_source(&cfg);
    TEST_CHECK(ret == 0);
    TEST_CHECK(cfg.token_source == FLB_OAUTH2_TOKEN_SOURCE_CLIENT_CREDENTIALS);
}

void test_metadata_cache_hit_within_validity_window(void)
{
    int ret;
    flb_sds_t token1 = NULL;
    flb_sds_t token2 = NULL;
    struct flb_config *config;
    struct flb_oauth2 *ctx;
    struct oauth2_metadata_mock_server server;

    memset(&server, 0, sizeof(server));
    snprintf(server.metadata_path, sizeof(server.metadata_path), "/token");
    server.response_status = 200;
    snprintf(server.response_body, sizeof(server.response_body),
             "{\"access_token\":\"cached-token\","
             "\"token_type\":\"Bearer\","
             "\"expires_in\":3600}");

    config = flb_config_init();
    TEST_CHECK(config != NULL);

    ret = oauth2_metadata_mock_server_start(&server);
    TEST_CHECK(ret == 0);

    /* Default refresh_skew of 60s leaves a generous window where a second
     * call must hit the in-memory cache rather than the metadata server. */
    ctx = create_metadata_oauth_ctx(config, &server, NULL);
    TEST_ASSERT(ctx != NULL);

    ret = oauth2_metadata_mock_server_wait_ready(&server);
    TEST_CHECK(ret == 0);
    flb_time_msleep(50);

    ret = flb_oauth2_get_access_token(ctx, &token1, FLB_FALSE);
    TEST_CHECK(ret == 0);
    TEST_ASSERT(token1 != NULL);
    TEST_CHECK(strcmp(token1, "cached-token") == 0);
    TEST_CHECK(server.metadata_get_requests == 1);

    ret = flb_oauth2_get_access_token(ctx, &token2, FLB_FALSE);
    TEST_CHECK(ret == 0);
    TEST_ASSERT(token2 != NULL);
    TEST_CHECK(strcmp(token2, "cached-token") == 0);
    /* Second call inside the validity window must be a cache hit and must
     * not contact the metadata server again. */
    TEST_CHECK(server.metadata_get_requests == 1);

    flb_oauth2_destroy(ctx);
    oauth2_metadata_mock_server_stop(&server);
    flb_config_exit(config);
}

void test_metadata_refresh_on_expiry(void)
{
    int ret;
    flb_sds_t token1 = NULL;
    flb_sds_t token2 = NULL;
    struct flb_config *config;
    struct flb_oauth2 *ctx;
    struct flb_oauth2_config cfg;
    struct oauth2_metadata_mock_server server;

    memset(&server, 0, sizeof(server));
    snprintf(server.metadata_path, sizeof(server.metadata_path), "/token");
    server.response_status = 200;
    /* The parser stores expires_in - expires_in/10, so 65 becomes 59.
     * Combined with refresh_skew = 58 this leaves a ~1s validity window
     * before oauth2_token_needs_refresh fires. */
    snprintf(server.response_body, sizeof(server.response_body),
             "{\"access_token\":\"first-token\","
             "\"token_type\":\"Bearer\","
             "\"expires_in\":65}");

    config = flb_config_init();
    TEST_CHECK(config != NULL);

    ret = oauth2_metadata_mock_server_start(&server);
    TEST_CHECK(ret == 0);

    memset(&cfg, 0, sizeof(cfg));
    cfg.enabled = FLB_TRUE;
    cfg.auth_method = FLB_OAUTH2_AUTH_METHOD_BASIC;
    cfg.token_source = FLB_OAUTH2_TOKEN_SOURCE_METADATA;
    cfg.refresh_skew = 58;
    cfg.metadata_url = flb_sds_create_size(64);
    TEST_CHECK(cfg.metadata_url != NULL);
    flb_sds_printf(&cfg.metadata_url, "http://127.0.0.1:%d/token", server.port);

    ctx = flb_oauth2_create_from_config(config, &cfg);
    flb_oauth2_config_destroy(&cfg);
    TEST_ASSERT(ctx != NULL);

    ret = oauth2_metadata_mock_server_wait_ready(&server);
    TEST_CHECK(ret == 0);
    flb_time_msleep(50);

    ret = flb_oauth2_get_access_token(ctx, &token1, FLB_FALSE);
    TEST_CHECK(ret == 0);
    TEST_ASSERT(token1 != NULL);
    TEST_CHECK(strcmp(token1, "first-token") == 0);
    TEST_CHECK(server.metadata_get_requests == 1);

    /* Rotate the mock response so the next refresh observably yields a
     * different access token. */
    snprintf(server.response_body, sizeof(server.response_body),
             "{\"access_token\":\"second-token\","
             "\"token_type\":\"Bearer\","
             "\"expires_in\":65}");

    sleep(2);

    ret = flb_oauth2_get_access_token(ctx, &token2, FLB_FALSE);
    TEST_CHECK(ret == 0);
    TEST_ASSERT(token2 != NULL);
    TEST_CHECK(strcmp(token2, "second-token") == 0);
    TEST_CHECK(server.metadata_get_requests == 2);

    flb_oauth2_destroy(ctx);
    oauth2_metadata_mock_server_stop(&server);
    flb_config_exit(config);
}

void test_metadata_invalidate_forces_refresh(void)
{
    int ret;
    flb_sds_t token1 = NULL;
    flb_sds_t token2 = NULL;
    struct flb_config *config;
    struct flb_oauth2 *ctx;
    struct oauth2_metadata_mock_server server;

    memset(&server, 0, sizeof(server));
    snprintf(server.metadata_path, sizeof(server.metadata_path), "/token");
    server.response_status = 200;
    snprintf(server.response_body, sizeof(server.response_body),
             "{\"access_token\":\"primed-token\","
             "\"token_type\":\"Bearer\","
             "\"expires_in\":3600}");

    config = flb_config_init();
    TEST_CHECK(config != NULL);

    ret = oauth2_metadata_mock_server_start(&server);
    TEST_CHECK(ret == 0);

    ctx = create_metadata_oauth_ctx(config, &server, NULL);
    TEST_ASSERT(ctx != NULL);

    ret = oauth2_metadata_mock_server_wait_ready(&server);
    TEST_CHECK(ret == 0);
    flb_time_msleep(50);

    ret = flb_oauth2_get_access_token(ctx, &token1, FLB_FALSE);
    TEST_CHECK(ret == 0);
    TEST_ASSERT(token1 != NULL);
    TEST_CHECK(strcmp(token1, "primed-token") == 0);
    TEST_CHECK(server.metadata_get_requests == 1);

    /* Switch the mock response so the post-invalidate refresh is observable
     * through a distinct token. */
    snprintf(server.response_body, sizeof(server.response_body),
             "{\"access_token\":\"refreshed-token\","
             "\"token_type\":\"Bearer\","
             "\"expires_in\":3600}");

    /* The 401 path in callers triggers flb_oauth2_invalidate_token; the
     * cache must drop and the next get must refresh regardless of the
     * still-valid expiry. */
    flb_oauth2_invalidate_token(ctx);

    ret = flb_oauth2_get_access_token(ctx, &token2, FLB_FALSE);
    TEST_CHECK(ret == 0);
    TEST_ASSERT(token2 != NULL);
    TEST_CHECK(strcmp(token2, "refreshed-token") == 0);
    TEST_CHECK(server.metadata_get_requests == 2);

    flb_oauth2_destroy(ctx);
    oauth2_metadata_mock_server_stop(&server);
    flb_config_exit(config);
}

struct concurrent_get_arg {
    struct flb_oauth2 *ctx;
    flb_sds_t token;
    int ret;
};

static void *concurrent_get_thread(void *data)
{
    struct concurrent_get_arg *arg = (struct concurrent_get_arg *) data;

    arg->ret = flb_oauth2_get_access_token(arg->ctx, &arg->token, FLB_FALSE);
    return NULL;
}

void test_metadata_concurrent_first_refresh(void)
{
    int ret;
    pthread_t t1;
    pthread_t t2;
    struct concurrent_get_arg a1;
    struct concurrent_get_arg a2;
    struct flb_config *config;
    struct flb_oauth2 *ctx;
    struct oauth2_metadata_mock_server server;

    memset(&server, 0, sizeof(server));
    snprintf(server.metadata_path, sizeof(server.metadata_path), "/token");
    server.response_status = 200;
    snprintf(server.response_body, sizeof(server.response_body),
             "{\"access_token\":\"shared-token\","
             "\"token_type\":\"Bearer\","
             "\"expires_in\":3600}");

    config = flb_config_init();
    TEST_CHECK(config != NULL);

    ret = oauth2_metadata_mock_server_start(&server);
    TEST_CHECK(ret == 0);

    ctx = create_metadata_oauth_ctx(config, &server, NULL);
    TEST_ASSERT(ctx != NULL);

    ret = oauth2_metadata_mock_server_wait_ready(&server);
    TEST_CHECK(ret == 0);
    flb_time_msleep(50);

    memset(&a1, 0, sizeof(a1));
    a1.ctx = ctx;
    memset(&a2, 0, sizeof(a2));
    a2.ctx = ctx;

    ret = pthread_create(&t1, NULL, concurrent_get_thread, &a1);
    TEST_ASSERT(ret == 0);
    ret = pthread_create(&t2, NULL, concurrent_get_thread, &a2);
    TEST_ASSERT(ret == 0);

    pthread_join(t1, NULL);
    pthread_join(t2, NULL);

    TEST_CHECK(a1.ret == 0);
    TEST_CHECK(a2.ret == 0);
    TEST_ASSERT(a1.token != NULL && a2.token != NULL);
    TEST_CHECK(strcmp(a1.token, "shared-token") == 0);
    TEST_CHECK(strcmp(a2.token, "shared-token") == 0);
    /* The flb_lock_t around oauth2_get_token_locked serialises both threads;
     * the loser of the race must see the token already cached and skip the
     * HTTP fetch entirely. */
    TEST_CHECK(server.metadata_get_requests == 1);

    flb_oauth2_destroy(ctx);
    oauth2_metadata_mock_server_stop(&server);
    flb_config_exit(config);
}

TEST_LIST = {
    {"token_source_parse_client_credentials",
     test_token_source_parse_client_credentials},
    {"token_source_parse_metadata", test_token_source_parse_metadata},
    {"token_source_parse_mixed_case", test_token_source_parse_mixed_case},
    {"metadata_split_header_simple", test_metadata_split_header_simple},
    {"metadata_split_header_no_space_after_colon",
     test_metadata_split_header_no_space_after_colon},
    {"metadata_split_header_extra_whitespace",
     test_metadata_split_header_extra_whitespace},
    {"metadata_split_header_multiple_colons",
     test_metadata_split_header_multiple_colons},
    {"metadata_split_header_missing_colon",
     test_metadata_split_header_missing_colon},
    {"metadata_split_header_empty_value",
     test_metadata_split_header_empty_value},
    {"metadata_split_header_injection_rejected",
     test_metadata_split_header_injection_rejected},
    {"metadata_build_url_bare", test_metadata_build_url_bare},
    {"metadata_build_url_scope_only", test_metadata_build_url_scope_only},
    {"metadata_build_url_audience_only", test_metadata_build_url_audience_only},
    {"metadata_build_url_scope_and_audience",
     test_metadata_build_url_scope_and_audience},
    {"metadata_build_url_scope_special_chars",
     test_metadata_build_url_scope_special_chars},
    {"metadata_build_url_existing_query",
     test_metadata_build_url_existing_query},
    {"metadata_build_url_query_delimiter_injection",
     test_metadata_build_url_query_delimiter_injection},
    {"metadata_mock_fragmented_round_trip",
     test_metadata_mock_fragmented_round_trip},
    {"metadata_refresh_fragmented_after_status_line",
     test_metadata_refresh_fragmented_after_status_line},
    {"metadata_refresh_fragmented_after_headers",
     test_metadata_refresh_fragmented_after_headers},
    {"metadata_refresh_fragmented_mid_body",
     test_metadata_refresh_fragmented_mid_body},
    {"metadata_refresh_success", test_metadata_refresh_success},
    {"metadata_refresh_4xx_response", test_metadata_refresh_4xx_response},
    {"metadata_refresh_5xx_response", test_metadata_refresh_5xx_response},
    {"metadata_refresh_malformed_json", test_metadata_refresh_malformed_json},
    {"metadata_refresh_invalid_metadata_header",
     test_metadata_refresh_invalid_metadata_header},
    {"metadata_refresh_url_wiring", test_metadata_refresh_url_wiring},
    {"metadata_refresh_header_wiring", test_metadata_refresh_header_wiring},
    {"upstream_bound_to_metadata_url", test_upstream_bound_to_metadata_url},
    {"dispatch_routes_to_client_credentials",
     test_dispatch_routes_to_client_credentials},
    {"dispatch_routes_to_metadata", test_dispatch_routes_to_metadata},
    {"create_from_config_metadata_missing_url",
     test_create_from_config_metadata_missing_url},
    {"create_from_config_client_credentials_missing_token_url",
     test_create_from_config_client_credentials_missing_token_url},
    {"create_from_config_invalid_token_source",
     test_create_from_config_invalid_token_source},
    {"create_from_config_token_source_str_metadata",
     test_create_from_config_token_source_str_metadata},
    {"create_from_config_token_source_str_invalid",
     test_create_from_config_token_source_str_invalid},
    {"resolve_token_source_metadata", test_resolve_token_source_metadata},
    {"resolve_token_source_invalid", test_resolve_token_source_invalid},
    {"resolve_token_source_noop", test_resolve_token_source_noop},
    {"metadata_cache_hit_within_validity_window",
     test_metadata_cache_hit_within_validity_window},
    {"metadata_refresh_on_expiry", test_metadata_refresh_on_expiry},
    {"metadata_invalidate_forces_refresh",
     test_metadata_invalidate_forces_refresh},
    {"metadata_concurrent_first_refresh",
     test_metadata_concurrent_first_refresh},
    {0}
};
