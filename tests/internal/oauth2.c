/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_http_client.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_oauth2.h>
#include <fluent-bit/flb_upstream.h>

#include "flb_tests_internal.h"

#define MOCK_BODY_SIZE 1024

struct oauth2_mock_server {
    int listen_fd;
    int port;
    int stop;
    int token_requests;
    int resource_requests;
    int resource_challenge;
    int expires_in;
    char latest_token[64];
    pthread_t thread;
};

static void compose_http_response(int fd, int status, const char *body)
{
    char buffer[MOCK_BODY_SIZE];
    int body_len = 0;

    if (body != NULL) {
        body_len = strlen(body);
    }

    snprintf(buffer, sizeof(buffer),
             "HTTP/1.1 %d\r\n"
             "Content-Length: %d\r\n"
             "Content-Type: application/json\r\n"
             "Connection: close\r\n\r\n"
             "%s",
             status, body_len, body ? body : "");

    send(fd, buffer, strlen(buffer), 0);
}

static void handle_token_request(struct oauth2_mock_server *server, int fd)
{
    char payload[MOCK_BODY_SIZE];

    server->token_requests++;
    snprintf(server->latest_token, sizeof(server->latest_token),
             "mock-token-%d", server->token_requests);

    snprintf(payload, sizeof(payload),
             "{\"access_token\":\"%s\",\"token_type\":\"Bearer\","\
             "\"expires_in\":%d}",
             server->latest_token, server->expires_in);

    compose_http_response(fd, 200, payload);
}

static void handle_resource_request(struct oauth2_mock_server *server, int fd,
                                    const char *request)
{
    int authorized = 0;
    const char *auth;

    server->resource_requests++;

    if (server->resource_challenge > 0) {
        server->resource_challenge--;
        compose_http_response(fd, 401, "");
        return;
    }

    auth = strstr(request, "Authorization: ");
    if (auth && strstr(auth, server->latest_token)) {
        authorized = 1;
    }

    if (authorized) {
        compose_http_response(fd, 200, "{\"ok\":true}");
    }
    else {
        compose_http_response(fd, 401, "");
    }
}

static void *oauth2_mock_server_thread(void *data)
{
    struct oauth2_mock_server *server = (struct oauth2_mock_server *) data;
    int client_fd;
    fd_set rfds;
    struct timeval tv;
    char buffer[MOCK_BODY_SIZE];

    while (!server->stop) {
        FD_ZERO(&rfds);
        FD_SET(server->listen_fd, &rfds);
        tv.tv_sec = 0;
        tv.tv_usec = 200000;

        if (select(server->listen_fd + 1, &rfds, NULL, NULL, &tv) <= 0) {
            continue;
        }

        client_fd = accept(server->listen_fd, NULL, NULL);
        if (client_fd < 0) {
            continue;
        }

        memset(buffer, 0, sizeof(buffer));
        recv(client_fd, buffer, sizeof(buffer) - 1, 0);

        if (strstr(buffer, "/token")) {
            handle_token_request(server, client_fd);
        }
        else if (strstr(buffer, "/resource")) {
            handle_resource_request(server, client_fd, buffer);
        }

        close(client_fd);
    }

    return NULL;
}

static int oauth2_mock_server_start(struct oauth2_mock_server *server, int expires_in,
                                    int resource_challenge)
{
    int flags;
    int on = 1;
    struct sockaddr_in addr;
    socklen_t len;

    memset(server, 0, sizeof(struct oauth2_mock_server));
    server->expires_in = expires_in;
    server->resource_challenge = resource_challenge;

    server->listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server->listen_fd < 0) {
        return -1;
    }

    setsockopt(server->listen_fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;

    if (bind(server->listen_fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
        close(server->listen_fd);
        return -1;
    }

    len = sizeof(addr);
    if (getsockname(server->listen_fd, (struct sockaddr *) &addr, &len) < 0) {
        close(server->listen_fd);
        return -1;
    }

    server->port = ntohs(addr.sin_port);

    if (listen(server->listen_fd, 4) < 0) {
        close(server->listen_fd);
        return -1;
    }

    flags = fcntl(server->listen_fd, F_GETFL, 0);
    fcntl(server->listen_fd, F_SETFL, flags | O_NONBLOCK);

    if (pthread_create(&server->thread, NULL, oauth2_mock_server_thread, server) != 0) {
        close(server->listen_fd);
        return -1;
    }

    return 0;
}

static void oauth2_mock_server_stop(struct oauth2_mock_server *server)
{
    if (server->listen_fd > 0) {
        server->stop = 1;
        shutdown(server->listen_fd, SHUT_RDWR);
        pthread_join(server->thread, NULL);
        close(server->listen_fd);
    }
}

static struct flb_oauth2 *create_oauth_ctx(struct flb_config *config,
                                           struct oauth2_mock_server *server,
                                           int refresh_skew)
{
    struct flb_oauth2_config cfg;

    memset(&cfg, 0, sizeof(cfg));
    cfg.enabled = FLB_TRUE;
    cfg.token_url = flb_sds_create_size(64);
    cfg.auth_method = FLB_OAUTH2_AUTH_METHOD_BASIC;
    cfg.refresh_skew = refresh_skew;
    cfg.client_id = flb_sds_create("id");
    cfg.client_secret = flb_sds_create("secret");

    flb_sds_printf(&cfg.token_url, "http://127.0.0.1:%d/token", server->port);

    struct flb_oauth2 *ctx = flb_oauth2_create_from_config(config, &cfg);

    flb_oauth2_config_destroy(&cfg);

    return ctx;
}

void test_parse_defaults(void)
{
    int ret;
    struct flb_oauth2 ctx;
    const char *payload = "{\"access_token\":\"abc\"}";

    memset(&ctx, 0, sizeof(ctx));
    ctx.refresh_skew = FLB_OAUTH2_DEFAULT_SKEW_SECS;

    ret = flb_oauth2_parse_json_response(payload, strlen(payload), &ctx);
    TEST_CHECK(ret == 0);
    TEST_CHECK(ctx.access_token != NULL);
    TEST_CHECK(strcmp(ctx.token_type, "Bearer") == 0);
    TEST_CHECK(ctx.expires_in == FLB_OAUTH2_DEFAULT_EXPIRES);

    flb_sds_destroy(ctx.access_token);
    flb_sds_destroy(ctx.token_type);
}

void test_caching_and_refresh(void)
{
    int ret;
    flb_sds_t token = NULL;
    struct flb_config *config;
    struct flb_oauth2 *ctx;
    struct oauth2_mock_server server;

    config = flb_config_init();
    TEST_CHECK(config != NULL);

    ret = oauth2_mock_server_start(&server, 2, 0);
    TEST_CHECK(ret == 0);

    ctx = create_oauth_ctx(config, &server, 1);
    TEST_CHECK(ctx != NULL);

    ret = flb_oauth2_get_access_token(ctx, &token, FLB_FALSE);
    TEST_CHECK(ret == 0);
    TEST_CHECK(strcmp(token, "mock-token-1") == 0);
    TEST_CHECK(server.token_requests == 1);

    ret = flb_oauth2_get_access_token(ctx, &token, FLB_FALSE);
    TEST_CHECK(ret == 0);
    TEST_CHECK(strcmp(token, "mock-token-1") == 0);
    TEST_CHECK(server.token_requests == 1);

    sleep(2);

    ret = flb_oauth2_get_access_token(ctx, &token, FLB_FALSE);
    TEST_CHECK(ret == 0);
    TEST_CHECK(strcmp(token, "mock-token-2") == 0);
    TEST_CHECK(server.token_requests == 2);

    flb_oauth2_destroy(ctx);
    oauth2_mock_server_stop(&server);
    flb_config_exit(config);
}

TEST_LIST = {
    {"parse_defaults", test_parse_defaults},
    {"caching_and_refresh", test_caching_and_refresh},
    {0}
};

