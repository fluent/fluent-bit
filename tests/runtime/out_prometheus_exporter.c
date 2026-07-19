/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit.h>
#include <fluent-bit/flb_output.h>

#include "../../plugins/out_prometheus_exporter/prom.h"
#include "../../plugins/out_prometheus_exporter/prom_http.h"

#include "flb_tests_runtime.h"

static int get_free_port(void)
{
    int ret;
    int port;
    flb_sockfd_t sock;
    socklen_t len;
    struct sockaddr_in addr;

    len = sizeof(addr);
    memset(&addr, 0, sizeof(addr));

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        return -1;
    }

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(0);

    ret = bind(sock, (struct sockaddr *) &addr, sizeof(addr));
    if (ret != 0) {
        flb_socket_close(sock);
        return -1;
    }

    ret = getsockname(sock, (struct sockaddr *) &addr, &len);
    if (ret != 0) {
        flb_socket_close(sock);
        return -1;
    }

    port = ntohs(addr.sin_port);
    flb_socket_close(sock);

    return port;
}

static void test_http_server_options(void)
{
    int ret;
    int port;
    int in_ffd;
    int out_ffd;
    char port_string[16];
    flb_ctx_t *ctx;
    struct prom_exporter *prom_ctx;
    struct prom_http *prom_http;
    struct flb_output_instance *out;

    port = get_free_port();
    TEST_CHECK(port > 0);
    snprintf(port_string, sizeof(port_string), "%d", port);

    ctx = flb_create();
    TEST_CHECK(ctx != NULL);

    ret = flb_service_set(ctx,
                          "Flush", "1",
                          "Grace", "1",
                          "Log_Level", "error",
                          NULL);
    TEST_CHECK(ret == 0);

    in_ffd = flb_input(ctx, "fluentbit_metrics", NULL);
    TEST_CHECK(in_ffd >= 0);
    ret = flb_input_set(ctx, in_ffd,
                        "tag", "metrics",
                        "scrape_interval", "1",
                        NULL);
    TEST_CHECK(ret == 0);

    out_ffd = flb_output(ctx, "prometheus_exporter", NULL);
    TEST_CHECK(out_ffd >= 0);
    ret = flb_output_set(ctx, out_ffd,
                         "match", "*",
                         "host", "127.0.0.1",
                         "port", port_string,
                         "http_server.buffer_chunk_size", "64K",
                         "http_server.workers", "2",
                         NULL);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    out = flb_output_get_instance(ctx->config, out_ffd);
    TEST_CHECK(out != NULL);

    prom_ctx = out->context;
    TEST_CHECK(prom_ctx != NULL);
    TEST_CHECK(prom_ctx->http != NULL);

    prom_http = prom_ctx->http;
    TEST_CHECK(prom_http->server.buffer_chunk_size ==
               out->http_server_config->buffer_chunk_size);
    TEST_CHECK(prom_http->server.workers == 2);
    TEST_CHECK(prom_http->server.runtime != NULL);

    flb_stop(ctx);
    flb_destroy(ctx);
}

TEST_LIST = {
    {"http_server_options", test_http_server_options},
    {NULL, NULL}
};
