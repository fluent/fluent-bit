/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_error.h>
#include <fluent-bit/flb_socket.h>
#include <fluent-bit/flb_http_client.h>

#include "flb_tests_internal.h"

struct test_ctx {
    struct flb_upstream   *u;
    struct flb_connection *u_conn;
    struct flb_config     *config;
};

struct test_ctx* test_ctx_create()
{
    struct test_ctx *ret_ctx = NULL;

    ret_ctx = flb_malloc(sizeof(struct test_ctx));
    if (!TEST_CHECK(ret_ctx != NULL)) {
        flb_errno();
        TEST_MSG("flb_malloc(test_ctx) failed");
        return NULL;
    }
    ret_ctx->u = NULL;
    ret_ctx->u_conn = NULL;

    ret_ctx->config = flb_config_init();
    if(!TEST_CHECK(ret_ctx->config != NULL)) {
        TEST_MSG("flb_config_init failed");
        flb_free(ret_ctx);
        return NULL;
    }

    ret_ctx->u = flb_upstream_create(ret_ctx->config, "127.0.0.1", 80, FLB_IO_TCP_KA, NULL);
    if (!TEST_CHECK(ret_ctx->u != NULL)) {
        TEST_MSG("flb_upstream_create failed");
        flb_config_exit(ret_ctx->config);
        flb_free(ret_ctx);
        return NULL;
    }

    ret_ctx->u_conn = flb_calloc(1, sizeof(struct flb_connection));
    if(!TEST_CHECK(ret_ctx->u_conn != NULL)) {
        flb_errno();
        TEST_MSG("flb_malloc(flb_connection) failed");
        flb_upstream_destroy(ret_ctx->u);
        flb_config_exit(ret_ctx->config);
        flb_free(ret_ctx);
        return NULL;
    }

    ret_ctx->u_conn->upstream = ret_ctx->u;

    return ret_ctx;
}

int test_ctx_destroy(struct test_ctx* ctx)
{
    if (!TEST_CHECK(ctx != NULL)) {
        return -1;
    }
    if (ctx->u_conn) {
        flb_free(ctx->u_conn);
    }
    if (ctx->u) {
        flb_upstream_destroy(ctx->u);
    }
    if (ctx->config) {
        flb_config_exit(ctx->config);
    }

    flb_free(ctx);
    return 0;
}

void test_http_buffer_increase()
{
    int ret;
    size_t s;
    struct test_ctx *ctx;
    struct flb_http_client *c;
    struct flb_http_client_response *resp;

    ctx = test_ctx_create();
    if (!TEST_CHECK(ctx != NULL)) {
        exit(EXIT_FAILURE);
    }

    /* Create HTTP client instance */
    c = flb_http_client(ctx->u_conn, FLB_HTTP_GET, "/", NULL, 0,
                        "127.0.0.1", 80, NULL, 0);
    TEST_CHECK(c != NULL);

    /* Do buffer tests */
    resp = &c->resp;
    TEST_CHECK(resp->data_len == 0);
    TEST_CHECK(resp->data_size == FLB_HTTP_DATA_SIZE_MAX);
    TEST_CHECK(resp->data_size_max == FLB_HTTP_DATA_SIZE_MAX);

    /* Invalid size */
    ret = flb_http_buffer_size(c, 1);
    TEST_CHECK(ret == -1);

    /* Increase max size to 8KB */
    flb_http_buffer_size(c, 8192);

    /* Request to allocate +4KB */
    ret = flb_http_buffer_increase(c, 4096, &s);
    TEST_CHECK(ret == 0);
    TEST_CHECK(s == 4096);

    /* Request to allocate 1 byte, it should fail */
    ret = flb_http_buffer_increase(c, 1, &s);
    TEST_CHECK(ret == -1);

    /* Test unlimited */
    flb_http_buffer_size(c, 0);
    ret = flb_http_buffer_increase(c, 1, &s);
    TEST_CHECK(ret == 0 && s == 1);

    /* Payload test */
    memcpy(c->resp.data, "00abc11def22ghi__PAYLOAD__8yz9900", 33);
    c->resp.data[33] = '\0';
    c->resp.data_len = 33;
    c->resp.payload = c->resp.data + 15;
    c->resp.payload_size = 11;

    ret = flb_http_buffer_increase(c, 819200, &s);
    TEST_CHECK(ret == 0);

    ret = strncmp(c->resp.payload, "__PAYLOAD__", 11);
    TEST_CHECK(ret == 0);

    flb_http_client_destroy(c);
    test_ctx_destroy(ctx);
}

void test_http_add_get_header()
{
    struct test_ctx *ctx;
    struct flb_http_client *c;
    flb_sds_t ret_str;
    char *ua = "Fluent-Bit";
    char *host = "127.0.0.1:80";
    int ret;

    ctx = test_ctx_create();
    if (!TEST_CHECK(ctx != NULL)) {
        exit(EXIT_FAILURE);
    }

    /* Create HTTP client instance */
    c = flb_http_client(ctx->u_conn, FLB_HTTP_GET, "/", NULL, 0,
                        "127.0.0.1", 80, NULL, 0);
    if(!TEST_CHECK(c != NULL)) {
        TEST_MSG("flb_http_client failed");
        test_ctx_destroy(ctx);
        exit(EXIT_FAILURE);
    }

    /* Check User-Agent */
    ret = flb_http_add_header(c, "User-Agent", 10, ua, strlen(ua));
    TEST_CHECK(ret == 0);

    ret_str = flb_http_get_header(c, "User-Agent", 10);
    if (!TEST_CHECK(ret_str != NULL)) {
        TEST_MSG("flb_http_get_header failed");
        flb_http_client_destroy(c);
        test_ctx_destroy(ctx);
        exit(EXIT_FAILURE);
    }

    if (!TEST_CHECK(flb_sds_cmp(ret_str, ua, strlen(ua)) == 0)) {
        TEST_MSG("strcmp failed. got=%s expect=%s", ret_str, ua);
    }
    flb_sds_destroy(ret_str);


    /* Check Host */
    ret_str = flb_http_get_header(c, "Host", 4);
    if (!TEST_CHECK(ret_str != NULL)) {
        TEST_MSG("flb_http_get_header failed");
        flb_http_client_destroy(c);
        test_ctx_destroy(ctx);
        exit(EXIT_FAILURE);
    }

    if (!TEST_CHECK(flb_sds_cmp(ret_str, host, strlen(host)) == 0)) {
        TEST_MSG("strcmp failed. got=%s expect=%s", ret_str, host);
    }

    flb_sds_destroy(ret_str);
    flb_http_client_destroy(c);
    test_ctx_destroy(ctx);
}

void test_http_set_keepalive()
{
    struct test_ctx *ctx;
    struct flb_http_client *c;
    flb_sds_t ret_str;
    int ret;

    ctx = test_ctx_create();
    if (!TEST_CHECK(ctx != NULL)) {
        exit(EXIT_FAILURE);
    }

    /* Create HTTP client instance */
    c = flb_http_client(ctx->u_conn, FLB_HTTP_GET, "/", NULL, 0,
                        "127.0.0.1", 80, NULL, 0);
    if(!TEST_CHECK(c != NULL)) {
        TEST_MSG("flb_http_client failed");
        test_ctx_destroy(ctx);
        exit(EXIT_FAILURE);
    }

    /* Set keepalive header */
    ret = flb_http_set_keepalive(c);
    TEST_CHECK(ret == 0);

    ret_str = flb_http_get_header(c, FLB_HTTP_HEADER_CONNECTION,
                                  strlen(FLB_HTTP_HEADER_CONNECTION));
    if (!TEST_CHECK(ret_str != NULL)) {
        TEST_MSG("flb_get_header failed");
        flb_http_client_destroy(c);
        test_ctx_destroy(ctx);
        exit(EXIT_FAILURE);
    }

    /* Compare */
    if (!TEST_CHECK(flb_sds_cmp(ret_str, FLB_HTTP_HEADER_KA, strlen(FLB_HTTP_HEADER_KA)) == 0)) {
        TEST_MSG("strcmp failed. got=%s expect=%s", ret_str, FLB_HTTP_HEADER_KA);
    }
    flb_sds_destroy(ret_str);
    flb_http_client_destroy(c);
    test_ctx_destroy(ctx);
}

void test_http_strip_port_from_host()
{
    struct test_ctx *ctx;
    struct flb_http_client *c;
    flb_sds_t ret_str;
    char *host_port = "127.0.0.1:80";
    char *host = "127.0.0.1";
    int ret;

    ctx = test_ctx_create();
    if (!TEST_CHECK(ctx != NULL)) {
        exit(EXIT_FAILURE);
    }

    /* Create HTTP client instance */
    c = flb_http_client(ctx->u_conn, FLB_HTTP_GET, "/", NULL, 0,
                        "127.0.0.1", 80, NULL, 0);
    if(!TEST_CHECK(c != NULL)) {
        TEST_MSG("flb_http_client failed");
        test_ctx_destroy(ctx);
        exit(EXIT_FAILURE);
    }

    /* Check Host. It should contain port number */
    ret_str = flb_http_get_header(c, "Host", 4);
    if (!TEST_CHECK(ret_str != NULL)) {
        TEST_MSG("flb_http_get_header failed");
        flb_http_client_destroy(c);
        test_ctx_destroy(ctx);
        exit(EXIT_FAILURE);
    }

    if (!TEST_CHECK(flb_sds_cmp(ret_str, host_port, strlen(host_port)) == 0)) {
        TEST_MSG("strcmp failed. got=%s expect=%s", ret_str, host_port);
    }
    flb_sds_destroy(ret_str);


    ret = flb_http_strip_port_from_host(c);
    TEST_CHECK(ret == 0);

    /* Check Host. Port number should be removed. */
    ret_str = flb_http_get_header(c, "Host", 4);
    if (!TEST_CHECK(ret_str != NULL)) {
        TEST_MSG("flb_http_get_header failed");
        flb_http_client_destroy(c);
        test_ctx_destroy(ctx);
        exit(EXIT_FAILURE);
    }

    if (!TEST_CHECK(flb_sds_cmp(ret_str, host, strlen(host)) == 0)) {
        TEST_MSG("strcmp failed. got=%s expect=%s", ret_str, host);
    }

    flb_sds_destroy(ret_str);
    flb_http_client_destroy(c);
    test_ctx_destroy(ctx);
}

void test_http_encoding_gzip()
{
    struct test_ctx *ctx;
    struct flb_http_client *c;
    flb_sds_t ret_str;
    char *gzip = "gzip";
    int ret;

    ctx = test_ctx_create();
    if (!TEST_CHECK(ctx != NULL)) {
        exit(EXIT_FAILURE);
    }

    /* Create HTTP client instance */
    c = flb_http_client(ctx->u_conn, FLB_HTTP_GET, "/", NULL, 0,
                        "127.0.0.1", 80, NULL, 0);
    if(!TEST_CHECK(c != NULL)) {
        TEST_MSG("flb_http_client failed");
        test_ctx_destroy(ctx);
        exit(EXIT_FAILURE);
    }

    /* Check encoding. It should be error */
    ret_str = flb_http_get_header(c, FLB_HTTP_HEADER_CONTENT_ENCODING,
                                  strlen(FLB_HTTP_HEADER_CONTENT_ENCODING));
    if (!TEST_CHECK(ret_str == NULL)) {
        TEST_MSG("Got encoding? Header:%s", ret_str);
        flb_sds_destroy(ret_str);
        flb_http_client_destroy(c);
        test_ctx_destroy(ctx);
        exit(EXIT_FAILURE);
    }

    ret = flb_http_set_content_encoding_gzip(c);
    TEST_CHECK(ret == 0);

    /* Check Encoding */
    ret_str = flb_http_get_header(c, FLB_HTTP_HEADER_CONTENT_ENCODING,
                                  strlen(FLB_HTTP_HEADER_CONTENT_ENCODING));
    if (!TEST_CHECK(ret_str != NULL)) {
        TEST_MSG("flb_http_get_header failed");
        flb_http_client_destroy(c);
        test_ctx_destroy(ctx);
        exit(EXIT_FAILURE);
    }

    if (!TEST_CHECK(flb_sds_cmp(ret_str, gzip, strlen(gzip)) == 0)) {
        TEST_MSG("strcmp failed. got=%s expect=%s", ret_str, gzip);
    }

    flb_sds_destroy(ret_str);
    flb_http_client_destroy(c);
    test_ctx_destroy(ctx);
}

void test_http_add_basic_auth_header()
{
    struct test_ctx *ctx;
    struct flb_http_client *c;
    flb_sds_t ret_str;
    char *expect = "Basic dXNlcjpwYXNzd29yZA=="; /* user:password in base64 */
    char *auth = FLB_HTTP_HEADER_AUTH;
    const char *user = "user";
    char *passwd = "password";
    int ret;

    ctx = test_ctx_create();
    if (!TEST_CHECK(ctx != NULL)) {
        exit(EXIT_FAILURE);
    }

    /* Create HTTP client instance */
    c = flb_http_client(ctx->u_conn, FLB_HTTP_GET, "/", NULL, 0,
                        "127.0.0.1", 80, NULL, 0);
    if(!TEST_CHECK(c != NULL)) {
        TEST_MSG("flb_http_client failed");
        test_ctx_destroy(ctx);
        exit(EXIT_FAILURE);
    }

    /* Check Autholization. It should be error. */
    ret_str = flb_http_get_header(c, auth, strlen(auth));
    if (!TEST_CHECK(ret_str == NULL)) {
        TEST_MSG("Got auth? Header:%s", ret_str);
        flb_sds_destroy(ret_str);
        flb_http_client_destroy(c);
        test_ctx_destroy(ctx);
        exit(EXIT_FAILURE);
    }

    ret = flb_http_basic_auth(c, user, passwd);
    TEST_CHECK(ret == 0);

    /* Check Autholization. */
    ret_str = flb_http_get_header(c, auth, strlen(auth));
    if (!TEST_CHECK(ret_str != NULL)) {
        TEST_MSG("flb_http_get_header failed");
        flb_http_client_destroy(c);
        test_ctx_destroy(ctx);
        exit(EXIT_FAILURE);
    }

    if (!TEST_CHECK(flb_sds_cmp(ret_str, expect, strlen(expect)) == 0)) {
        TEST_MSG("strcmp failed. got=%s expect=%s", ret_str, expect);
    }

    flb_sds_destroy(ret_str);
    flb_http_client_destroy(c);
    test_ctx_destroy(ctx);
}

void test_http_add_proxy_auth_header()
{
    struct test_ctx *ctx;
    struct flb_http_client *c;
    flb_sds_t ret_str;
    char *expect = "Basic dXNlcjpwYXNzd29yZA=="; /* user:password in base64 */
    char *auth = FLB_HTTP_HEADER_PROXY_AUTH;
    const char *user = "user";
    char *passwd = "password";
    int ret;

    ctx = test_ctx_create();
    if (!TEST_CHECK(ctx != NULL)) {
        exit(EXIT_FAILURE);
    }

    /* Create HTTP client instance */
    c = flb_http_client(ctx->u_conn, FLB_HTTP_GET, "/", NULL, 0,
                        "127.0.0.1", 80, NULL, 0);
    if(!TEST_CHECK(c != NULL)) {
        TEST_MSG("flb_http_client failed");
        test_ctx_destroy(ctx);
        exit(EXIT_FAILURE);
    }

    /* Check autholization header. It should be error. */
    ret_str = flb_http_get_header(c, auth, strlen(auth));
    if (!TEST_CHECK(ret_str == NULL)) {
        TEST_MSG("Got auth? Header:%s", ret_str);
        flb_sds_destroy(ret_str);
        flb_http_client_destroy(c);
        test_ctx_destroy(ctx);
        exit(EXIT_FAILURE);
    }

    ret = flb_http_proxy_auth(c, user, passwd);
    TEST_CHECK(ret == 0);

    /* Check autholization header. */
    ret_str = flb_http_get_header(c, auth, strlen(auth));
    if (!TEST_CHECK(ret_str != NULL)) {
        TEST_MSG("flb_http_get_header failed");
        flb_http_client_destroy(c);
        test_ctx_destroy(ctx);
        exit(EXIT_FAILURE);
    }

    if (!TEST_CHECK(flb_sds_cmp(ret_str, expect, strlen(expect)) == 0)) {
        TEST_MSG("strcmp failed. got=%s expect=%s", ret_str, expect);
    }

    flb_sds_destroy(ret_str);
    flb_http_client_destroy(c);
    test_ctx_destroy(ctx);
}

/* Helper function to verify Host header value */
static void check_host_header(struct flb_http_client *c, const char *expected)
{
    flb_sds_t ret_str = flb_http_get_header(c, "Host", 4);
    if (!TEST_CHECK(ret_str != NULL)) {
        TEST_MSG("flb_http_get_header failed");
        exit(EXIT_FAILURE);
    }

    if (!TEST_CHECK(flb_sds_cmp(ret_str, expected, strlen(expected)) == 0)) {
        TEST_MSG("strcmp failed. got=%s expect=%s", ret_str, expected);
    }

    flb_sds_destroy(ret_str);
}

/* Helper to test basic host header formatting */
static void test_host_header_format(const char *host, int port, const char *expected)
{
    struct test_ctx *ctx = test_ctx_create();
    if (!TEST_CHECK(ctx != NULL)) {
        exit(EXIT_FAILURE);
    }

    struct flb_http_client *c = flb_http_client(ctx->u_conn, FLB_HTTP_GET, "/", 
                                                 NULL, 0, host, port, NULL, 0);
    if (!TEST_CHECK(c != NULL)) {
        TEST_MSG("flb_http_client failed");
        test_ctx_destroy(ctx);
        exit(EXIT_FAILURE);
    }

    check_host_header(c, expected);
    flb_http_client_destroy(c);
    test_ctx_destroy(ctx);
}

/* Helper to test TLS host header formatting */
static void test_tls_host_header_format(const char *host, int port, const char *expected)
{
    struct test_ctx *ctx = test_ctx_create();
    if (!TEST_CHECK(ctx != NULL)) {
        exit(EXIT_FAILURE);
    }

    struct flb_upstream *u_tls = flb_upstream_create(ctx->config, host, port, FLB_IO_TLS, NULL);
    if (!TEST_CHECK(u_tls != NULL)) {
        TEST_MSG("flb_upstream_create failed");
        test_ctx_destroy(ctx);
        exit(EXIT_FAILURE);
    }

    struct flb_connection *u_conn_tls = flb_calloc(1, sizeof(struct flb_connection));
    if (!TEST_CHECK(u_conn_tls != NULL)) {
        TEST_MSG("flb_calloc failed");
        flb_upstream_destroy(u_tls);
        test_ctx_destroy(ctx);
        exit(EXIT_FAILURE);
    }
    u_conn_tls->upstream = u_tls;

    struct flb_http_client *c = flb_http_client(u_conn_tls, FLB_HTTP_GET, "/",
                                                 NULL, 0, host, port, NULL, 0);
    if (!TEST_CHECK(c != NULL)) {
        TEST_MSG("flb_http_client failed");
        flb_free(u_conn_tls);
        flb_upstream_destroy(u_tls);
        test_ctx_destroy(ctx);
        exit(EXIT_FAILURE);
    }

    check_host_header(c, expected);
    flb_http_client_destroy(c);
    flb_free(u_conn_tls);
    flb_upstream_destroy(u_tls);
    test_ctx_destroy(ctx);
}

void test_http_ipv6_host_header()
{
    test_host_header_format("::1", 8080, "[::1]:8080");
}

void test_http_ipv6_bracketed_host_header()
{
    test_host_header_format("[::1]", 8080, "[::1]:8080");
}

void test_http_ipv4_host_header()
{
    test_host_header_format("192.168.1.1", 8080, "192.168.1.1:8080");
}

void test_http_domain_host_header()
{
    test_host_header_format("example.com", 8080, "example.com:8080");
}

void test_https_default_port_host_header()
{
    test_tls_host_header_format("example.com", 443, "example.com");
}

/* Test various IPv6 address formats */
void test_ipv6_formats_host_header()
{
    size_t index;
    struct {
        const char *input;
        const char *expected;
    } test_cases[] = {
        {"2001:db8::1", "[2001:db8::1]:8080"},
        {"2001:0db8:0000:0000:0000:0000:0000:0001", "[2001:0db8:0000:0000:0000:0000:0000:0001]:8080"},
        {"::ffff:192.0.2.1", "[::ffff:192.0.2.1]:8080"},
        {"fe80::1", "[fe80::1]:8080"},
        {"::1", "[::1]:8080"},
        {"::", "[::]:8080"},
        {NULL, NULL}
    };

    for (index = 0; test_cases[index].input != NULL; index++) {
        test_host_header_format(test_cases[index].input, 8080, test_cases[index].expected);
    }
}

void test_http_port_80_host_header()
{
    test_host_header_format("example.com", 80, "example.com");
}

void test_http_non_standard_port_host_header()
{
    test_host_header_format("example.com", 8080, "example.com:8080");
}

void test_port_443_without_tls_host_header()
{
    test_host_header_format("example.com", 443, "example.com:443");
}

void test_ipv6_zone_id_host_header()
{
    test_host_header_format("fe80::1%eth0", 8080, "[fe80::1]:8080");
}

void test_https_non_standard_port_host_header()
{
    test_tls_host_header_format("example.com", 8443, "example.com:8443");
}

void test_ipv6_bracketed_zone_id_host_header()
{
    /* Already bracketed input - zone ID detection only works on unbracketed addresses,
     * so this passes through as-is. In practice, bracketed input shouldn't have zone IDs. */
    test_host_header_format("[fe80::1%eth0]", 8080, "[fe80::1%eth0]:8080");
}

void test_https_ipv6_default_port_host_header()
{
    test_tls_host_header_format("::1", 443, "[::1]");
}

void test_https_ipv6_non_standard_port_host_header()
{
    test_tls_host_header_format("::1", 8443, "[::1]:8443");
}

void test_https_ipv6_zone_id_default_port_host_header()
{
    test_tls_host_header_format("fe80::1%eth0", 443, "[fe80::1]");
}

void test_https_ipv6_zone_id_non_standard_port_host_header()
{
    test_tls_host_header_format("fe80::1%eth0", 8443, "[fe80::1]:8443");
}

TEST_LIST = {
    { "http_buffer_increase"  , test_http_buffer_increase},
    { "add_get_header"        , test_http_add_get_header},
    { "set_keepalive"         , test_http_set_keepalive},
    { "strip_port_from_host"  , test_http_strip_port_from_host},
    { "encoding_gzip"         , test_http_encoding_gzip},
    { "add_basic_auth_header" , test_http_add_basic_auth_header},
    { "add_proxy_auth_header" , test_http_add_proxy_auth_header},
    { "ipv6_host_header"      , test_http_ipv6_host_header},
    { "ipv6_bracketed_host_header", test_http_ipv6_bracketed_host_header},
    { "ipv4_host_header"      , test_http_ipv4_host_header},
    { "domain_host_header"    , test_http_domain_host_header},
    { "https_default_port_host_header", test_https_default_port_host_header},
    { "ipv6_formats_host_header", test_ipv6_formats_host_header},
    { "http_port_80_host_header", test_http_port_80_host_header},
    { "http_non_standard_port_host_header", test_http_non_standard_port_host_header},
    { "port_443_without_tls_host_header", test_port_443_without_tls_host_header},
    { "ipv6_zone_id_host_header", test_ipv6_zone_id_host_header},
    { "https_non_standard_port_host_header", test_https_non_standard_port_host_header},
    { "ipv6_bracketed_zone_id_host_header", test_ipv6_bracketed_zone_id_host_header},
    { "https_ipv6_default_port_host_header", test_https_ipv6_default_port_host_header},
    { "https_ipv6_non_standard_port_host_header", test_https_ipv6_non_standard_port_host_header},
    { "https_ipv6_zone_id_default_port_host_header", test_https_ipv6_zone_id_default_port_host_header},
    { "https_ipv6_zone_id_non_standard_port_host_header", test_https_ipv6_zone_id_non_standard_port_host_header},
    { 0 }
};
