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
    test_host_header_format("example.com", 80, "example.com:80");
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

static void append_response_fragment(struct flb_http_client *c,
                                     const char *fragment)
{
    size_t length;

    length = strlen(fragment);
    memcpy(c->resp.data + c->resp.data_len, fragment, length);
    c->resp.data_len += length;
    c->resp.data[c->resp.data_len] = '\0';
}

void test_http_response_header_lookup()
{
    int ret;
    flb_sds_t value;
    struct test_ctx *ctx;
    struct flb_http_client *c;

    ctx = test_ctx_create();
    if (!TEST_CHECK(ctx != NULL)) {
        exit(EXIT_FAILURE);
    }

    c = flb_http_client(ctx->u_conn, FLB_HTTP_GET, "/", NULL, 0,
                        "127.0.0.1", 80, NULL, FLB_HTTP_11);
    if (!TEST_CHECK(c != NULL)) {
        TEST_MSG("flb_http_client failed");
        test_ctx_destroy(ctx);
        exit(EXIT_FAILURE);
    }

    append_response_fragment(c,
                             "HTTP/1.1 204 No Content\r\n"
                             "X-Trace: abc123\r\n"
                             "\r\n");

    ret = flb_http_client_process_response_buffer(c);
    TEST_CHECK(ret == FLB_HTTP_OK);

    value = flb_http_get_response_header(c, "X-Trace", 7);
    TEST_CHECK(value != NULL);
    if (value != NULL) {
        TEST_CHECK(strcmp(value, "abc123") == 0);
        flb_sds_destroy(value);
    }

    flb_http_client_destroy(c);
    test_ctx_destroy(ctx);
}

void test_http_response_chunked_trailers()
{
    int ret;
    flb_sds_t value;
    struct test_ctx *ctx;
    struct flb_http_client *c;

    ctx = test_ctx_create();
    if (!TEST_CHECK(ctx != NULL)) {
        exit(EXIT_FAILURE);
    }

    c = flb_http_client(ctx->u_conn, FLB_HTTP_GET, "/", NULL, 0,
                        "127.0.0.1", 80, NULL, FLB_HTTP_11);
    if (!TEST_CHECK(c != NULL)) {
        TEST_MSG("flb_http_client failed");
        test_ctx_destroy(ctx);
        exit(EXIT_FAILURE);
    }

    append_response_fragment(c,
                             "HTTP/1.1 200 OK\r\n"
                             "Transfer-Encoding: chunked\r\n"
                             "Trailer: Expires, X-Trace\r\n"
                             "\r\n"
                             "4;foo=bar\r\n"
                             "Wiki\r\n"
                             "5\r\n"
                             "pedia\r\n"
                             "0;done=yes\r\n"
                             "Expires: tomorrow\r\n"
                             "X-Trace: abc\r\n"
                             "\r\n");

    ret = flb_http_client_process_response_buffer(c);
    TEST_CHECK(ret == FLB_HTTP_OK);
    TEST_CHECK(c->resp.payload_size == strlen("Wikipedia"));
    TEST_CHECK(strncmp(c->resp.payload, "Wikipedia", strlen("Wikipedia")) == 0);

    value = flb_http_get_response_header(c, "Transfer-Encoding", 17);
    TEST_CHECK(value != NULL);
    if (value != NULL) {
        TEST_CHECK(strcmp(value, "chunked") == 0);
        flb_sds_destroy(value);
    }

    value = flb_http_get_response_header(c, "Expires", 7);
    TEST_CHECK(value != NULL);
    if (value != NULL) {
        TEST_CHECK(strcmp(value, "tomorrow") == 0);
        flb_sds_destroy(value);
    }

    value = flb_http_get_response_header(c, "X-Trace", 7);
    TEST_CHECK(value != NULL);
    if (value != NULL) {
        TEST_CHECK(strcmp(value, "abc") == 0);
        flb_sds_destroy(value);
    }

    flb_http_client_destroy(c);
    test_ctx_destroy(ctx);
}

void test_http_response_chunked_incremental()
{
    int ret;
    flb_sds_t value;
    struct test_ctx *ctx;
    struct flb_http_client *c;

    ctx = test_ctx_create();
    if (!TEST_CHECK(ctx != NULL)) {
        exit(EXIT_FAILURE);
    }

    c = flb_http_client(ctx->u_conn, FLB_HTTP_GET, "/", NULL, 0,
                        "127.0.0.1", 80, NULL, FLB_HTTP_11);
    if (!TEST_CHECK(c != NULL)) {
        TEST_MSG("flb_http_client failed");
        test_ctx_destroy(ctx);
        exit(EXIT_FAILURE);
    }

    append_response_fragment(c,
                             "HTTP/1.1 200 OK\r\n"
                             "Transfer-Encoding: chunked\r\n"
                             "\r\n"
                             "4\r\n"
                             "Wi");
    ret = flb_http_client_process_response_buffer(c);
    TEST_CHECK(ret == FLB_HTTP_MORE);

    append_response_fragment(c, "ki\r\n5\r\npedia\r\n");
    ret = flb_http_client_process_response_buffer(c);
    TEST_CHECK(ret == FLB_HTTP_CHUNK_AVAILABLE);
    TEST_CHECK(c->resp.payload_size == strlen("Wikipedia"));
    TEST_CHECK(strncmp(c->resp.payload, "Wikipedia", strlen("Wikipedia")) == 0);

    append_response_fragment(c, "0\r\n");
    ret = flb_http_client_process_response_buffer(c);
    TEST_CHECK(ret == FLB_HTTP_MORE);

    append_response_fragment(c, "X-Trace: stream\r\n\r\n");
    ret = flb_http_client_process_response_buffer(c);
    TEST_CHECK(ret == FLB_HTTP_OK);

    value = flb_http_get_response_header(c, "X-Trace", 7);
    TEST_CHECK(value != NULL);
    if (value != NULL) {
        TEST_CHECK(strcmp(value, "stream") == 0);
        flb_sds_destroy(value);
    }

    flb_http_client_destroy(c);
    test_ctx_destroy(ctx);
}

void test_http_response_chunked_invalid_trailer()
{
    int ret;
    struct test_ctx *ctx;
    struct flb_http_client *c;

    ctx = test_ctx_create();
    if (!TEST_CHECK(ctx != NULL)) {
        exit(EXIT_FAILURE);
    }

    c = flb_http_client(ctx->u_conn, FLB_HTTP_GET, "/", NULL, 0,
                        "127.0.0.1", 80, NULL, FLB_HTTP_11);
    if (!TEST_CHECK(c != NULL)) {
        TEST_MSG("flb_http_client failed");
        test_ctx_destroy(ctx);
        exit(EXIT_FAILURE);
    }

    append_response_fragment(c,
                             "HTTP/1.1 200 OK\r\n"
                             "Transfer-Encoding: chunked\r\n"
                             "\r\n"
                             "4\r\n"
                             "Wiki\r\n"
                             "0\r\n"
                             "Broken-Trailer\r\n"
                             "\r\n");

    ret = flb_http_client_process_response_buffer(c);
    TEST_CHECK(ret == FLB_HTTP_ERROR);

    flb_http_client_destroy(c);
    test_ctx_destroy(ctx);
}

void test_http_response_chunked_empty_terminal_split()
{
    int ret;
    struct test_ctx *ctx;
    struct flb_http_client *c;

    ctx = test_ctx_create();
    if (!TEST_CHECK(ctx != NULL)) {
        exit(EXIT_FAILURE);
    }

    c = flb_http_client(ctx->u_conn, FLB_HTTP_GET, "/", NULL, 0,
                        "127.0.0.1", 80, NULL, FLB_HTTP_11);
    if (!TEST_CHECK(c != NULL)) {
        TEST_MSG("flb_http_client failed");
        test_ctx_destroy(ctx);
        exit(EXIT_FAILURE);
    }

    append_response_fragment(c,
                             "HTTP/1.1 200 OK\r\n"
                             "Transfer-Encoding: chunked\r\n"
                             "\r\n"
                             "4\r\n"
                             "Wiki\r\n"
                             "0\r\n");
    ret = flb_http_client_process_response_buffer(c);
    TEST_CHECK(ret == FLB_HTTP_MORE || ret == FLB_HTTP_CHUNK_AVAILABLE);

    append_response_fragment(c, "\r\n");
    ret = flb_http_client_process_response_buffer(c);
    TEST_CHECK(ret == FLB_HTTP_OK);
    TEST_CHECK(c->resp.payload_size == strlen("Wiki"));
    TEST_CHECK(strncmp(c->resp.payload, "Wiki", strlen("Wiki")) == 0);

    flb_http_client_destroy(c);
    test_ctx_destroy(ctx);
}

void test_http_response_chunked_uppercase_hex_whitespace()
{
    int ret;
    struct test_ctx *ctx;
    struct flb_http_client *c;

    ctx = test_ctx_create();
    if (!TEST_CHECK(ctx != NULL)) {
        exit(EXIT_FAILURE);
    }

    c = flb_http_client(ctx->u_conn, FLB_HTTP_GET, "/", NULL, 0,
                        "127.0.0.1", 80, NULL, FLB_HTTP_11);
    if (!TEST_CHECK(c != NULL)) {
        TEST_MSG("flb_http_client failed");
        test_ctx_destroy(ctx);
        exit(EXIT_FAILURE);
    }

    append_response_fragment(c,
                             "HTTP/1.1 200 OK\r\n"
                             "Transfer-Encoding: chunked\r\n"
                             "\r\n"
                             "  A ;foo=bar\r\n"
                             "0123456789\r\n"
                             "0\r\n\r\n");

    ret = flb_http_client_process_response_buffer(c);
    TEST_CHECK(ret == FLB_HTTP_OK);
    TEST_CHECK(c->resp.payload_size == strlen("0123456789"));
    TEST_CHECK(strncmp(c->resp.payload, "0123456789", strlen("0123456789")) == 0);

    flb_http_client_destroy(c);
    test_ctx_destroy(ctx);
}

void test_http_response_chunked_multi_stage_trailers()
{
    int ret;
    flb_sds_t value;
    struct test_ctx *ctx;
    struct flb_http_client *c;

    ctx = test_ctx_create();
    if (!TEST_CHECK(ctx != NULL)) {
        exit(EXIT_FAILURE);
    }

    c = flb_http_client(ctx->u_conn, FLB_HTTP_GET, "/", NULL, 0,
                        "127.0.0.1", 80, NULL, FLB_HTTP_11);
    if (!TEST_CHECK(c != NULL)) {
        TEST_MSG("flb_http_client failed");
        test_ctx_destroy(ctx);
        exit(EXIT_FAILURE);
    }

    append_response_fragment(c,
                             "HTTP/1.1 200 OK\r\n"
                             "Transfer-Encoding: chunked\r\n"
                             "\r\n"
                             "4\r\n"
                             "Wiki\r\n"
                             "0\r\n"
                             "X-One: 1\r\n");
    ret = flb_http_client_process_response_buffer(c);
    TEST_CHECK(ret == FLB_HTTP_CHUNK_AVAILABLE);

    append_response_fragment(c, "X-Two: 2\r\n");
    ret = flb_http_client_process_response_buffer(c);
    TEST_CHECK(ret == FLB_HTTP_MORE);

    append_response_fragment(c, "\r\n");
    ret = flb_http_client_process_response_buffer(c);
    TEST_CHECK(ret == FLB_HTTP_OK);

    value = flb_http_get_response_header(c, "X-One", 5);
    TEST_CHECK(value != NULL);
    if (value != NULL) {
        TEST_CHECK(strcmp(value, "1") == 0);
        flb_sds_destroy(value);
    }

    value = flb_http_get_response_header(c, "X-Two", 5);
    TEST_CHECK(value != NULL);
    if (value != NULL) {
        TEST_CHECK(strcmp(value, "2") == 0);
        flb_sds_destroy(value);
    }

    flb_http_client_destroy(c);
    test_ctx_destroy(ctx);
}

void test_http_response_chunked_partial_trailer_preserves_chunk_available()
{
    int ret;
    struct test_ctx *ctx;
    struct flb_http_client *c;

    ctx = test_ctx_create();
    if (!TEST_CHECK(ctx != NULL)) {
        exit(EXIT_FAILURE);
    }

    c = flb_http_client(ctx->u_conn, FLB_HTTP_GET, "/", NULL, 0,
                        "127.0.0.1", 80, NULL, FLB_HTTP_11);
    if (!TEST_CHECK(c != NULL)) {
        TEST_MSG("flb_http_client failed");
        test_ctx_destroy(ctx);
        exit(EXIT_FAILURE);
    }

    append_response_fragment(c,
                             "HTTP/1.1 200 OK\r\n"
                             "Transfer-Encoding: chunked\r\n"
                             "\r\n"
                             "4\r\n"
                             "Wiki\r\n"
                             "0\r\n"
                             "X-Trace: partial");

    ret = flb_http_client_process_response_buffer(c);
    TEST_CHECK(ret == FLB_HTTP_CHUNK_AVAILABLE);
    TEST_CHECK(c->resp.payload_size == strlen("Wiki"));
    TEST_CHECK(strncmp(c->resp.payload, "Wiki", strlen("Wiki")) == 0);

    flb_http_client_destroy(c);
    test_ctx_destroy(ctx);
}

void test_http_response_chunked_invalid_size_suffix()
{
    int ret;
    struct test_ctx *ctx;
    struct flb_http_client *c;

    ctx = test_ctx_create();
    if (!TEST_CHECK(ctx != NULL)) {
        exit(EXIT_FAILURE);
    }

    c = flb_http_client(ctx->u_conn, FLB_HTTP_GET, "/", NULL, 0,
                        "127.0.0.1", 80, NULL, FLB_HTTP_11);
    if (!TEST_CHECK(c != NULL)) {
        TEST_MSG("flb_http_client failed");
        test_ctx_destroy(ctx);
        exit(EXIT_FAILURE);
    }

    append_response_fragment(c,
                             "HTTP/1.1 200 OK\r\n"
                             "Transfer-Encoding: chunked\r\n"
                             "\r\n"
                             "1g\r\n"
                             "A\r\n"
                             "0\r\n\r\n");

    ret = flb_http_client_process_response_buffer(c);
    TEST_CHECK(ret == FLB_HTTP_ERROR);

    flb_http_client_destroy(c);
    test_ctx_destroy(ctx);
}

void test_http_response_chunked_oversized_length()
{
    int ret;
    struct test_ctx *ctx;
    struct flb_http_client *c;

    ctx = test_ctx_create();
    if (!TEST_CHECK(ctx != NULL)) {
        exit(EXIT_FAILURE);
    }

    c = flb_http_client(ctx->u_conn, FLB_HTTP_GET, "/", NULL, 0,
                        "127.0.0.1", 80, NULL, FLB_HTTP_11);
    if (!TEST_CHECK(c != NULL)) {
        TEST_MSG("flb_http_client failed");
        test_ctx_destroy(ctx);
        exit(EXIT_FAILURE);
    }

    append_response_fragment(c,
                             "HTTP/1.1 200 OK\r\n"
                             "Transfer-Encoding: chunked\r\n"
                             "\r\n"
                             "ffffffffffffffffffffffffffffffff\r\n");

    ret = flb_http_client_process_response_buffer(c);
    TEST_CHECK(ret == FLB_HTTP_ERROR);

    flb_http_client_destroy(c);
    test_ctx_destroy(ctx);
}

void test_http_timeout_setters_preserve_upstream_io_timeout()
{
    struct test_ctx *ctx;
    struct flb_http_client *c;

    ctx = test_ctx_create();
    if (!TEST_CHECK(ctx != NULL)) {
        exit(EXIT_FAILURE);
    }

    ctx->u->base.net.io_timeout = 10;

    c = flb_http_client(ctx->u_conn, FLB_HTTP_GET, "/", NULL, 0,
                        "127.0.0.1", 80, NULL, FLB_HTTP_11);
    if (!TEST_CHECK(c != NULL)) {
        TEST_MSG("flb_http_client failed");
        test_ctx_destroy(ctx);
        exit(EXIT_FAILURE);
    }

    TEST_CHECK(flb_http_set_response_timeout(c, 5) == 0);
    TEST_CHECK(ctx->u->base.net.io_timeout == 10);
    TEST_CHECK(c->u_conn->net->io_timeout == 5);

    TEST_CHECK(flb_http_set_read_idle_timeout(c, 3) == 0);
    TEST_CHECK(ctx->u->base.net.io_timeout == 10);
    TEST_CHECK(c->u_conn->net->io_timeout == 3);

    TEST_CHECK(flb_http_set_response_timeout(c, 8) == 0);
    TEST_CHECK(ctx->u->base.net.io_timeout == 10);
    TEST_CHECK(c->u_conn->net->io_timeout == 3);

    flb_http_client_destroy(c);
    test_ctx_destroy(ctx);
}

static void test_http_request_target_validation(void)
{
    struct test_ctx *ctx;
    struct flb_http_client *c;
    int i;
    char target[] = "/badXtarget";
    const char *valid[] = {"/", "/pods/a-b.c", "/search?q=a%20b&n=1"};

    ctx = test_ctx_create();
    TEST_ASSERT(ctx != NULL);
    for (i = 1; i <= 0x7f; i++) {
        if (i > 0x20 && i != 0x7f) {
            continue;
        }
        target[4] = i;
        c = flb_http_client(ctx->u_conn, FLB_HTTP_GET, target,
                            NULL, 0, NULL, 0, NULL, 0);
        TEST_CHECK(c == NULL);
        if (c != NULL) {
            flb_http_client_destroy(c);
        }
    }
    for (i = 0; i < sizeof(valid) / sizeof(valid[0]); i++) {
        c = flb_http_client(ctx->u_conn, FLB_HTTP_GET, valid[i],
                            NULL, 0, NULL, 0, NULL, 0);
        TEST_CHECK(c != NULL);
        if (c != NULL) {
            flb_http_client_destroy(c);
        }
    }
    test_ctx_destroy(ctx);
}

void test_http_header_validation(void)
{
    unsigned int byte;
    int expected;
    size_t sent;
    char name[] = "X-Test";
    char value[] = "aXb";
    struct test_ctx *ctx;
    struct flb_http_client *client;
    struct flb_http_request *request;
    struct flb_kv *header;

    ctx = test_ctx_create();
    TEST_ASSERT(ctx != NULL);
    ctx->u_conn->stream = &ctx->u->base;
    for (byte = 0; byte <= 255; byte++) {
        value[1] = (char) byte;
        expected = (byte < 0x20 && byte != '\t') || byte == 0x7f ? -1 : 0;
        client = flb_http_client(ctx->u_conn, FLB_HTTP_GET, "/", NULL, 0, NULL, 0, NULL, 0);
        request = flb_http_request_create();
        TEST_ASSERT(client != NULL);
        TEST_ASSERT(request != NULL);
        TEST_CHECK(flb_http_add_header(client, name, 6, value, 3) == expected);
        TEST_CHECK(flb_http_request_set_header(request, name, 6, value, 3) == expected);
        if (expected == -1) {
            sent = 0;
            TEST_CHECK(flb_http_do_request(client, &sent) == FLB_HTTP_ERROR);
            TEST_CHECK(sent == 0);
            TEST_CHECK(flb_http_request_commit(request) == -1);
        }
        flb_http_request_destroy(request);
        flb_free(request);
        flb_http_client_destroy(client);
    }
    for (byte = 0; byte <= 255; byte++) {
        name[2] = (char) byte;
        expected = ((byte >= 'a' && byte <= 'z') || (byte >= 'A' && byte <= 'Z') ||
                    (byte >= '0' && byte <= '9') ||
                    (byte != 0 && strchr("!#$%&'*+-.^_`|~", byte) != NULL)) ? 0 : -1;
        TEST_CHECK(flb_http_header_validate(name, 6, "ok", 2) == expected);
        client = flb_http_client(ctx->u_conn, FLB_HTTP_GET, "/", NULL, 0, NULL, 0, NULL, 0);
        request = flb_http_request_create();
        TEST_ASSERT(client != NULL);
        TEST_ASSERT(request != NULL);
        TEST_CHECK(flb_http_add_header(client, name, 6, "ok", 2) == expected);
        TEST_CHECK(flb_http_request_set_header(request, name, 6, "ok", 2) == expected);
        flb_http_request_destroy(request);
        flb_free(request);
        flb_http_client_destroy(client);
    }
    TEST_CHECK(flb_http_header_validate("", 0, "ok", 2) == -1);
    TEST_CHECK(flb_http_header_validate(NULL, 1, "ok", 2) == -1);
    TEST_CHECK(flb_http_header_validate("X", 1, NULL, 1) == -1);
    TEST_CHECK(flb_http_header_validate("X", 1, "", 0) == 0);
    TEST_CHECK(flb_http_header_validate("X", 1, "acme\r\nX-Evil: yes", 17) == -1);
    TEST_CHECK(flb_http_header_validate("X", 1, "acme\r\n\r\n", 8) == -1);
    client = flb_http_client(ctx->u_conn, FLB_HTTP_GET, "/", NULL, 0, NULL, 0, NULL, 0);
    TEST_ASSERT(client != NULL);
    header = flb_kv_item_create_len(&client->headers, "X-Test", 6, "bad\r\nvalue", 10);
    TEST_ASSERT(header != NULL);
    sent = 0;
    TEST_CHECK(flb_http_do_request(client, &sent) == FLB_HTTP_ERROR);
    TEST_CHECK(sent == 0);
    flb_http_client_destroy(client);

    request = flb_http_request_create();
    TEST_ASSERT(request != NULL);
    TEST_CHECK(flb_http_request_set_header(request, "X-Test", 0, "", 0) == 0);
    TEST_CHECK(strcmp(flb_http_request_get_header(request, "x-test"), "") == 0);
    TEST_CHECK(flb_http_request_set_header(request, "X-Test", 0, "safe", 0) == 0);
    TEST_CHECK(flb_http_request_set_header(request, "X-Test", 0, "bad\n", 0) == -1);
    TEST_CHECK(strcmp(flb_http_request_get_header(request, "x-test"), "safe") == 0);
    flb_http_request_destroy(request);
    flb_free(request);
    test_ctx_destroy(ctx);
}

void test_http1_header_serialization_validation(void)
{
    struct flb_http_request *request;
    struct flb_http_client_session session = {0};
    struct flb_http_stream stream = {0};

    request = flb_http_request_create();
    TEST_ASSERT(request != NULL);
    stream.parent = &session;
    request->stream = &stream;
    request->protocol_version = HTTP_PROTOCOL_VERSION_11;
    request->method = HTTP_METHOD_GET;
    request->path = cfl_sds_create("/");
    TEST_ASSERT(request->path != NULL);
    TEST_CHECK(flb_hash_table_add(request->headers, "X-Test", 6, "bad\r\nvalue", 10) >= 0);
    TEST_CHECK(flb_http1_request_commit(request) == -6);
    TEST_CHECK(session.outgoing_data == NULL);
    flb_hash_table_del(request->headers, "X-Test");
    request->host = cfl_sds_create("localhost\r\nX-Evil: yes");
    TEST_ASSERT(request->host != NULL);
    TEST_CHECK(flb_http1_request_commit(request) == -7);
    TEST_CHECK(session.outgoing_data == NULL);
    flb_http_request_destroy(request);
    flb_free(request);

    request = flb_http_request_create();
    TEST_ASSERT(request != NULL);
    request->stream = &stream;
    request->protocol_version = HTTP_PROTOCOL_VERSION_20;
    stream.role = HTTP_STREAM_ROLE_SERVER;
    TEST_CHECK(flb_http_request_set_header(request, ":method", 0, "GET", 0) == 0);
    TEST_CHECK(flb_http_request_set_header(request, ":path", 0, "/", 0) == 0);
    stream.role = HTTP_STREAM_ROLE_CLIENT;
    TEST_CHECK(flb_http_request_set_header(request, ":method", 0, "GET", 0) == -1);
    flb_http_request_destroy(request);
    flb_free(request);
}

void test_http1_empty_header_serialization(void)
{
    struct flb_http_request *request;
    struct flb_http_client_session session = {0};
    struct flb_http_stream stream = {0};
    const char expected[] = "GET / HTTP/1.1\r\nX-Empty: \r\n\r\n";

    request = flb_http_request_create();
    TEST_ASSERT(request != NULL);
    stream.parent = &session;
    stream.role = HTTP_STREAM_ROLE_CLIENT;
    session.http1.parent = &session;
    session.outgoing_data = cfl_sds_create("");
    TEST_ASSERT(session.outgoing_data != NULL);
    request->stream = &stream;
    request->protocol_version = HTTP_PROTOCOL_VERSION_11;
    request->method = HTTP_METHOD_GET;
    request->path = cfl_sds_create("/");
    TEST_ASSERT(request->path != NULL);

    TEST_CHECK(flb_http_request_set_header(request, "X-Empty", 0, "", 0) == 0);
    TEST_CHECK(flb_http1_request_commit(request) == 0);
    TEST_CHECK(cfl_sds_len(session.outgoing_data) == sizeof(expected) - 1);
    TEST_CHECK(strcmp(session.outgoing_data, expected) == 0);

    /* Replacing a nonempty value must preserve the same empty wire value. */
    TEST_CHECK(flb_http_request_set_header(request, "X-Empty", 0, "value", 0) == 0);
    TEST_CHECK(flb_http_request_set_header(request, "X-Empty", 0, "", 0) == 0);
    cfl_sds_len_set(session.outgoing_data, 0);
    TEST_CHECK(flb_http1_request_commit(request) == 0);
    TEST_CHECK(cfl_sds_len(session.outgoing_data) == sizeof(expected) - 1);
    TEST_CHECK(strcmp(session.outgoing_data, expected) == 0);

    cfl_sds_destroy(session.outgoing_data);
    flb_http_request_destroy(request);
    flb_free(request);
}

TEST_LIST = {
    { "http1_empty_header_serialization", test_http1_empty_header_serialization},
    { "http1_header_serialization_validation", test_http1_header_serialization_validation},
    { "header_validation", test_http_header_validation},
    { "request_target_validation", test_http_request_target_validation},
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
    { "port_443_without_tls_host_header", test_port_443_without_tls_host_header},
    { "ipv6_zone_id_host_header", test_ipv6_zone_id_host_header},
    { "https_non_standard_port_host_header", test_https_non_standard_port_host_header},
    { "ipv6_bracketed_zone_id_host_header", test_ipv6_bracketed_zone_id_host_header},
    { "https_ipv6_default_port_host_header", test_https_ipv6_default_port_host_header},
    { "https_ipv6_non_standard_port_host_header", test_https_ipv6_non_standard_port_host_header},
    { "https_ipv6_zone_id_default_port_host_header", test_https_ipv6_zone_id_default_port_host_header},
    { "https_ipv6_zone_id_non_standard_port_host_header", test_https_ipv6_zone_id_non_standard_port_host_header},
    { "response_header_lookup", test_http_response_header_lookup},
    { "response_chunked_trailers", test_http_response_chunked_trailers},
    { "response_chunked_incremental", test_http_response_chunked_incremental},
    { "response_chunked_invalid_trailer", test_http_response_chunked_invalid_trailer},
    { "response_chunked_empty_terminal_split", test_http_response_chunked_empty_terminal_split},
    { "response_chunked_uppercase_hex_whitespace", test_http_response_chunked_uppercase_hex_whitespace},
    { "response_chunked_multi_stage_trailers", test_http_response_chunked_multi_stage_trailers},
    { "response_chunked_partial_trailer_preserves_chunk_available", test_http_response_chunked_partial_trailer_preserves_chunk_available},
    { "response_chunked_invalid_size_suffix", test_http_response_chunked_invalid_size_suffix},
    { "response_chunked_oversized_length", test_http_response_chunked_oversized_length},
    { "timeout_setters_preserve_upstream_io_timeout", test_http_timeout_setters_preserve_upstream_io_timeout},
    { 0 }
};
