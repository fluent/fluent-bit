/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_error.h>
#include <fluent-bit/flb_socket.h>
#include <fluent-bit/flb_http_client.h>

#include "flb_tests_internal.h"

void test_http_buffer_increase()
{
    int ret;
    size_t s;
    struct flb_http_client *c;
    struct flb_http_response *resp;
    struct flb_upstream *u;
    struct flb_upstream_conn *u_conn;
    struct flb_config *config;

    config = flb_config_init();
    TEST_CHECK(config != NULL);

    u = flb_upstream_create(config, "127.0.0.1", 80, 0, NULL);
    TEST_CHECK(u != NULL);

    u_conn = flb_malloc(sizeof(struct flb_upstream_conn));
    TEST_CHECK(u_conn != NULL);
    u_conn->u = u;

    /* Create HTTP client instance */
    c = flb_http_client(u_conn, FLB_HTTP_GET, "/", NULL, 0,
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

    flb_free(u_conn);
    flb_http_client_destroy(c);
    flb_upstream_destroy(u);
    flb_config_exit(config);
}

TEST_LIST = {
    { "http_buffer_increase", test_http_buffer_increase},
    { 0 }
};
