/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit.h>
#include <fluent-bit/flb_http_client.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_regex.h>
#include <fluent-bit/flb_time.h>
#include <time.h>

#include "flb_tests_runtime.h"

struct http_client_ctx {
    struct flb_upstream *u;
    struct flb_connection *u_conn;
    struct flb_config *config;
    struct mk_event_loop *evl;
};

struct http_client_ctx *http_client_ctx_create()
{
    struct http_client_ctx *ret_ctx = NULL;
    struct mk_event_loop *evl       = NULL;

    ret_ctx = flb_calloc(1, sizeof(struct http_client_ctx));
    if (!TEST_CHECK(ret_ctx != NULL)) {
        flb_errno();
        TEST_MSG("flb_calloc(http_client_ctx) failed");
        return NULL;
    }

    evl = mk_event_loop_create(16);
    if (!TEST_CHECK(evl != NULL)) {
        TEST_MSG("mk_event_loop failed");
        flb_free(ret_ctx);
        return NULL;
    }
    ret_ctx->evl = evl;
    flb_engine_evl_init();
    flb_engine_evl_set(evl);

    ret_ctx->config = flb_config_init();
    if (!TEST_CHECK(ret_ctx->config != NULL)) {
        TEST_MSG("flb_config_init failed");
        mk_event_loop_destroy(evl);
        flb_free(ret_ctx);
        return NULL;
    }

    ret_ctx->u = flb_upstream_create(ret_ctx->config, "127.0.0.1", 2020, 0, NULL);
    if (!TEST_CHECK(ret_ctx->u != NULL)) {
        TEST_MSG("flb_upstream_create failed");
        flb_config_exit(ret_ctx->config);
        mk_event_loop_destroy(evl);
        flb_free(ret_ctx);
        return NULL;
    }

    ret_ctx->u_conn = flb_upstream_conn_get(ret_ctx->u);
    TEST_CHECK(ret_ctx->u_conn != NULL);

    ret_ctx->u_conn->upstream = ret_ctx->u;

    return ret_ctx;
}

void http_client_ctx_destroy(struct http_client_ctx *http_ctx)
{
    TEST_CHECK(flb_upstream_conn_release(http_ctx->u_conn) == 0);
    flb_upstream_destroy(http_ctx->u);
    mk_event_loop_destroy(http_ctx->evl);
    flb_config_exit(http_ctx->config);
    flb_free(http_ctx);
}

/* Check for expected Prometheus metrics. If the prom scrape endpoints returns a non-200
 * and fail_test is FLB_FALSE, this returns without failing the test.
 * This returns 0 if all the assertions were checked and no retry is necessary.
 */
int assert_internal_log_metrics(struct http_client_ctx *http_ctx, int fail_test)
{
    struct flb_http_client *http_client;
    size_t b_sent;
    struct flb_regex *regex;

    http_client = flb_http_client(http_ctx->u_conn,
                                  FLB_HTTP_GET,
                                  "/api/v2/metrics/prometheus",
                                  "", /* body */
                                  0,  /* len(body) */
                                  "127.0.0.1",
                                  2020,
                                  NULL,
                                  0);
    TEST_ASSERT(http_client != NULL);

    TEST_ASSERT(flb_http_do(http_client, &b_sent) == 0);

    if (http_client->resp.status != 200 && !fail_test) {
        flb_http_client_destroy(http_client);
        return -1;
    }

    TEST_MSG(http_client->resp.payload);
    if (!TEST_CHECK(http_client->resp.status == 200)) {
        TEST_MSG("http response code error. expect: 200, got: %d\n",
                 http_client->resp.status);
    }

    /* There be no errors logged */
    if (!TEST_CHECK(
            strstr(http_client->resp.payload,
                   "fluentbit_logger_logs_total{message_type=\"error\"} 0")
            != NULL)) {
        TEST_MSG("response payload: %s", http_client->resp.payload);
    }

    /* The process startup should have logged at least 1 info log */
    regex = flb_regex_create(
        "fluentbit_logger_logs_total\\{message_type=\"info\"\\} [1-9]+[0-9]*");
    if (!TEST_CHECK(regex != NULL)) {
        TEST_MSG("Failed to create regex for info log count check");
        flb_http_client_destroy(http_client);
        return -1;
    }
    if (!TEST_CHECK(flb_regex_match(
            regex, http_client->resp.payload, http_client->resp.payload_size))) {
        TEST_MSG("response payload: %s\n", http_client->resp.payload);
    }

    flb_regex_destroy(regex);
    flb_http_client_destroy(http_client);

    return 0;
}

/*
 * Test that internal logs (i.e. those created by flb_info, flb_error, etc)
 * tick internal v2 metrics.
 */
static void test_internal_log_metrics()
{
    flb_ctx_t *ctx;
    int ret;
    struct http_client_ctx *http_ctx;
    struct flb_http_client *http_client;
    size_t b_sent;
    struct flb_regex *regex;
    int i;
    int attempt_count = 30;

    ctx = flb_create();
    TEST_ASSERT(ctx != NULL);

    TEST_ASSERT(flb_service_set(ctx,
                                "HTTP_Server",
                                "On",
                                "HTTP_Listen",
                                "127.0.0.1",
                                "HTTP_Port",
                                "2020",
                                NULL) == 0);

    ret = flb_start(ctx);
    TEST_ASSERT(ret == 0);

    http_ctx = http_client_ctx_create();
    TEST_ASSERT(http_ctx != NULL);

    /* If the assertion fails, retry in a sleep loop since the fluent-bit's HTTP server
     * may not be ready yet */
    for (i = 0; i < attempt_count; i++) {
        if (assert_internal_log_metrics(http_ctx, i == (attempt_count - 1)) ) {
            break;
        }
        flb_time_msleep(100);
    }

    http_client_ctx_destroy(http_ctx);
    TEST_CHECK(flb_stop(ctx) == 0);
    flb_destroy(ctx);
}

/* Test list */
TEST_LIST = {
    {"internal_log_metrics", test_internal_log_metrics},
    {NULL, NULL},
};
