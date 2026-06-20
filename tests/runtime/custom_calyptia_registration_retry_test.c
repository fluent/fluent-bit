/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit.h>
#include <fluent-bit/flb_custom.h>
#include <monkey/mk_core.h>
#include <monkey/mk_lib.h>
#include <fluent-bit/flb_time.h>
#include <stdlib.h>
#include <string.h>

#include "flb_tests_runtime.h"

#define MOCK_SERVER_HOST "127.0.0.1"
#define MOCK_SERVER_PORT 9876

static int registration_count = 0;

static void mock_server_cb_empty_token(mk_request_t *request, void *data)
{
    registration_count++;
    if (registration_count == 1) {
        /* Use a local buffer with correct size */
        const char *response = "{\"id\":\"test-id\"}";
        size_t response_len = strlen(response); // Ensure size is accurate

        mk_http_status(request, 200);
        mk_http_header(request, "Content-Type", sizeof("Content-Type") - 1,
                       "application/json", sizeof("application/json") - 1);
        mk_http_send(request, (char *) response, response_len, NULL);
    } else {
        mk_http_status(request, 500);
        mk_http_header(request, "Content-Type", sizeof("Content-Type") - 1,
                       "text/plain", sizeof("text/plain") - 1);
        mk_http_send(request, (char *) "Internal Server Error",
                     sizeof("Internal Server Error") - 1, NULL);
    }
    mk_http_done(request);
}

static void mock_server_cb(mk_request_t *request, void *data)
{
    registration_count++;
    mk_http_status(request, 500);
    mk_http_header(request, "Content-Type", sizeof("Content-Type") - 1,
                    "text/plain", sizeof("text/plain") - 1);
    mk_http_send(request, (char *) "Internal Server Error",
                 sizeof("Internal Server Error") - 1, NULL);
    mk_http_done(request);
}

/* Test function */
void test_calyptia_register_retry()
{
    flb_ctx_t *ctx;
    int ret;
    int in_ffd;
    mk_ctx_t *mock_ctx;
    int vid;
    char tmp[256];
    struct flb_custom_instance *calyptia;

    /* Reset registration count */
    registration_count = 0;

    /* Init mock server */
    mock_ctx = mk_create();
    TEST_CHECK(mock_ctx != NULL);

    /* Compose listen address */
    snprintf(tmp, sizeof(tmp) - 1, "%s:%d", MOCK_SERVER_HOST, MOCK_SERVER_PORT);
    ret = mk_config_set(mock_ctx, "Listen", tmp, NULL);
    TEST_CHECK(ret == 0);

    vid = mk_vhost_create(mock_ctx, NULL);
    TEST_CHECK(vid >= 0);

    ret = mk_vhost_handler(mock_ctx, vid, "/v1/agents", mock_server_cb, NULL);
    TEST_CHECK(ret == 0);

    ret = mk_vhost_handler(mock_ctx, vid, "/v1/agents/test-id", mock_server_cb, NULL);
    TEST_CHECK(ret == 0);

    ret = mk_start(mock_ctx);
    TEST_CHECK(ret == 0);

    flb_time_msleep(500);  // Allow the mock server to initialize

    /* Init Fluent Bit context */
    ctx = flb_create();
    TEST_CHECK(ctx != NULL);

    ret = flb_service_set(ctx,
                          "Log_Level", "debug",
                          NULL);
    TEST_CHECK(ret == 0);

    /* Create dummy input */
    in_ffd = flb_input(ctx, (char *)"dummy", NULL);
    TEST_CHECK(in_ffd >= 0);

    /* Create custom Calyptia plugin */
    calyptia = flb_custom_new(ctx->config, (char *)"calyptia", NULL);
    TEST_CHECK(calyptia != NULL);

    /* Set custom plugin properties */
    flb_custom_set_property(calyptia, "api_key", "test-key");
    flb_custom_set_property(calyptia, "log_level", "debug");
    flb_custom_set_property(calyptia, "add_label", "pipeline_id test-pipeline-id");
    flb_custom_set_property(calyptia, "calyptia_host", MOCK_SERVER_HOST);
    flb_custom_set_property(calyptia, "calyptia_port", "9876");
    flb_custom_set_property(calyptia, "register_retry_on_flush", "true");
    flb_custom_set_property(calyptia, "calyptia_tls", "off");
    flb_custom_set_property(calyptia, "calyptia_tls.verify", "off");

    /* Start the engine */
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* First registration attempt should have failed */
    TEST_CHECK(registration_count == 1);

    flb_time_msleep(1000); 
    flb_lib_push(ctx, in_ffd, "{\"key\":\"val\"}", 13);

    /* Wait for processing */
    flb_time_msleep(10000);
    TEST_CHECK(registration_count > 1);

    /* Cleanup */
    flb_stop(ctx);
    flb_destroy(ctx);
    mk_stop(mock_ctx);
    mk_destroy(mock_ctx);
}

static void test_calyptia_register_retry_empty_token()
{
    flb_ctx_t *ctx;
    int ret;
    int in_ffd;
    mk_ctx_t *mock_ctx;
    int vid;
    char tmp[256];
    struct flb_custom_instance *calyptia;

    /* Reset registration count */
    registration_count = 0;

    /* Init mock server */
    mock_ctx = mk_create();
    TEST_CHECK(mock_ctx != NULL);

    /* Compose listen address */
    snprintf(tmp, sizeof(tmp) - 1, "%s:%d", MOCK_SERVER_HOST, MOCK_SERVER_PORT);
    ret = mk_config_set(mock_ctx, "Listen", tmp, NULL);
    TEST_CHECK(ret == 0);

    vid = mk_vhost_create(mock_ctx, NULL);
    TEST_CHECK(vid >= 0);

    ret = mk_vhost_handler(mock_ctx, vid, "/v1/agents", mock_server_cb_empty_token, NULL);
    TEST_CHECK(ret == 0);

    ret = mk_vhost_handler(mock_ctx, vid, "/v1/agents/test-id", mock_server_cb_empty_token, NULL);
    TEST_CHECK(ret == 0);

    ret = mk_start(mock_ctx);
    TEST_CHECK(ret == 0);

    flb_time_msleep(500);  // Allow the mock server to initialize

    /* Init Fluent Bit context */
    ctx = flb_create();
    TEST_CHECK(ctx != NULL);

    ret = flb_service_set(ctx,
                          "Log_Level", "debug",
                          NULL);
    TEST_CHECK(ret == 0);

    /* Create dummy input */
    in_ffd = flb_input(ctx, (char *)"dummy", NULL);
    TEST_CHECK(in_ffd >= 0);

    /* Create custom Calyptia plugin */
    calyptia = flb_custom_new(ctx->config, (char *)"calyptia", NULL);
    TEST_CHECK(calyptia != NULL);

    /* Set custom plugin properties */
    flb_custom_set_property(calyptia, "api_key", "test-key");
    flb_custom_set_property(calyptia, "log_level", "debug");
    flb_custom_set_property(calyptia, "add_label", "pipeline_id test-pipeline-id");
    flb_custom_set_property(calyptia, "calyptia_host", MOCK_SERVER_HOST);
    flb_custom_set_property(calyptia, "calyptia_port", "9876");
    flb_custom_set_property(calyptia, "register_retry_on_flush", "false");
    flb_custom_set_property(calyptia, "calyptia_tls", "off");
    flb_custom_set_property(calyptia, "calyptia_tls.verify", "off");

    /* Start the engine */
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* First registration should be successful but with an empty token */
    TEST_CHECK(registration_count == 1);

    /* Push some data to trigger flush */
    flb_time_msleep(1000);
    flb_lib_push(ctx, in_ffd, "{\"key\":\"val\"}", 13);

    /* Wait for processing */
    flb_time_msleep(10000);

    /* Verify the plugin fails due to empty token */
    TEST_CHECK(registration_count == 1);

    /* Cleanup */
    flb_stop(ctx);
    flb_destroy(ctx);
    mk_stop(mock_ctx);
    mk_destroy(mock_ctx);
}

static void test_calyptia_register_retry_empty_token_retry_true()
{
    flb_ctx_t *ctx;
    int ret;
    int in_ffd;
    mk_ctx_t *mock_ctx;
    int vid;
    char tmp[256];
    struct flb_custom_instance *calyptia;

    /* Reset registration count */
    registration_count = 0;

    /* Init mock server */
    mock_ctx = mk_create();
    TEST_CHECK(mock_ctx != NULL);

    /* Compose listen address */
    snprintf(tmp, sizeof(tmp) - 1, "%s:%d", MOCK_SERVER_HOST, MOCK_SERVER_PORT);
    ret = mk_config_set(mock_ctx, "Listen", tmp, NULL);
    TEST_CHECK(ret == 0);

    vid = mk_vhost_create(mock_ctx, NULL);
    TEST_CHECK(vid >= 0);

    ret = mk_vhost_handler(mock_ctx, vid, "/v1/agents", mock_server_cb_empty_token, NULL);
    TEST_CHECK(ret == 0);

    ret = mk_vhost_handler(mock_ctx, vid, "/v1/agents/test-id", mock_server_cb_empty_token, NULL);
    TEST_CHECK(ret == 0);

    ret = mk_start(mock_ctx);
    TEST_CHECK(ret == 0);

    flb_time_msleep(500);  // Allow the mock server to initialize

    /* Init Fluent Bit context */
    ctx = flb_create();
    TEST_CHECK(ctx != NULL);

    ret = flb_service_set(ctx,
                          "Log_Level", "debug",
                          NULL);
    TEST_CHECK(ret == 0);

    /* Create dummy input */
    in_ffd = flb_input(ctx, (char *)"dummy", NULL);
    TEST_CHECK(in_ffd >= 0);

    /* Create custom Calyptia plugin */
    calyptia = flb_custom_new(ctx->config, (char *)"calyptia", NULL);
    TEST_CHECK(calyptia != NULL);

    /* Set custom plugin properties */
    flb_custom_set_property(calyptia, "api_key", "test-key");
    flb_custom_set_property(calyptia, "log_level", "debug");
    flb_custom_set_property(calyptia, "add_label", "pipeline_id test-pipeline-id");
    flb_custom_set_property(calyptia, "calyptia_host", MOCK_SERVER_HOST);
    flb_custom_set_property(calyptia, "calyptia_port", "9876");
    flb_custom_set_property(calyptia, "register_retry_on_flush", "true");
    flb_custom_set_property(calyptia, "calyptia_tls", "off");
    flb_custom_set_property(calyptia, "calyptia_tls.verify", "off");

    /* Start the engine */
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* First registration should be successful but with an empty token */
    TEST_CHECK(registration_count == 1);

    /* Push some data to trigger flush */
    flb_time_msleep(1000);
    flb_lib_push(ctx, in_ffd, "{\"key\":\"val\"}", 13);

    /* Wait for processing */
    flb_time_msleep(10000);

    /* Verify the plugin fails due to empty token */
    TEST_CHECK(registration_count > 1);

    /* Cleanup */
    flb_stop(ctx);
    flb_destroy(ctx);
    mk_stop(mock_ctx);
    mk_destroy(mock_ctx);
}

TEST_LIST = {
    {"register_retry", test_calyptia_register_retry},
    {"register_retry_empty_token", test_calyptia_register_retry_empty_token},
    {"register_retry_empty_token_retry_true", test_calyptia_register_retry_empty_token_retry_true},
    {NULL, NULL}
};
