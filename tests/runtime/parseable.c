/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
#include <fluent-bit.h>
#include "flb_tests_runtime.h"
/* Test data */
#define JSON_BASIC    "[1448403340, {\"message\":\"test message\", \"kubernetes\":{\"namespace_name\":\"test-ns\"}}]"
#define JSON_EXCLUDE  "[1448403340, {\"message\":\"excluded message\", \"kubernetes\":{\"namespace_name\":\"kube-system\"}}]"
/* Test callbacks */
static void cb_check_basic_config(void *ctx, int ffd,
                                int res_ret, void *res_data, size_t res_size,
                                void *data)
{
    char *p;
    char *out_js = res_data;
    /* Check that source field was added */
    p = strstr(out_js, "\"source\":\"fluent bit parseable plugin\"");
    TEST_CHECK(p != NULL);
    /* Check X-P-Stream header value */
    p = strstr(out_js, "\"X-P-Stream\":\"test-stream\"");
    TEST_CHECK(p != NULL);
    flb_sds_destroy(res_data);
}
static void cb_check_namespace_stream(void *ctx, int ffd,
                                    int res_ret, void *res_data, size_t res_size,
                                    void *data)
{
    char *p;
    char *out_js = res_data;
    /* Check that namespace from kubernetes metadata is used as stream */
    p = strstr(out_js, "\"X-P-Stream\":\"test-ns\"");
    TEST_CHECK(p != NULL);
    flb_sds_destroy(res_data);
}
static void cb_check_exclude_namespace(void *ctx, int ffd,
                                     int res_ret, void *res_data, size_t res_size,
                                     void *data)
{
    /* This callback should not be called if namespace exclusion works */
    TEST_CHECK(false);
    flb_sds_destroy(res_data);
}
/* Test functions */
void flb_test_basic_config()
{
    int ret;
    int size = sizeof(JSON_BASIC) - 1;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    /* Create context, flush every second */
    ctx = flb_create();
    flb_service_set(ctx, "flush", "1", "grace", "1", NULL);
    /* Lib input mode */
    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);
    /* Parseable output */
    out_ffd = flb_output(ctx, (char *) "parseable", NULL);
    flb_output_set(ctx, out_ffd,
                   "match", "test",
                   "server_host", "localhost",
                   "server_port", "8000",
                   "username", "test-user",
                   "password", "test-pass",
                   "stream", "test-stream",
                   NULL);
    /* Enable test mode */
    ret = flb_output_set_test(ctx, out_ffd, "formatter",
                             cb_check_basic_config,
                             NULL, NULL);
    /* Start */
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);
    /* Ingest data sample */
    flb_lib_push(ctx, in_ffd, (char *) JSON_BASIC, size);
    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}
void flb_test_namespace_stream()
{
    int ret;
    int size = sizeof(JSON_BASIC) - 1;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    /* Create context, flush every second */
    ctx = flb_create();
    flb_service_set(ctx, "flush", "1", "grace", "1", NULL);
    /* Lib input mode */
    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);
    /* Parseable output with $NAMESPACE stream */
    out_ffd = flb_output(ctx, (char *) "parseable", NULL);
    flb_output_set(ctx, out_ffd,
                   "match", "test",
                   "server_host", "localhost",
                   "server_port", "8000",
                   "username", "test-user",
                   "password", "test-pass",
                   "stream", "$NAMESPACE",
                   NULL);
    /* Enable test mode */
    ret = flb_output_set_test(ctx, out_ffd, "formatter",
                             cb_check_namespace_stream,
                             NULL, NULL);
    /* Start */
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);
    /* Ingest data sample */
    flb_lib_push(ctx, in_ffd, (char *) JSON_BASIC, size);
    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}
void flb_test_exclude_namespace()
{
    int ret;
    int size = sizeof(JSON_EXCLUDE) - 1;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    /* Create context, flush every second */
    ctx = flb_create();
    flb_service_set(ctx, "flush", "1", "grace", "1", NULL);
    /* Lib input mode */
    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);
    /* Parseable output with excluded namespace */
    out_ffd = flb_output(ctx, (char *) "parseable", NULL);
    flb_output_set(ctx, out_ffd,
                   "match", "test",
                   "server_host", "localhost",
                   "server_port", "8000",
                   "username", "test-user",
                   "password", "test-pass",
                   "stream", "test-stream",
                   "exclude_namespaces", "kube-system",
                   NULL);
    /* Enable test mode */
    ret = flb_output_set_test(ctx, out_ffd, "formatter",
                             cb_check_exclude_namespace,
                             NULL, NULL);
    /* Start */
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);
    /* Ingest data sample */
    flb_lib_push(ctx, in_ffd, (char *) JSON_EXCLUDE, size);
    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}
/* Test list */
TEST_LIST = {
    {"basic_config", flb_test_basic_config},
    {"namespace_stream", flb_test_namespace_stream},
    {"exclude_namespace", flb_test_exclude_namespace},
    {NULL, NULL}
};
