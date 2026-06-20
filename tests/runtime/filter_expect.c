/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_sds.h>
#include "flb_tests_runtime.h"

struct test_ctx {
    flb_ctx_t *flb;    /* Fluent Bit library context */
    int i_ffd;         /* Input fd  */
    int f_ffd;         /* Filter fd */
    int o_ffd;         /* Output fd */
};

pthread_mutex_t result_mutex = PTHREAD_MUTEX_INITIALIZER;
int num_output = 0;
static int get_output_num()
{
    int ret;
    pthread_mutex_lock(&result_mutex);
    ret = num_output;
    pthread_mutex_unlock(&result_mutex);

    return ret;
}

static void set_output_num(int num)
{
    pthread_mutex_lock(&result_mutex);
    num_output = num;
    pthread_mutex_unlock(&result_mutex);
}

static void clear_output_num()
{
    set_output_num(0);
}

/* Callback to check expected results */
static int cb_check_result_json(void *record, size_t size, void *data)
{
    char *p;
    char *expected;
    char *result;
    int num = get_output_num();

    set_output_num(num+1);

    expected = (char *) data;
    result = (char *) record;

    p = strstr(result, expected);
    if (!TEST_CHECK(p != NULL)) {
        TEST_MSG("Expected to find: '%s' in result '%s'",
                  expected, result);
    }
    /*
     * If you want to debug your test
     *
     * printf("Expect: '%s' in result '%s'", expected, result);
     */
    flb_free(record);
    return 0;
}


static struct test_ctx *test_ctx_create(struct flb_lib_out_cb *data)
{
    int i_ffd;
    int f_ffd;
    int o_ffd;
    struct test_ctx *ctx;

    ctx = flb_malloc(sizeof(struct test_ctx));
    if (!ctx) {
        flb_errno();
        return NULL;
    }

    /* Service config */
    ctx->flb = flb_create();
    flb_service_set(ctx->flb,
                    "Flush", "0.200000000",
                    "Grace", "1",
                    "Log_Level", "Error",
                    NULL);

    /* Input */
    i_ffd = flb_input(ctx->flb, (char *) "lib", NULL);
    TEST_CHECK(i_ffd >= 0);
    flb_input_set(ctx->flb, i_ffd, "tag", "test", NULL);
    ctx->i_ffd = i_ffd;

    /* Filter configuration */
    f_ffd = flb_filter(ctx->flb, (char *) "expect", NULL);
    TEST_CHECK(f_ffd >= 0);
    flb_filter_set(ctx->flb, f_ffd, 
                   "match", "*", "action", "result_key",
                   "result_key", "result", 
                   NULL);
    ctx->f_ffd = f_ffd;

    /* Output */
    o_ffd = flb_output(ctx->flb, (char *) "lib", (void *) data);
    TEST_CHECK(o_ffd >= 0);
    flb_output_set(ctx->flb, o_ffd,
                   "match", "test",
                   "format", "json",
                   NULL);
    ctx->o_ffd = o_ffd;

    return ctx;
}

static void test_ctx_destroy(struct test_ctx *ctx)
{
    flb_stop(ctx->flb);
    flb_destroy(ctx->flb);
    flb_free(ctx);
}

void flb_test_key_exists_matched()
{
    struct flb_lib_out_cb cb_data;
    struct test_ctx *ctx;
    int len;
    int ret;
    int bytes;
    char *input = "[0, {\"key\":\"val\"}]";

    clear_output_num();
    cb_data.cb = cb_check_result_json;
    cb_data.data = "\"result\":true";

    ctx = test_ctx_create(&cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
        exit(EXIT_FAILURE);
    }

    ret = flb_filter_set(ctx->flb, ctx->f_ffd,
                         "key_exists", "key",
                         NULL);
    TEST_CHECK(ret == 0);

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* Ingest data samples */
    len = strlen(input);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, input, len);
    TEST_CHECK(bytes == len);
    flb_time_msleep(500);

    ret = get_output_num();
    if (!TEST_CHECK(ret > 0)) {
        TEST_MSG("no output");
    }

    test_ctx_destroy(ctx);
}

void flb_test_key_exists_not_matched()
{
    struct flb_lib_out_cb cb_data;
    struct test_ctx *ctx;
    int len;
    int ret;
    int bytes;
    char *input = "[0, {\"key\":\"val\"}]";

    clear_output_num();
    cb_data.cb = cb_check_result_json;
    cb_data.data = "\"result\":false";

    ctx = test_ctx_create(&cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
        exit(EXIT_FAILURE);
    }

    ret = flb_filter_set(ctx->flb, ctx->f_ffd,
                         "key_exists", "not_key",
                         NULL);
    TEST_CHECK(ret == 0);

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* Ingest data samples */
    len = strlen(input);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, input, len);
    TEST_CHECK(bytes == len);
    flb_time_msleep(500);

    ret = get_output_num();
    if (!TEST_CHECK(ret > 0)) {
        TEST_MSG("no output");
    }

    test_ctx_destroy(ctx);
}

void flb_test_key_not_exists_matched()
{
    struct flb_lib_out_cb cb_data;
    struct test_ctx *ctx;
    int len;
    int ret;
    int bytes;
    char *input = "[0, {\"key\":\"val\"}]";

    clear_output_num();
    cb_data.cb = cb_check_result_json;
    cb_data.data = "\"result\":true";

    ctx = test_ctx_create(&cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
        exit(EXIT_FAILURE);
    }

    ret = flb_filter_set(ctx->flb, ctx->f_ffd,
                         "key_not_exists", "not_key",
                         NULL);
    TEST_CHECK(ret == 0);

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* Ingest data samples */
    len = strlen(input);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, input, len);
    TEST_CHECK(bytes == len);
    flb_time_msleep(500);

    ret = get_output_num();
    if (!TEST_CHECK(ret > 0)) {
        TEST_MSG("no output");
    }

    test_ctx_destroy(ctx);
}

void flb_test_key_not_exists_not_matched()
{
    struct flb_lib_out_cb cb_data;
    struct test_ctx *ctx;
    int len;
    int ret;
    int bytes;
    char *input = "[0, {\"key\":\"val\"}]";

    clear_output_num();
    cb_data.cb = cb_check_result_json;
    cb_data.data = "\"result\":false";

    ctx = test_ctx_create(&cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
        exit(EXIT_FAILURE);
    }

    ret = flb_filter_set(ctx->flb, ctx->f_ffd,
                         "key_not_exists", "key",
                         NULL);
    TEST_CHECK(ret == 0);

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* Ingest data samples */
    len = strlen(input);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, input, len);
    TEST_CHECK(bytes == len);
    flb_time_msleep(500);

    ret = get_output_num();
    if (!TEST_CHECK(ret > 0)) {
        TEST_MSG("no output");
    }

    test_ctx_destroy(ctx);
}

void flb_test_key_val_is_null_matched()
{
    struct flb_lib_out_cb cb_data;
    struct test_ctx *ctx;
    int len;
    int ret;
    int bytes;
    char *input = "[0, {\"key\":null}]";

    clear_output_num();
    cb_data.cb = cb_check_result_json;
    cb_data.data = "\"result\":true";

    ctx = test_ctx_create(&cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
        exit(EXIT_FAILURE);
    }

    ret = flb_filter_set(ctx->flb, ctx->f_ffd,
                         "key_val_is_null", "key",
                         NULL);
    TEST_CHECK(ret == 0);

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* Ingest data samples */
    len = strlen(input);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, input, len);
    TEST_CHECK(bytes == len);
    flb_time_msleep(500);

    ret = get_output_num();
    if (!TEST_CHECK(ret > 0)) {
        TEST_MSG("no output");
    }

    test_ctx_destroy(ctx);
}

void flb_test_key_val_is_null_not_matched()
{
    struct flb_lib_out_cb cb_data;
    struct test_ctx *ctx;
    int len;
    int ret;
    int bytes;
    char *input = "[0, {\"key\":\"val\"}]";

    clear_output_num();
    cb_data.cb = cb_check_result_json;
    cb_data.data = "\"result\":false";

    ctx = test_ctx_create(&cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
        exit(EXIT_FAILURE);
    }

    ret = flb_filter_set(ctx->flb, ctx->f_ffd,
                         "key_val_is_null", "key",
                         NULL);
    TEST_CHECK(ret == 0);

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* Ingest data samples */
    len = strlen(input);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, input, len);
    TEST_CHECK(bytes == len);
    flb_time_msleep(500);

    ret = get_output_num();
    if (!TEST_CHECK(ret > 0)) {
        TEST_MSG("no output");
    }

    test_ctx_destroy(ctx);
}

void flb_test_key_val_is_not_null_matched()
{
    struct flb_lib_out_cb cb_data;
    struct test_ctx *ctx;
    int len;
    int ret;
    int bytes;
    char *input = "[0, {\"key\":\"val\"}]";

    clear_output_num();
    cb_data.cb = cb_check_result_json;
    cb_data.data = "\"result\":true";

    ctx = test_ctx_create(&cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
        exit(EXIT_FAILURE);
    }

    ret = flb_filter_set(ctx->flb, ctx->f_ffd,
                         "key_val_is_not_null", "key",
                         NULL);
    TEST_CHECK(ret == 0);

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* Ingest data samples */
    len = strlen(input);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, input, len);
    TEST_CHECK(bytes == len);
    flb_time_msleep(500);

    ret = get_output_num();
    if (!TEST_CHECK(ret > 0)) {
        TEST_MSG("no output");
    }

    test_ctx_destroy(ctx);
}

void flb_test_key_val_is_not_null_not_matched()
{
    struct flb_lib_out_cb cb_data;
    struct test_ctx *ctx;
    int len;
    int ret;
    int bytes;
    char *input = "[0, {\"key\":null}]";

    clear_output_num();
    cb_data.cb = cb_check_result_json;
    cb_data.data = "\"result\":false";

    ctx = test_ctx_create(&cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
        exit(EXIT_FAILURE);
    }

    ret = flb_filter_set(ctx->flb, ctx->f_ffd,
                         "key_val_is_not_null", "key",
                         NULL);
    TEST_CHECK(ret == 0);

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* Ingest data samples */
    len = strlen(input);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, input, len);
    TEST_CHECK(bytes == len);
    flb_time_msleep(500);

    ret = get_output_num();
    if (!TEST_CHECK(ret > 0)) {
        TEST_MSG("no output");
    }

    test_ctx_destroy(ctx);
}

void flb_test_key_val_eq_matched()
{
    struct flb_lib_out_cb cb_data;
    struct test_ctx *ctx;
    int len;
    int ret;
    int bytes;
    char *input = "[0, {\"key\":\"val\"}]";

    clear_output_num();
    cb_data.cb = cb_check_result_json;
    cb_data.data = "\"result\":true";

    ctx = test_ctx_create(&cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
        exit(EXIT_FAILURE);
    }

    ret = flb_filter_set(ctx->flb, ctx->f_ffd,
                         "key_val_eq", "key val",
                         NULL);
    TEST_CHECK(ret == 0);

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* Ingest data samples */
    len = strlen(input);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, input, len);
    TEST_CHECK(bytes == len);
    flb_time_msleep(500);

    ret = get_output_num();
    if (!TEST_CHECK(ret > 0)) {
        TEST_MSG("no output");
    }

    test_ctx_destroy(ctx);
}

void flb_test_key_val_eq_not_matched()
{
    struct flb_lib_out_cb cb_data;
    struct test_ctx *ctx;
    int len;
    int ret;
    int bytes;
    char *input = "[0, {\"key\":\"val\"}]";

    clear_output_num();
    cb_data.cb = cb_check_result_json;
    cb_data.data = "\"result\":false";

    ctx = test_ctx_create(&cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
        exit(EXIT_FAILURE);
    }

    ret = flb_filter_set(ctx->flb, ctx->f_ffd,
                         "key_val_eq", "not_key val",
                         NULL);
    TEST_CHECK(ret == 0);

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* Ingest data samples */
    len = strlen(input);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, input, len);
    TEST_CHECK(bytes == len);
    flb_time_msleep(500);

    ret = get_output_num();
    if (!TEST_CHECK(ret > 0)) {
        TEST_MSG("no output");
    }

    test_ctx_destroy(ctx);
}


TEST_LIST = {
    {"key_exists_matched", flb_test_key_exists_matched},
    {"key_exists_not_matched", flb_test_key_exists_not_matched},
    {"key_not_exists_matched", flb_test_key_not_exists_matched},
    {"key_not_exists_not_matched", flb_test_key_not_exists_not_matched},
    {"key_val_is_null_matched", flb_test_key_val_is_null_matched},
    {"key_val_is_null_not_matched", flb_test_key_val_is_null_not_matched},
    {"key_val_is_not_null_matched", flb_test_key_val_is_not_null_matched},
    {"key_val_is_not_null_not_matched", flb_test_key_val_is_not_null_not_matched},
    {"key_val_eq_matched", flb_test_key_val_eq_matched},
    {"key_val_eq_not_matched", flb_test_key_val_eq_not_matched},
    {NULL, NULL}
};
