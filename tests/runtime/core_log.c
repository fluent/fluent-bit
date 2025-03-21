/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit.h>
#include <fluent-bit/flb_log.h>

#include "flb_tests_runtime.h"


static void check_result(char *level, int ret, int expect_truncated)
{
    if (expect_truncated == FLB_TRUE) {
        if (!TEST_CHECK(ret > 0)) {
            TEST_MSG("log is not truncated.level=%s ret=%d",level, ret);
            /*
              printf("ret=%d\n", ret);
            */
        }
    }
    else {
        if (!TEST_CHECK(ret == 0)) {
            TEST_MSG("log is truncated.level=%s ret=%d",level, ret);
            /*
              printf("ret=%d\n", ret);
            */
        }
    }

}
static void check_if_truncated(char* data, int expect_truncated)
{
    int ret;
    ret = flb_error_is_truncated("%s", data);
    check_result("error", ret, expect_truncated);

    ret = flb_warn_is_truncated("%s", data);
    check_result("warn", ret, expect_truncated);

    ret = flb_info_is_truncated("%s", data);
    check_result("info", ret, expect_truncated);

    ret = flb_debug_is_truncated("%s", data);
    check_result("debug", ret, expect_truncated);
}

static int cb_not_truncated_log(void *record, size_t size, void *data)
{
    check_if_truncated((char*)data, FLB_FALSE);

    flb_free(record);
    return 0;
}


static int cb_truncated_log(void *record, size_t size, void *data)
{
    check_if_truncated((char*)data, FLB_TRUE);

    flb_free(record);
    return 0;
}

static int cb_resize(void *record, size_t size, void *data)
{
    int ret;
    char *log = (char*)data;

    ret = flb_error_is_truncated("%s", log);
    if (!TEST_CHECK(ret > 0)) {
        TEST_MSG("log is not truncated.ret=%d", ret);
    }

    ret = flb_error_is_truncated("%.*s", (int)(strlen(log) - ret), log);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("log is truncated.ret=%d", ret);
    }

    flb_free(record);
    return 0;
}

static int cb_log_level(void *record, size_t size, void *data)
{
    int ret;
    char *log = (char*)data;

    ret = flb_error_is_truncated("%s", log);
    if (!TEST_CHECK(ret > 0)) {
        TEST_MSG("log is not truncated.ret=%d", ret);
    }

    /* log_level is error. The function will return 0 */
    ret = flb_info_is_truncated("%s", log);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("log is truncated.ret=%d", ret);
    }

    flb_free(record);
    return 0;
}

void test_not_truncated_log()
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    int i;
    char *msg = "[1, {\"msg\":\"body\"}]";
    char log[128] = {0};
    struct flb_lib_out_cb cb_data;

    cb_data.cb = cb_not_truncated_log;
    cb_data.data = &log[0];

    for (i=0; i<sizeof(log)-1; i++) {
        log[i] = 'a';
    }

    ctx = flb_create();
    TEST_CHECK(ctx != NULL);

    flb_service_set(ctx,
                    "Flush", "0.200000000",
                    "Grace", "1",
                    "Log_Level", "debug",
                    NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);

    out_ffd = flb_output(ctx, (char *) "lib", (void*)&cb_data);
    TEST_CHECK(out_ffd >= 0);
    ret = flb_output_set(ctx, out_ffd,
                         "match", "*",
                         NULL);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    ret = flb_lib_push(ctx, in_ffd, msg, strlen(msg));
    TEST_CHECK(ret >= 0);

    sleep(1);

    flb_stop(ctx);
    flb_destroy(ctx);

}

void test_truncated_log()
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    int i;
    char *msg = "[1, {\"msg\":\"body\"}]";
    char log[4096 * 5] = {0};
    struct flb_lib_out_cb cb_data;

    cb_data.cb = cb_truncated_log;
    cb_data.data = &log[0];

    for (i=0; i<sizeof(log)-1; i++) {
        log[i] = 'a';
    }

    ctx = flb_create();
    TEST_CHECK(ctx != NULL);

    flb_service_set(ctx,
                    "Flush", "0.200000000",
                    "Grace", "1",
                    "Log_Level", "debug",
                    NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);

    out_ffd = flb_output(ctx, (char *) "lib", (void*)&cb_data);
    TEST_CHECK(out_ffd >= 0);
    ret = flb_output_set(ctx, out_ffd,
                         "match", "*",
                         NULL);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    ret = flb_lib_push(ctx, in_ffd, msg, strlen(msg));
    TEST_CHECK(ret >= 0);

    sleep(1);

    flb_stop(ctx);
    flb_destroy(ctx);

}

void test_resize()
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    int i;
    char *msg = "[1, {\"msg\":\"body\"}]";
    char log[4096 * 5] = {0};
    struct flb_lib_out_cb cb_data;

    cb_data.cb = cb_resize;
    cb_data.data = &log[0];

    for (i=0; i<sizeof(log)-1; i++) {
        log[i] = 'a';
    }

    ctx = flb_create();
    TEST_CHECK(ctx != NULL);

    flb_service_set(ctx,
                    "Flush", "0.200000000",
                    "Grace", "1",
                    "Log_Level", "error",
                    NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);

    out_ffd = flb_output(ctx, (char *) "lib", (void*)&cb_data);
    TEST_CHECK(out_ffd >= 0);
    ret = flb_output_set(ctx, out_ffd,
                         "match", "*",
                         NULL);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    ret = flb_lib_push(ctx, in_ffd, msg, strlen(msg));
    TEST_CHECK(ret >= 0);

    sleep(1);

    flb_stop(ctx);
    flb_destroy(ctx);

}

void test_log_level()
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    int i;
    char *msg = "[1, {\"msg\":\"body\"}]";
    char log[4096 * 5] = {0};
    struct flb_lib_out_cb cb_data;

    cb_data.cb = cb_log_level;
    cb_data.data = &log[0];

    for (i=0; i<sizeof(log)-1; i++) {
        log[i] = 'a';
    }

    ctx = flb_create();
    TEST_CHECK(ctx != NULL);

    flb_service_set(ctx,
                    "Flush", "0.200000000",
                    "Grace", "1",
                    "Log_Level", "error",
                    NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);

    out_ffd = flb_output(ctx, (char *) "lib", (void*)&cb_data);
    TEST_CHECK(out_ffd >= 0);
    ret = flb_output_set(ctx, out_ffd,
                         "match", "*",
                         NULL);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    ret = flb_lib_push(ctx, in_ffd, msg, strlen(msg));
    TEST_CHECK(ret >= 0);

    sleep(1);

    flb_stop(ctx);
    flb_destroy(ctx);

}

/* Test list */
TEST_LIST = {
    {"not_truncated_log", test_not_truncated_log },
    {"truncated_log", test_truncated_log },
    {"resize", test_resize },
    {"log_level", test_log_level },
    {NULL, NULL}
};
