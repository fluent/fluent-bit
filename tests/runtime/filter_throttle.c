/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit.h>
#include "flb_tests_runtime.h"

/* Test data */

/* Utility functions */
pthread_mutex_t result_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Test functions */
void flb_test_filter_throttle(void);
void flb_test_filter_window_0(void);

/* Test list */
TEST_LIST = {
    {"throttle",   flb_test_filter_throttle   },
    {"window_0",   flb_test_filter_window_0   },
    {NULL, NULL}
};


void flb_test_filter_throttle(void)
{
    int i;
    int ret;
    int bytes;
    char p[100];
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    int filter_ffd;

    ctx = flb_create();

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "stdout", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "test", NULL);

    filter_ffd = flb_filter(ctx, (char *) "throttle", NULL);
    TEST_CHECK(filter_ffd >= 0);
    ret = flb_filter_set(ctx, filter_ffd, "match", "*", NULL);
    TEST_CHECK(ret == 0);
    ret = flb_filter_set(ctx, filter_ffd, "rate", "9", NULL);
    TEST_CHECK(ret == 0);
    ret = flb_filter_set(ctx, filter_ffd, "window", "3", NULL);
    TEST_CHECK(ret == 0);
    ret = flb_filter_set(ctx, filter_ffd, "interval", "3s", NULL);
    TEST_CHECK(ret == 0);
    ret = flb_filter_set(ctx, filter_ffd, "print_status", "true", NULL);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Send log messages all should go through */
    for (i = 0; i < 256; i++) {
        memset(p, '\0', sizeof(p));
        snprintf(p, sizeof(p), "[%d, {\"val\": \"%d\",\"END_KEY\": \"JSON_END\"}]", i,  i);
        bytes = flb_lib_push(ctx, in_ffd, p, strlen(p));
        TEST_CHECK(bytes == strlen(p));
    }

    sleep(1); /* waiting flush */

    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_filter_window_0(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    int filter_ffd;

    ctx = flb_create();

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "stdout", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "test", NULL);

    filter_ffd = flb_filter(ctx, (char *) "throttle", NULL);
    TEST_CHECK(filter_ffd >= 0);
    ret = flb_filter_set(ctx, filter_ffd, "match", "*",
                         "window", "0",
                         NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    sleep(1); /* waiting flush */

    flb_stop(ctx);
    flb_destroy(ctx);
}
