/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit.h>
#include "flb_tests_runtime.h"

/* Test data */

/* Test functions */
void flb_test_filter_stdout_json_multiple(void);
void flb_test_filter_stdout_case_insensitive(void);

/* Test list */
TEST_LIST = {
    {"json_multiple", flb_test_filter_stdout_json_multiple },
    {"case_insensitive_name", flb_test_filter_stdout_case_insensitive},
    {NULL, NULL}
};

/* 
 * This test case is to check if fluent-bit allows case-insensitive plugin name.
 * This test is not unique to filter_stdout, but we test here :) ,
 */

void flb_test_filter_stdout_case_insensitive(void)
{
    int filter_ffd;
    char filter_name[] = "stDoUt";
    flb_ctx_t *ctx;

    ctx = flb_create();

    filter_ffd = flb_filter(ctx, (char *) filter_name, NULL);
    if(!TEST_CHECK(filter_ffd >= 0)) {
        TEST_MSG("%s should be valid\n", filter_name);
    }

    /* Initialize thread local storage (FLB_TLS) properly when without calling flb_start().
     * Then, FLB_TLS_GET working on macOS.
     * In general, macOS requests surely initialization for pthread stuffs.
     */
    flb_init_env();
    flb_destroy(ctx);
}

void flb_test_filter_stdout_json_multiple(void)
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

    out_ffd = flb_output(ctx, (char *) "null", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "test", NULL);

    filter_ffd = flb_filter(ctx, (char *) "stdout", NULL);
    TEST_CHECK(filter_ffd >= 0);
    flb_filter_set(ctx, filter_ffd, "match", "test", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    for (i = 0; i < 256; i++) {
        memset(p, '\0', sizeof(p));
        snprintf(p, sizeof(p), "[%d, {\"val\": %d,\"END_KEY\": \"JSON_END\"}]", i, (i * i));
        bytes = flb_lib_push(ctx, in_ffd, p, strlen(p));
        TEST_CHECK(bytes == strlen(p));
    }

    sleep(1); /* waiting flush */

    flb_stop(ctx);
    flb_destroy(ctx);
}
