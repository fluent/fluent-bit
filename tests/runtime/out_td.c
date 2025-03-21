/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
#include <fluent-bit.h>
#include "flb_tests_runtime.h"

/* Test data */
#include "data/td/json_td.h" /* JSON_TD */

/* Test functions */
void flb_test_td_json_long(void);

/* Test list */
TEST_LIST = {
    {"json_long",    flb_test_td_json_long },
    {NULL, NULL}
};


/* It writes a big JSON message (> 3.5MB) */
void flb_test_td_json_long(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    ctx = flb_create();

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx,in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "td", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd,"match", "test", NULL);

    ret = flb_lib_config_file(ctx, (char *) "/tmp/td.conf");

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    flb_lib_push(ctx, in_ffd, (char *) JSON_TD , (int) sizeof(JSON_TD) - 1);

    flb_stop(ctx);
    flb_destroy(ctx);
}
