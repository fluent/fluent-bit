/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit-minimal.h>
#include "flb_tests_runtime.h"

void flb_test_input_event()
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    ctx = flb_create();

    in_ffd = flb_input(ctx, (char *) "event_test", NULL);
    TEST_CHECK(in_ffd >= 0);

    out_ffd = flb_output(ctx, (char *) "null", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "test", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    sleep(8);

    flb_stop(ctx);
    flb_destroy(ctx);
}

/* Test list */
TEST_LIST = {
    {"event_test",  flb_test_input_event},
    {NULL, NULL}
};
