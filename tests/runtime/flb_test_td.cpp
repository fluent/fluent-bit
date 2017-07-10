/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <gtest/gtest.h>
#include <fluent-bit.h>
#include "data/json_td.h"

/* It writes a big JSON message (> 3.5MB) */
TEST(TD, json_long) {
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    ctx = flb_create();

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    EXPECT_TRUE(in_ffd >= 0);
    flb_input_set(ctx,in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "td", NULL);
    EXPECT_TRUE(out_ffd >= 0);
    flb_output_set(ctx, out_ffd,"match", "test", NULL);

    ret = flb_lib_config_file(ctx, (char *) "/tmp/td.conf");

    ret = flb_start(ctx);
    EXPECT_EQ(ret, 0);

    flb_lib_push(ctx, in_ffd, (char *) JSON_TD , (int) sizeof(JSON_TD) - 1);

    flb_stop(ctx);
    flb_destroy(ctx);
}
