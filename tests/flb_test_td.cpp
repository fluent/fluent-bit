/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <gtest/gtest.h>
#include <fluent-bit.h>
#include "data/json_td.h"

/* It writes a big JSON message (> 3.5MB) */
TEST(TD, json_long) {
    int ret;
    struct flb_lib_ctx *ctx;

    ctx = flb_lib_init((char *) "td");
    EXPECT_TRUE(ctx != NULL);

    flb_config_verbose(FLB_TRUE);
    ret = flb_lib_config_file(ctx, (char *) "/tmp/td.conf");

    ret = flb_lib_start(ctx);
    EXPECT_EQ(ret, 0);

    flb_lib_push(ctx, (char *) JSON_TD , (int) sizeof(JSON_TD) - 1);
    flb_lib_stop(ctx);
    flb_lib_exit(ctx);
}
