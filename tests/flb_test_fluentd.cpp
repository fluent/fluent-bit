/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <gtest/gtest.h>
#include <fluent-bit.h>
#include "data/json_long.h"

TEST(Outputs, json_long_fluentd) {
    int ret;
    int size = sizeof(JSON_LONG) - 1;
    struct flb_lib_ctx *ctx;

    ctx = flb_lib_init((char *) "fluentd://127.0.0.1:12225");
    EXPECT_TRUE(ctx != NULL);

    ret = flb_lib_start(ctx);
    EXPECT_EQ(ret, 0);

    flb_lib_push(ctx, (char *)JSON_LONG, size);
    flb_lib_stop(ctx);
    flb_lib_exit(ctx);
}
