/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <gtest/gtest.h>
#include <fluent-bit.h>
#include "data_td.h"

/* It writes a big JSON message (> 3.5MB) */
TEST(Lib, push_big_json) {
    int ret;
    char *p = (char *) JSON_TD;
    struct flb_lib_ctx *ctx;

    ctx = flb_lib_init((char *) "stdout");
    EXPECT_TRUE(ctx != NULL);

    ret = flb_lib_start(ctx);
    EXPECT_EQ(ret, 0);

    flb_lib_push(ctx, p, (int) sizeof(JSON_TD) - 1);
    flb_lib_stop(ctx);
}
