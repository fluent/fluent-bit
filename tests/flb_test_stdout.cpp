/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <gtest/gtest.h>
#include <fluent-bit.h>
#include "flb_data.h"

/* It writes a very long JSON map (> 100KB) byte by byte */
TEST(Outputs, json_long_stdout) {
    int i;
    int ret;
    int total;
    int bytes;
    char *p = (char *) JSON_LONG;
    struct flb_lib_ctx *ctx;

    ctx = flb_lib_init((char *) "stdout");
    EXPECT_TRUE(ctx != NULL);

    ret = flb_lib_start(ctx);
    EXPECT_EQ(ret, 0);

    total = 0;
    for (i = 0; i < (int) sizeof(JSON_LONG) - 1; i++) {
        bytes = flb_lib_push(ctx, p + i, 1);
        EXPECT_EQ(bytes, 1);
        total++;
    }
    flb_lib_stop(ctx);
    flb_lib_exit(ctx);
}

TEST(Outputs, json_small_stdout) {
    int i;
    int ret;
    int total;
    int bytes;
    char *p = (char *) JSON_SMALL;
    struct flb_lib_ctx *ctx;

    ctx = flb_lib_init((char *) "stdout");
    EXPECT_TRUE(ctx != NULL);

    ret = flb_lib_start(ctx);
    EXPECT_EQ(ret, 0);

    total = 0;
    for (i = 0; i < (int) sizeof(JSON_SMALL) - 1; i++) {
        bytes = flb_lib_push(ctx, p + i, 1);
        EXPECT_EQ(bytes, 1);
        total++;
    }
    flb_lib_stop(ctx);
    flb_lib_exit(ctx);
}

TEST(Outputs, json_invalid) {
    int i;
    int ret;
    int total;
    int bytes;
    char *p = (char *) JSON_INVALID;
    struct flb_lib_ctx *ctx;

    ctx = flb_lib_init((char *) "stdout");
    EXPECT_TRUE(ctx != NULL);

    ret = flb_lib_start(ctx);
    EXPECT_EQ(ret, 0);

    total = 0;
    for (i = 0; i < (int) sizeof(JSON_INVALID) - 1; i++) {
        bytes = flb_lib_push(ctx, p + i, 1);
        EXPECT_EQ(bytes, 1);
        total++;
    }
    flb_lib_stop(ctx);
    flb_lib_exit(ctx);
}
