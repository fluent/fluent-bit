/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <gtest/gtest.h>
#include <fluent-bit.h>
#include "data/json_es.h"

TEST(Outputs, json_es) {
    int ret;
    int size = sizeof(JSON_ES) - 1;
    struct flb_lib_ctx *ctx;

    ctx = flb_lib_init((char *) "es");
    EXPECT_TRUE(ctx != NULL);

    ret = flb_lib_start(ctx);
    EXPECT_EQ(ret, 0);

    flb_lib_push(ctx, (char *) JSON_ES, size);
    flb_lib_stop(ctx);
    flb_lib_exit(ctx);
}
