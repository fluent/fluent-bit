/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <gtest/gtest.h>
#include <fluent-bit.h>
#include "data/json_long.h"

TEST(Outputs, json_long_fluentd) {
    int ret;
    int size = sizeof(JSON_LONG) - 1;
    flb_ctx_t *ctx;
    flb_input_t *input;
    flb_output_t *output;

    ctx = flb_create();

    input = flb_input(ctx, (char *) "lib", NULL);
    EXPECT_TRUE(input != NULL);
    flb_input_set(input, "tag", "test");

    output = flb_output(ctx, (char *) "fluentd://127.0.0.1:24224", NULL);
    EXPECT_TRUE(output != NULL);
    flb_output_set(output, "tag", "test");

    ret = flb_start(ctx);
    EXPECT_EQ(ret, 0);

    flb_lib_push(input, (char *)JSON_LONG, size);

    flb_stop(ctx);
    flb_destroy(ctx);
}
