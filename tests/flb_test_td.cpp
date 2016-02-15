/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <gtest/gtest.h>
#include <fluent-bit.h>
#include "data/json_td.h"

/* It writes a big JSON message (> 3.5MB) */
TEST(TD, json_long) {
    int ret;
    flb_ctx_t *ctx;
    flb_input_t *input;
    flb_output_t *output;

    ctx = flb_create();

    input = flb_input(ctx, (char *) "lib", NULL);
    EXPECT_TRUE(input != NULL);
    flb_input_set(input, "tag", "test");

    output = flb_output(ctx, (char *) "td", NULL);
    EXPECT_TRUE(output != NULL);
    flb_output_set(output, "tag", "test");

    flb_config_verbose(FLB_TRUE);
    ret = flb_lib_config_file(ctx, (char *) "/tmp/td.conf");

    ret = flb_start(ctx);
    EXPECT_EQ(ret, 0);

    flb_lib_push(input, (char *) JSON_TD , (int) sizeof(JSON_TD) - 1);

    flb_stop(ctx);
    flb_destroy(ctx);
}
