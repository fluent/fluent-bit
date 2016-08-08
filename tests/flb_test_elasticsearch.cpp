/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <gtest/gtest.h>
#include <fluent-bit.h>
#include "data/json_es.h"

TEST(Outputs, json_es) {
    int ret;
    int size = sizeof(JSON_ES) - 1;
    flb_ctx_t *ctx;
    flb_input_t *input;
    flb_output_t *output;

    ctx = flb_create();
    EXPECT_TRUE(ctx != NULL);

    input = flb_input(ctx, (char *) "lib", NULL);
    EXPECT_TRUE(input != NULL);
    flb_input_set(input, "tag", "test", NULL);

    output = flb_output(ctx, (char *) "es", NULL);
    EXPECT_TRUE(output != NULL);
    flb_output_set(output, "match", "test", NULL);

    ret = flb_start(ctx);
    EXPECT_EQ(ret, 0);

    flb_lib_push(input, (char *) JSON_ES, size);

    flb_stop(ctx);
    flb_destroy(ctx);
}
