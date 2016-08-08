/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <gtest/gtest.h>
#include <fluent-bit.h>
#include "data/json_invalid.h"
#include "data/json_small.h"
#include "data/json_long.h"

TEST(Outputs, json_invalid) {
    int i;
    int ret;
    int total;
    int bytes;
    char *p = (char *) JSON_INVALID;
    flb_ctx_t *ctx;
    flb_input_t *input;
    flb_output_t *output;

    ctx = flb_create();

    input = flb_input(ctx, (char *) "lib", NULL);
    EXPECT_TRUE(input != NULL);
    flb_input_set(input, "tag", "test", NULL);

    output = flb_output(ctx, (char *) "stdout", NULL);
    EXPECT_TRUE(output != NULL);
    flb_output_set(output, "match", "test", NULL);

    ret = flb_start(ctx);
    EXPECT_EQ(ret, 0);

    total = 0;
    for (i = 0; i < (int) sizeof(JSON_INVALID) - 1; i++) {
        bytes = flb_lib_push(input, p + i, 1);
        EXPECT_EQ(bytes, 1);
        total++;
    }

    flb_stop(ctx);
    flb_destroy(ctx);
}

/* It writes a very long JSON map (> 100KB) byte by byte */
TEST(Outputs, json_long) {
    int i;
    int ret;
    int total;
    int bytes;
    char *p = (char *) JSON_LONG;
    flb_ctx_t *ctx;
    flb_input_t *input;
    flb_output_t *output;

    ctx = flb_create();

    input = flb_input(ctx, (char *) "lib", NULL);
    EXPECT_TRUE(input != NULL);
    flb_input_set(input, "tag", "test", NULL);

    output = flb_output(ctx, (char *) "stdout", NULL);
    EXPECT_TRUE(output != NULL);
    flb_output_set(output, "match", "test", NULL);

    ret = flb_start(ctx);
    EXPECT_EQ(ret, 0);

    total = 0;
    for (i = 0; i < (int) sizeof(JSON_LONG) - 1; i++) {
        bytes = flb_lib_push(input, p + i, 1);
        EXPECT_EQ(bytes, 1);
        total++;
    }

    flb_stop(ctx);
    flb_destroy(ctx);
}

TEST(Outputs, json_small) {
    int i;
    int ret;
    int total;
    int bytes;
    char *p = (char *) JSON_SMALL;
    flb_ctx_t *ctx;
    flb_input_t *input;
    flb_output_t *output;

    ctx = flb_create();

    input = flb_input(ctx, (char *) "lib", NULL);
    EXPECT_TRUE(input != NULL);
    flb_input_set(input, "tag", "test", NULL);

    output = flb_output(ctx, (char *) "stdout", NULL);
    EXPECT_TRUE(output != NULL);
    flb_output_set(output, "match", "test", NULL);

    ret = flb_start(ctx);
    EXPECT_EQ(ret, 0);

    total = 0;
    for (i = 0; i < (int) sizeof(JSON_SMALL) - 1; i++) {
        bytes = flb_lib_push(input, p + i, 1);
        EXPECT_EQ(bytes, 1);
        total++;
    }

    flb_stop(ctx);
    flb_destroy(ctx);
}
