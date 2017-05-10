/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <gtest/gtest.h>
#include <fluent-bit.h>
#include "data/json_invalid.h"
#include "data/json_small.h"
#include "data/json_long.h"

#define TEST_LOGFILE "flb-test-file.log"

TEST(Outputs, json_invalid) {
    int i;
    int ret;
    int bytes;
    char *p = (char *) JSON_INVALID;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    FILE *fp;

    remove(TEST_LOGFILE);

    ctx = flb_create();

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    EXPECT_TRUE(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "file", NULL);
    EXPECT_TRUE(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "test", NULL);
    flb_output_set(ctx, out_ffd, "Path", TEST_LOGFILE, NULL);

    ret = flb_start(ctx);
    EXPECT_EQ(ret, 0);

    for (i = 0; i < (int) sizeof(JSON_INVALID) - 1; i++) {
        bytes = flb_lib_push(ctx, in_ffd, p + i, 1);
        EXPECT_EQ(bytes, 1);
    }

    flb_stop(ctx);
    flb_destroy(ctx);

    fp = fopen(TEST_LOGFILE, "r");
    EXPECT_TRUE(fp == NULL);
    if (fp != NULL) {
        fclose(fp);
        remove(TEST_LOGFILE);
    }
}

/* It writes a very long JSON map (> 100KB) byte by byte */
TEST(Outputs, json_long) {
    int i;
    int ret;
    int bytes;
    char *p = (char *) JSON_LONG;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    FILE *fp;

    remove(TEST_LOGFILE);

    ctx = flb_create();

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    EXPECT_TRUE(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "file", NULL);
    EXPECT_TRUE(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "test", NULL);
    flb_output_set(ctx, out_ffd, "Path", TEST_LOGFILE, NULL);

    ret = flb_start(ctx);
    EXPECT_EQ(ret, 0);

    for (i = 0; i < (int) sizeof(JSON_LONG) - 1; i++) {
        bytes = flb_lib_push(ctx, in_ffd, p + i, 1);
        EXPECT_EQ(bytes, 1);
    }

    sleep(1); /* waiting flush */

    flb_stop(ctx);
    flb_destroy(ctx);

    fp = fopen(TEST_LOGFILE, "r");
    EXPECT_TRUE(fp != NULL);
    if (fp != NULL) {
        fclose(fp);
        remove(TEST_LOGFILE);
    }
}

TEST(Outputs, json_small) {
    int i;
    int ret;
    int bytes;
    char *p = (char *) JSON_SMALL;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    FILE *fp;

    remove(TEST_LOGFILE);

    ctx = flb_create();

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    EXPECT_TRUE(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "file", NULL);
    EXPECT_TRUE(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "test", NULL);
    flb_output_set(ctx, out_ffd, "Path", TEST_LOGFILE, NULL);

    ret = flb_start(ctx);
    EXPECT_EQ(ret, 0);

    for (i = 0; i < (int) sizeof(JSON_SMALL) - 1; i++) {
        bytes = flb_lib_push(ctx, in_ffd, p + i, 1);
        EXPECT_EQ(bytes, 1);
    }

    sleep(1); /* waiting flush */

    flb_stop(ctx);
    flb_destroy(ctx);

    fp = fopen(TEST_LOGFILE, "r");
    EXPECT_TRUE(fp != NULL);
    if (fp != NULL) {
        fclose(fp);
        remove(TEST_LOGFILE);
    }
}

TEST(Outputs, format_csv) {
    int i;
    int ret;
    int bytes;
    char *p = (char *) JSON_SMALL;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    FILE *fp;

    remove(TEST_LOGFILE);

    ctx = flb_create();

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    EXPECT_TRUE(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "file", NULL);
    EXPECT_TRUE(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "test", NULL);
    flb_output_set(ctx, out_ffd, "Path", TEST_LOGFILE, NULL);
    flb_output_set(ctx, out_ffd, "Format", "csv", NULL);
    flb_output_set(ctx, out_ffd, "delimiter", "comma", NULL);

    ret = flb_start(ctx);
    EXPECT_EQ(ret, 0);

    for (i = 0; i < (int) sizeof(JSON_SMALL) - 1; i++) {
        bytes = flb_lib_push(ctx, in_ffd, p + i, 1);
        EXPECT_EQ(bytes, 1);
    }

    sleep(1); /* waiting flush */

    flb_stop(ctx);
    flb_destroy(ctx);

    fp = fopen(TEST_LOGFILE, "r");
    EXPECT_TRUE(fp != NULL);
    if (fp != NULL) {
        fclose(fp);
        remove(TEST_LOGFILE);
    }
}

TEST(Outputs, format_ltsv) {
    int i;
    int ret;
    int bytes;
    char *p = (char *) JSON_SMALL;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    FILE *fp;

    remove(TEST_LOGFILE);

    ctx = flb_create();

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    EXPECT_TRUE(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "file", NULL);
    EXPECT_TRUE(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "test", NULL);
    flb_output_set(ctx, out_ffd, "Path", TEST_LOGFILE, NULL);
    flb_output_set(ctx, out_ffd, "Format", "ltsv", NULL);
    flb_output_set(ctx, out_ffd, "delimiter", "tab", NULL);
    flb_output_set(ctx, out_ffd, "label_delimiter", "comma", NULL);

    ret = flb_start(ctx);
    EXPECT_EQ(ret, 0);

    for (i = 0; i < (int) sizeof(JSON_SMALL) - 1; i++) {
        bytes = flb_lib_push(ctx, in_ffd, p + i, 1);
        EXPECT_EQ(bytes, 1);
    }

    sleep(1); /* waiting flush */

    flb_stop(ctx);
    flb_destroy(ctx);

    fp = fopen(TEST_LOGFILE, "r");
    EXPECT_TRUE(fp != NULL);
    if (fp != NULL) {
        fclose(fp);
        remove(TEST_LOGFILE);
    }
}

TEST(Outputs, format_invalid) {
    int i;
    int ret;
    int bytes;
    char *p = (char *) JSON_SMALL;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    FILE *fp;

    remove(TEST_LOGFILE);

    ctx = flb_create();

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    EXPECT_TRUE(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "file", NULL);
    EXPECT_TRUE(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "test", NULL);
    flb_output_set(ctx, out_ffd, "Path", TEST_LOGFILE, NULL);
    flb_output_set(ctx, out_ffd, "Format", "xxx", NULL);
    flb_output_set(ctx, out_ffd, "delimiter", "yyy", NULL);
    flb_output_set(ctx, out_ffd, "label_delimiter", "zzz", NULL);

    ret = flb_start(ctx);
    EXPECT_EQ(ret, 0);

    for (i = 0; i < (int) sizeof(JSON_SMALL) - 1; i++) {
        bytes = flb_lib_push(ctx, in_ffd, p + i, 1);
        EXPECT_EQ(bytes, 1);
    }

    sleep(1); /* waiting flush */

    flb_stop(ctx);
    flb_destroy(ctx);

    fp = fopen(TEST_LOGFILE, "r");
    EXPECT_TRUE(fp != NULL);
    if (fp != NULL) {
        fclose(fp);
        remove(TEST_LOGFILE);
    }
}
