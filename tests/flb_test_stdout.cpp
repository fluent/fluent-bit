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
    struct flb_config *config;

    config = flb_config_init();
    EXPECT_TRUE(config != NULL);

    ret = flb_lib_init(config, (char *) "stdout");
    EXPECT_EQ(ret, 0);

    ret = flb_lib_start(config);
    EXPECT_EQ(ret, 0);

    printf("JSON LONG=%lu\n", sizeof(JSON_LONG) - 1);

    total = 0;
    for (i = 0; i < (int) sizeof(JSON_LONG) - 1; i++) {
        bytes = flb_lib_push(config, p + i, 1);
        EXPECT_EQ(bytes, 1);
        total++;
    }
    printf("total=%i\n", total);
    flb_lib_stop(config);
}

TEST(Outputs, json_small_stdout) {
    int i;
    int ret;
    int total;
    int bytes;
    char *p = (char *) JSON_SMALL;
    struct flb_config *config;

    config = flb_config_init();
    EXPECT_TRUE(config != NULL);

    ret = flb_lib_init(config, (char *) "stdout");
    EXPECT_EQ(ret, 0);

    ret = flb_lib_start(config);
    EXPECT_EQ(ret, 0);

    printf("JSON LONG=%lu\n", sizeof(JSON_SMALL) - 1);

    total = 0;
    for (i = 0; i < (int) sizeof(JSON_SMALL) - 1; i++) {
        bytes = flb_lib_push(config, p + i, 1);
        EXPECT_EQ(bytes, 1);
        total++;
    }
    printf("total=%i\n", total);
    flb_lib_stop(config);
}

TEST(Outputs, json_invalid) {
    int i;
    int ret;
    int total;
    int bytes;
    char *p = (char *) JSON_INVALID;
    struct flb_config *config;

    config = flb_config_init();
    EXPECT_TRUE(config != NULL);

    ret = flb_lib_init(config, (char *) "stdout");
    EXPECT_EQ(ret, 0);

    ret = flb_lib_start(config);
    EXPECT_EQ(ret, 0);

    printf("JSON invalid=%lu\n", sizeof(JSON_INVALID) - 1);

    total = 0;
    for (i = 0; i < (int) sizeof(JSON_INVALID) - 1; i++) {
        bytes = flb_lib_push(config, p + i, 1);
        EXPECT_EQ(bytes, 1);
        total++;
    }
    printf("total=%i\n", total);
    flb_lib_stop(config);
}
