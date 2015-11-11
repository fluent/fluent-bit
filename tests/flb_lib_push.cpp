/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <gtest/gtest.h>
#include <fluent-bit.h>
#include "data_td.h"

/* It writes a big JSON message (> 3.5MB) */
TEST(Lib, push_big_json) {
    int i;
    int ret;
    int total;
    int bytes;
    char *p = (char *) JSON_TD;
    struct flb_config *config;

    config = flb_config_init();
    EXPECT_TRUE(config != NULL);

    ret = flb_lib_init(config, (char *) "stdout");
    EXPECT_EQ(ret, 0);

    ret = flb_lib_start(config);
    EXPECT_EQ(ret, 0);

    total = 0;
    bytes = flb_lib_push(config, p, (int) sizeof(JSON_TD) - 1);
    flb_lib_stop(config);
}
