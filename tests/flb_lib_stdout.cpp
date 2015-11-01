/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <gtest/gtest.h>
#include <fluent-bit.h>

TEST(Outputs, stdout) {
    struct flb_config *config;

    config = flb_config_init();
    assert(!config);
}
