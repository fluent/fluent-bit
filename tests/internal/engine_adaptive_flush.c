/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_engine.h>
#include "flb_tests_internal.h"

static void test_target_level_thresholds()
{
    struct flb_config *config;

    config = flb_config_init();
    TEST_CHECK(config != NULL);
    if (config == NULL) {
        return;
    }

    config->flush_adaptive_low_pressure = 25.0;
    config->flush_adaptive_medium_pressure = 50.0;
    config->flush_adaptive_high_pressure = 75.0;

    TEST_CHECK(flb_engine_adaptive_flush_target_level(config, 0.0) == 0);
    TEST_CHECK(flb_engine_adaptive_flush_target_level(config, 25.0) == 0);
    TEST_CHECK(flb_engine_adaptive_flush_target_level(config, 25.1) == 1);
    TEST_CHECK(flb_engine_adaptive_flush_target_level(config, 49.9) == 1);
    TEST_CHECK(flb_engine_adaptive_flush_target_level(config, 50.0) == 2);
    TEST_CHECK(flb_engine_adaptive_flush_target_level(config, 74.9) == 2);
    TEST_CHECK(flb_engine_adaptive_flush_target_level(config, 75.0) == 3);
    TEST_CHECK(flb_engine_adaptive_flush_target_level(config, 100.0) == 3);

    flb_config_exit(config);
}

static void test_interval_levels_and_bounds()
{
    struct flb_config *config;

    config = flb_config_init();
    TEST_CHECK(config != NULL);
    if (config == NULL) {
        return;
    }

    config->flush = 1.0;
    config->flush_adaptive_min_interval = 0.5;
    config->flush_adaptive_max_interval = 2.0;

    TEST_CHECK(flb_engine_adaptive_flush_interval(config, 0) == 2.0);
    TEST_CHECK(flb_engine_adaptive_flush_interval(config, 1) == 1.0);
    TEST_CHECK(flb_engine_adaptive_flush_interval(config, 2) == 0.75);
    TEST_CHECK(flb_engine_adaptive_flush_interval(config, 3) == 0.5);

    /* clamp low/high out-of-range levels */
    TEST_CHECK(flb_engine_adaptive_flush_interval(config, -1) == 2.0);
    TEST_CHECK(flb_engine_adaptive_flush_interval(config, 9) == 0.5);

    /* clamp by min/max bounds */
    config->flush = 10.0;
    TEST_CHECK(flb_engine_adaptive_flush_interval(config, 3) == 2.0);

    config->flush = 0.1;
    TEST_CHECK(flb_engine_adaptive_flush_interval(config, 3) == 0.5);

    flb_config_exit(config);
}

TEST_LIST = {
    { "target_level_thresholds", test_target_level_thresholds },
    { "interval_levels_and_bounds", test_interval_levels_and_bounds },
    { 0 }
};
