/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
#include <fluent-bit.h>
#include "flb_tests_runtime.h"

/* Test functions */
void flb_test_config_map_opts(void);

/* Test list */
TEST_LIST = {
    {"config_map_opts",    flb_test_config_map_opts },
    {NULL, NULL}
};

void flb_test_config_map_opts(void)
{
    flb_ctx_t    *ctx    = NULL;
    int in_ffd, r;

    flb_init_env();

    ctx = flb_create();
    in_ffd = flb_input(ctx, (char *) "tail", NULL);
    r = flb_input_property_check(ctx, in_ffd, "invalid_option", "invalid value");
    TEST_CHECK(r != 0);

    in_ffd = flb_filter(ctx, (char *) "kubernetes", NULL);
    r = flb_filter_property_check(ctx, in_ffd, "invalid_option", "invalid value");
    TEST_CHECK(r != 0);

    in_ffd = flb_output(ctx, (char *) "stdout", NULL);
    r = flb_output_property_check(ctx, in_ffd, "invalid_option", "invalid value");
    TEST_CHECK(r != 0);

    flb_destroy(ctx);
}
