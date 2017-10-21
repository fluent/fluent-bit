/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_sds.h>

#include "flb_tests_internal.h"

static void test_sds_usage()
{
    flb_sds_t s;

    s = flb_sds_create("test");
    TEST_CHECK(s != NULL);
    TEST_CHECK(flb_sds_len(s) == 4);
    TEST_CHECK(flb_sds_alloc(s) == 4);
    TEST_CHECK(strcmp("test", s) == 0);

    s = flb_sds_cat(s, ",cat message", 12);
    TEST_CHECK(strcmp("test,cat message", s) == 0);

    flb_sds_destroy(s);
}

TEST_LIST = {
    { "sds_usage", test_sds_usage},
    { 0 }
};
