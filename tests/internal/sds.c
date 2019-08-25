/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_sds.h>

#include "flb_tests_internal.h"

static void test_sds_usage()
{
    flb_sds_t s1;

    s1 = flb_sds_create("test");
    TEST_CHECK(s1 != NULL);
    TEST_CHECK(flb_sds_len(s1) == 4);
    TEST_CHECK(flb_sds_alloc(s1) == 4);
    TEST_CHECK(strcmp("test", s1) == 0);

    s1 = flb_sds_cat(s1, ",cat message", 12);
    TEST_CHECK(strcmp("test,cat message", s1) == 0);
    flb_sds_destroy(s1);


    flb_sds_t s2;

    s2 = flb_sds_create("تست");
    TEST_CHECK(s2 != NULL);
    TEST_CHECK(flb_sds_len(s2) == 6);
    TEST_CHECK(flb_sds_alloc(s2) == 6);
    TEST_CHECK(strcmp("تست", s2) == 0);

    s2 = flb_sds_cat_utf8(s2, "، پیام افزوده", 24);
    TEST_CHECK(strcmp("تست، پیام افزوده", s2) == 0);
    flb_sds_destroy(s2);
}

TEST_LIST = {
    { "sds_usage", test_sds_usage},
    { 0 }
};
