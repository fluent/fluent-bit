/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit/flb_str.h>

#include "flb_tests_internal.h"

static void test_strlcpy()
{
    char buf[16];
    size_t n;

    /* Normal case */
    n = flb_strlcpy(buf, "aiueo", 6);
    TEST_CHECK(memcmp(buf, "aiueo", 6) == 0);
    TEST_CHECK(n == 5);

    /* Enough buffer */
    n = flb_strlcpy(buf, "aiueo", 16);
    TEST_CHECK(memcmp(buf, "aiueo", 6) == 0);
    TEST_CHECK(n == 5);

    /* Buffer short by one */
    n = flb_strlcpy(buf, "aiueo", 5);
    TEST_CHECK(memcmp(buf, "aiue", 5) == 0);
    TEST_CHECK(n == 5);

    /* Buffer short by two */
    n = flb_strlcpy(buf, "aiueo", 4);
    TEST_CHECK(memcmp(buf, "aiu", 4) == 0);
    TEST_CHECK(n == 5);

    /* No buffer */
    n = flb_strlcpy(buf, "aiueo", 0);
    TEST_CHECK(n == 5);
}

TEST_LIST = {
    { "strlcpy", test_strlcpy},
    { 0 }
};
