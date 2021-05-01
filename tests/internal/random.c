/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit/flb_random.h>

#include "flb_tests_internal.h"

void test_random_bytes()
{
    int ret;
    unsigned char buf1[64] = {0};
    unsigned char buf2[64] = {0};

    /* The following tests check whether:
     *
     * (1) the random generator fills the buffer with numbers at all.
     * (2) a successive call generates different numbers.
     *
     * These tests are probabilistic by nature; If we assume an ideal random
     * generator, they are expected to fail once in 2^192 (= 10^57) runs.
     */
    ret = flb_random_bytes(buf1, 64);
    TEST_CHECK(ret == 0);
    TEST_CHECK(memcmp(buf1, buf2, 64) != 0);

    ret = flb_random_bytes(buf2, 64);
    TEST_CHECK(ret == 0);
    TEST_CHECK(memcmp(buf1, buf2, 64) != 0);
}

TEST_LIST = {
    {"random_bytes", test_random_bytes},
    { 0 }
};
