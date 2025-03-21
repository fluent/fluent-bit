/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_utils.h>

#include "flb_tests_internal.h"

#define to_bytes flb_utils_size_to_bytes

void test_unit_sizes()
{
    int64_t KB = 1000;
    int64_t MB = 1000 * KB;
    int64_t GB = 1000 * MB;

    /* Bytes, no prefixes */
    TEST_CHECK(to_bytes("1") == 1);
    TEST_CHECK(to_bytes("50") == 50);
    TEST_CHECK(to_bytes("1000") == 1*KB);

    /* Decimal prefix: KB */
    TEST_CHECK(to_bytes("1KB") == KB);
    TEST_CHECK(to_bytes("1K") == KB);
    TEST_CHECK(to_bytes("1kB") == KB);
    TEST_CHECK(to_bytes("1kb") == KB);
    TEST_CHECK(to_bytes("1k") == KB);

    /* Decimal prefix: MB */
    TEST_CHECK(to_bytes("1MB") == MB);
    TEST_CHECK(to_bytes("1M") == MB);
    TEST_CHECK(to_bytes("1mB") == MB);
    TEST_CHECK(to_bytes("1mb") == MB);
    TEST_CHECK(to_bytes("1m") == MB);
    TEST_CHECK(to_bytes("5m") == 5*MB);

    /* Decimal prefix: GB */
    TEST_CHECK(to_bytes("1GB") == GB);
    TEST_CHECK(to_bytes("1G") == GB);
    TEST_CHECK(to_bytes("1gB") == GB);
    TEST_CHECK(to_bytes("1gb") == GB);
    TEST_CHECK(to_bytes("1g") == GB);
    TEST_CHECK(to_bytes("5g") == 5*GB);
    TEST_CHECK(to_bytes("32g") == 32*GB);

    /* Invalid values */
    TEST_CHECK(to_bytes("aabb") == -1);
    TEST_CHECK(to_bytes("") == -1);

    /* Invlid prefixes */
    TEST_CHECK(to_bytes("1kX") == -1);
    TEST_CHECK(to_bytes("1kX") == -1);
    TEST_CHECK(to_bytes("1MX") == -1);
    TEST_CHECK(to_bytes("1GX") == -1);
}

TEST_LIST = {
    { "unit_sizes", test_unit_sizes },
    { 0 }
};
