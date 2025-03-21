/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_endian.h>

#include "flb_tests_internal.h"

/* This test case sets a specific value to a variable and compares
 * the memory representation against the byte order detected by
 * cmake.
 */
static void flb_test_endianness_detection()
{
    volatile uint64_t  source_value;
    volatile uint8_t  *test_value;

    /* ~TEA, COFFEE */
    source_value = 0x08140C0FFEE;
    test_value = (volatile uint8_t *) &source_value;

#if FLB_BYTE_ORDER == FLB_LITTLE_ENDIAN
    TEST_CHECK(test_value[0] == 0xEE);
#else
    TEST_CHECK(test_value[0] != 0xEE);
#endif
}

TEST_LIST = {
    { "test_endianness_detection", flb_test_endianness_detection },

    { 0 }
};
