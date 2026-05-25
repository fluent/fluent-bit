/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_mem.h>

#include "flb_tests_internal.h"

void test_heap_mem_accounting(void)
{
    size_t baseline;
    size_t calloc_size;
    void *buffer;
    void *zeroed;
    void *resized;

    baseline = flb_mem_usage_get();

    buffer = flb_malloc(32);
    TEST_CHECK(buffer != NULL);
    if (!buffer) {
        return;
    }
    TEST_CHECK(flb_mem_usage_get() == baseline + FLB_MEM_SIZE(buffer));

    zeroed = flb_calloc(4, 16);
    TEST_CHECK(zeroed != NULL);
    if (!zeroed) {
        flb_free(buffer);
        return;
    }
    calloc_size = FLB_MEM_SIZE(zeroed);
    TEST_CHECK(flb_mem_usage_get() == baseline + FLB_MEM_SIZE(buffer) + calloc_size);

    resized = flb_realloc(buffer, 256);
    TEST_CHECK(resized != NULL);
    if (!resized) {
        flb_free(buffer);
        flb_free(zeroed);
        return;
    }
    buffer = resized;
    TEST_CHECK(flb_mem_usage_get() == baseline + FLB_MEM_SIZE(buffer) + calloc_size);

    flb_free(buffer);
    flb_free(zeroed);
    TEST_CHECK(flb_mem_usage_get() == baseline);
}

void test_heap_mem_accounting_underflow(void)
{
    size_t baseline;

    baseline = flb_mem_usage_get();

    flb_mem_account_sub(baseline + 1);
    TEST_CHECK(flb_mem_usage_get() == 0);

    flb_mem_account_add(baseline);
    TEST_CHECK(flb_mem_usage_get() == baseline);
}

TEST_LIST = {
    {"heap_mem_accounting", test_heap_mem_accounting},
    {"heap_mem_accounting_underflow", test_heap_mem_accounting_underflow},
    {NULL, NULL}
};
