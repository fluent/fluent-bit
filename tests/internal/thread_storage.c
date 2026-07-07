/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit/flb_thread_storage.h>

#include "flb_tests_internal.h"

struct thread_storage_test {
    int value;
};

FLB_TLS_DEFINE(struct thread_storage_test, thread_storage_ctx);

void test_thread_storage_get_before_init(void)
{
    struct thread_storage_test context;

    context.value = 42;

    TEST_CHECK(FLB_TLS_GET(thread_storage_ctx) == NULL);

    FLB_TLS_SET(thread_storage_ctx, &context);
    TEST_CHECK(FLB_TLS_GET(thread_storage_ctx) == &context);
    TEST_CHECK(((struct thread_storage_test *) FLB_TLS_GET(thread_storage_ctx))->value == 42);

    FLB_TLS_INIT(thread_storage_ctx);
    TEST_CHECK(FLB_TLS_GET(thread_storage_ctx) == &context);

    FLB_TLS_SET(thread_storage_ctx, NULL);
    TEST_CHECK(FLB_TLS_GET(thread_storage_ctx) == NULL);
}

TEST_LIST = {
    {"get_before_init", test_thread_storage_get_before_init},
    { 0 }
};
