/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_error.h>
#include <fluent-bit/flb_socket.h>
#include <fluent-bit/flb_task.h>

#include "flb_tests_internal.h"

#define TASK_COUNT_LIMIT (FLB_CONFIG_DEFAULT_TASK_MAP_SIZE_LIMIT + 1)

struct test_ctx {
    struct flb_config     *config;
};

struct test_ctx* test_ctx_create()
{
    struct test_ctx *ret_ctx = NULL;

    ret_ctx = flb_calloc(1, sizeof(struct test_ctx));
    if (!TEST_CHECK(ret_ctx != NULL)) {
        flb_errno();
        TEST_MSG("flb_malloc(test_ctx) failed");
        return NULL;
    }

    ret_ctx->config = flb_config_init();
    if(!TEST_CHECK(ret_ctx->config != NULL)) {
        TEST_MSG("flb_config_init failed");
        flb_free(ret_ctx);
        return NULL;
    }

    return ret_ctx;
}

int test_ctx_destroy(struct test_ctx* ctx)
{
    if (!TEST_CHECK(ctx != NULL)) {
        return -1;
    }

    if (ctx->config) {
        flb_config_exit(ctx->config);
    }

    flb_free(ctx);
    return 0;
}

void test_task_map_limit()
{
    struct test_ctx *ctx;
    ssize_t index;
    struct flb_task *tasks[TASK_COUNT_LIMIT];
    int failure_detected;

    ctx = test_ctx_create();

    if (!TEST_CHECK(ctx != NULL)) {
        return;
    }

    failure_detected = FLB_FALSE;

    for (index = 0 ; index < TASK_COUNT_LIMIT ; index++) {
        tasks[index] = task_alloc(ctx->config);

        if (tasks[index] == NULL) {
            failure_detected = FLB_TRUE;

            break;
        }
    }

    if (TEST_CHECK(failure_detected == FLB_TRUE)) {
        TEST_CHECK(index == FLB_CONFIG_DEFAULT_TASK_MAP_SIZE_LIMIT);
    }

    while (index >= 0) {
        if (tasks[index] != NULL) {
            flb_task_destroy(tasks[index], FLB_TRUE);
        }
        index--;
    }

    test_ctx_destroy(ctx);
}

TEST_LIST = {
    { "task_map_limit" , test_task_map_limit},
    { 0 }
};
