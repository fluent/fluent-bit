/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_error.h>
#include <fluent-bit/flb_socket.h>
#include <fluent-bit/flb_task.h>
#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_scheduler.h>
#include <string.h>

#include "flb_tests_internal.h"

#define TASK_COUNT_LIMIT (FLB_CONFIG_DEFAULT_TASK_MAP_SIZE_LIMIT + 1)

struct test_ctx {
    struct flb_config     *config;
    struct mk_event_loop  *evl;
};

struct test_ctx* test_ctx_create()
{
    struct test_ctx *ret_ctx = NULL;
#ifdef _WIN32
    WSADATA wsa_data;
#endif

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

#ifdef _WIN32
    WSAStartup(0x0201, &wsa_data);
#endif
    ret_ctx->evl = mk_event_loop_create(8);
    if(!TEST_CHECK(ret_ctx->evl != NULL)) {
        flb_config_exit(ret_ctx->config);
        flb_free(ret_ctx);
        return NULL;
    }

    ret_ctx->config->evl = ret_ctx->evl;
    ret_ctx->config->sched = flb_sched_create(ret_ctx->config, ret_ctx->evl);
    if(!TEST_CHECK(ret_ctx->config->sched != NULL)) {
        mk_event_loop_destroy(ret_ctx->evl);
        flb_config_exit(ret_ctx->config);
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

void test_task_route_data_preserved_across_retry()
{
    int ret;
    int records;
    size_t bytes;
    struct test_ctx *ctx;
    struct flb_task *task;
    struct flb_output_instance out_a;
    struct flb_output_instance out_b;
    struct flb_task_route *route_a;
    struct flb_task_route *route_b;
    struct flb_task_retry *retry;

    ctx = test_ctx_create();
    if (!TEST_CHECK(ctx != NULL)) {
        return;
    }

    task = task_alloc(ctx->config);
    if (!TEST_CHECK(task != NULL)) {
        test_ctx_destroy(ctx);
        return;
    }

    /* Avoid input chunk up/down side effects in retry creation. */
    task->users = 2;

    memset(&out_a, 0, sizeof(out_a));
    memset(&out_b, 0, sizeof(out_b));
    out_a.retry_limit = 5;
    out_b.retry_limit = 5;

    route_a = flb_calloc(1, sizeof(struct flb_task_route));
    route_b = flb_calloc(1, sizeof(struct flb_task_route));
    TEST_CHECK(route_a != NULL);
    TEST_CHECK(route_b != NULL);
    if (!route_a || !route_b) {
        flb_free(route_a);
        flb_free(route_b);
        flb_task_destroy(task, FLB_TRUE);
        test_ctx_destroy(ctx);
        return;
    }

    route_a->status = FLB_TASK_ROUTE_ACTIVE;
    route_a->out = &out_a;
    route_a->records = 3;
    route_a->bytes = 300;
    route_b->status = FLB_TASK_ROUTE_ACTIVE;
    route_b->out = &out_b;
    route_b->records = 7;
    route_b->bytes = 700;
    mk_list_add(&route_a->_head, &task->routes);
    mk_list_add(&route_b->_head, &task->routes);

    flb_task_set_route_data(task, &out_a, 1, 111);
    ret = flb_task_get_route_data(task, &out_a, &records, &bytes);
    TEST_CHECK(ret == 0);
    TEST_CHECK(records == 1);
    TEST_CHECK(bytes == 111);

    retry = flb_task_retry_create(task, &out_a);
    TEST_CHECK(retry != NULL);
    if (retry != NULL) {
        TEST_CHECK(retry->attempts == 1);
    }

    retry = flb_task_retry_create(task, &out_a);
    TEST_CHECK(retry != NULL);
    if (retry != NULL) {
        TEST_CHECK(retry->attempts == 2);
    }

    ret = flb_task_get_route_data(task, &out_a, &records, &bytes);
    TEST_CHECK(ret == 0);
    TEST_CHECK(records == 1);
    TEST_CHECK(bytes == 111);

    flb_task_retry_clean(task, &out_a);
    flb_task_destroy(task, FLB_TRUE);
    test_ctx_destroy(ctx);
}

TEST_LIST = {
    { "task_map_limit" , test_task_map_limit},
    { "task_route_data_preserved_across_retry", test_task_route_data_preserved_across_retry},
    { 0 }
};
