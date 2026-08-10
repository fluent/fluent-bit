/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <stdlib.h>
#include <string.h>

#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_engine_dispatch.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_input_chunk.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_scheduler.h>
#include <fluent-bit/flb_socket.h>
#include <fluent-bit/flb_storage.h>
#include <fluent-bit/flb_task.h>

#include <chunkio/chunkio.h>
#include <chunkio/cio_memfs.h>

#include "flb_tests_internal.h"

struct test_ctx {
    struct flb_config *config;
    struct cio_ctx *cio;
    struct flb_input_instance *input;
};

static void test_ctx_destroy(struct test_ctx *ctx)
{
    if (ctx == NULL) {
        return;
    }

    if (ctx->config != NULL) {
        flb_input_exit_all(ctx->config);
    }

    if (ctx->cio != NULL) {
        cio_destroy(ctx->cio);
        ctx->config->cio = NULL;
    }

    if (ctx->config != NULL) {
        flb_config_exit(ctx->config);
    }

    flb_free(ctx);
}

static struct test_ctx *test_ctx_create(void)
{
    int ret;
    struct test_ctx *ctx;
    struct cio_options options;
#ifdef _WIN32
    WSADATA wsa_data;
#endif

    ctx = flb_calloc(1, sizeof(struct test_ctx));
    if (ctx == NULL) {
        flb_errno();
        return NULL;
    }

    ctx->config = flb_config_init();
    if (ctx->config == NULL) {
        test_ctx_destroy(ctx);
        return NULL;
    }

#ifdef _WIN32
    WSAStartup(0x0201, &wsa_data);
#endif

    ctx->config->evl = mk_event_loop_create(8);
    if (ctx->config->evl == NULL) {
        test_ctx_destroy(ctx);
        return NULL;
    }

    ctx->config->sched = flb_sched_create(ctx->config, ctx->config->evl);
    if (ctx->config->sched == NULL) {
        test_ctx_destroy(ctx);
        return NULL;
    }

    cio_options_init(&options);
    options.flags = CIO_OPEN;
    ctx->cio = cio_create(&options);
    if (ctx->cio == NULL) {
        test_ctx_destroy(ctx);
        return NULL;
    }
    ctx->config->cio = ctx->cio;

    ctx->input = flb_input_new(ctx->config, "dummy", NULL, FLB_FALSE);
    if (ctx->input == NULL) {
        test_ctx_destroy(ctx);
        return NULL;
    }

    ret = flb_storage_input_create(ctx->cio, ctx->input);
    if (ret != 0) {
        test_ctx_destroy(ctx);
        return NULL;
    }

    return ctx;
}

static struct flb_task_retry *create_retry_dispatch_task(
                                        struct test_ctx *ctx,
                                        struct flb_output_instance *output,
                                        int *task_id,
                                        char **chunk_buffer)
{
    struct cio_memfs *memfs;
    struct flb_input_chunk *chunk;
    struct flb_task *task;
    struct flb_task_route *route;
    struct flb_task_retry *retry;

    chunk = flb_input_chunk_create(ctx->input, FLB_INPUT_LOGS, "test", 4);
    if (chunk == NULL) {
        return NULL;
    }

    task = task_alloc(ctx->config);
    if (task == NULL) {
        flb_input_chunk_destroy(chunk, FLB_TRUE);
        return NULL;
    }

    task->i_ins = ctx->input;
    task->ic = chunk;
    chunk->task = task;
    chunk->busy = FLB_TRUE;
    mk_list_add(&task->_head, &ctx->input->tasks);

    route = flb_calloc(1, sizeof(struct flb_task_route));
    if (route == NULL) {
        flb_task_destroy(task, FLB_TRUE);
        return NULL;
    }
    route->out = output;
    route->status = FLB_TASK_ROUTE_INACTIVE;
    mk_list_add(&route->_head, &task->routes);

    retry = flb_calloc(1, sizeof(struct flb_task_retry));
    if (retry == NULL) {
        flb_task_destroy(task, FLB_TRUE);
        return NULL;
    }
    retry->attempts = 1;
    retry->o_ins = output;
    retry->parent = task;
    mk_list_add(&retry->_head, &task->retries);

    /* Force flb_input_chunk_flush() to return NULL without altering production code. */
    memfs = ((struct cio_chunk *) chunk->chunk)->backend;
    *chunk_buffer = memfs->buf_data;
    memfs->buf_data = NULL;
    *task_id = task->id;

    return retry;
}

static void test_retry_flush_failure_releases_last_task_owner(void)
{
    int ret;
    int task_id;
    char *chunk_buffer;
    struct test_ctx *ctx;
    struct flb_task *replacement;
    struct flb_task_retry *retry;
    struct flb_output_instance output;

    ctx = test_ctx_create();
    TEST_CHECK(ctx != NULL);
    if (ctx == NULL) {
        return;
    }

    memset(&output, 0, sizeof(output));
    retry = create_retry_dispatch_task(ctx, &output, &task_id, &chunk_buffer);
    TEST_CHECK(retry != NULL);
    if (retry == NULL) {
        test_ctx_destroy(ctx);
        return;
    }

    ret = flb_engine_dispatch_retry(retry, ctx->config);
    TEST_CHECK(ret == -1);
    TEST_CHECK(ctx->config->task_map[task_id].task == NULL);
    TEST_CHECK(mk_list_size(&ctx->input->tasks) == 0);
    TEST_CHECK(mk_list_size(&ctx->input->chunks) == 0);

    free(chunk_buffer);

    replacement = task_alloc(ctx->config);
    TEST_CHECK(replacement != NULL);
    if (replacement != NULL) {
        TEST_CHECK(replacement->id == task_id);
        flb_task_destroy(replacement, FLB_TRUE);
    }

    test_ctx_destroy(ctx);
}

static void test_retry_flush_failure_preserves_active_task_owner(void)
{
    int ret;
    int task_id;
    char *chunk_buffer;
    struct cio_memfs *memfs;
    struct test_ctx *ctx;
    struct flb_input_chunk *chunk;
    struct flb_task *task;
    struct flb_task_retry *retry;
    struct flb_output_instance output;

    ctx = test_ctx_create();
    TEST_CHECK(ctx != NULL);
    if (ctx == NULL) {
        return;
    }

    memset(&output, 0, sizeof(output));
    retry = create_retry_dispatch_task(ctx, &output, &task_id, &chunk_buffer);
    TEST_CHECK(retry != NULL);
    if (retry == NULL) {
        test_ctx_destroy(ctx);
        return;
    }

    task = retry->parent;
    task->users = 1;

    ret = flb_engine_dispatch_retry(retry, ctx->config);
    TEST_CHECK(ret == -1);
    TEST_CHECK(ctx->config->task_map[task_id].task == task);
    TEST_CHECK(task->users == 1);
    TEST_CHECK(mk_list_size(&task->retries) == 0);
    TEST_CHECK(mk_list_size(&ctx->input->tasks) == 1);
    TEST_CHECK(mk_list_size(&ctx->input->chunks) == 1);

    if (ctx->config->task_map[task_id].task == task) {
        chunk = task->ic;
        memfs = ((struct cio_chunk *) chunk->chunk)->backend;
        memfs->buf_data = chunk_buffer;
        task->users = 0;
        flb_task_users_release(task);
    }
    else {
        free(chunk_buffer);
    }

    TEST_CHECK(ctx->config->task_map[task_id].task == NULL);
    TEST_CHECK(mk_list_size(&ctx->input->tasks) == 0);
    TEST_CHECK(mk_list_size(&ctx->input->chunks) == 0);

    test_ctx_destroy(ctx);
}

static void test_retry_flush_failure_preserves_pending_retry(void)
{
    int ret;
    int task_id;
    char *chunk_buffer;
    struct cio_memfs *memfs;
    struct test_ctx *ctx;
    struct flb_input_chunk *chunk;
    struct flb_task *task;
    struct flb_task_route *route;
    struct flb_task_retry *remaining_retry;
    struct flb_task_retry *retry;
    struct flb_output_instance output_a;
    struct flb_output_instance output_b;

    ctx = test_ctx_create();
    TEST_CHECK(ctx != NULL);
    if (ctx == NULL) {
        return;
    }

    memset(&output_a, 0, sizeof(output_a));
    memset(&output_b, 0, sizeof(output_b));
    retry = create_retry_dispatch_task(ctx, &output_a, &task_id, &chunk_buffer);
    TEST_CHECK(retry != NULL);
    if (retry == NULL) {
        test_ctx_destroy(ctx);
        return;
    }
    task = retry->parent;

    route = flb_calloc(1, sizeof(struct flb_task_route));
    remaining_retry = flb_calloc(1, sizeof(struct flb_task_retry));
    TEST_CHECK(route != NULL);
    TEST_CHECK(remaining_retry != NULL);
    if (route == NULL || remaining_retry == NULL) {
        flb_free(route);
        flb_free(remaining_retry);
        chunk = task->ic;
        memfs = ((struct cio_chunk *) chunk->chunk)->backend;
        memfs->buf_data = chunk_buffer;
        flb_task_destroy(task, FLB_TRUE);
        test_ctx_destroy(ctx);
        return;
    }

    route->out = &output_b;
    route->status = FLB_TASK_ROUTE_INACTIVE;
    mk_list_add(&route->_head, &task->routes);

    remaining_retry->attempts = 1;
    remaining_retry->o_ins = &output_b;
    remaining_retry->parent = task;
    mk_list_add(&remaining_retry->_head, &task->retries);

    ret = flb_engine_dispatch_retry(retry, ctx->config);
    TEST_CHECK(ret == -1);
    TEST_CHECK(ctx->config->task_map[task_id].task == task);
    TEST_CHECK(task->users == 0);
    TEST_CHECK(mk_list_size(&task->retries) == 1);
    TEST_CHECK(mk_list_size(&ctx->input->tasks) == 1);
    TEST_CHECK(mk_list_size(&ctx->input->chunks) == 1);

    if (ctx->config->task_map[task_id].task == task) {
        chunk = task->ic;
        memfs = ((struct cio_chunk *) chunk->chunk)->backend;
        memfs->buf_data = chunk_buffer;
        flb_task_retry_destroy(remaining_retry);
        flb_task_users_release(task);
    }
    else {
        free(chunk_buffer);
    }

    TEST_CHECK(ctx->config->task_map[task_id].task == NULL);
    TEST_CHECK(mk_list_size(&ctx->input->tasks) == 0);
    TEST_CHECK(mk_list_size(&ctx->input->chunks) == 0);

    test_ctx_destroy(ctx);
}

TEST_LIST = {
    { "retry_flush_failure_releases_last_task_owner",
      test_retry_flush_failure_releases_last_task_owner },
    { "retry_flush_failure_preserves_active_task_owner",
      test_retry_flush_failure_preserves_active_task_owner },
    { "retry_flush_failure_preserves_pending_retry",
      test_retry_flush_failure_preserves_pending_retry },
    { 0 }
};
