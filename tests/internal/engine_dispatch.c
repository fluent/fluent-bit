/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <stdlib.h>
#include <string.h>

#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_engine_dispatch.h>
#include <fluent-bit/flb_event.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_input_chunk.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_metrics.h>
#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_router.h>
#include <fluent-bit/flb_scheduler.h>
#include <fluent-bit/flb_socket.h>
#include <fluent-bit/flb_storage.h>
#include <fluent-bit/flb_task.h>

#include <chunkio/chunkio.h>
#include <chunkio/cio_memfs.h>

#include "flb_tests_internal.h"

#define TEST_ROUTE_RECORDS 7
#define TEST_ROUTE_BYTES   29
#define TEST_CHUNK_RECORDS 13

struct test_ctx {
    struct flb_config *config;
    struct cio_ctx *cio;
    struct flb_input_instance *input;
#ifdef _WIN32
    int winsock_initialized;
#endif
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

#ifdef _WIN32
    if (ctx->winsock_initialized == FLB_TRUE) {
        WSACleanup();
        ctx->winsock_initialized = FLB_FALSE;
    }
#endif

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
    ret = WSAStartup(0x0201, &wsa_data);
    if (ret != 0) {
        test_ctx_destroy(ctx);
        return NULL;
    }
    ctx->winsock_initialized = FLB_TRUE;
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

static int test_output_init(struct flb_output_instance *output, const char *name)
{
    memset(output, 0, sizeof(struct flb_output_instance));
    strncpy(output->name, name, sizeof(output->name) - 1);

    output->cmt = cmt_create();
    if (output->cmt == NULL) {
        return -1;
    }

    output->cmt_retries_failed = cmt_counter_create(output->cmt,
                                                     "fluentbit",
                                                     "output",
                                                     "retries_failed_total",
                                                     "Failed retries",
                                                     1,
                                                     (char *[]) {"name"});
    output->cmt_dropped_records = cmt_counter_create(output->cmt,
                                                      "fluentbit",
                                                      "output",
                                                      "dropped_records_total",
                                                      "Dropped records",
                                                      1,
                                                      (char *[]) {"name"});
    if (output->cmt_retries_failed == NULL ||
        output->cmt_dropped_records == NULL) {
        cmt_destroy(output->cmt);
        output->cmt = NULL;
        return -1;
    }

#ifdef FLB_HAVE_METRICS
    output->metrics = flb_metrics_create(name);
    if (output->metrics == NULL ||
        flb_metrics_add(FLB_METRIC_OUT_RETRY_FAILED,
                        "retries_failed", output->metrics) == -1 ||
        flb_metrics_add(FLB_METRIC_OUT_DROPPED_RECORDS,
                        "dropped_records", output->metrics) == -1) {
        if (output->metrics != NULL) {
            flb_metrics_destroy(output->metrics);
            output->metrics = NULL;
        }
        cmt_destroy(output->cmt);
        output->cmt = NULL;
        return -1;
    }
#endif

    return 0;
}

static void test_output_destroy(struct flb_output_instance *output)
{
#ifdef FLB_HAVE_METRICS
    if (output->metrics != NULL) {
        flb_metrics_destroy(output->metrics);
        output->metrics = NULL;
    }
#endif

    if (output->cmt != NULL) {
        cmt_destroy(output->cmt);
        output->cmt = NULL;
    }
}

static void check_retry_failure_metrics(struct test_ctx *ctx,
                                        struct flb_output_instance *output)
{
    int ret;
    double value;
    char *input_name;
    char *output_name;
#ifdef FLB_HAVE_METRICS
    struct flb_metric *metric;
#endif

    input_name = (char *) flb_input_name(ctx->input);
    output_name = (char *) flb_output_name(output);

    ret = cmt_counter_get_val(output->cmt_retries_failed,
                              1, (char *[]) {output_name}, &value);
    TEST_CHECK(ret == 0);
    TEST_CHECK(value == 1);

    ret = cmt_counter_get_val(output->cmt_dropped_records,
                              1, (char *[]) {output_name}, &value);
    TEST_CHECK(ret == 0);
    TEST_CHECK(value == TEST_ROUTE_RECORDS);

    ret = cmt_counter_get_val(ctx->config->router->logs_drop_records_total,
                              2, (char *[]) {input_name, output_name}, &value);
    TEST_CHECK(ret == 0);
    TEST_CHECK(value == TEST_ROUTE_RECORDS);

    ret = cmt_counter_get_val(ctx->config->router->logs_drop_bytes_total,
                              2, (char *[]) {input_name, output_name}, &value);
    TEST_CHECK(ret == 0);
    TEST_CHECK(value == TEST_ROUTE_BYTES);

#ifdef FLB_HAVE_METRICS
    metric = flb_metrics_get_id(FLB_METRIC_OUT_RETRY_FAILED, output->metrics);
    TEST_CHECK(metric != NULL);
    if (metric != NULL) {
        TEST_CHECK(metric->val == 1);
    }

    metric = flb_metrics_get_id(FLB_METRIC_OUT_DROPPED_RECORDS, output->metrics);
    TEST_CHECK(metric != NULL);
    if (metric != NULL) {
        TEST_CHECK(metric->val == TEST_ROUTE_RECORDS);
    }
#endif
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

    memfs = ((struct cio_chunk *) chunk->chunk)->backend;
    task->event_chunk = flb_event_chunk_create(FLB_EVENT_TYPE_LOGS,
                                               TEST_CHUNK_RECORDS,
                                               "test", 4,
                                               memfs->buf_data,
                                               memfs->buf_len);
    if (task->event_chunk == NULL) {
        flb_task_destroy(task, FLB_TRUE);
        return NULL;
    }

    route = flb_calloc(1, sizeof(struct flb_task_route));
    if (route == NULL) {
        flb_task_destroy(task, FLB_TRUE);
        return NULL;
    }
    route->out = output;
    route->status = FLB_TASK_ROUTE_INACTIVE;
    route->records = TEST_ROUTE_RECORDS;
    route->bytes = TEST_ROUTE_BYTES;
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

    ret = test_output_init(&output, "output_a");
    TEST_CHECK(ret == 0);
    if (ret != 0) {
        test_ctx_destroy(ctx);
        return;
    }
    retry = create_retry_dispatch_task(ctx, &output, &task_id, &chunk_buffer);
    TEST_CHECK(retry != NULL);
    if (retry == NULL) {
        test_output_destroy(&output);
        test_ctx_destroy(ctx);
        return;
    }

    ret = flb_engine_dispatch_retry(retry, ctx->config);
    TEST_CHECK(ret == -1);
    TEST_CHECK(ctx->config->task_map[task_id].task == NULL);
    TEST_CHECK(mk_list_size(&ctx->input->tasks) == 0);
    TEST_CHECK(mk_list_size(&ctx->input->chunks) == 0);
    check_retry_failure_metrics(ctx, &output);

    free(chunk_buffer);

    replacement = task_alloc(ctx->config);
    TEST_CHECK(replacement != NULL);
    if (replacement != NULL) {
        TEST_CHECK(replacement->id == task_id);
        flb_task_destroy(replacement, FLB_TRUE);
    }

    test_output_destroy(&output);
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

    ret = test_output_init(&output, "output_a");
    TEST_CHECK(ret == 0);
    if (ret != 0) {
        test_ctx_destroy(ctx);
        return;
    }
    retry = create_retry_dispatch_task(ctx, &output, &task_id, &chunk_buffer);
    TEST_CHECK(retry != NULL);
    if (retry == NULL) {
        test_output_destroy(&output);
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
    check_retry_failure_metrics(ctx, &output);

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

    test_output_destroy(&output);
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

    ret = test_output_init(&output_a, "output_a");
    TEST_CHECK(ret == 0);
    if (ret != 0) {
        test_ctx_destroy(ctx);
        return;
    }
    memset(&output_b, 0, sizeof(output_b));
    strncpy(output_b.name, "output_b", sizeof(output_b.name) - 1);
    retry = create_retry_dispatch_task(ctx, &output_a, &task_id, &chunk_buffer);
    TEST_CHECK(retry != NULL);
    if (retry == NULL) {
        test_output_destroy(&output_a);
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
        test_output_destroy(&output_a);
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
    check_retry_failure_metrics(ctx, &output_a);

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

    test_output_destroy(&output_a);
    test_ctx_destroy(ctx);
}

/*
 * With retry budget left the chunk must be kept and the attempt re-scheduled,
 * otherwise a transient read failure would delete records a later attempt
 * could still deliver.
 */
static void test_retry_flush_failure_reschedules_within_retry_limit(void)
{
    int ret;
    int task_id;
    double value;
    char *chunk_buffer;
    char *output_name;
    struct test_ctx *ctx;
    struct flb_task *task;
    struct flb_task_retry *retry;
    struct flb_output_instance output;

    ctx = test_ctx_create();
    TEST_CHECK(ctx != NULL);
    if (ctx == NULL) {
        return;
    }

    ret = test_output_init(&output, "output_a");
    TEST_CHECK(ret == 0);
    if (ret != 0) {
        test_ctx_destroy(ctx);
        return;
    }

    /* the retry starts with attempts=1, so this leaves budget available */
    output.retry_limit = 5;

    retry = create_retry_dispatch_task(ctx, &output, &task_id, &chunk_buffer);
    TEST_CHECK(retry != NULL);
    if (retry == NULL) {
        test_output_destroy(&output);
        test_ctx_destroy(ctx);
        return;
    }
    task = retry->parent;

    ret = flb_engine_dispatch_retry(retry, ctx->config);
    TEST_CHECK(ret == 0);

    /* the task keeps its slot, its chunk and a pending retry */
    TEST_CHECK(ctx->config->task_map[task_id].task == task);
    TEST_CHECK(mk_list_size(&ctx->input->tasks) == 1);
    TEST_CHECK(mk_list_size(&ctx->input->chunks) == 1);
    TEST_CHECK(mk_list_size(&task->retries) == 1);
    TEST_CHECK(retry->attempts == 2);

    /*
     * Nothing was dropped, so no drop accounting must be recorded. An untouched
     * counter has no series yet, so cmt_counter_get_val() reports a failure.
     */
    output_name = (char *) flb_output_name(&output);
    ret = cmt_counter_get_val(output.cmt_retries_failed,
                              1, (char *[]) {output_name}, &value);
    TEST_CHECK(ret != 0 || value == 0);

    ret = cmt_counter_get_val(output.cmt_dropped_records,
                              1, (char *[]) {output_name}, &value);
    TEST_CHECK(ret != 0 || value == 0);

    flb_task_destroy(task, FLB_TRUE);
    free(chunk_buffer);

    test_output_destroy(&output);
    test_ctx_destroy(ctx);
}

TEST_LIST = {
    { "retry_flush_failure_releases_last_task_owner",
      test_retry_flush_failure_releases_last_task_owner },
    { "retry_flush_failure_reschedules_within_retry_limit",
      test_retry_flush_failure_reschedules_within_retry_limit },
    { "retry_flush_failure_preserves_active_task_owner",
      test_retry_flush_failure_preserves_active_task_owner },
    { "retry_flush_failure_preserves_pending_retry",
      test_retry_flush_failure_preserves_pending_retry },
    { 0 }
};
