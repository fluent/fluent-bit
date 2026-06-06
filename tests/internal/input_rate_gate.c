/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_input_chunk.h>
#include <fluent-bit/flb_task.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_time.h>

#include "flb_tests_internal.h"

struct test_context {
    struct flb_config *config;
    struct flb_input_instance *input;
};

static int test_context_init(struct test_context *ctx)
{
    ctx->config = flb_config_init();
    if (ctx->config == NULL) {
        return -1;
    }

    ctx->input = flb_input_new(ctx->config, "dummy", NULL, FLB_FALSE);
    if (ctx->input == NULL) {
        flb_config_exit(ctx->config);
        return -1;
    }

    return 0;
}

static void test_context_destroy(struct test_context *ctx)
{
    flb_input_exit_all(ctx->config);
    flb_config_exit(ctx->config);
}

static void test_rate_gate_backpressure_limited()
{
    int ret;
    struct test_context ctx;
    struct flb_input_chunk *chunk;
    struct flb_task *task;
    struct flb_task_retry *retry;

    ret = test_context_init(&ctx);
    TEST_CHECK(ret == 0);
    if (ret != 0) {
        return;
    }

    chunk = flb_calloc(1, sizeof(struct flb_input_chunk));
    task = flb_calloc(1, sizeof(struct flb_task));
    retry = flb_calloc(1, sizeof(struct flb_task_retry));
    TEST_CHECK(chunk != NULL);
    TEST_CHECK(task != NULL);
    TEST_CHECK(retry != NULL);
    if (chunk == NULL || task == NULL || retry == NULL) {
        flb_free(chunk);
        flb_free(task);
        flb_free(retry);
        test_context_destroy(&ctx);
        return;
    }

    chunk->busy = FLB_TRUE;
    mk_list_add(&chunk->_head, &ctx.input->chunks);

    mk_list_init(&task->retries);
    mk_list_add(&task->_head, &ctx.input->tasks);

    retry->attempts = 3;
    mk_list_add(&retry->_head, &task->retries);

    ctx.input->rate_window_start = cfl_time_now();
    ctx.input->rate_window_size = 10 * FLB_NSEC_IN_SEC;
    ctx.input->rate_bytes = 26.0;
    ctx.input->rate_gate_enabled = FLB_TRUE;
    ctx.input->rate_gate_status = FLB_INPUT_RUNNING;
    ctx.input->rate_gate_use_backpressure = FLB_TRUE;
    ctx.input->rate_gate_max_bytes = 100;
    ctx.input->rate_gate_max_records = 0;

    ret = flb_input_rate_gate_protect(ctx.input);
    TEST_CHECK(ret == FLB_TRUE);
    TEST_CHECK(ctx.input->rate_gate_status == FLB_INPUT_PAUSED);
    TEST_CHECK(ctx.input->rate_gate_busy_chunks == 1);
    TEST_CHECK(ctx.input->rate_gate_retry_attempts == 3);

    mk_list_del(&retry->_head);
    mk_list_del(&task->_head);
    mk_list_del(&chunk->_head);
    flb_free(retry);
    flb_free(task);
    flb_free(chunk);
    test_context_destroy(&ctx);
}

static void test_rate_gate_backpressure_disabled()
{
    int ret;
    struct test_context ctx;
    struct flb_input_chunk *chunk;
    struct flb_task *task;
    struct flb_task_retry *retry;

    ret = test_context_init(&ctx);
    TEST_CHECK(ret == 0);
    if (ret != 0) {
        return;
    }

    chunk = flb_calloc(1, sizeof(struct flb_input_chunk));
    task = flb_calloc(1, sizeof(struct flb_task));
    retry = flb_calloc(1, sizeof(struct flb_task_retry));
    TEST_CHECK(chunk != NULL);
    TEST_CHECK(task != NULL);
    TEST_CHECK(retry != NULL);
    if (chunk == NULL || task == NULL || retry == NULL) {
        flb_free(chunk);
        flb_free(task);
        flb_free(retry);
        test_context_destroy(&ctx);
        return;
    }

    chunk->busy = FLB_TRUE;
    mk_list_add(&chunk->_head, &ctx.input->chunks);

    mk_list_init(&task->retries);
    mk_list_add(&task->_head, &ctx.input->tasks);

    retry->attempts = 3;
    mk_list_add(&retry->_head, &task->retries);

    ctx.input->rate_window_start = cfl_time_now();
    ctx.input->rate_window_size = 10 * FLB_NSEC_IN_SEC;
    ctx.input->rate_bytes = 26.0;
    ctx.input->rate_gate_enabled = FLB_TRUE;
    ctx.input->rate_gate_status = FLB_INPUT_RUNNING;
    ctx.input->rate_gate_use_backpressure = FLB_FALSE;
    ctx.input->rate_gate_max_bytes = 100;
    ctx.input->rate_gate_max_records = 0;

    ret = flb_input_rate_gate_protect(ctx.input);
    TEST_CHECK(ret == FLB_FALSE);
    TEST_CHECK(ctx.input->rate_gate_status == FLB_INPUT_RUNNING);
    TEST_CHECK(ctx.input->rate_gate_busy_chunks == 0);
    TEST_CHECK(ctx.input->rate_gate_retry_attempts == 0);

    mk_list_del(&retry->_head);
    mk_list_del(&task->_head);
    mk_list_del(&chunk->_head);
    flb_free(retry);
    flb_free(task);
    flb_free(chunk);
    test_context_destroy(&ctx);
}

static void test_rate_gate_property_parsing()
{
    int ret;
    struct test_context ctx;

    ret = test_context_init(&ctx);
    TEST_CHECK(ret == 0);
    if (ret != 0) {
        return;
    }

    ret = flb_input_set_property(ctx.input, "rate_window", "5");
    TEST_CHECK(ret == 0);
    ret = flb_input_set_property(ctx.input, "rate_gate", "true");
    TEST_CHECK(ret == 0);
    ret = flb_input_set_property(ctx.input, "rate_gate.max_bytes", "200");
    TEST_CHECK(ret == 0);
    ret = flb_input_set_property(ctx.input, "rate_gate.max_records", "30");
    TEST_CHECK(ret == 0);
    ret = flb_input_set_property(ctx.input, "rate_gate.backpressure", "false");
    TEST_CHECK(ret == 0);
    ret = flb_input_set_property(ctx.input, "rate_gate.resume_ratio", "0.70");
    TEST_CHECK(ret == 0);

    TEST_CHECK(ctx.input->rate_window_size == (5 * FLB_NSEC_IN_SEC));
    TEST_CHECK(ctx.input->rate_gate_enabled == FLB_TRUE);
    TEST_CHECK(ctx.input->rate_gate_max_bytes == 200);
    TEST_CHECK(ctx.input->rate_gate_max_records == 30);
    TEST_CHECK(ctx.input->rate_gate_use_backpressure == FLB_FALSE);
    TEST_CHECK(ctx.input->rate_gate_resume_ratio > 0.69 &&
               ctx.input->rate_gate_resume_ratio < 0.71);

    test_context_destroy(&ctx);
}

static void test_rate_update_window_rollover()
{
    int ret;
    uint64_t ts;
    struct test_context ctx;

    ret = test_context_init(&ctx);
    TEST_CHECK(ret == 0);
    if (ret != 0) {
        return;
    }

    ctx.input->rate_window_size = FLB_NSEC_IN_SEC;
    ts = cfl_time_now();
    ctx.input->rate_window_start = ts;

    flb_input_rate_update(ctx.input, ts + (100 * (FLB_NSEC_IN_SEC / 1000)), 20, 200);
    TEST_CHECK(ctx.input->rate_records == 0.0);
    TEST_CHECK(ctx.input->rate_bytes == 0.0);
    TEST_CHECK(ctx.input->rate_window_records == 20);
    TEST_CHECK(ctx.input->rate_window_bytes == 200);

    flb_input_rate_update(ctx.input, ts + FLB_NSEC_IN_SEC, 0, 0);
    TEST_CHECK(ctx.input->rate_records == 20.0);
    TEST_CHECK(ctx.input->rate_bytes == 200.0);
    TEST_CHECK(ctx.input->rate_window_records == 0);
    TEST_CHECK(ctx.input->rate_window_bytes == 0);

    flb_input_rate_update(ctx.input, ts + FLB_NSEC_IN_SEC +
                          (200 * (FLB_NSEC_IN_SEC / 1000)), 4, 40);
    TEST_CHECK(ctx.input->rate_window_records == 4);
    TEST_CHECK(ctx.input->rate_window_bytes == 40);

    test_context_destroy(&ctx);
}

static void test_rate_gate_hysteresis_resume()
{
    int ret;
    struct test_context ctx;

    ret = test_context_init(&ctx);
    TEST_CHECK(ret == 0);
    if (ret != 0) {
        return;
    }

    ctx.input->rate_gate_enabled = FLB_TRUE;
    ctx.input->rate_gate_status = FLB_INPUT_RUNNING;
    ctx.input->rate_gate_use_backpressure = FLB_FALSE;
    ctx.input->rate_gate_max_bytes = 100;
    ctx.input->rate_gate_resume_ratio = 0.80;
    ctx.input->rate_window_start = cfl_time_now();
    ctx.input->rate_window_size = 10 * FLB_NSEC_IN_SEC;

    ctx.input->rate_bytes = 110.0;
    ret = flb_input_rate_gate_protect(ctx.input);
    TEST_CHECK(ret == FLB_TRUE);
    TEST_CHECK(ctx.input->rate_gate_status == FLB_INPUT_PAUSED);

    ctx.input->rate_bytes = 85.0;
    flb_input_rate_gate_maybe_resume(ctx.input);
    TEST_CHECK(ctx.input->rate_gate_status == FLB_INPUT_PAUSED);

    ctx.input->rate_bytes = 75.0;
    flb_input_rate_gate_maybe_resume(ctx.input);
    TEST_CHECK(ctx.input->rate_gate_status == FLB_INPUT_RUNNING);

    test_context_destroy(&ctx);
}

static void test_rate_gate_pause_resume_stability()
{
    int ret;
    struct test_context ctx;

    ret = test_context_init(&ctx);
    TEST_CHECK(ret == 0);
    if (ret != 0) {
        return;
    }

    ctx.input->rate_gate_enabled = FLB_TRUE;
    ctx.input->rate_gate_status = FLB_INPUT_RUNNING;
    ctx.input->rate_gate_use_backpressure = FLB_FALSE;
    ctx.input->rate_gate_max_records = 10;
    ctx.input->rate_window_start = cfl_time_now();
    ctx.input->rate_window_size = 10 * FLB_NSEC_IN_SEC;

    ctx.input->rate_records = 11.0;
    ret = flb_input_rate_gate_protect(ctx.input);
    TEST_CHECK(ret == FLB_TRUE);
    TEST_CHECK(ctx.input->rate_gate_status == FLB_INPUT_PAUSED);

    ctx.input->mem_buf_status = FLB_INPUT_PAUSED;
    ctx.input->rate_records = 1.0;
    flb_input_rate_gate_maybe_resume(ctx.input);
    TEST_CHECK(ctx.input->rate_gate_status == FLB_INPUT_PAUSED);
    TEST_CHECK(ctx.input->mem_buf_status == FLB_INPUT_PAUSED);

    ctx.input->rate_gate_status = FLB_INPUT_PAUSED;
    ctx.input->mem_buf_status = FLB_INPUT_RUNNING;
    ctx.input->rate_window_records = 200;
    flb_input_rate_gate_maybe_resume(ctx.input);
    TEST_CHECK(ctx.input->rate_gate_status == FLB_INPUT_PAUSED);
    TEST_CHECK(ctx.input->rate_window_records == 200);

    test_context_destroy(&ctx);
}

static void test_resume_without_context_is_safe()
{
    int ret;
    struct test_context ctx;

    ret = test_context_init(&ctx);
    TEST_CHECK(ret == 0);
    if (ret != 0) {
        return;
    }

    TEST_CHECK(ctx.input->context == NULL);

    ret = flb_input_resume(ctx.input);
    TEST_CHECK(ret == 0);

    test_context_destroy(&ctx);
}

TEST_LIST = {
    {"rate_gate_backpressure_limited", test_rate_gate_backpressure_limited},
    {"rate_gate_backpressure_disabled", test_rate_gate_backpressure_disabled},
    {"rate_gate_property_parsing", test_rate_gate_property_parsing},
    {"rate_update_window_rollover", test_rate_update_window_rollover},
    {"rate_gate_hysteresis_resume", test_rate_gate_hysteresis_resume},
    {"rate_gate_pause_resume_stability", test_rate_gate_pause_resume_stability},
    {"resume_without_context_is_safe", test_resume_without_context_is_safe},
    {0}
};
