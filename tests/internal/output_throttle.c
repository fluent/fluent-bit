/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <stdint.h>

#include <fluent-bit/flb_output_throttle.h>
#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_output_thread.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_engine_dispatch.h>
#include <fluent-bit/flb_task.h>

#include "flb_tests_internal.h"

static void test_deadline_and_generation(void)
{
    uint64_t token;
    struct flb_output_throttle gate;
    struct flb_output_throttle_snapshot snapshot;

    TEST_CHECK(flb_output_throttle_init(&gate, FLB_TRUE, 1000, 60000) == 0);
    TEST_CHECK(flb_output_throttle_admit(&gate, 100, &token) == FLB_TRUE);
    TEST_CHECK(token == 0);
    TEST_CHECK(flb_output_throttle_publish(&gate, 100, FLB_TRUE, 5000, 0) == 5100);
    TEST_CHECK(flb_output_throttle_admit(&gate, 5099, &token) == FLB_FALSE);
    TEST_CHECK(flb_output_throttle_admit(&gate, 5100, &token) == FLB_TRUE);
    TEST_CHECK(token == 1);

    flb_output_throttle_success(&gate, 5101, token);
    flb_output_throttle_snapshot(&gate, &snapshot);
    TEST_CHECK(snapshot.consecutive_rounds == 0);
    flb_output_throttle_destroy(&gate);
}

static void test_publication_rules(void)
{
    uint64_t token;
    struct flb_output_throttle gate;
    struct flb_output_throttle_snapshot snapshot;

    TEST_CHECK(flb_output_throttle_init(&gate, FLB_TRUE, 1000, 2000) == 0);
    TEST_CHECK(flb_output_throttle_publish(&gate, 0, FLB_TRUE, 600000, 0) == 600000);
    TEST_CHECK(flb_output_throttle_publish(&gate, 100, FLB_TRUE, 10, 0) == 600000);
    flb_output_throttle_snapshot(&gate, &snapshot);
    TEST_CHECK(snapshot.consecutive_rounds == 1);
    TEST_CHECK(snapshot.events == 2);

    TEST_CHECK(flb_output_throttle_admit(&gate, 600000, &token) == FLB_TRUE);
    TEST_CHECK(flb_output_throttle_publish(&gate, 600000, FLB_FALSE, 0, 1000) == 602000);
    flb_output_throttle_snapshot(&gate, &snapshot);
    TEST_CHECK(snapshot.consecutive_rounds == 2);
    flb_output_throttle_destroy(&gate);
}

static void test_stale_success_and_saturation(void)
{
    uint64_t old_token;
    struct flb_output_throttle gate;
    struct flb_output_throttle_snapshot snapshot;

    TEST_CHECK(flb_output_throttle_init(&gate, FLB_TRUE, 1000, 60000) == 0);
    TEST_CHECK(flb_output_throttle_admit(&gate, 0, &old_token) == FLB_TRUE);
    TEST_CHECK(flb_output_throttle_publish(&gate, 1, FLB_TRUE, UINT64_MAX, 0) == UINT64_MAX);
    flb_output_throttle_success(&gate, 2000, old_token);
    flb_output_throttle_snapshot(&gate, &snapshot);
    TEST_CHECK(snapshot.state == FLB_OUTPUT_THROTTLE_COOLDOWN);
    TEST_CHECK(snapshot.consecutive_rounds == 1);
    flb_output_throttle_destroy(&gate);
}

static void test_disabled_and_stopping(void)
{
    uint64_t token;
    struct flb_output_throttle gate;

    TEST_CHECK(flb_output_throttle_init(&gate, FLB_FALSE, 1000, 60000) == 0);
    TEST_CHECK(flb_output_throttle_publish(&gate, 0, FLB_TRUE, 5000, 0) == 0);
    TEST_CHECK(flb_output_throttle_admit(&gate, 1, &token) == FLB_TRUE);
    flb_output_throttle_stop(&gate);
    TEST_CHECK(flb_output_throttle_admit(&gate, UINT64_MAX, &token) == FLB_FALSE);
    flb_output_throttle_destroy(&gate);

    TEST_CHECK(flb_output_throttle_init(&gate, FLB_TRUE, 0, 1) == -1);
    TEST_CHECK(flb_output_throttle_init(&gate, FLB_TRUE, 2, 1) == -1);
}

static void test_result_encoding(void)
{
    uint32_t encoded;

    encoded = FLB_TASK_SET(FLB_THROTTLE, 0x3fff, 0x3fff);
    TEST_CHECK(FLB_TASK_RET(encoded) == FLB_THROTTLE);
    TEST_CHECK(FLB_TASK_ID(encoded) == 0x3fff);
    TEST_CHECK(FLB_TASK_OUT(encoded) == 0x3fff);
    TEST_CHECK(FLB_ERROR == 0);
    TEST_CHECK(FLB_OK == 1);
    TEST_CHECK(FLB_RETRY == 2);
}

static void test_output_properties(void)
{
    struct flb_config *config;
    struct flb_output_instance output;

    config = flb_config_init();
    TEST_CHECK(config != NULL);
    if (config == NULL) {
        return;
    }

    memset(&output, 0, sizeof(struct flb_output_instance));
    output.config = config;
    TEST_CHECK(flb_output_throttle_init(&output.throttle,
                                        FLB_FALSE, 1000, 60000) == 0);

    TEST_CHECK(flb_output_set_property(&output, "throttle", "true") == 0);
    TEST_CHECK(output.throttle.enabled == FLB_TRUE);
    TEST_CHECK(flb_output_set_property(&output, "throttle.base", "120") == 0);
    TEST_CHECK(flb_output_set_property(&output, "throttle.cap", "180") == 0);
    TEST_CHECK(output.throttle.base_ms == 120000);
    TEST_CHECK(output.throttle.cap_ms == 180000);

    TEST_CHECK(flb_output_set_property(&output, "throttle.base", "0") == -1);
    TEST_CHECK(flb_output_set_property(&output, "throttle.base", "1s") == -1);
    TEST_CHECK(flb_output_set_property(&output, "throttle.cap", "-1") == -1);

    flb_output_throttle_destroy(&output.throttle);
    flb_config_exit(config);
}

static void init_route_fixture(struct flb_task *task,
                               struct flb_task_route *route,
                               struct flb_output_instance *output)
{
    memset(task, 0, sizeof(struct flb_task));
    memset(route, 0, sizeof(struct flb_task_route));
    memset(output, 0, sizeof(struct flb_output_instance));

    mk_list_init(&task->routes);
    mk_list_init(&task->retries);
    mk_list_init(&output->throttle_deferred_routes);
    route->task = task;
    route->out = output;
    route->dispatch_state = FLB_TASK_ROUTE_DISPATCH_UNQUEUED;
    mk_list_init(&route->_deferred_head);
    mk_list_add(&route->_head, &task->routes);
}

static void test_deferred_route_ownership(void)
{
    struct flb_task task;
    struct flb_task_route route;
    struct flb_output_instance output;

    init_route_fixture(&task, &route, &output);

    TEST_CHECK(flb_task_route_defer(&task, &output, FLB_FALSE) == 0);
    TEST_CHECK(task.users == 0);
    TEST_CHECK(task.deferred_routes == 1);
    TEST_CHECK(output.throttle_deferred_count == 1);
    TEST_CHECK(route.dispatch_state == FLB_TASK_ROUTE_DISPATCH_DEFERRED);
    TEST_CHECK(flb_task_is_releasable(&task) == FLB_FALSE);

    /* A fresh duplicate is idempotent and does not gain another owner. */
    TEST_CHECK(flb_task_route_defer(&task, &output, FLB_FALSE) == 0);
    TEST_CHECK(task.deferred_routes == 1);
    TEST_CHECK(output.throttle_deferred_count == 1);

    TEST_CHECK(flb_task_route_resume(&task, &output) == 0);
    TEST_CHECK(task.users == 1);
    TEST_CHECK(task.deferred_routes == 0);
    TEST_CHECK(output.throttle_deferred_count == 0);
    TEST_CHECK(route.dispatch_state == FLB_TASK_ROUTE_DISPATCH_QUEUED);
    TEST_CHECK(flb_task_is_releasable(&task) == FLB_FALSE);

    /* Queued -> deferred transfers, rather than duplicates, its owner. */
    TEST_CHECK(flb_task_route_defer(&task, &output, FLB_TRUE) == 0);
    TEST_CHECK(task.users == 0);
    TEST_CHECK(task.deferred_routes == 1);
    TEST_CHECK(flb_task_route_defer(&task, &output, FLB_TRUE) == -1);
    TEST_CHECK(task.users == 0);
    TEST_CHECK(task.deferred_routes == 1);

    TEST_CHECK(flb_task_route_cancel_deferred(&task, &output) == 0);
    TEST_CHECK(task.deferred_routes == 0);
    TEST_CHECK(output.throttle_deferred_count == 0);
    TEST_CHECK(route.dispatch_state == FLB_TASK_ROUTE_DISPATCH_UNQUEUED);
    TEST_CHECK(flb_task_is_releasable(&task) == FLB_TRUE);
}

static void test_dispatch_state_and_envelope(void)
{
    uint64_t before;
    uint64_t after;
    struct flb_task task;
    struct flb_task_route route;
    struct flb_output_instance output;
    struct flb_output_dispatch *dispatch;

    init_route_fixture(&task, &route, &output);

    TEST_CHECK(flb_task_route_queue(&task, &output) == 0);
    TEST_CHECK(task.users == 1);
    TEST_CHECK(output.dispatches_inflight == 1);
    TEST_CHECK(route.dispatch_state == FLB_TASK_ROUTE_DISPATCH_QUEUED);
    TEST_CHECK(flb_task_route_queue(&task, &output) == -1);

    dispatch = flb_output_dispatch_create(&task, &output, NULL);
    TEST_CHECK(dispatch != NULL);
    if (dispatch != NULL) {
        TEST_CHECK(dispatch->magic == FLB_OUTPUT_DISPATCH_MAGIC);
        TEST_CHECK(dispatch->type == FLB_OUTPUT_DISPATCH_TASK);
        TEST_CHECK(dispatch->task == &task);
        TEST_CHECK(dispatch->out == &output);
        flb_output_dispatch_destroy(dispatch);
    }

    TEST_CHECK(flb_task_route_complete(&task, &output) == 0);
    TEST_CHECK(route.dispatch_state == FLB_TASK_ROUTE_DISPATCH_COMPLETING);
    TEST_CHECK(flb_task_route_unqueue(&task, &output) == 0);
    TEST_CHECK(route.dispatch_state == FLB_TASK_ROUTE_DISPATCH_UNQUEUED);
    TEST_CHECK(output.dispatches_inflight == 0);
    flb_task_users_dec(&task, FLB_FALSE);
    TEST_CHECK(flb_task_is_releasable(&task) == FLB_TRUE);

    before = flb_output_throttle_now_ms();
    after = flb_output_throttle_now_ms();
    TEST_CHECK(after >= before);
}

static void test_dispatch_result_fallback_queue(void)
{
    struct flb_config config;
    struct flb_config other_config;
    struct flb_task task;
    struct flb_task_route route;
    struct flb_output_instance output;
    struct flb_out_thread_instance thread;
    struct flb_output_dispatch *dispatch;
    struct flb_output_dispatch *popped;

    memset(&config, 0, sizeof(struct flb_config));
    memset(&other_config, 0, sizeof(struct flb_config));
    memset(&thread, 0, sizeof(struct flb_out_thread_instance));
    init_route_fixture(&task, &route, &output);
    output.log_level = FLB_LOG_OFF;
    output.ch_events[1] = -1;
    thread.ins = &output;
    thread.ch_thread_events[1] = -1;

    dispatch = flb_output_dispatch_create(&task, &output, &config);
    TEST_CHECK(dispatch != NULL);
    if (dispatch == NULL) {
        return;
    }

    TEST_CHECK(flb_output_thread_post_dispatch_result(
                   &thread, dispatch, FLB_OUTPUT_DEFERRED) == 1);
    TEST_CHECK(flb_output_thread_result_fallback_pop(&other_config) == NULL);
    popped = flb_output_thread_result_fallback_pop(&config);
    TEST_CHECK(popped == dispatch);
    if (popped != NULL) {
        TEST_CHECK(popped->result == FLB_OUTPUT_DEFERRED);
        flb_output_dispatch_destroy(popped);
    }

    dispatch = flb_output_dispatch_create(&task, &output, &config);
    TEST_CHECK(dispatch != NULL);
    if (dispatch == NULL) {
        return;
    }
    TEST_CHECK(flb_task_route_queue(&task, &output) == 0);
    TEST_CHECK(task.users == 1);
    TEST_CHECK(output.dispatches_inflight == 1);
    TEST_CHECK(flb_output_thread_post_dispatch_result(
                   &thread, dispatch, FLB_ERROR) == 1);
    flb_output_thread_result_fallback_remove(&output);
    TEST_CHECK(flb_output_thread_result_fallback_pop(&config) == NULL);
    TEST_CHECK(task.users == 0);
    TEST_CHECK(output.dispatches_inflight == 0);
    TEST_CHECK(route.dispatch_state == FLB_TASK_ROUTE_DISPATCH_UNQUEUED);
}

static void test_advisory_dispatch_deferral(void)
{
    struct flb_task task;
    struct flb_task_route route;
    struct flb_output_instance output;

    init_route_fixture(&task, &route, &output);
    TEST_CHECK(flb_output_throttle_init(&output.throttle,
                                        FLB_TRUE, 1000, 60000) == 0);
    flb_output_throttle_publish(&output.throttle,
                                flb_output_throttle_now_ms(),
                                FLB_TRUE, 60000, 0);

    TEST_CHECK(flb_output_task_flush(&task, &output, NULL) ==
               FLB_OUTPUT_DEFERRED);
    TEST_CHECK(task.users == 0);
    TEST_CHECK(task.deferred_routes == 1);
    TEST_CHECK(route.dispatch_state == FLB_TASK_ROUTE_DISPATCH_DEFERRED);

    TEST_CHECK(flb_task_route_cancel_deferred(&task, &output) == 0);
    flb_output_throttle_destroy(&output.throttle);
}

static void test_flush_completion_publication(void)
{
    int ret;
    struct flb_output_flush flush;
    struct flb_output_instance output;
    struct flb_output_throttle_snapshot snapshot;

    memset(&flush, 0, sizeof(struct flb_output_flush));
    memset(&output, 0, sizeof(struct flb_output_instance));
    flush.o_ins = &output;

    TEST_CHECK(flb_output_throttle_init(&output.throttle,
                                        FLB_FALSE, 1000, 60000) == 0);
    ret = flb_output_throttle_complete(&flush, FLB_THROTTLE);
    TEST_CHECK(ret == FLB_RETRY);
    flb_output_throttle_snapshot(&output.throttle, &snapshot);
    TEST_CHECK(snapshot.events == 0);
    flb_output_throttle_destroy(&output.throttle);

    TEST_CHECK(flb_output_throttle_init(&output.throttle,
                                        FLB_TRUE, 1000, 60000) == 0);
    flush.retry_after_present = FLB_TRUE;
    flush.retry_after_ms = 120000;
    ret = flb_output_throttle_complete(&flush, FLB_THROTTLE);
    TEST_CHECK(ret == FLB_THROTTLE);
    flb_output_throttle_snapshot(&output.throttle, &snapshot);
    TEST_CHECK(snapshot.state == FLB_OUTPUT_THROTTLE_COOLDOWN);
    TEST_CHECK(snapshot.events == 1);
    TEST_CHECK(snapshot.until_ms >= flb_output_throttle_now_ms() + 119000);

    flush.admission_generation = snapshot.generation;
    ret = flb_output_throttle_complete(&flush, FLB_OK);
    TEST_CHECK(ret == FLB_OK);
    flb_output_throttle_snapshot(&output.throttle, &snapshot);
    TEST_CHECK(snapshot.consecutive_rounds == 1);
    flb_output_throttle_destroy(&output.throttle);
}

static void test_due_retry_defers_without_attempt(void)
{
    struct flb_task task;
    struct flb_task_retry retry;
    struct flb_task_route route;
    struct flb_output_instance output;

    init_route_fixture(&task, &route, &output);
    memset(&retry, 0, sizeof(struct flb_task_retry));
    retry.attempts = 3;
    retry.parent = &task;
    retry.o_ins = &output;

    TEST_CHECK(flb_output_throttle_init(&output.throttle,
                                        FLB_TRUE, 1000, 60000) == 0);
    flb_output_throttle_publish(&output.throttle,
                                flb_output_throttle_now_ms(),
                                FLB_TRUE, 60000, 0);

    TEST_CHECK(flb_engine_dispatch_retry(&retry, NULL) == 0);
    TEST_CHECK(retry.attempts == 3);
    TEST_CHECK(route.dispatch_state == FLB_TASK_ROUTE_DISPATCH_DEFERRED);
    TEST_CHECK(task.deferred_routes == 1);
    TEST_CHECK(output.throttle_wakeup_pending == FLB_TRUE);

    TEST_CHECK(flb_task_route_cancel_deferred(&task, &output) == 0);
    flb_output_throttle_wakeup_cancel(&output);

    TEST_CHECK(flb_task_route_queue(&task, &output) == 0);
    TEST_CHECK(flb_engine_dispatch_retry(&retry, NULL) == 0);
    TEST_CHECK(retry.attempts == 3);
    TEST_CHECK(task.users == 0);
    TEST_CHECK(route.dispatch_state == FLB_TASK_ROUTE_DISPATCH_DEFERRED);
    TEST_CHECK(output.dispatches_inflight == 0);

    TEST_CHECK(flb_task_route_cancel_deferred(&task, &output) == 0);
    flb_output_throttle_wakeup_cancel(&output);
    flb_output_throttle_destroy(&output.throttle);
}

static void test_metrics_union_duration(void)
{
    int ret;
    double value;
    char *labels[] = {"test.0"};
    struct flb_output_instance output;

    memset(&output, 0, sizeof(struct flb_output_instance));
    snprintf(output.name, sizeof(output.name), "test.0");
    output.cmt = cmt_create();
    TEST_CHECK(output.cmt != NULL);
    if (output.cmt == NULL) {
        return;
    }

    output.cmt_throttle_events = cmt_counter_create(output.cmt, "fluentbit",
                                                     "output",
                                                     "throttle_events_total",
                                                     "test", 1,
                                                     (char *[]) {"name"});
    output.cmt_throttle_active = cmt_gauge_create(output.cmt, "fluentbit",
                                                   "output", "throttle_active",
                                                   "test", 1,
                                                   (char *[]) {"name"});
    output.cmt_throttle_remaining = cmt_gauge_create(output.cmt, "fluentbit",
                                                      "output",
                                                      "throttle_remaining_seconds",
                                                      "test", 1,
                                                      (char *[]) {"name"});
    output.cmt_throttle_deferred_routes = cmt_gauge_create(output.cmt,
                                                      "fluentbit", "output",
                                                      "throttle_deferred_routes",
                                                      "test", 1,
                                                      (char *[]) {"name"});
    output.cmt_throttle_duration = cmt_counter_create(output.cmt, "fluentbit",
                                                      "output",
                                                      "throttle_duration_seconds_total",
                                                      "test", 1,
                                                      (char *[]) {"name"});
    TEST_CHECK(output.cmt_throttle_events != NULL);
    TEST_CHECK(output.cmt_throttle_active != NULL);
    TEST_CHECK(output.cmt_throttle_remaining != NULL);
    TEST_CHECK(output.cmt_throttle_deferred_routes != NULL);
    TEST_CHECK(output.cmt_throttle_duration != NULL);
    if (output.cmt_throttle_events == NULL ||
        output.cmt_throttle_active == NULL ||
        output.cmt_throttle_remaining == NULL ||
        output.cmt_throttle_deferred_routes == NULL ||
        output.cmt_throttle_duration == NULL) {
        cmt_destroy(output.cmt);
        return;
    }

    TEST_CHECK(flb_output_throttle_init(&output.throttle,
                                        FLB_TRUE, 1000, 60000) == 0);
    flb_output_throttle_publish(&output.throttle, 1000,
                                FLB_TRUE, 5000, 0);
    flb_output_throttle_metrics_update(&output, 2000);

    ret = cmt_gauge_get_val(output.cmt_throttle_active, 1, labels, &value);
    TEST_CHECK(ret == 0);
    TEST_CHECK(value == 1.0);
    ret = cmt_gauge_get_val(output.cmt_throttle_remaining, 1, labels, &value);
    TEST_CHECK(ret == 0);
    TEST_CHECK(value == 4.0);

    /* The extension adds only newly elapsed closed-gate time. */
    flb_output_throttle_publish(&output.throttle, 2000,
                                FLB_TRUE, 10000, 0);
    flb_output_throttle_metrics_update(&output, 3000);
    flb_output_throttle_metrics_update(&output, 12000);
    ret = cmt_counter_get_val(output.cmt_throttle_duration, 1, labels, &value);
    TEST_CHECK(ret == 0);
    TEST_CHECK(value == 11.0);

    ret = cmt_gauge_get_val(output.cmt_throttle_active, 1, labels, &value);
    TEST_CHECK(ret == 0);
    TEST_CHECK(value == 0.0);
    ret = cmt_gauge_get_val(output.cmt_throttle_remaining, 1, labels, &value);
    TEST_CHECK(ret == 0);
    TEST_CHECK(value == 0.0);

    flb_output_throttle_destroy(&output.throttle);
    cmt_destroy(output.cmt);
}

TEST_LIST = {
    {"deadline_and_generation", test_deadline_and_generation},
    {"publication_rules", test_publication_rules},
    {"stale_success_and_saturation", test_stale_success_and_saturation},
    {"disabled_and_stopping", test_disabled_and_stopping},
    {"result_encoding", test_result_encoding},
    {"output_properties", test_output_properties},
    {"deferred_route_ownership", test_deferred_route_ownership},
    {"dispatch_state_and_envelope", test_dispatch_state_and_envelope},
    {"dispatch_result_fallback_queue", test_dispatch_result_fallback_queue},
    {"advisory_dispatch_deferral", test_advisory_dispatch_deferral},
    {"flush_completion_publication", test_flush_completion_publication},
    {"due_retry_defers_without_attempt", test_due_retry_defers_without_attempt},
    {"metrics_union_duration", test_metrics_union_duration},
    {0}
};
