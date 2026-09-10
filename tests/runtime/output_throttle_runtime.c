/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <stdint.h>
#include <string.h>

#include <fluent-bit.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_time.h>
#include <chunkio/cio_utils.h>

#include "flb_tests_runtime.h"
#include "../include/flb_tests_tmpdir.h"

#define SCRIPT_CAPACITY 64
#define TEST_TIMEOUT_MS 5000
#define TEST_COOLDOWN_MS 1200

static int stop_engine(flb_ctx_t *ctx)
{
    uint64_t deadline;
    int ret;

    /* On macOS flb_stop() cancels an active pipeline before its TLS cleanup. */
    ret = flb_engine_exit(ctx->config);
    TEST_CHECK_(ret >= 0, "requesting graceful engine shutdown");

    deadline = flb_output_throttle_now_ms() + TEST_TIMEOUT_MS;
    while (ctx->status == FLB_LIB_OK && flb_output_throttle_now_ms() < deadline) {
        flb_time_msleep(10);
    }
    TEST_CHECK_(ctx->status != FLB_LIB_OK,
                "engine did not stop within %d ms", TEST_TIMEOUT_MS);

    return flb_stop(ctx);
}

struct scripted_output {
    pthread_mutex_t lock;
    pthread_cond_t condition;
    uint64_t blocked_calls;
    uint64_t released_calls;
    int outcomes[3];
    uint64_t hints[3];
    size_t outcome_count;
    size_t calls;
    uint64_t timestamps[SCRIPT_CAPACITY];
    uint64_t generations[SCRIPT_CAPACITY];
    char tag_markers[SCRIPT_CAPACITY];
};

static void scripted_output_init(struct scripted_output *script,
                                 int first_outcome)
{
    memset(script, 0, sizeof(struct scripted_output));
    pthread_mutex_init(&script->lock, NULL);
    pthread_cond_init(&script->condition, NULL);
    script->outcomes[0] = first_outcome;
    script->outcomes[1] = FLB_OK;
    script->outcomes[2] = FLB_OK;
    script->hints[0] = TEST_COOLDOWN_MS;
    script->outcome_count = 3;
}

static void scripted_output_destroy(struct scripted_output *script)
{
    pthread_cond_destroy(&script->condition);
    pthread_mutex_destroy(&script->lock);
}

static int scripted_init(struct flb_output_instance *ins,
                         struct flb_config *config, void *data)
{
    (void) config;
    flb_output_set_context(ins, data);
    return 0;
}

static void scripted_flush(struct flb_event_chunk *event_chunk,
                           struct flb_output_flush *out_flush,
                           struct flb_input_instance *i_ins,
                           void *out_context,
                           struct flb_config *config)
{
    int outcome;
    size_t index;
    struct scripted_output *script;

    (void) event_chunk;
    (void) i_ins;
    (void) config;

    script = out_context;
    pthread_mutex_lock(&script->lock);
    index = script->calls;
    if (index < SCRIPT_CAPACITY) {
        script->timestamps[index] = flb_output_throttle_now_ms();
        script->generations[index] = out_flush->admission_generation;
        script->tag_markers[index] = event_chunk->tag[0];
    }
    script->calls++;
    pthread_cond_broadcast(&script->condition);

    while (index < 64 &&
           (script->blocked_calls & (UINT64_C(1) << index)) != 0 &&
           (script->released_calls & (UINT64_C(1) << index)) == 0) {
        pthread_cond_wait(&script->condition, &script->lock);
    }

    if (index < script->outcome_count) {
        outcome = script->outcomes[index];
    }
    else {
        outcome = FLB_OK;
    }
    pthread_mutex_unlock(&script->lock);

    if (outcome == FLB_THROTTLE) {
        flb_output_set_retry_after(out_flush, script->hints[index]);
    }
    FLB_OUTPUT_RETURN(outcome);
}

static struct flb_output_plugin scripted_plugin = {
    .name = "m6_scripted",
    .description = "M6 deterministic throttle output",
    .cb_init = scripted_init,
    .cb_flush = scripted_flush,
    .flags = 0
};

static int register_scripted_plugin(flb_ctx_t *ctx, const char *name, int flags)
{
    struct flb_output_plugin *plugin;

    plugin = flb_malloc(sizeof(struct flb_output_plugin));
    if (plugin == NULL) {
        return -1;
    }

    memcpy(plugin, &scripted_plugin, sizeof(struct flb_output_plugin));
    plugin->name = (char *) name;
    plugin->flags = flags;
    mk_list_add(&plugin->_head, &ctx->config->out_plugins);
    return 0;
}

static size_t scripted_calls(struct scripted_output *script)
{
    size_t calls;

    pthread_mutex_lock(&script->lock);
    calls = script->calls;
    pthread_mutex_unlock(&script->lock);
    return calls;
}

static uint64_t scripted_timestamp(struct scripted_output *script, size_t index)
{
    uint64_t value;

    pthread_mutex_lock(&script->lock);
    value = script->timestamps[index];
    pthread_mutex_unlock(&script->lock);
    return value;
}

static uint64_t scripted_generation(struct scripted_output *script, size_t index)
{
    uint64_t value;

    pthread_mutex_lock(&script->lock);
    value = script->generations[index];
    pthread_mutex_unlock(&script->lock);
    return value;
}

static char scripted_tag_marker(struct scripted_output *script, size_t index)
{
    char value;

    pthread_mutex_lock(&script->lock);
    value = script->tag_markers[index];
    pthread_mutex_unlock(&script->lock);
    return value;
}

static int wait_for_calls(struct scripted_output *script, size_t expected,
                          int timeout_ms)
{
    uint64_t deadline;

    deadline = flb_output_throttle_now_ms() + timeout_ms;
    while (flb_output_throttle_now_ms() < deadline) {
        if (scripted_calls(script) >= expected) {
            return 0;
        }
        flb_time_msleep(10);
    }

    return -1;
}

static int wait_for_gate_events(struct flb_output_instance *output,
                                uint64_t expected, int timeout_ms)
{
    uint64_t deadline;
    struct flb_output_throttle_snapshot snapshot;

    deadline = flb_output_throttle_now_ms() + timeout_ms;
    while (flb_output_throttle_now_ms() < deadline) {
        flb_output_throttle_snapshot(&output->throttle, &snapshot);
        if (snapshot.events >= expected) {
            return 0;
        }
        flb_time_msleep(10);
    }

    return -1;
}

static void release_call(struct scripted_output *script, size_t index)
{
    pthread_mutex_lock(&script->lock);
    script->released_calls |= UINT64_C(1) << index;
    pthread_cond_broadcast(&script->condition);
    pthread_mutex_unlock(&script->lock);
}

static double counter_value(struct cmt_counter *counter, const char *name)
{
    double value;
    char *labels[] = {(char *) name};

    if (cmt_counter_get_val(counter, 1, labels, &value) != 0) {
        return -1;
    }
    return value;
}

static double gauge_value(struct cmt_gauge *gauge, const char *name)
{
    double value;
    char *labels[] = {(char *) name};

    if (cmt_gauge_get_val(gauge, 1, labels, &value) != 0) {
        return -1;
    }
    return value;
}

static int wait_for_deferred_routes(struct flb_output_instance *output,
                                    double expected, int timeout_ms)
{
    uint64_t deadline;

    deadline = flb_output_throttle_now_ms() + timeout_ms;
    while (flb_output_throttle_now_ms() < deadline) {
        if (gauge_value(output->cmt_throttle_deferred_routes,
                        flb_output_name(output)) >= expected) {
            return 0;
        }
        flb_time_msleep(10);
    }

    return -1;
}

static void run_fanout_case(int workers, int flags)
{
    int input_id;
    int output_a_id;
    int output_b_id;
    int ret;
    uint64_t first_admission;
    char workers_buffer[16];
    struct flb_output_instance *output_a;
    struct scripted_output output_a_script;
    struct scripted_output output_b_script;
    flb_ctx_t *ctx;
    const char *record = "[1, {\"m6\":true}]";

    scripted_output_init(&output_a_script, FLB_THROTTLE);
    scripted_output_init(&output_b_script, FLB_OK);

    ctx = flb_create();
    TEST_CHECK(ctx != NULL);
    if (ctx == NULL) {
        scripted_output_destroy(&output_a_script);
        scripted_output_destroy(&output_b_script);
        return;
    }

    TEST_CHECK(register_scripted_plugin(ctx, "m6_scripted", flags) == 0);
    TEST_CHECK(register_scripted_plugin(ctx, "m6_healthy", 0) == 0);
    input_id = flb_input(ctx, "lib", NULL);
    TEST_CHECK(input_id >= 0);
    flb_input_set(ctx, input_id, "tag", "m6", NULL);

    output_a_id = flb_output(ctx, "m6_scripted",
                             (struct flb_lib_out_cb *) &output_a_script);
    output_b_id = flb_output(ctx, "m6_healthy",
                             (struct flb_lib_out_cb *) &output_b_script);
    TEST_CHECK(output_a_id >= 0);
    TEST_CHECK(output_b_id >= 0);
    flb_output_set(ctx, output_a_id, "match", "m6", "throttle", "true",
                   "throttle.base", "1", "throttle.cap", "1",
                   "retry_limit", "3", NULL);
    flb_output_set(ctx, output_b_id, "match", "m6", NULL);
    if (workers > 0) {
        snprintf(workers_buffer, sizeof(workers_buffer), "%d", workers);
        flb_output_set(ctx, output_a_id, "workers", workers_buffer, NULL);
    }
    flb_service_set(ctx, "Flush", "0.1", "Grace", "1",
                    "Log_Level", "error", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);
    if (ret != 0) {
        flb_destroy(ctx);
        scripted_output_destroy(&output_a_script);
        scripted_output_destroy(&output_b_script);
        return;
    }

    TEST_CHECK(flb_lib_push(ctx, input_id, record, strlen(record)) > 0);
    TEST_CHECK(wait_for_calls(&output_a_script, 1, TEST_TIMEOUT_MS) == 0);
    TEST_CHECK(wait_for_calls(&output_b_script, 1, TEST_TIMEOUT_MS) == 0);
    first_admission = scripted_timestamp(&output_a_script, 0);

    TEST_CHECK(flb_lib_push(ctx, input_id, record, strlen(record)) > 0);
    ret = wait_for_calls(&output_b_script, 2, 1000);
    if (ret != 0) {
        fprintf(stderr, "healthy output stalled: workers=%d flags=%d calls=%zu\n",
                workers, flags, scripted_calls(&output_b_script));
    }
    TEST_CHECK(ret == 0);
    flb_time_msleep(100);
    TEST_CHECK(scripted_calls(&output_a_script) == 1);

    output_a = flb_output_get_instance(ctx->config, output_a_id);
    TEST_CHECK(output_a != NULL);
    if (output_a != NULL) {
        TEST_CHECK(counter_value(output_a->cmt_throttle_events,
                                 flb_output_name(output_a)) == 1.0);
        TEST_CHECK(gauge_value(output_a->cmt_throttle_active,
                               flb_output_name(output_a)) == 1.0);
        TEST_CHECK(gauge_value(output_a->cmt_throttle_deferred_routes,
                               flb_output_name(output_a)) >= 1.0);
        TEST_CHECK(counter_value(output_a->cmt_retries,
                                 flb_output_name(output_a)) == 0.0);
    }

    TEST_CHECK(wait_for_calls(&output_a_script, 2, TEST_TIMEOUT_MS) == 0);
    TEST_CHECK(scripted_timestamp(&output_a_script, 1) >=
               first_admission + TEST_COOLDOWN_MS);
    TEST_CHECK(scripted_generation(&output_a_script, 1) >
               scripted_generation(&output_a_script, 0));

    if (output_a != NULL) {
        flb_time_msleep(50);
        TEST_CHECK(gauge_value(output_a->cmt_throttle_active,
                               flb_output_name(output_a)) == 0.0);
        TEST_CHECK(gauge_value(output_a->cmt_throttle_remaining,
                               flb_output_name(output_a)) == 0.0);
        TEST_CHECK(counter_value(output_a->cmt_throttle_duration,
                                 flb_output_name(output_a)) >= 1.0);
        TEST_CHECK(counter_value(output_a->cmt_retries,
                                 flb_output_name(output_a)) == 0.0);
    }

    stop_engine(ctx);
    flb_destroy(ctx);
    scripted_output_destroy(&output_a_script);
    scripted_output_destroy(&output_b_script);
}

static void test_fanout_and_modes(void)
{
    run_fanout_case(0, 0);
    run_fanout_case(1, 0);
    run_fanout_case(4, 0);
    run_fanout_case(0, FLB_OUTPUT_SYNCHRONOUS);
    run_fanout_case(0, FLB_OUTPUT_NO_MULTIPLEX);
}

static void test_inflight_before_publication(void)
{
    int input_id;
    int output_id;
    int ret;
    struct scripted_output script;
    flb_ctx_t *ctx;
    const char *record = "[1, {\"barrier\":true}]";

    scripted_output_init(&script, FLB_THROTTLE);
    script.blocked_calls = UINT64_C(1);
    ctx = flb_create();
    TEST_CHECK(ctx != NULL);
    if (ctx == NULL) {
        scripted_output_destroy(&script);
        return;
    }

    TEST_CHECK(register_scripted_plugin(ctx, "m6_scripted", 0) == 0);
    input_id = flb_input(ctx, "lib", NULL);
    flb_input_set(ctx, input_id, "tag", "barrier", NULL);
    output_id = flb_output(ctx, "m6_scripted",
                           (struct flb_lib_out_cb *) &script);
    flb_output_set(ctx, output_id, "match", "barrier", "workers", "4",
                   "throttle", "true", "throttle.base", "1",
                   "throttle.cap", "1", "retry_limit", "3", NULL);
    flb_service_set(ctx, "Flush", "0.1", "Grace", "1",
                    "Log_Level", "error", NULL);
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    TEST_CHECK(flb_lib_push(ctx, input_id, record, strlen(record)) > 0);
    TEST_CHECK(wait_for_calls(&script, 1, TEST_TIMEOUT_MS) == 0);
    TEST_CHECK(flb_lib_push(ctx, input_id, record, strlen(record)) > 0);
    TEST_CHECK(wait_for_calls(&script, 2, TEST_TIMEOUT_MS) == 0);
    TEST_CHECK(scripted_generation(&script, 0) == scripted_generation(&script, 1));

    release_call(&script, 0);

    TEST_CHECK(flb_lib_push(ctx, input_id, record, strlen(record)) > 0);
    flb_time_msleep(200);
    TEST_CHECK(scripted_calls(&script) == 2);
    TEST_CHECK(wait_for_calls(&script, 3, TEST_TIMEOUT_MS) == 0);
    TEST_CHECK(scripted_timestamp(&script, 2) >=
               scripted_timestamp(&script, 0) + TEST_COOLDOWN_MS);

    stop_engine(ctx);
    flb_destroy(ctx);
    scripted_output_destroy(&script);
}

static void test_extended_deadline_rechecks_old_timer(void)
{
    int input_id;
    int output_id;
    int ret;
    uint64_t first_release;
    uint64_t second_release;
    struct flb_output_instance *output;
    struct scripted_output script;
    flb_ctx_t *ctx;
    const char *record = "[1, {\"extension\":true}]";

    scripted_output_init(&script, FLB_THROTTLE);
    script.outcomes[1] = FLB_THROTTLE;
    script.hints[0] = TEST_COOLDOWN_MS;
    script.hints[1] = 2000;
    script.blocked_calls = UINT64_C(3);
    ctx = flb_create();
    TEST_CHECK(ctx != NULL);
    if (ctx == NULL) {
        scripted_output_destroy(&script);
        return;
    }

    TEST_CHECK(register_scripted_plugin(ctx, "m6_scripted", 0) == 0);
    input_id = flb_input(ctx, "lib", NULL);
    flb_input_set(ctx, input_id, "tag", "extension", NULL);
    output_id = flb_output(ctx, "m6_scripted",
                           (struct flb_lib_out_cb *) &script);
    flb_output_set(ctx, output_id, "match", "extension", "workers", "4",
                   "throttle", "true", "throttle.base", "1",
                   "throttle.cap", "1", "retry_limit", "3", NULL);
    flb_service_set(ctx, "Flush", "0.1", "Grace", "1",
                    "Log_Level", "error", NULL);
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    TEST_CHECK(flb_lib_push(ctx, input_id, record, strlen(record)) > 0);
    TEST_CHECK(wait_for_calls(&script, 1, TEST_TIMEOUT_MS) == 0);
    TEST_CHECK(flb_lib_push(ctx, input_id, record, strlen(record)) > 0);
    TEST_CHECK(wait_for_calls(&script, 2, TEST_TIMEOUT_MS) == 0);

    output = flb_output_get_instance(ctx->config, output_id);
    TEST_CHECK(output != NULL);

    first_release = flb_output_throttle_now_ms();
    release_call(&script, 0);
    if (output != NULL) {
        TEST_CHECK(wait_for_gate_events(output, 1, TEST_TIMEOUT_MS) == 0);
    }
    flb_time_msleep(300);
    second_release = flb_output_throttle_now_ms();
    release_call(&script, 1);
    TEST_CHECK(flb_lib_push(ctx, input_id, record, strlen(record)) > 0);

    while (flb_output_throttle_now_ms() < first_release + 1400) {
        flb_time_msleep(10);
    }
    TEST_CHECK(scripted_calls(&script) == 2);
    TEST_CHECK(wait_for_calls(&script, 3, TEST_TIMEOUT_MS) == 0);
    TEST_CHECK(scripted_timestamp(&script, 2) >= second_release + script.hints[1]);

    stop_engine(ctx);
    flb_destroy(ctx);
    scripted_output_destroy(&script);
}

static void test_repeated_throttle_does_not_spend_retry_limit(void)
{
    int input_id;
    int output_id;
    int ret;
    struct flb_output_instance *output;
    struct scripted_output script;
    flb_ctx_t *ctx;
    const char *record = "[1, {\"repeated_throttle\":true}]";

    scripted_output_init(&script, FLB_THROTTLE);
    script.outcomes[1] = FLB_THROTTLE;
    script.outcomes[2] = FLB_OK;
    script.hints[1] = TEST_COOLDOWN_MS;

    ctx = flb_create();
    TEST_CHECK(ctx != NULL);
    if (ctx == NULL) {
        scripted_output_destroy(&script);
        return;
    }

    TEST_CHECK(register_scripted_plugin(ctx, "m6_scripted", 0) == 0);
    input_id = flb_input(ctx, "lib", NULL);
    TEST_CHECK(input_id >= 0);
    flb_input_set(ctx, input_id, "tag", "repeated_throttle", NULL);
    output_id = flb_output(ctx, "m6_scripted",
                           (struct flb_lib_out_cb *) &script);
    TEST_CHECK(output_id >= 0);
    flb_output_set(ctx, output_id, "match", "repeated_throttle",
                   "workers", "4", "throttle", "true",
                   "throttle.base", "1", "throttle.cap", "1",
                   "retry_limit", "1", NULL);
    flb_service_set(ctx, "Flush", "0.1", "Grace", "1",
                    "Log_Level", "error", NULL);
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);
    if (ret != 0) {
        flb_destroy(ctx);
        scripted_output_destroy(&script);
        return;
    }

    TEST_CHECK(flb_lib_push(ctx, input_id, record, strlen(record)) > 0);
    TEST_CHECK(wait_for_calls(&script, 3, TEST_TIMEOUT_MS) == 0);
    TEST_CHECK(scripted_calls(&script) == 3);
    TEST_CHECK(scripted_timestamp(&script, 1) >=
               scripted_timestamp(&script, 0) + TEST_COOLDOWN_MS);
    TEST_CHECK(scripted_timestamp(&script, 2) >=
               scripted_timestamp(&script, 1) + TEST_COOLDOWN_MS);

    output = flb_output_get_instance(ctx->config, output_id);
    TEST_CHECK(output != NULL);
    if (output != NULL) {
        TEST_CHECK(counter_value(output->cmt_retries,
                                 flb_output_name(output)) == 0.0);
        TEST_CHECK(counter_value(output->cmt_retries_failed,
                                 flb_output_name(output)) == 0.0);
    }

    stop_engine(ctx);
    flb_destroy(ctx);
    scripted_output_destroy(&script);
}

static void test_throttle_preserves_existing_retry_attempt(void)
{
    int input_id;
    int output_id;
    int ret;
    struct flb_output_instance *output;
    struct scripted_output script;
    flb_ctx_t *ctx;
    const char *record = "[1, {\"retry_then_throttle\":true}]";

    scripted_output_init(&script, FLB_RETRY);
    script.outcomes[1] = FLB_THROTTLE;
    script.outcomes[2] = FLB_OK;
    script.hints[1] = TEST_COOLDOWN_MS;

    ctx = flb_create();
    TEST_CHECK(ctx != NULL);
    if (ctx == NULL) {
        scripted_output_destroy(&script);
        return;
    }

    TEST_CHECK(register_scripted_plugin(ctx, "m6_scripted", 0) == 0);
    input_id = flb_input(ctx, "lib", NULL);
    TEST_CHECK(input_id >= 0);
    flb_input_set(ctx, input_id, "tag", "retry_then_throttle", NULL);
    output_id = flb_output(ctx, "m6_scripted",
                           (struct flb_lib_out_cb *) &script);
    TEST_CHECK(output_id >= 0);
    flb_output_set(ctx, output_id, "match", "retry_then_throttle",
                   "workers", "4", "throttle", "true",
                   "throttle.base", "1", "throttle.cap", "1",
                   "retry_limit", "1", NULL);
    flb_service_set(ctx, "Flush", "0.1", "Grace", "1",
                    "Log_Level", "error", "scheduler.base", "1",
                    "scheduler.cap", "1", NULL);
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);
    if (ret != 0) {
        flb_destroy(ctx);
        scripted_output_destroy(&script);
        return;
    }

    TEST_CHECK(flb_lib_push(ctx, input_id, record, strlen(record)) > 0);
    TEST_CHECK(wait_for_calls(&script, 3, TEST_TIMEOUT_MS) == 0);
    TEST_CHECK(scripted_calls(&script) == 3);
    TEST_CHECK(scripted_timestamp(&script, 2) >=
               scripted_timestamp(&script, 1) + TEST_COOLDOWN_MS);

    output = flb_output_get_instance(ctx->config, output_id);
    TEST_CHECK(output != NULL);
    if (output != NULL) {
        TEST_CHECK(counter_value(output->cmt_retries,
                                 flb_output_name(output)) == 1.0);
        TEST_CHECK(counter_value(output->cmt_retries_failed,
                                 flb_output_name(output)) == 0.0);
    }

    stop_engine(ctx);
    flb_destroy(ctx);
    scripted_output_destroy(&script);
}

static void run_deferred_wakeup_serialization_case(int flags)
{
    int input_id;
    int output_id;
    int ret;
    struct flb_output_instance *output;
    struct scripted_output script;
    flb_ctx_t *ctx;
    const char *record = "[1, {\"serialized_wakeup\":true}]";

    scripted_output_init(&script, FLB_THROTTLE);
    script.blocked_calls = UINT64_C(1) << 1;
    ctx = flb_create();
    TEST_CHECK(ctx != NULL);
    if (ctx == NULL) {
        scripted_output_destroy(&script);
        return;
    }

    TEST_CHECK(register_scripted_plugin(ctx, "m6_serialized", flags) == 0);
    input_id = flb_input(ctx, "lib", NULL);
    TEST_CHECK(input_id >= 0);
    flb_input_set(ctx, input_id, "tag", "serialized_wakeup", NULL);
    output_id = flb_output(ctx, "m6_serialized",
                           (struct flb_lib_out_cb *) &script);
    TEST_CHECK(output_id >= 0);
    flb_output_set(ctx, output_id, "match", "serialized_wakeup",
                   "throttle", "true", "throttle.base", "1",
                   "throttle.cap", "1", "retry_limit", "3", NULL);
    if ((flags & FLB_OUTPUT_SYNCHRONOUS) == 0) {
        flb_output_set(ctx, output_id, "workers", "4", NULL);
    }
    flb_service_set(ctx, "Flush", "0.1", "Grace", "1",
                    "Log_Level", "error", NULL);
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);
    if (ret != 0) {
        flb_destroy(ctx);
        scripted_output_destroy(&script);
        return;
    }

    output = flb_output_get_instance(ctx->config, output_id);
    TEST_CHECK(output != NULL);
    TEST_CHECK(flb_lib_push(ctx, input_id, record, strlen(record)) > 0);
    TEST_CHECK(wait_for_calls(&script, 1, TEST_TIMEOUT_MS) == 0);
    if (output != NULL) {
        TEST_CHECK(wait_for_gate_events(output, 1, TEST_TIMEOUT_MS) == 0);
    }

    /* Create separate tasks while the output gate is closed. */
    TEST_CHECK(flb_lib_push(ctx, input_id, record, strlen(record)) > 0);
    flb_time_msleep(200);
    TEST_CHECK(flb_lib_push(ctx, input_id, record, strlen(record)) > 0);
    flb_time_msleep(200);
    TEST_CHECK(scripted_calls(&script) == 1);

    TEST_CHECK(wait_for_calls(&script, 2, TEST_TIMEOUT_MS) == 0);
    flb_time_msleep(300);
    TEST_CHECK(scripted_calls(&script) == 2);

    release_call(&script, 1);
    TEST_CHECK(wait_for_calls(&script, 3, TEST_TIMEOUT_MS) == 0);

    stop_engine(ctx);
    flb_destroy(ctx);
    scripted_output_destroy(&script);
}

static void test_deferred_wakeups_preserve_serialization(void)
{
    run_deferred_wakeup_serialization_case(FLB_OUTPUT_NO_MULTIPLEX);
    run_deferred_wakeup_serialization_case(FLB_OUTPUT_SYNCHRONOUS);
}

static void test_no_multiplex_prioritizes_deferred_routes(void)
{
    int old_input_id;
    int new_input_id;
    int output_id;
    int healthy_output_id;
    int ret;
    struct flb_output_instance *output;
    struct scripted_output script;
    struct scripted_output healthy_script;
    flb_ctx_t *ctx;
    const char *record = "[1, {\"deferred_priority\":true}]";

    scripted_output_init(&script, FLB_THROTTLE);
    script.hints[0] = 60000;
    scripted_output_init(&healthy_script, FLB_OK);
    ctx = flb_create();
    TEST_CHECK(ctx != NULL);
    if (ctx == NULL) {
        scripted_output_destroy(&script);
        scripted_output_destroy(&healthy_script);
        return;
    }

    TEST_CHECK(register_scripted_plugin(ctx, "m6_priority",
                                        FLB_OUTPUT_NO_MULTIPLEX) == 0);
    TEST_CHECK(register_scripted_plugin(ctx, "m6_priority_healthy", 0) == 0);
    old_input_id = flb_input(ctx, "lib", NULL);
    new_input_id = flb_input(ctx, "lib", NULL);
    TEST_CHECK(old_input_id >= 0);
    TEST_CHECK(new_input_id >= 0);
    flb_input_set(ctx, old_input_id, "tag", "old", NULL);
    flb_input_set(ctx, new_input_id, "tag", "new", NULL);
    output_id = flb_output(ctx, "m6_priority",
                           (struct flb_lib_out_cb *) &script);
    TEST_CHECK(output_id >= 0);
    flb_output_set(ctx, output_id, "match", "*", "workers", "4",
                   "throttle", "true", "throttle.base", "1",
                   "throttle.cap", "1", "retry_limit", "3", NULL);
    healthy_output_id = flb_output(ctx, "m6_priority_healthy",
                                   (struct flb_lib_out_cb *) &healthy_script);
    TEST_CHECK(healthy_output_id >= 0);
    flb_output_set(ctx, healthy_output_id, "match", "new", NULL);
    flb_service_set(ctx, "Flush", "0.1", "Grace", "1",
                    "Log_Level", "error", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);
    if (ret != 0) {
        flb_destroy(ctx);
        scripted_output_destroy(&script);
        scripted_output_destroy(&healthy_script);
        return;
    }

    output = flb_output_get_instance(ctx->config, output_id);
    TEST_CHECK(output != NULL);
    TEST_CHECK(flb_lib_push(ctx, old_input_id, record, strlen(record)) > 0);
    TEST_CHECK(wait_for_calls(&script, 1, TEST_TIMEOUT_MS) == 0);
    TEST_CHECK(scripted_tag_marker(&script, 0) == 'o');
    if (output != NULL) {
        TEST_CHECK(wait_for_gate_events(output, 1, TEST_TIMEOUT_MS) == 0);
        TEST_CHECK(wait_for_deferred_routes(output, 1, TEST_TIMEOUT_MS) == 0);

        /* Open the gate while its old deferred-route wakeup remains far away. */
        pthread_mutex_lock(&output->throttle.lock);
        output->throttle.until_ms = flb_output_throttle_now_ms();
        pthread_mutex_unlock(&output->throttle.lock);
    }

    TEST_CHECK(flb_lib_push(ctx, new_input_id, record, strlen(record)) > 0);
    TEST_CHECK(wait_for_calls(&healthy_script, 1, TEST_TIMEOUT_MS) == 0);
    flb_time_msleep(300);
    TEST_CHECK(scripted_calls(&script) == 1);
    if (output != NULL) {
        TEST_CHECK(wait_for_deferred_routes(output, 2, TEST_TIMEOUT_MS) == 0);
    }

    stop_engine(ctx);
    flb_destroy(ctx);
    scripted_output_destroy(&script);
    scripted_output_destroy(&healthy_script);
}

static void run_no_retry_case(const char *storage_type)
{
    int input_id;
    int output_id;
    int ret;
    uint64_t first_admission;
    char *storage_path;
    struct flb_output_instance *output;
    struct scripted_output script;
    flb_ctx_t *ctx;
    const char *record = "[1, {\"no_retry\":true}]";

    storage_path = NULL;
    scripted_output_init(&script, FLB_THROTTLE);
    ctx = flb_create();
    TEST_CHECK(ctx != NULL);
    if (ctx == NULL) {
        scripted_output_destroy(&script);
        return;
    }

    if (storage_type != NULL && strcmp(storage_type, "filesystem") == 0) {
        storage_path = flb_test_tmpdir_cat("/flb-output-throttle-XXXXXX");
        TEST_CHECK(storage_path != NULL);
        if (storage_path == NULL || mkdtemp(storage_path) == NULL) {
            flb_free(storage_path);
            flb_destroy(ctx);
            scripted_output_destroy(&script);
            return;
        }
        flb_service_set(ctx, "storage.path", storage_path, NULL);
    }

    TEST_CHECK(register_scripted_plugin(ctx, "m6_scripted", 0) == 0);
    input_id = flb_input(ctx, "lib", NULL);
    TEST_CHECK(input_id >= 0);
    flb_input_set(ctx, input_id, "tag", "no_retry", NULL);
    if (storage_type != NULL) {
        flb_input_set(ctx, input_id, "storage.type", storage_type, NULL);
    }
    output_id = flb_output(ctx, "m6_scripted",
                           (struct flb_lib_out_cb *) &script);
    TEST_CHECK(output_id >= 0);
    flb_output_set(ctx, output_id, "match", "no_retry", "workers", "4",
                   "throttle", "true", "throttle.base", "1",
                   "throttle.cap", "1", "retry_limit", "no_retries", NULL);
    flb_service_set(ctx, "Flush", "0.1", "Grace", "1",
                    "Log_Level", "error", NULL);
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);
    if (ret != 0) {
        flb_destroy(ctx);
        if (storage_path != NULL) {
            cio_utils_recursive_delete(storage_path);
            flb_free(storage_path);
        }
        scripted_output_destroy(&script);
        return;
    }

    output = flb_output_get_instance(ctx->config, output_id);
    TEST_CHECK(output != NULL);
    TEST_CHECK(flb_lib_push(ctx, input_id, record, strlen(record)) > 0);
    TEST_CHECK(wait_for_calls(&script, 1, TEST_TIMEOUT_MS) == 0);
    first_admission = scripted_timestamp(&script, 0);
    if (output != NULL) {
        TEST_CHECK(wait_for_gate_events(output, 1, TEST_TIMEOUT_MS) == 0);
    }

    TEST_CHECK(flb_lib_push(ctx, input_id, record, strlen(record)) > 0);
    flb_time_msleep(200);
    TEST_CHECK(scripted_calls(&script) == 1);
    TEST_CHECK(wait_for_calls(&script, 2, TEST_TIMEOUT_MS) == 0);
    TEST_CHECK(scripted_timestamp(&script, 1) >= first_admission + TEST_COOLDOWN_MS);
    if (output != NULL) {
        TEST_CHECK(counter_value(output->cmt_throttle_events,
                                 flb_output_name(output)) == 1.0);
        TEST_CHECK(counter_value(output->cmt_retries,
                                 flb_output_name(output)) == 0.0);
    }

    stop_engine(ctx);
    flb_destroy(ctx);
    if (storage_path != NULL) {
        cio_utils_recursive_delete(storage_path);
        flb_free(storage_path);
    }
    scripted_output_destroy(&script);
}

static void test_no_retry_gate_storage_modes(void)
{
    run_no_retry_case(NULL);
    run_no_retry_case("filesystem");
    run_no_retry_case("memrb");
}

static void test_shutdown_cancels_long_cooldown(void)
{
    int input_id;
    int output_id;
    int ret;
    uint64_t stop_started;
    struct flb_output_instance *output;
    struct scripted_output script;
    flb_ctx_t *ctx;
    const char *record = "[1, {\"shutdown\":true}]";

    scripted_output_init(&script, FLB_THROTTLE);
    script.hints[0] = 60000;
    ctx = flb_create();
    TEST_CHECK(ctx != NULL);
    if (ctx == NULL) {
        scripted_output_destroy(&script);
        return;
    }

    TEST_CHECK(register_scripted_plugin(ctx, "m6_scripted", 0) == 0);
    input_id = flb_input(ctx, "lib", NULL);
    TEST_CHECK(input_id >= 0);
    flb_input_set(ctx, input_id, "tag", "shutdown", NULL);
    output_id = flb_output(ctx, "m6_scripted",
                           (struct flb_lib_out_cb *) &script);
    TEST_CHECK(output_id >= 0);
    flb_output_set(ctx, output_id, "match", "shutdown", "workers", "4",
                   "throttle", "true", "throttle.base", "1",
                   "throttle.cap", "1", "retry_limit", "3", NULL);
    flb_service_set(ctx, "Flush", "0.1", "Grace", "1",
                    "Log_Level", "error", NULL);
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);
    if (ret != 0) {
        flb_destroy(ctx);
        scripted_output_destroy(&script);
        return;
    }

    output = flb_output_get_instance(ctx->config, output_id);
    TEST_CHECK(output != NULL);
    TEST_CHECK(flb_lib_push(ctx, input_id, record, strlen(record)) > 0);
    TEST_CHECK(wait_for_calls(&script, 1, TEST_TIMEOUT_MS) == 0);
    if (output != NULL) {
        TEST_CHECK(wait_for_gate_events(output, 1, TEST_TIMEOUT_MS) == 0);
    }

    stop_started = flb_output_throttle_now_ms();
    stop_engine(ctx);
    TEST_CHECK(flb_output_throttle_now_ms() - stop_started < 5000);
    TEST_CHECK(scripted_calls(&script) == 1);
    flb_destroy(ctx);
    scripted_output_destroy(&script);
}

static void test_disabled_mode_is_not_gated(void)
{
    int input_id;
    int output_id;
    int ret;
    struct flb_output_instance *output;
    struct scripted_output script;
    flb_ctx_t *ctx;
    const char *record = "[1, {\"disabled\":true}]";

    scripted_output_init(&script, FLB_THROTTLE);
    ctx = flb_create();
    TEST_CHECK(ctx != NULL);
    if (ctx == NULL) {
        scripted_output_destroy(&script);
        return;
    }

    TEST_CHECK(register_scripted_plugin(ctx, "m6_scripted", 0) == 0);
    input_id = flb_input(ctx, "lib", NULL);
    flb_input_set(ctx, input_id, "tag", "disabled", NULL);
    output_id = flb_output(ctx, "m6_scripted",
                           (struct flb_lib_out_cb *) &script);
    flb_output_set(ctx, output_id, "match", "disabled", "workers", "4",
                   "retry_limit", "3", NULL);
    flb_service_set(ctx, "Flush", "0.1", "Grace", "1",
                    "Log_Level", "error", NULL);
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    TEST_CHECK(flb_lib_push(ctx, input_id, record, strlen(record)) > 0);
    TEST_CHECK(wait_for_calls(&script, 1, TEST_TIMEOUT_MS) == 0);
    TEST_CHECK(flb_lib_push(ctx, input_id, record, strlen(record)) > 0);
    TEST_CHECK(wait_for_calls(&script, 2, 1000) == 0);
    TEST_CHECK(scripted_generation(&script, 0) == 0);
    TEST_CHECK(scripted_generation(&script, 1) == 0);

    output = flb_output_get_instance(ctx->config, output_id);
    TEST_CHECK(output != NULL);
    if (output != NULL) {
        TEST_CHECK(counter_value(output->cmt_throttle_events,
                                 flb_output_name(output)) == 0.0);
        TEST_CHECK(gauge_value(output->cmt_throttle_active,
                               flb_output_name(output)) == 0.0);
        TEST_CHECK(gauge_value(output->cmt_throttle_deferred_routes,
                               flb_output_name(output)) == 0.0);
    }

    stop_engine(ctx);
    flb_destroy(ctx);
    scripted_output_destroy(&script);
}

TEST_LIST = {
    {"fanout_and_modes", test_fanout_and_modes},
    {"inflight_before_publication", test_inflight_before_publication},
    {"extended_deadline_rechecks_old_timer",
     test_extended_deadline_rechecks_old_timer},
    {"repeated_throttle_does_not_spend_retry_limit",
     test_repeated_throttle_does_not_spend_retry_limit},
    {"throttle_preserves_existing_retry_attempt",
     test_throttle_preserves_existing_retry_attempt},
    {"deferred_wakeups_preserve_serialization",
     test_deferred_wakeups_preserve_serialization},
    {"no_multiplex_prioritizes_deferred_routes",
     test_no_multiplex_prioritizes_deferred_routes},
    {"no_retry_gate_storage_modes", test_no_retry_gate_storage_modes},
    {"shutdown_cancels_long_cooldown",
     test_shutdown_cancels_long_cooldown},
    {"disabled_mode_is_not_gated", test_disabled_mode_is_not_gated},
    {NULL, NULL}
};
