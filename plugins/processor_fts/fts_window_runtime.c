/* Fluent Bit: Lua window requests and owner-thread engine integration. */
#include <math.h>
#include <string.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_plugin.h>
#include <fluent-bit/flb_scheduler.h>
#include <cmetrics/cmt_counter.h>
#include "fts.h"
#include "fts_window.h"

void fts_window_count(struct fts_runtime *ctx, const char *outcome, size_t count)
{
    char *labels[6];

    if (ctx->window_outcomes == NULL || count == 0) {
        return;
    }
    labels[0] = ctx->recipe_owner;
    labels[1] = ctx->recipe_scope;
    labels[2] = ctx->recipe_processor;
    labels[3] = ctx->recipe_stage;
    labels[4] = "logs";
    labels[5] = (char *) outcome;
    cmt_counter_add(ctx->window_outcomes, cfl_time_now(), count, 6, labels);
}

static int emit(void *data, void **buffer, size_t bytes, size_t records,
                 const char *tag, size_t tag_length)
{
    struct fts_runtime *ctx;
    int result;

    ctx = data;
    result = flb_input_ingress_try_resume_log(ctx->window_input, ctx->instance->pu->stage + 1,
                                             tag, tag_length,
                                             buffer, bytes, records);
    if (result == 0) {
        flb_processor_log_release(ctx->instance, records);
        fts_window_count(ctx, "released", records);
        fts_window_count(ctx, "release_batches", 1);
    }
    else {
        fts_window_count(ctx, "release_retry", 1);
    }
    return result;
}

static void drop(void *data, size_t records, const char *reason)
{
    struct fts_runtime *ctx;

    ctx = data;
    flb_processor_log_discard(ctx->instance, records);
    fts_window_count(ctx, reason, records);
}

static void tick(struct flb_config *config, void *data)
{
    struct fts_runtime *ctx;

    (void) config;
    ctx = data;
    fts_window_poll(ctx->window, emit, drop, ctx);
}

static uint64_t integer(lua_State *l, int index, uint64_t minimum, uint64_t maximum)
{
    lua_Number number;

    number = luaL_checknumber(l, index);
    if (!isfinite(number) || number < minimum || number > maximum || floor(number) != number) {
        luaL_error(l, "invalid_parameter");
        return 0;
    }
    return (uint64_t) number;
}

static int configure(lua_State *l)
{
    struct fts_runtime *ctx;
    struct flb_processor *parent;
    struct flb_input_instance *input;
    const char *name;
    size_t max_keys;
    size_t max_key_bytes;
    uint64_t hold_ms;
    uint64_t late_ms;
    uint64_t ready_ms;

    ctx = lua_touserdata(l, lua_upvalueindex(1));
    if (ctx->instance == NULL || ctx->instance->pu == NULL ||
        ctx->window || ctx->state || !ctx->state_input || !ctx->state_commit ||
        strcmp(ctx->state_commit, "local") != 0) {
        return luaL_error(l, "invalid_configuration");
    }
    parent = ctx->instance->pu->parent;
    input = parent ? parent->data : NULL;
    if (input == NULL || input->p == NULL) {
        return luaL_error(l, "invalid_configuration");
    }
    name = input->p->name;
    if (strcmp(name, "dummy") != 0 && strcmp(name, "tail") != 0 &&
        strcmp(name, "forward") != 0 && strcmp(name, "http") != 0 &&
        strcmp(name, "opentelemetry") != 0) {
        return luaL_error(l, "invalid_configuration");
    }
    hold_ms = integer(l, 1, 1, 86400000);
    late_ms = integer(l, 2, 0, 86400000);
    ready_ms = integer(l, 3, 1, 86400000);
    max_keys = integer(l, 4, 1, 65536);
    max_key_bytes = integer(l, 5, 1, 65536);
    if (max_key_bytes + 1 >= ctx->state_limit) {
        return luaL_error(l, "invalid_configuration");
    }
    ctx->window = fts_window_create(max_keys, max_key_bytes,
        ctx->state_limit - max_key_bytes - 1, hold_ms, late_ms, ready_ms);
    if (ctx->window == NULL) {
        return luaL_error(l, "invalid_configuration");
    }
    ctx->window_key = flb_malloc(max_key_bytes + 1);
    if (ctx->window_key == NULL) {
        return luaL_error(l, "budget_exceeded");
    }
    ctx->window_key_limit = max_key_bytes;
    ctx->window_input = input;
    return 0;
}

static int request(lua_State *l)
{
    struct fts_runtime *ctx;
    const char *key;
    size_t length;
    int result;

    ctx = lua_touserdata(l, lua_upvalueindex(1));
    key = luaL_checklstring(l, 1, &length);
    result = fts_window_classify_work(ctx->window, key, length, &ctx->instructions_left);
    if (result == FTS_WINDOW_BUDGET) {
        return luaL_error(l, "budget_exceeded");
    }
    if (result < 0) {
        return luaL_error(l, "invalid_context");
    }
    ctx->window_classification = result;
    if (result == FTS_WINDOW_ACCEPT) {
        memcpy(ctx->window_key, key, length);
        ctx->window_key_length = length;
        ctx->window_error = lua_toboolean(l, 2);
        ctx->window_baseline = lua_toboolean(l, 3);
        ctx->window_requested = 1;
    }
    lua_pushboolean(l, result == FTS_WINDOW_ACCEPT);
    return 1;
}

int fts_window_register(struct fts_runtime *ctx)
{
    lua_State *l;

    l = ctx->vm->state;
    lua_pushlightuserdata(l, ctx);
    lua_pushcclosure(l, configure, 1);
    lua_setfield(l, -2, "_recipe_window_configure");
    lua_pushlightuserdata(l, ctx);
    lua_pushcclosure(l, request, 1);
    lua_setfield(l, -2, "_recipe_window_request");
    return 0;
}

int fts_window_runtime_start(struct fts_runtime *ctx)
{
    struct cmt *metrics;
    struct cfl_list *head;
    struct cmt_counter *counter;

    if (ctx->window == NULL) {
        return 0;
    }
    metrics = ctx->window_input->cmt;
    if (metrics == NULL) {
        return -1;
    }
    cfl_list_foreach(head, &metrics->counters) {
        counter = cfl_list_entry(head, struct cmt_counter, _head);
        if (counter->opts.fqname && strcmp(counter->opts.fqname, "fluentbit_fts_window_events_total") == 0) {
            ctx->window_outcomes = counter;
            break;
        }
    }
    if (ctx->window_outcomes == NULL) {
        ctx->window_outcomes = cmt_counter_create(metrics, "fluentbit", "fts",
            "window_events_total", "Window admission and settlement events.", 6,
            (char *[]) {"name", "scope", "processor", "stage", "signal", "outcome"});
    }
    if (ctx->window_outcomes == NULL || flb_input_ingress_enable(ctx->window_input) != 0) {
        return -1;
    }
    return flb_sched_timer_cb_create(flb_sched_ctx_get(), FLB_SCHED_TIMER_CB_PERM,
                                    25, tick, ctx, &ctx->window_timer);
}

void fts_window_runtime_stop(struct fts_runtime *ctx)
{
    size_t records;

    if (ctx == NULL || ctx->window == NULL) {
        return;
    }
    if (ctx->window_timer != NULL) {
        flb_sched_timer_invalidate(ctx->window_timer);
        ctx->window_timer = NULL;
    }
    records = fts_window_records(ctx->window);
    fts_window_stop(ctx->window, drop, ctx);
    if (records != 0) {
        flb_plg_warn(ctx->instance, "%zu retained log records discarded at input stop", records);
    }
}

void fts_window_runtime_destroy(struct fts_runtime *ctx)
{
    if (ctx->window_timer != NULL) {
        flb_sched_timer_invalidate(ctx->window_timer);
        ctx->window_timer = NULL;
    }
    fts_window_destroy(ctx->window);
    ctx->window = NULL;
    flb_free(ctx->window_key);
    ctx->window_key = NULL;
}
