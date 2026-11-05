/* Fluent Bit: owned metric freezing/release; no gauge reduction runs in C. */
#include <math.h>
#include <string.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_plugin.h>
#include <fluent-bit/flb_scheduler.h>
#include <cmetrics/cmt_decode_opentelemetry.h>
#include <cmetrics/cmt_counter.h>
#include <cmetrics/cmt_gauge.h>
#include "fts_metric_window.h"
#include "fts_snapshot_window.h"
#include "fts_telemetry.h"

static void labels(struct fts_runtime *ctx, char **values)
{
    values[0] = ctx->recipe_owner;
    values[1] = "input";
    values[2] = ctx->recipe_processor;
    values[3] = ctx->recipe_stage;
    values[4] = "metrics";
    values[5] = "metric_families";
}

static void count(struct fts_runtime *ctx, const char *outcome, size_t amount)
{
    char *values[7];

    if (ctx->metric_window_events && amount) {
        labels(ctx, values);
        values[6] = (char *) outcome;
        cmt_counter_add(ctx->metric_window_events, cfl_time_now(), amount, 7, values);
    }
}

static void inventory(struct fts_runtime *ctx)
{
    char *values[6];

    if (ctx->metric_window_inventory) {
        labels(ctx, values);
        cmt_gauge_set(ctx->metric_window_inventory, cfl_time_now(),
                      fts_snapshot_window_held(ctx->metric_window), 6, values);
    }
}

static uint64_t integer(lua_State *l, int index, uint64_t minimum, uint64_t maximum)
{
    lua_Number value;

    value = luaL_checknumber(l, index);
    if (!isfinite(value) || value < minimum || value > maximum || floor(value) != value) {
        luaL_error(l, "invalid_parameter");
        return 0;
    }
    return (uint64_t) value;
}

static int configure(lua_State *l)
{
    struct fts_runtime *ctx;
    struct flb_processor *parent;
    struct flb_input_instance *input;
    size_t max_keys;
    size_t max_bytes;
    size_t max_samples;
    uint64_t interval;
    uint64_t timeout;

    ctx = lua_touserdata(l, lua_upvalueindex(1));
    if (!ctx->instance || !ctx->instance->pu || !ctx->state_input ||
        ctx->adapter->event_type != FLB_PROCESSOR_METRICS ||
        !ctx->state_commit || strcmp(ctx->state_commit, "local") != 0 ||
        ctx->metric_window || ctx->state || ctx->window) {
        return luaL_error(l, "invalid_context");
    }
    parent = ctx->instance->pu->parent;
    input = parent ? parent->data : NULL;
    if (!input || !input->p || strcmp(input->p->name, "opentelemetry") != 0) {
        return luaL_error(l, "invalid_context");
    }
    interval = integer(l, 1, 1, 86400000);
    timeout = integer(l, 2, 1, 86400000);
    max_keys = integer(l, 3, 1, 65536);
    max_bytes = integer(l, 4, 1, 65536);
    max_samples = integer(l, 5, 1, 1000000);
    ctx->metric_window = fts_snapshot_window_create(max_keys, max_bytes, max_samples,
                                                    ctx->state_limit, interval, timeout);
    if (!ctx->metric_window) {
        return luaL_error(l, "invalid_parameter");
    }
    ctx->metric_window_input = input;
    ctx->metric_window_key_limit = max_bytes;
    return 0;
}

static struct fts_runtime *runtime(lua_State *l)
{
    return lua_touserdata(l, lua_upvalueindex(1));
}

static int get(lua_State *l)
{
    struct fts_runtime *ctx;
    const struct cfl_variant *value;
    struct fts_value *owner;
    const char *key;
    size_t length;
    size_t work;
    size_t samples;

    ctx = runtime(l);
    if (!ctx->metric_window || !ctx->metric_window_active) {
        return luaL_error(l, "invalid_context");
    }
    if (lua_type(l, 1) != LUA_TSTRING) {
        return luaL_error(l, "wrong_type");
    }
    key = luaL_checklstring(l, 1, &length);
    work = length / 8 + 1;
    if (ctx->instructions_left < 0 || work > (size_t) ctx->instructions_left) {
        ctx->instructions_left = 0;
        return luaL_error(l, "budget_exceeded");
    }
    ctx->instructions_left -= (int) work;
    value = fts_snapshot_window_get(ctx->metric_window, key, length, &samples, &ctx->instructions_left);
    if (ctx->instructions_left <= 0) {
        return luaL_error(l, "budget_exceeded");
    }
    if (!value) {
        lua_pushnil(l);
        lua_pushnumber(l, 0);
        return 2;
    }
    owner = fts_push_owned(l, NULL, FLB_FALSE);
    fts_charge_value(l, owner, fts_value_cost((struct cfl_variant *) value, 0));
    owner->owned = fts_copy_value((struct cfl_variant *) value, 0);
    if (!owner->owned) {
        return luaL_error(l, "budget_exceeded");
    }
    lua_pushnumber(l, samples);
    return 2;
}

static void clear_request(struct fts_runtime *ctx)
{
    if (ctx->metric_window_request_ref > 0 && ctx->vm) {
        luaL_unref(ctx->vm->state, LUA_REGISTRYINDEX, ctx->metric_window_request_ref);
    }
    ctx->metric_window_request_ref = 0;
    ctx->metric_window_request_value = NULL;
    if (ctx->metric_window_key) {
        ctx->native_bytes -= ctx->metric_window_request_bytes;
        flb_free(ctx->metric_window_key);
        ctx->metric_window_key = NULL;
    }
    ctx->metric_window_request_bytes = 0;
}

static int request(lua_State *l)
{
    struct fts_runtime *ctx;
    const char *key;
    const char *tag;
    size_t key_length;
    size_t tag_length;
    size_t cost;

    ctx = runtime(l);
    if (!ctx->metric_window || !ctx->metric_window_active || ctx->metric_window_request_ref > 0) {
        return luaL_error(l, "invalid_context");
    }
    if (lua_type(l, 1) != LUA_TSTRING || lua_type(l, 3) != LUA_TSTRING) {
        return luaL_error(l, "wrong_type");
    }
    key = luaL_checklstring(l, 1, &key_length);
    tag = luaL_checklstring(l, 3, &tag_length);
    if (key_length > ctx->metric_window_key_limit) {
        count(ctx, "overflow", 1);
        return luaL_error(l, "budget_exceeded");
    }
    fts_resolve_value(l, 2, 0);
    if (key_length > SIZE_MAX - tag_length) {
        return luaL_error(l, "budget_exceeded");
    }
    cost = key_length + tag_length;
    if (cost > ctx->memory_limit || ctx->native_bytes > ctx->memory_limit - cost ||
        ctx->lua_bytes > ctx->memory_limit - cost - ctx->native_bytes) {
        return luaL_error(l, "budget_exceeded");
    }
    ctx->metric_window_key = flb_malloc(cost ? cost : 1);
    if (!ctx->metric_window_key) {
        return luaL_error(l, "budget_exceeded");
    }
    ctx->metric_window_request_bytes = cost;
    ctx->native_bytes += cost;
    ctx->native_allocated += cost;
    memcpy(ctx->metric_window_key, key, key_length);
    memcpy(ctx->metric_window_key + key_length, tag, tag_length);
    ctx->metric_window_key_length = key_length;
    ctx->metric_window_tag_length = tag_length;
    ctx->metric_window_request_value = lua_touserdata(l, 2);
    lua_pushvalue(l, 2);
    ctx->metric_window_request_ref = luaL_ref(l, LUA_REGISTRYINDEX);
    return 0;
}

int fts_metric_window_requested(struct fts_runtime *ctx)
{
    return ctx->metric_window_request_ref > 0;
}

int fts_metric_window_propose(struct fts_runtime *ctx)
{
    void *payload;
    size_t size;
    int result;

    payload = NULL;
    size = 0;
    if (!fts_metric_window_requested(ctx) ||
        fts_metric_snapshot_encode(ctx->metric_window_request_value->owned,
                                   ctx->output_limit, &payload, &size) != 0) {
        return -1;
    }
    result = fts_snapshot_window_put(ctx->metric_window, ctx->metric_window_key,
        ctx->metric_window_key_length, ctx->metric_window_request_value->owned,
        &payload, size, ctx->metric_window_key + ctx->metric_window_key_length,
        ctx->metric_window_tag_length, &ctx->instructions_left);
    flb_free(payload);
    if (result == FTS_SNAPSHOT_OVERFLOW) {
        count(ctx, "overflow", 1);
    }
    clear_request(ctx);
    return result;
}

void fts_metric_window_item_end(struct fts_runtime *ctx, int accept)
{
    clear_request(ctx);
    if (ctx->metric_window) {
        fts_snapshot_window_item(ctx->metric_window, accept);
    }
}

void fts_metric_window_begin(struct fts_runtime *ctx)
{
    if (ctx->metric_window) {
        fts_snapshot_window_begin(ctx->metric_window);
        ctx->metric_window_active = 1;
    }
}

void fts_metric_window_finish(struct fts_runtime *ctx, int commit)
{
    size_t pending;

    if (ctx->metric_window) {
        clear_request(ctx);
        pending = fts_snapshot_window_pending(ctx->metric_window);
        fts_snapshot_window_finish(ctx->metric_window, commit);
        if (commit) {
            count(ctx, "held", pending);
        }
        inventory(ctx);
        ctx->metric_window_active = 0;
    }
}

static int emit(void *data, const void *payload, size_t size, size_t charge,
                  const char *tag, size_t tag_length)
{
    struct fts_runtime *ctx;
    struct cfl_list contexts;
    struct cmt *context;
    size_t offset;
    int result;

    ctx = data;
    cfl_list_init(&contexts);
    offset = 0;
    result = cmt_decode_opentelemetry_create(&contexts, (char *) payload, size, &offset);
    if (result != 0 || cfl_list_size(&contexts) != 1) {
        cmt_decode_opentelemetry_destroy(&contexts);
        count(ctx, "release_retry", 1);
        return -1;
    }
    context = cfl_list_entry(contexts.next, struct cmt, _head);
    result = flb_input_ingress_try_resume_metrics(ctx->metric_window_input,
        ctx->instance->pu->stage + 1, tag, tag_length, &context, charge);
    cmt_decode_opentelemetry_destroy(&contexts);
    if (result != 0) {
        count(ctx, "release_retry", 1);
    }
    return result;
}

static void settle(void *data, size_t samples, const char *reason)
{
    struct fts_runtime *ctx;

    ctx = data;
    if (strcmp(reason, "released") == 0) {
        count(ctx, "released", 1);
        if (samples > 1) {
            count(ctx, "reduced", samples - 1);
        }
    }
    else {
        count(ctx, reason, samples);
    }
    inventory(ctx);
}

static void tick(struct flb_config *config, void *data)
{
    struct fts_runtime *ctx;

    (void) config;
    ctx = data;
    fts_snapshot_window_poll(ctx->metric_window, emit, settle, ctx);
}

int fts_metric_window_start(struct fts_runtime *ctx)
{
    struct cmt *metrics;
    struct cfl_list *head;
    struct cmt_counter *counter;
    struct cmt_gauge *gauge;
    char *values[7];
    const char *outcomes[] = {"held", "released", "reduced", "overflow", "expired",
                              "shutdown", "release_retry", NULL};
    size_t i;

    if (!ctx->metric_window) {
        return 0;
    }
    metrics = ctx->metric_window_input->cmt;
    if (!metrics) {
        return -1;
    }
    cfl_list_foreach(head, &metrics->counters) {
        counter = cfl_list_entry(head, struct cmt_counter, _head);
        if (counter->opts.fqname &&
            strcmp(counter->opts.fqname, "fluentbit_fts_metric_window_family_events_total") == 0) {
            ctx->metric_window_events = counter;
        }
    }
    cfl_list_foreach(head, &metrics->gauges) {
        gauge = cfl_list_entry(head, struct cmt_gauge, _head);
        if (gauge->opts.fqname &&
            strcmp(gauge->opts.fqname, "fluentbit_fts_metric_window_pending_input_families") == 0) {
            ctx->metric_window_inventory = gauge;
        }
    }
    if (!ctx->metric_window_events) {
        ctx->metric_window_events = cmt_counter_create(metrics, "fluentbit", "fts_metric_window",
            "family_events_total", "Input-family retention, output-family release and reduction.",
            7, (char *[]) {"name", "scope", "processor", "stage", "signal", "unit", "outcome"});
    }
    if (!ctx->metric_window_inventory) {
        ctx->metric_window_inventory = cmt_gauge_create(metrics, "fluentbit", "fts_metric_window",
            "pending_input_families", "Input metric families retained; not datapoints or delivery.",
            6, (char *[]) {"name", "scope", "processor", "stage", "signal", "unit"});
    }
    if (!ctx->metric_window_events || !ctx->metric_window_inventory) {
        return -1;
    }
    labels(ctx, values);
    for (i = 0; outcomes[i]; i++) {
        values[6] = (char *) outcomes[i];
        if (cmt_counter_add(ctx->metric_window_events, cfl_time_now(), 0, 7, values) != 0) {
            return -1;
        }
    }
    inventory(ctx);
    if (flb_input_ingress_enable(ctx->metric_window_input) != 0) {
        return -1;
    }
    return flb_sched_timer_cb_create(flb_sched_ctx_get(), FLB_SCHED_TIMER_CB_PERM,
                                    25, tick, ctx, &ctx->metric_window_timer);
}

void fts_metric_window_stop(struct fts_runtime *ctx)
{
    size_t held;

    if (!ctx || !ctx->metric_window) {
        return;
    }
    if (ctx->metric_window_timer) {
        flb_sched_timer_invalidate(ctx->metric_window_timer);
        ctx->metric_window_timer = NULL;
    }
    clear_request(ctx);
    ctx->metric_window_active = 0;
    held = fts_snapshot_window_held(ctx->metric_window);
    fts_snapshot_window_stop(ctx->metric_window, settle, ctx);
    if (held) {
        flb_plg_warn(ctx->instance, "%zu retained metric families discarded at input stop", held);
    }
}

void fts_metric_window_destroy(struct fts_runtime *ctx)
{
    if (ctx->metric_window_timer != NULL) {
        flb_sched_timer_invalidate(ctx->metric_window_timer);
        ctx->metric_window_timer = NULL;
    }
    clear_request(ctx);
    fts_snapshot_window_destroy(ctx->metric_window);
    ctx->metric_window = NULL;
}

int fts_metric_window_register(struct fts_runtime *ctx)
{
    lua_State *l;

    l = ctx->vm->state;
    lua_pushlightuserdata(l, ctx);
    lua_pushcclosure(l, configure, 1);
    lua_setfield(l, -2, "_metric_window_configure");
    lua_pushlightuserdata(l, ctx);
    lua_pushcclosure(l, get, 1);
    lua_setfield(l, -2, "_metric_window_get");
    lua_pushlightuserdata(l, ctx);
    lua_pushcclosure(l, request, 1);
    lua_setfield(l, -2, "_metric_window_request");
    return 0;
}
