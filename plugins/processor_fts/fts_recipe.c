/* Fluent Bit: native recipe loading, Apache-2.0. */
#include <string.h>
#include <stdio.h>
#include <inttypes.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_plugin.h>
#include <cmetrics/cmt_counter.h>
#include <opentelemetry/proto/metrics/v1/metrics.pb-c.h>
#include "fts.h"
#include "fts_state.h"
#include "fts_window.h"
#include "fts_metric_window.h"
#include "fts_helpers.h"

static int recipe_mark(lua_State *l)
{
    struct fts_runtime *ctx;
    const char *step;
    size_t length;
    size_t i;
    const char *error_class;
    const char *classes[] = {"operation_failed", "budget_exceeded", "wrong_type",
                            "unsupported_conversion", "invalid_parameter", "invalid_context",
                            "missing_field", "collision", "invalid_configuration", "invalid_json", "invalid_timestamp", "invalid_utf8", "validation_failed", NULL};

    ctx = lua_touserdata(l, lua_upvalueindex(1));
    step = luaL_checklstring(l, 1, &length);
    if (length > 64) {
        return luaL_error(l, "invalid step");
    }
    memcpy(ctx->recipe_step, step, length);
    ctx->recipe_step[length] = '\0';
    ctx->recipe_error_class = "operation_failed";
    ctx->recipe_parameter[0] = '\0';
    ctx->recipe_reason[0] = '\0';
    if (lua_isstring(l, 2)) {
        error_class = lua_tostring(l, 2);
        for (i = 0; classes[i]; i++) {
            if (strcmp(classes[i], error_class) == 0) {
                ctx->recipe_error_class = classes[i];
                break;
            }
        }
    }
    /* Only the private validator supplies these schema names and fixed reasons. */
    if (lua_isstring(l, 3) && lua_isstring(l, 4)) {
        snprintf(ctx->recipe_parameter, sizeof(ctx->recipe_parameter), "%.64s", lua_tostring(l, 3));
        snprintf(ctx->recipe_reason, sizeof(ctx->recipe_reason), "%.31s", lua_tostring(l, 4));
    }
    return 0;
}

/* Configuration is bounded before binding. Never round integer constants. */
static void push_configuration(lua_State *l, struct cfl_variant *v, int depth)
{
    struct cfl_list *head;
    struct cfl_kvpair *pair;
    size_t i;
    char integer[32];

    if (!v || depth > 40 || !lua_checkstack(l, 6)) {
        luaL_error(l, "configuration depth exceeded");
        return;
    }
    switch (v->type) {
    case CFL_VARIANT_STRING:
        lua_pushlstring(l, v->data.as_string, cfl_sds_len(v->data.as_string));
        break;
    case CFL_VARIANT_BOOL:
        lua_pushboolean(l, v->data.as_bool);
        break;
    case CFL_VARIANT_INT:
    case CFL_VARIANT_UINT:
        if (v->type == CFL_VARIANT_INT) {
            snprintf(integer, sizeof(integer), "%" PRId64, v->data.as_int64);
        }
        else {
            snprintf(integer, sizeof(integer), "%" PRIu64, v->data.as_uint64);
        }
        lua_newtable(l);
        lua_pushliteral(l, "integer");
        lua_setfield(l, -2, "type");
        lua_pushstring(l, integer);
        lua_setfield(l, -2, "value");
        break;
    case CFL_VARIANT_DOUBLE:
        lua_newtable(l);
        lua_pushliteral(l, "double");
        lua_setfield(l, -2, "type");
        lua_pushnumber(l, v->data.as_double);
        lua_setfield(l, -2, "value");
        break;
    case CFL_VARIANT_ARRAY:
        if (v->data.as_array->entry_count > 1024) {
            luaL_error(l, "configuration array limit");
            return;
        }
        lua_newtable(l);
        for (i = 0; i < v->data.as_array->entry_count; i++) {
            push_configuration(l, v->data.as_array->entries[i], depth + 1);
            lua_rawseti(l, -2, i + 1);
        }
        break;
    case CFL_VARIANT_KVLIST:
        lua_newtable(l);
        cfl_list_foreach(head, &v->data.as_kvlist->list) {
            pair = cfl_list_entry(head, struct cfl_kvpair, _head);
            lua_pushlstring(l, pair->key, cfl_sds_len(pair->key));
            lua_pushvalue(l, -1);
            lua_rawget(l, -3);
            if (!lua_isnil(l, -1)) {
                luaL_error(l, "duplicate configuration key");
                return;
            }
            lua_pop(l, 1);
            push_configuration(l, pair->val, depth + 1);
            lua_rawset(l, -3);
        }
        break;
    default:
        luaL_error(l, "unsupported configuration value");
    }
}

int fts_recipe_register(lua_State *l)
{
    return fts_load_helpers(l, fts_recipe_helpers, sizeof(fts_recipe_helpers) - 1,
                            "fts_recipe");
}

static int metric_name_exists(lua_State *l)
{
    struct fts_runtime *ctx;
    int cache;
    int names;
    int projected;

    ctx = lua_touserdata(l, lua_upvalueindex(1));
    luaL_checktype(l, 1, LUA_TSTRING);
    if (ctx->recipe_metric_names_ref <= 0) {
        return luaL_error(l, "invalid_context");
    }
    if (!lua_isfunction(l, 2)) {
        lua_rawgeti(l, LUA_REGISTRYINDEX, ctx->recipe_metric_names_ref);
        lua_pushvalue(l, 1);
        lua_rawget(l, -2);
        lua_pushboolean(l, !lua_isnil(l, -1));
        return 1;
    }
    /* Each immutable projection is evaluated once per scope, not per family. */
    lua_rawgeti(l, LUA_REGISTRYINDEX, ctx->recipe_metric_projection_ref);
    cache = lua_gettop(l);
    lua_pushvalue(l, 2);
    lua_rawget(l, cache);
    if (lua_isnil(l, -1)) {
        lua_pop(l, 1);
        lua_newtable(l);
        projected = lua_gettop(l);
        lua_rawgeti(l, LUA_REGISTRYINDEX, ctx->recipe_metric_names_ref);
        names = lua_gettop(l);
        lua_pushnil(l);
        while (lua_next(l, names) != 0) {
            if (--ctx->instructions_left <= 0) {
                return luaL_error(l, "budget_exceeded");
            }
            lua_pop(l, 1);
            lua_pushvalue(l, 2);
            lua_pushvalue(l, -2);
            lua_call(l, 1, 1);
            if (lua_type(l, -1) == LUA_TSTRING) {
                lua_pushboolean(l, 1);
                lua_rawset(l, projected);
            }
            else {
                lua_pop(l, 1);
            }
        }
        lua_pop(l, 1);
        lua_pushvalue(l, 2);
        lua_pushvalue(l, projected);
        lua_rawset(l, cache);
    }
    lua_pushvalue(l, 1);
    lua_rawget(l, -2);
    lua_pushboolean(l, !lua_isnil(l, -1));
    return 1;
}

struct recipe_names_call {
    struct fts_runtime *ctx;
    Opentelemetry__Proto__Metrics__V1__Metric **items;
    size_t count;
};

static int prepare_metric_names(lua_State *l)
{
    struct recipe_names_call *call;
    size_t i;

    call = lua_touserdata(l, 1);
    lua_newtable(l);
    for (i = 0; i < call->count; i++) {
        if (--call->ctx->instructions_left <= 0) {
            return luaL_error(l, "metric namespace budget exceeded");
        }
        lua_pushstring(l, call->items[i]->name);
        lua_pushboolean(l, 1);
        lua_rawset(l, -3);
    }
    call->ctx->recipe_metric_names_ref = luaL_ref(l, LUA_REGISTRYINDEX);
    lua_newtable(l);
    call->ctx->recipe_metric_projection_ref = luaL_ref(l, LUA_REGISTRYINDEX);
    return 0;
}

int fts_recipe_metric_names(struct fts_runtime *ctx, void *items, size_t count)
{
    struct recipe_names_call call;
    lua_State *l;
    int base;
    int ret;

    if (!ctx->recipe || !ctx->recipe_needs_metric_names) {
        return 0;
    }
    l = ctx->vm->state;
    if (ctx->recipe_metric_names_ref > 0) {
        luaL_unref(l, LUA_REGISTRYINDEX, ctx->recipe_metric_names_ref);
        ctx->recipe_metric_names_ref = 0;
    }
    if (ctx->recipe_metric_projection_ref > 0) {
        luaL_unref(l, LUA_REGISTRYINDEX, ctx->recipe_metric_projection_ref);
        ctx->recipe_metric_projection_ref = 0;
    }
    if (!items) {
        return 0;
    }
    base = lua_gettop(l);
    call.ctx = ctx;
    call.items = items;
    call.count = count;
    ctx->instructions_left = ctx->instruction_limit;
    lua_pushcfunction(l, prepare_metric_names);
    lua_pushlightuserdata(l, &call);
    ret = lua_pcall(l, 1, 0, 0);
    if (ret) {
        fts_sanitizer_forget_unwound_frames();
    }
    lua_settop(l, base);
    return ret ? -1 : 0;
}

/* Validate the complete input before cutting at a UTF-8 codepoint boundary. */
static int truncate_utf8(lua_State *l)
{
    struct fts_runtime *ctx;
    const char *text;
    size_t length;
    size_t limit;
    lua_Integer requested;
    void *data;

    text = luaL_checklstring(l, 1, &length);
    requested = luaL_checkinteger(l, 2);
    if (requested < 0 || requested > 1048576) {
        return luaL_error(l, "invalid_parameter");
    }
    lua_getallocf(l, &data);
    ctx = data;
    if (length / 8 > (size_t) ctx->instructions_left) {
        ctx->instructions_left = 0;
        return luaL_error(l, "budget_exceeded");
    }
    ctx->instructions_left -= length / 8;
    if (!fts_valid_utf8(text, length)) {
        return luaL_error(l, "invalid_utf8");
    }
    limit = (size_t) requested;
    if (length <= limit) {
        lua_pushvalue(l, 1);
        lua_pushboolean(l, 0);
        return 2;
    }
    while (limit > 0 && ((unsigned char) text[limit] & 0xc0) == 0x80) {
        limit--;
    }
    lua_pushlstring(l, text, limit);
    lua_pushboolean(l, 1);
    return 2;
}

/* Pack paths are portable relative references; configuration itself is trusted. */
static int package_relative_path(const char *path, size_t length)
{
    size_t i;
    size_t start;

    if (length == 0 || length > 1024 || path[0] == '/') {
        return 0;
    }
    start = 0;
    for (i = 0; i <= length; i++) {
        if (i < length && (path[i] == '\0' || path[i] == '\\' || path[i] == ':')) {
            return 0;
        }
        if (i == length || path[i] == '/') {
            if (i == start || (i - start == 1 && path[start] == '.') ||
                (i - start == 2 && path[start] == '.' && path[start + 1] == '.')) {
                return 0;
            }
            start = i + 1;
        }
    }
    return 1;
}

/* Close the file before any Lua API can longjmp. The runtime owns the buffer
 * until pushlstring succeeds, including failures due to the Lua memory limit. */
static void package_read(lua_State *l, struct fts_runtime *ctx, const char *path)
{
    FILE *file;
    size_t length;
    size_t capacity;
    long file_size;
    int failed;

    file = fopen(path, "rb");
    if (!file) {
        luaL_error(l, "invalid_package_file");
        return;
    }
    if (fseek(file, 0, SEEK_END) != 0 || (file_size = ftell(file)) <= 0 ||
        file_size > 262144 || fseek(file, 0, SEEK_SET) != 0) {
        fclose(file);
        luaL_error(l, "invalid_package_file");
        return;
    }
    capacity = (size_t) file_size + 1;
    if (ctx->native_bytes > ctx->memory_limit ||
        ctx->lua_bytes > ctx->memory_limit - ctx->native_bytes ||
        capacity > ctx->memory_limit - ctx->native_bytes - ctx->lua_bytes) {
        fclose(file);
        luaL_error(l, "budget_exceeded");
        return;
    }
    ctx->package_buffer = flb_malloc(capacity);
    if (!ctx->package_buffer) {
        fclose(file);
        luaL_error(l, "budget_exceeded");
        return;
    }
    ctx->package_buffer_size = capacity;
    ctx->native_bytes += capacity;
    length = fread(ctx->package_buffer, 1, capacity, file);
    failed = ferror(file);
    fclose(file);
    if (failed || length != (size_t) file_size) {
        flb_free(ctx->package_buffer);
        ctx->package_buffer = NULL;
        ctx->package_buffer_size = 0;
        ctx->native_bytes -= capacity;
        luaL_error(l, "invalid_package_file");
        return;
    }
    lua_pushlstring(l, ctx->package_buffer, length);
    flb_free(ctx->package_buffer);
    ctx->package_buffer = NULL;
    ctx->package_buffer_size = 0;
    ctx->native_bytes -= capacity;
}

static int package_source(lua_State *l)
{
    struct fts_runtime *ctx;
    const char *base;
    const char *relative;
    size_t length;
    char path[4096];
    int written;

    ctx = lua_touserdata(l, lua_upvalueindex(1));
    base = lua_tostring(l, lua_upvalueindex(2));
    relative = luaL_checklstring(l, 1, &length);
    if (!package_relative_path(relative, length) || length < 5 ||
        strcmp(relative + length - 4, ".lua") != 0) {
        return luaL_error(l, "invalid_package_path");
    }
    written = snprintf(path, sizeof(path), "%s/%s", base, relative);
    if (written < 0 || (size_t) written >= sizeof(path)) {
        return luaL_error(l, "invalid_package_path");
    }
    package_read(l, ctx, path);
    return 1;
}

static void package_load(lua_State *l, struct fts_runtime *ctx)
{
    struct cfl_variant *manifest;
    size_t i;
    size_t length;
    int written;
    char path[4096];
    char *slash;

    if (!ctx->packs) {
        return;
    }
    if (ctx->packs->type != CFL_VARIANT_ARRAY ||
        ctx->packs->data.as_array->entry_count > 16) {
        luaL_error(l, "invalid_packages");
        return;
    }
    for (i = 0; i < ctx->packs->data.as_array->entry_count; i++) {
        manifest = ctx->packs->data.as_array->entries[i];
        if (manifest->type != CFL_VARIANT_STRING) {
            luaL_error(l, "invalid_package_path");
            return;
        }
        length = cfl_sds_len(manifest->data.as_string);
        if (!package_relative_path(manifest->data.as_string, length)) {
            luaL_error(l, "invalid_package_path");
            return;
        }
        written = snprintf(path, sizeof(path), "%s/%s", ctx->packages_dir,
                           manifest->data.as_string);
        if (written < 0 || (size_t) written >= sizeof(path)) {
            luaL_error(l, "invalid_package_path");
            return;
        }
        lua_getfield(l, -1, "_recipe_register_pack");
        package_read(l, ctx, path);
        slash = strrchr(path, '/');
        *slash = '\0';
        lua_pushlightuserdata(l, ctx);
        lua_pushstring(l, path);
        lua_pushcclosure(l, package_source, 2);
        lua_call(l, 2, 0);
    }
}

int fts_recipe_initialize(lua_State *l, struct fts_runtime *ctx)
{
    const char *signal;

    if (fts_recipe_register(l) != 0) {
        return lua_error(l);
    }
    signal = ctx->adapter->event_type == FLB_PROCESSOR_LOGS ? "logs" :
             ctx->adapter->event_type == FLB_PROCESSOR_METRICS ? "metrics" : "traces";
    lua_rawgeti(l, LUA_REGISTRYINDEX, ctx->module_ref);
    lua_pushlightuserdata(l, ctx);
    lua_pushcclosure(l, metric_name_exists, 1);
    lua_setfield(l, -2, "_recipe_metric_name_exists");
    lua_pushcfunction(l, truncate_utf8);
    lua_setfield(l, -2, "_recipe_truncate_utf8");
    fts_state_register(ctx);
    fts_window_register(ctx);
    fts_metric_window_register(ctx);
    package_load(l, ctx);
    lua_getfield(l, -1, "_recipe_compile");
    lua_remove(l, -2);
    push_configuration(l, ctx->recipe, 0);
    lua_pushstring(l, signal);
    lua_pushstring(l, ctx->error_mode);
    lua_pushstring(l, ctx->recipe_context);
    lua_pushlightuserdata(l, ctx);
    lua_pushcclosure(l, recipe_mark, 1);
    lua_pushboolean(l, ctx->state_input);
    lua_pushstring(l, ctx->state_commit);
    lua_call(l, 7, 2);
    ctx->recipe_needs_metric_names = lua_toboolean(l, -1);
    lua_pop(l, 1);
    ctx->policy_ref = luaL_ref(l, LUA_REGISTRYINDEX);
    return 0;
}

void fts_recipe_report_error(struct flb_processor_instance *ins, struct fts_runtime *ctx,
                             const char *error_class)
{
    if (!error_class) {
        error_class = ctx->recipe_error_class ? ctx->recipe_error_class : "operation_failed";
    }
    if (strcmp(error_class, "invalid_configuration") == 0) {
        flb_plg_error(ins, "FTS recipe step=%s class=%s param=%s reason=%s",
                      ctx->recipe_step[0] ? ctx->recipe_step : "initialization", error_class,
                      ctx->recipe_parameter[0] ? ctx->recipe_parameter : "recipe",
                      ctx->recipe_reason[0] ? ctx->recipe_reason : "invalid");
        return;
    }
    /* Only validated step identifiers and fixed classes cross the log boundary. */
    flb_plg_error(ins, "FTS recipe step=%s class=%s; edits rolled back",
                  ctx->recipe_step[0] ? ctx->recipe_step : "initialization", error_class);
}

int fts_recipe_metrics_initialize(struct flb_processor_instance *ins, struct fts_runtime *ctx)
{
    struct flb_processor *proc;
    struct cmt *metrics = NULL;
    struct cfl_list *head;
    struct cmt_counter *counter;
    char *labels[] = {"name", "scope", "processor", "stage", "signal", "outcome"};

    if (!ctx->recipe || !ins->pu || !ins->pu->parent) {
        return 0;
    }
    proc = ins->pu->parent;
    if (proc->data && proc->source_plugin_type == FLB_PLUGIN_INPUT) {
        metrics = ((struct flb_input_instance *) proc->data)->cmt;
        ctx->recipe_owner = (char *) flb_input_name((struct flb_input_instance *) proc->data);
        ctx->recipe_scope = "input";
    }
    else if (proc->data && proc->source_plugin_type == FLB_PLUGIN_OUTPUT) {
        metrics = ((struct flb_output_instance *) proc->data)->cmt;
        ctx->recipe_owner = (char *) flb_output_name((struct flb_output_instance *) proc->data);
        ctx->recipe_scope = "output";
    }
    if (!metrics) {
        return 0;
    }
    ctx->recipe_processor = ins->pu->name;
    snprintf(ctx->recipe_stage, sizeof(ctx->recipe_stage), "%zu", ins->pu->stage);
    cfl_list_foreach(head, &metrics->counters) {
        counter = cfl_list_entry(head, struct cmt_counter, _head);
        if (strcmp(counter->opts.fqname, "fluentbit_fts_recipe_callbacks_total") == 0) {
            ctx->recipe_outcomes = counter;
            return fts_state_metrics_initialize(ctx, metrics);
        }
    }
    ctx->recipe_outcomes = cmt_counter_create(metrics, "fluentbit", "fts",
        "recipe_callbacks_total", "Recipe callback outcomes; not delivery acknowledgments.", 6, labels);
    return ctx->recipe_outcomes ? fts_state_metrics_initialize(ctx, metrics) : -1;
}

void fts_recipe_count(struct fts_runtime *ctx, const char *outcome)
{
    char *labels[6];

    if (!ctx->recipe_outcomes) {
        return;
    }
    labels[0] = ctx->recipe_owner;
    labels[1] = ctx->recipe_scope;
    labels[2] = ctx->recipe_processor;
    labels[3] = ctx->recipe_stage;
    labels[4] = ctx->adapter->event_type == FLB_PROCESSOR_LOGS ? "logs" :
                ctx->adapter->event_type == FLB_PROCESSOR_METRICS ? "metrics" : "traces";
    labels[5] = (char *) outcome;
    cmt_counter_inc(ctx->recipe_outcomes, cfl_time_now(), 6, labels);
}
