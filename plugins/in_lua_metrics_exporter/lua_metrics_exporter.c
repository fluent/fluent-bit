/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2026 The Fluent Bit Authors
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_luajit.h>
#include <cmetrics/cmt_counter.h>
#include <cmetrics/cmt_gauge.h>
#include <math.h>

#define LM_MAX_LABELS 32
#define LM_MAX_FAMILIES 1024
#define LM_MAX_SAMPLES 10000

struct lua_metrics {
    char *script;
    char *call;
    int scrape_interval;
    int collector_id;
    struct flb_luajit *lua;
    struct flb_input_instance *ins;
};

/* Read raw fields: user metatables must not execute outside lua_pcall(). */
static void get_field(lua_State *state, int index, const char *key)
{
    lua_pushstring(state, key);
    lua_rawget(state, index);
}

static const char *get_string(lua_State *state, int index, const char *key)
{
    const char *value = NULL;
    size_t length;

    get_field(state, index, key);
    if (lua_type(state, -1) == LUA_TSTRING) {
        value = lua_tolstring(state, -1, &length);
        if (strlen(value) != length) {
            value = NULL;
        }
    }
    lua_pop(state, 1);
    return value;
}

static int valid_name(const char *name, int metric)
{
    const unsigned char *p;

    if (!name || !*name) {
        return FLB_FALSE;
    }
    for (p = (const unsigned char *) name; *p; p++) {
        if ((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
            *p == '_' || (metric && *p == ':') ||
            (p != (const unsigned char *) name && *p >= '0' && *p <= '9')) {
            continue;
        }
        return FLB_FALSE;
    }
    return FLB_TRUE;
}

/* Reject sparse arrays, map keys and oversized results instead of truncating. */
static int array_size(lua_State *state, int index, int limit)
{
    int count = 0;
    size_t length;
    lua_Number key;

    if (!lua_istable(state, index)) {
        return -1;
    }
    length = lua_objlen(state, index);
    if (length > limit) {
        return -1;
    }
    lua_pushnil(state);
    while (lua_next(state, index)) {
        key = lua_tonumber(state, -2);
        if (lua_type(state, -2) != LUA_TNUMBER || key < 1 || key > length ||
            key != (int) key || ++count > limit) {
            lua_pop(state, 2);
            return -1;
        }
        lua_pop(state, 1);
    }
    return count == length ? count : -1;
}

static int read_labels(lua_State *state, int index, const char *field,
                       char **labels, int keys)
{
    int table;
    int count;
    int i;
    int j;
    size_t length;
    const char *value;

    get_field(state, index, field);
    if (lua_isnil(state, -1)) {
        lua_pop(state, 1);
        return 0;
    }
    table = lua_gettop(state);
    count = array_size(state, table, LM_MAX_LABELS);
    for (i = 0; i < count; i++) {
        lua_rawgeti(state, table, i + 1);
        if (lua_type(state, -1) != LUA_TSTRING) {
            lua_pop(state, 2);
            return -1;
        }
        value = lua_tolstring(state, -1, &length);
        if (strlen(value) != length ||
            (keys && (!valid_name(value, FLB_FALSE) || strncmp(value, "__", 2) == 0))) {
            lua_pop(state, 2);
            return -1;
        }
        labels[i] = (char *) value;
        if (keys) {
            for (j = 0; j < i; j++) {
                if (strcmp(labels[j], labels[i]) == 0) {
                    lua_pop(state, 2);
                    return -1;
                }
            }
        }
        lua_pop(state, 1);
    }
    lua_pop(state, 1);
    return count;
}

static int decode_family(lua_State *state, int family, struct cmt *cmt,
                         uint64_t timestamp)
{
    const char *name;
    const char *help;
    const char *type;
    char *keys[LM_MAX_LABELS];
    char *values[LM_MAX_LABELS];
    int label_count;
    int sample_count;
    int samples;
    int sample;
    int i;
    int ret;
    double value;
    struct cmt_gauge *gauge = NULL;
    struct cmt_counter *counter = NULL;

    if (!lua_istable(state, family)) {
        return -1;
    }
    name = get_string(state, family, "name");
    help = get_string(state, family, "help");
    type = get_string(state, family, "type");
    label_count = read_labels(state, family, "label_keys", keys, FLB_TRUE);
    if (!valid_name(name, FLB_TRUE) || !help || !*help || !type || label_count < 0) {
        return -1;
    }
    if (strcmp(type, "gauge") == 0) {
        gauge = cmt_gauge_create(cmt, "", "", (char *) name, (char *) help, label_count, keys);
        if (!gauge) {
            return -1;
        }
    }
    else if (strcmp(type, "counter") == 0) {
        counter = cmt_counter_create(cmt, "", "", (char *) name, (char *) help, label_count, keys);
        if (!counter) {
            return -1;
        }
    }
    else {
        return -1;
    }

    get_field(state, family, "samples");
    samples = lua_gettop(state);
    sample_count = array_size(state, samples, LM_MAX_SAMPLES);
    if (sample_count < 1) {
        return -1;
    }
    for (i = 0; i < sample_count; i++) {
        lua_rawgeti(state, samples, i + 1);
        sample = lua_gettop(state);
        if (!lua_istable(state, sample) ||
            read_labels(state, sample, "label_values", values, FLB_FALSE) != label_count) {
            return -1;
        }
        get_field(state, sample, "value");
        if (lua_type(state, -1) != LUA_TNUMBER) {
            return -1;
        }
        value = lua_tonumber(state, -1);
        lua_pop(state, 1);
        if (!isfinite(value) || (counter && value < 0)) {
            return -1;
        }
        if (gauge) {
            ret = cmt_gauge_set(gauge, timestamp, value, label_count, values);
        }
        else {
            ret = cmt_counter_set(counter, timestamp, value, label_count, values);
        }
        if (ret != 0) {
            return -1;
        }
        lua_pop(state, 1);
    }
    lua_pop(state, 1);
    return 0;
}

static int collect_metrics(struct flb_input_instance *ins, struct flb_config *config,
                           void *data)
{
    struct lua_metrics *ctx = data;
    lua_State *state = ctx->lua->state;
    struct cmt *cmt = NULL;
    const char *name;
    int count;
    int i;
    int ret = -1;
    uint64_t timestamp;

    lua_settop(state, 0);
    get_field(state, LUA_GLOBALSINDEX, ctx->call);
    if (lua_pcall(state, 0, 1, 0) != 0) {
        flb_plg_error(ins, "collection callback failed: %s",
                      lua_type(state, -1) == LUA_TSTRING ? lua_tostring(state, -1) : "Lua error");
        goto done;
    }
    count = array_size(state, 1, LM_MAX_FAMILIES);
    if (count < 0) {
        goto invalid;
    }
    if (count == 0) {
        ret = 0;
        goto done;
    }
    cmt = cmt_create();
    if (!cmt) {
        goto done;
    }
    timestamp = cfl_time_now();
    lua_newtable(state); /* Names must be unique within a collection. */
    for (i = 0; i < count; i++) {
        lua_rawgeti(state, 1, i + 1);
        if (!lua_istable(state, 3)) {
            goto invalid;
        }
        name = get_string(state, 3, "name");
        if (!name) {
            goto invalid;
        }
        get_field(state, 2, name);
        if (!lua_isnil(state, -1)) {
            goto invalid;
        }
        lua_pop(state, 1);
        lua_pushstring(state, name);
        lua_pushboolean(state, 1);
        lua_rawset(state, 2);
        if (decode_family(state, 3, cmt, timestamp) != 0) {
            goto invalid;
        }
        lua_pop(state, 1);
    }
    ret = flb_input_metrics_append(ins, NULL, 0, cmt);
    if (ret != 0) {
        flb_plg_error(ins, "could not append metrics");
    }
    goto done;

invalid:
    flb_plg_error(ins, "invalid metrics result; discarding collection");
done:
    if (cmt) {
        cmt_destroy(cmt);
    }
    lua_settop(state, 0);
    return ret;
}

static int cb_init(struct flb_input_instance *ins, struct flb_config *config, void *data)
{
    struct lua_metrics *ctx;
    lua_State *state;

    ctx = flb_calloc(1, sizeof(struct lua_metrics));
    if (!ctx) {
        return -1;
    }
    ctx->ins = ins;
    if (flb_input_config_map_set(ins, ctx) != 0 || !ctx->script || !ctx->call ||
        !*ctx->call || ctx->scrape_interval <= 0) {
        flb_plg_error(ins, "script, call and a positive scrape_interval are required");
        goto error;
    }
    ctx->lua = flb_luajit_create(config);
    if (!ctx->lua) {
        goto error;
    }
    state = ctx->lua->state;
    if (flb_luajit_load_script(ctx->lua, ctx->script) != 0 ||
        lua_pcall(state, 0, 0, 0) != 0) {
        flb_plg_error(ins, "could not load script %s", ctx->script);
        goto error;
    }
    get_field(state, LUA_GLOBALSINDEX, ctx->call);
    if (!lua_isfunction(state, -1)) {
        flb_plg_error(ins, "callback %s is not a function", ctx->call);
        goto error;
    }
    lua_pop(state, 1);
    ctx->collector_id = flb_input_set_collector_time(ins, collect_metrics,
                                                    ctx->scrape_interval, 0, config);
    if (ctx->collector_id < 0) {
        goto error;
    }
    flb_input_set_context(ins, ctx);
    return 0;

error:
    if (ctx->lua) {
        flb_luajit_destroy(ctx->lua);
    }
    flb_free(ctx);
    return -1;
}

static void cb_pause(void *data, struct flb_config *config)
{
    struct lua_metrics *ctx = data;

    flb_input_collector_pause(ctx->collector_id, ctx->ins);
}

static void cb_resume(void *data, struct flb_config *config)
{
    struct lua_metrics *ctx = data;

    flb_input_collector_resume(ctx->collector_id, ctx->ins);
}

static int cb_exit(void *data, struct flb_config *config)
{
    struct lua_metrics *ctx = data;

    flb_luajit_destroy(ctx->lua);
    flb_free(ctx);
    return 0;
}

static struct flb_config_map config_map[] = {
    {FLB_CONFIG_MAP_STR, "script", NULL, 0, FLB_TRUE,
     offsetof(struct lua_metrics, script), "Path to the Lua script."},
    {FLB_CONFIG_MAP_STR, "call", "collect", 0, FLB_TRUE,
     offsetof(struct lua_metrics, call), "Lua collection function."},
    {FLB_CONFIG_MAP_TIME, "scrape_interval", "10s", 0, FLB_TRUE,
     offsetof(struct lua_metrics, scrape_interval), "Collection interval (at least one second)."},
    {0}
};

struct flb_input_plugin in_lua_metrics_exporter_plugin = {
    .name = "lua_metrics_exporter",
    .description = "Collect native metrics from Lua scripts",
    .cb_init = cb_init,
    .cb_collect = collect_metrics,
    .cb_pause = cb_pause,
    .cb_resume = cb_resume,
    .cb_exit = cb_exit,
    .config_map = config_map,
    .flags = FLB_INPUT_THREADED
};
