/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2024 The Fluent Bit Authors
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

#include <fluent-bit/flb_filter.h>
#include <fluent-bit/flb_lib.h>
#include <fluent-bit/flb_lua.h>
#include <fluent-bit/flb_luajit.h>
#include <fluent-bit/flb_mp.h>
#include <fluent-bit/flb_processor_plugin.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_hash.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_processor.h>
#include <fluent-bit/flb_log_event_decoder.h>
#include <fluent-bit/flb_log_event_encoder.h>

#include "calyptia_defs.h"
#include "calyptia_logs.h"
#include "calyptia_metrics.h"
#include "calyptia_traces.h"
#include "cfl_to_lua.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

static void calyptia_config_destroy(struct calyptia_context *ctx)
{
    if (!ctx) {
        return;
    }

    if (ctx->code) {
        flb_sds_destroy(ctx->code);
        ctx->code = NULL;
    }

    if (ctx->script) {
        flb_sds_destroy(ctx->script);
        ctx->script = NULL;
    }

    if (ctx->lua) {
        flb_luajit_destroy(ctx->lua);
        ctx->lua = NULL;
    }

    flb_free(ctx);
}

static struct calyptia_context *
calyptia_config_create(struct flb_processor_instance *ins,
                       struct flb_config *config)
{
    int ret;
    int err;
    char buf[PATH_MAX];
    const char *tmp = NULL;
    const char *script = NULL;
    struct stat st;
    struct flb_luajit *lj;
    (void) config;
    struct calyptia_context *ctx;

    /* Allocate context */
    ctx = flb_calloc(1, sizeof(struct calyptia_context));
    if (!ctx) {
        flb_errno();
        return NULL;
    }
    ret = flb_processor_instance_config_map_set(ins, (void *) ctx);
    if (ret < 0) {
        flb_errno();
        flb_plg_error(ins, "configuration error");
        flb_free(ctx);
        return NULL;
    }

    ctx->ins = ins;

    /* config: code */
    tmp = flb_processor_instance_get_property("code", ins);
    if (tmp) {
        ctx->code = flb_sds_create(tmp);
    }
    else {
        /* config: script */
        script = flb_processor_instance_get_property("script", ins);
        if (!script) {
            flb_plg_error(ins, "either \"script\" or \"code\" must be set");
            calyptia_config_destroy(ctx);
            return NULL;
        }

        /* Compose path */
        ret = stat(script, &st);
        if (ret == -1 && errno == ENOENT) {
            if (script[0] == '/') {
                flb_plg_error(ins, "cannot access script '%s'", script);
                calyptia_config_destroy(ctx);
                return NULL;
            }

            if (config->conf_path) {
                snprintf(buf, sizeof(buf) - 1, "%s%s", config->conf_path,
                         script);
                script = buf;
            }
        }

        /* Validate script path */
        ret = access(script, R_OK);
        if (ret == -1) {
            flb_plg_error(ins, "cannot access script '%s'", script);
            calyptia_config_destroy(ctx);
            return NULL;
        }

        ctx->script = flb_sds_create(script);
        if (!ctx->script) {
            flb_plg_error(ins, "could not allocate string");
            calyptia_config_destroy(ctx);
            return NULL;
        }
    }

    if (!ctx->call) {
        flb_plg_error(ctx->ins, "\"call\" is not set");
        calyptia_config_destroy(ctx);
        return NULL;
    }

    /* Create LuaJIT state/vm */
    lj = flb_luajit_create(config);
    if (!lj) {
        calyptia_config_destroy(ctx);
        return NULL;
    }

    ctx->lua = lj;

    /* Load the lua helpers */
    if (flb_luajit_load_buffer(ctx->lua, calyptia_processor_lua_helpers,
                               strlen(calyptia_processor_lua_helpers),
                               "processor_helpers.lua")) {
        calyptia_config_destroy(ctx);
        return NULL;
    }

    /* this is here to allow passing options to the lua helpers */
    lua_createtable(ctx->lua->state, 0, 1);
    lua_pushboolean(ctx->lua->state, ctx->disable_warnings);
    lua_setfield(ctx->lua->state, -2, "disable_warnings");
    lua_setglobal(ctx->lua->state, "LUA_HELPERS_OPTS");

    /* execute the lua helpers script, we expect 3 helper functions as return
     * value */
    err = lua_pcall(ctx->lua->state, 0, 3, 0);
    if (err) {
        flb_error("[luajit] invalid lua content, error=%d: %s", err,
                  lua_tostring(lj->state, -1));
        calyptia_config_destroy(ctx);
        return NULL;
    }

    /* push registry key for logs helper */
    lua_pushlightuserdata(ctx->lua->state, (void *) LUA_LOGS_HELPER_KEY);
    /* push the logs helper function */
    lua_pushvalue(ctx->lua->state, -4);
    /* store it in the registry */
    lua_settable(ctx->lua->state, LUA_REGISTRYINDEX);

    /* push registry key for metrics helper */
    lua_pushlightuserdata(ctx->lua->state, (void *) LUA_METRICS_HELPER_KEY);
    /* push the metrics helper function */
    lua_pushvalue(ctx->lua->state, -3);
    /* store it in the registry */
    lua_settable(ctx->lua->state, LUA_REGISTRYINDEX);

    /* push registry key for traces helper */
    lua_pushlightuserdata(ctx->lua->state, (void *) LUA_TRACES_HELPER_KEY);
    /* push the traces helper function */
    lua_pushvalue(ctx->lua->state, -2);
    /* store it in the registry */
    lua_settable(ctx->lua->state, LUA_REGISTRYINDEX);
    /* pop the helpers */
    lua_pop(ctx->lua->state, 3);

    /* Load the lua script */
    if (ctx->code) {
        if (flb_luajit_load_buffer(ctx->lua, ctx->code, flb_sds_len(ctx->code),
                                   "processor.lua")) {
            calyptia_config_destroy(ctx);
            return NULL;
        }
    }
    else if (flb_luajit_load_script(ctx->lua, ctx->script)) {
        calyptia_config_destroy(ctx);
        return NULL;
    }

    if (ctx->opts) {
        push_variant(ctx->lua->state, ctx->opts);
    }

    /* Execute the lua script */
    err = lua_pcall(ctx->lua->state, ctx->opts ? 1 : 0, 0, 0);
    if (err) {
        flb_error("[luajit] invalid lua content, error=%d: %s", err,
                  lua_tostring(lj->state, -1));
        calyptia_config_destroy(ctx);
        return NULL;
    }

    if (flb_lua_is_valid_func(ctx->lua->state, ctx->call) != FLB_TRUE) {
        flb_plg_error(ctx->ins, "function %s is not found", ctx->call);
        calyptia_config_destroy(ctx);
        return NULL;
    }

    return ctx;
}

static int cb_init(struct flb_processor_instance *ins,
                   void *source_plugin_instance, int source_plugin_type,
                   struct flb_config *config)
{
    struct calyptia_context *ctx;

    ctx = calyptia_config_create(ins, config);
    if (!ctx) {
        return -1;
    }

    flb_processor_instance_set_context(ins, ctx);

    return FLB_PROCESSOR_SUCCESS;
}

static int cb_exit(struct flb_processor_instance *ins, void *data)
{
    struct calyptia_context *ctx;

    if (!ins) {
        return FLB_PROCESSOR_SUCCESS;
    }

    ctx = data;
    if (ctx) {
        calyptia_config_destroy(ctx);
    }

    return FLB_PROCESSOR_SUCCESS;
}

static struct flb_config_map config_map[]
    = { { FLB_CONFIG_MAP_STR, "code", NULL, 0, FLB_FALSE, 0,
          "String that contains the Lua script source code" },
        { FLB_CONFIG_MAP_STR, "script", NULL, 0, FLB_FALSE, 0,
          "The path of lua script." },
        { FLB_CONFIG_MAP_STR, "call", NULL, 0, FLB_TRUE,
          offsetof(struct calyptia_context, call),
          "Lua function that will be called to process logs." },
        { FLB_CONFIG_MAP_BOOL, "disable_warnings", "false", 0, FLB_TRUE,
          offsetof(struct calyptia_context, disable_warnings),
          "Disable warnings from lua helpers." },
        { FLB_CONFIG_MAP_VARIANT, "opts", NULL, 0, FLB_TRUE,
          offsetof(struct calyptia_context, opts),
          "Arguments object passed to Lua script" },
        { 0 } };

struct flb_processor_plugin processor_calyptia_plugin
    = { .name = "calyptia",
        .description = "Use lua to process logs, metrics and traces",
        .cb_init = cb_init,
        .cb_process_logs = calyptia_process_logs,
        .cb_process_metrics = calyptia_process_metrics,
        .cb_process_traces = calyptia_process_traces,
        .cb_exit = cb_exit,
        .config_map = config_map,
        .flags = 0 };
