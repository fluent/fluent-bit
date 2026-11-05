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

#include <fluent-bit/flb_mem.h>

#include <limits.h>
#include <string.h>

#include "fts.h"
#include "fts_state.h"
#include "fts_window.h"
#include "fts_metric_window.h"
#include <fluent-bit/flb_plugin.h>
#include "fts_telemetry.h"

static int cb_exit(struct flb_processor_instance *ins, void *data)
{
    struct fts_runtime *ctx = data;

    if (!ctx) {
        return FLB_PROCESSOR_SUCCESS;
    }

    fts_runtime_destroy(ctx);
    flb_free(ctx);

    return FLB_PROCESSOR_SUCCESS;
}

static int config_validate(struct flb_processor_instance *ins, struct fts_runtime *ctx)
{
    if (!!ctx->script + !!ctx->code + !!ctx->recipe != 1) {
        flb_plg_error(ins, "FTS requires exactly one of script, code or recipe");
        return -1;
    }

    if (ctx->packs && (!ctx->recipe || !ctx->packages_dir)) {
        flb_plg_error(ins, "packs require recipe and an explicit packages_dir");
        return -1;
    }

    if (ctx->recipe && (strcmp(ctx->recipe_version, "1") != 0 || ctx->jit)) {
        flb_plg_error(ins, "recipe requires recipe_version=1 and jit=false");
        return -1;
    }
    if (strcmp(ctx->recipe_context, "native") != 0 &&
        strcmp(ctx->recipe_context, "otel") != 0 &&
        strcmp(ctx->recipe_context, "any") != 0) {
        flb_plg_error(ins, "context must be native, otel or any");
        return -1;
    }

    if (ctx->state_commit && (!ctx->recipe || strcmp(ctx->state_commit, "local") != 0)) {
        flb_plg_error(ins, "state_commit requires a recipe and value local");
        return -1;
    }

    if (strcmp(ctx->error_mode, "keep") != 0 && strcmp(ctx->error_mode, "drop") != 0) {
        flb_plg_error(ins, "error_mode must be keep or drop");
        return -1;
    }

    if (ctx->jit && ctx->instruction_limit != 0) {
        flb_plg_error(ins, "jit requires instruction_limit=0");
        return -1;
    }

    if (!ctx->jit && ctx->instruction_limit < 1000) {
        flb_plg_error(ins, "instruction_limit must be between 1000 and %d with jit disabled",
                      INT_MAX);
        return -1;
    }

    if (ctx->memory_limit < 262144) {
        flb_plg_error(ins, "memory_limit must be at least 262144 bytes (256 KiB)");
        return -1;
    }

    if (ctx->output_limit < 65536) {
        flb_plg_error(ins, "output_limit must be at least 65536 bytes (64 KiB)");
        return -1;
    }

    return 0;
}

static int initialize_context(struct flb_processor_instance *ins, struct flb_config *config,
                              int preflight)
{
    int ret;
    lua_State *l;
    struct fts_runtime *ctx;

    if (ins->event_type != FLB_PROCESSOR_LOGS && ins->event_type != FLB_PROCESSOR_METRICS &&
        ins->event_type != FLB_PROCESSOR_TRACES) {
        flb_plg_error(ins, "FTS supports logs, metrics and traces");
        return FLB_PROCESSOR_FAILURE;
    }

    ctx = flb_calloc(1, sizeof(struct fts_runtime));
    if (!ctx) {
        flb_errno();
        return FLB_PROCESSOR_FAILURE;
    }

    if (ins->event_type == FLB_PROCESSOR_LOGS) {
        ctx->adapter = &fts_logs_adapter;
    }
    else if (ins->event_type == FLB_PROCESSOR_METRICS) {
        ctx->adapter = &fts_metrics_adapter;
    }
    else {
        ctx->adapter = &fts_traces_adapter;
    }

    ret = flb_processor_instance_config_map_set(ins, ctx);
    if (ret != 0) {
        flb_plg_error(ins, "invalid FTS configuration value");
        cb_exit(ins, ctx);
        return FLB_PROCESSOR_FAILURE;
    }

    if (config_validate(ins, ctx) != 0) {
        cb_exit(ins, ctx);
        return FLB_PROCESSOR_FAILURE;
    }

    ctx->instance = ins;
    ctx->state_input = ins->pu && ins->pu->parent &&
        ((struct flb_processor *) ins->pu->parent)->source_plugin_type == FLB_PLUGIN_INPUT;

    /* Load the helpers and the policy script into a private Lua state */
    ret = fts_runtime_initialize(ctx, config);
    if (ret != FLB_PROCESSOR_SUCCESS) {
        l = ctx->vm ? ctx->vm->state : NULL;
        if (!l) {
            flb_plg_error(ins, "FTS initialization failed: VM allocation error");
        }
        else if (ctx->recipe) {
            fts_recipe_report_error(ins, ctx, "invalid_configuration");
            if (lua_type(l, -1) == LUA_TSTRING &&
                strcmp(lua_tostring(l, -1),
                       "merge_histogram_buckets must precede metrics.scale") == 0) {
                flb_plg_error(ins, "merge_histogram_buckets must precede metrics.scale");
            }
        }
        else if (lua_type(l, -1) == LUA_TSTRING) {
            flb_plg_error(ins, "FTS initialization failed: %.256s", lua_tostring(l, -1));
        }
        else {
            flb_plg_error(ins, "FTS initialization failed: non-string error");
        }
        cb_exit(ins, ctx);
        return FLB_PROCESSOR_FAILURE;
    }

    if (preflight) {
        cb_exit(ins, ctx);
        return FLB_PROCESSOR_SUCCESS;
    }

    if (fts_recipe_metrics_initialize(ins, ctx) != 0) {
        cb_exit(ins, ctx);
        return FLB_PROCESSOR_FAILURE;
    }

    if (fts_window_runtime_start(ctx) != 0 || fts_metric_window_start(ctx) != 0) {
        cb_exit(ins, ctx);
        return FLB_PROCESSOR_FAILURE;
    }

    flb_processor_instance_set_context(ins, ctx);

    return FLB_PROCESSOR_SUCCESS;
}

static int cb_input_stop(struct flb_processor_instance *ins, void *data)
{
    (void) ins;
    fts_window_runtime_stop(data);
    fts_metric_window_stop(data);
    return FLB_PROCESSOR_SUCCESS;
}

static int cb_init(struct flb_processor_instance *ins, void *source, int type,
                   struct flb_config *config)
{
    return initialize_context(ins, config, FLB_FALSE);
}

static int cb_preflight(struct flb_processor_instance *ins, struct flb_config *config)
{
    return initialize_context(ins, config, FLB_TRUE);
}

static struct flb_config_map config_map[] = {
    {
     FLB_CONFIG_MAP_VARIANT, "secret_refs", NULL,
     0, FLB_TRUE, offsetof(struct fts_runtime, secret_refs),
     "Map opaque HMAC key references to environment variable names, resolved at init."
    },
    {
     FLB_CONFIG_MAP_VARIANT, "packs", NULL,
     0, FLB_TRUE, offsetof(struct fts_runtime, packs),
     "Local pack manifest paths relative to packages_dir. No downloads."
    },
    {
     FLB_CONFIG_MAP_STR, "packages_dir", NULL,
     0, FLB_TRUE, offsetof(struct fts_runtime, packages_dir),
     "Directory containing trusted local Lua packs."
    },
    {
     FLB_CONFIG_MAP_VARIANT, "recipe", NULL,
     0, FLB_TRUE, offsetof(struct fts_runtime, recipe),
     "Ordered built-in block steps. Exclusive with script and code."
    },
    {
     FLB_CONFIG_MAP_STR, "recipe_version", "1",
     0, FLB_TRUE, offsetof(struct fts_runtime, recipe_version),
     "Recipe grammar version."
    },
    {
     FLB_CONFIG_MAP_STR, "context", "any",
     0, FLB_TRUE, offsetof(struct fts_runtime, recipe_context),
     "Recipe log context: native, otel or any."
    },
    {
     FLB_CONFIG_MAP_STR, "script", NULL,
     0, FLB_TRUE, offsetof(struct fts_runtime, script),
     "Path to the Lua policy script. Exclusive with 'code'."
    },
    {
     FLB_CONFIG_MAP_STR, "code", NULL,
     0, FLB_TRUE, offsetof(struct fts_runtime, code),
     "Inline Lua policy script. Exclusive with 'script'."
    },
    {
     FLB_CONFIG_MAP_STR, "call", "process",
     0, FLB_TRUE, offsetof(struct fts_runtime, call),
     "Name of the Lua function invoked for every telemetry item."
    },
    {
     FLB_CONFIG_MAP_STR, "error_mode", "drop",
     0, FLB_TRUE, offsetof(struct fts_runtime, error_mode),
     "Action when a policy fails: 'drop' the item or 'keep' the original."
    },
    {
     FLB_CONFIG_MAP_BOOL, "jit", "false",
     0, FLB_TRUE, offsetof(struct fts_runtime, jit),
     "Enable the LuaJIT compiler for trusted policies. Requires instruction_limit=0."
    },
    {
     FLB_CONFIG_MAP_INT, "instruction_limit", "1000000",
     0, FLB_TRUE, offsetof(struct fts_runtime, instruction_limit),
     "Maximum number of Lua instructions per callback."
    },
    {
     FLB_CONFIG_MAP_SIZE, "output_limit", "64M",
     0, FLB_TRUE, offsetof(struct fts_runtime, output_limit),
     "Maximum serialized size of a processed batch."
    },
    {
     FLB_CONFIG_MAP_SIZE, "memory_limit", "32M",
     0, FLB_TRUE, offsetof(struct fts_runtime, memory_limit),
     "Maximum memory used by the policy: Lua heap plus typed values."
    },

    {
     FLB_CONFIG_MAP_STR, "state_commit", NULL,
     0, FLB_TRUE, offsetof(struct fts_runtime, state_commit),
     "Stateful recipes require explicit local commit; no delivery guarantee."
    },
    {
     FLB_CONFIG_MAP_SIZE, "state_limit", "1M",
     0, FLB_TRUE, offsetof(struct fts_runtime, state_limit),
     "Maximum native state bytes, including provisional entries and bookkeeping."
    },

    /* EOF */
    {0}
};

struct flb_processor_plugin processor_fts_plugin = {
    .name = "fts",
    .description = "Fluent Typed Scripting: Lua-powered typed telemetry policies",
    .cb_preflight = cb_preflight,
    .cb_init = cb_init,
    .cb_process_logs = fts_process_logs,
    .cb_process_metrics = fts_process_metrics,
    .cb_process_traces = fts_process_traces,
    .cb_exit = cb_exit,
    .cb_input_stop = cb_input_stop,
    .config_map = config_map,
    .flags = FLB_PROCESSOR_FLAG_PREFLIGHT | FLB_PROCESSOR_FLAG_LOG_WINDOWS |
             FLB_PROCESSOR_FLAG_INPUT_STOP
};
