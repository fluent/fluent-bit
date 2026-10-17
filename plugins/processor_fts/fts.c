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
    if ((!ctx->script && !ctx->code) || (ctx->script && ctx->code)) {
        flb_plg_error(ins, "FTS requires exactly one of script or code");
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

static int cb_init(struct flb_processor_instance *ins, void *source, int type,
                   struct flb_config *config)
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

    /* Load the helpers and the policy script into a private Lua state */
    ret = fts_runtime_initialize(ctx, config);
    if (ret != FLB_PROCESSOR_SUCCESS) {
        l = ctx->vm ? ctx->vm->state : NULL;
        if (!l) {
            flb_plg_error(ins, "FTS initialization failed: VM allocation error");
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

    flb_processor_instance_set_context(ins, ctx);

    return FLB_PROCESSOR_SUCCESS;
}

static struct flb_config_map config_map[] = {
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

    /* EOF */
    {0}
};

struct flb_processor_plugin processor_fts_plugin = {
    .name = "fts",
    .description = "Fluent Typed Scripting: Lua-powered typed telemetry policies",
    .cb_init = cb_init,
    .cb_process_logs = fts_process_logs,
    .cb_process_metrics = fts_process_metrics,
    .cb_process_traces = fts_process_traces,
    .cb_exit = cb_exit,
    .config_map = config_map,
    .flags = FLB_PROCESSOR_FLAG_LOG_WINDOWS
};
