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


#include <fluent-bit/flb_processor_plugin.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_hash.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_processor.h>
#include <fluent-bit/flb_log_event_decoder.h>
#include <fluent-bit/flb_log_event_encoder.h>

#include "cm.h"
#include "cm_config.h"

static int cb_init(struct flb_processor_instance *ins, void *source_plugin_instance,
                   int source_plugin_type, struct flb_config *config)
{
    struct content_modifier_ctx *ctx;

    ctx = cm_config_create(ins, config);
    if (!ctx) {
        return -1;
    }

    flb_processor_instance_set_context(ins, ctx);

    return FLB_PROCESSOR_SUCCESS;
}

static int cb_exit(struct flb_processor_instance *ins, void *data)
{
    struct content_modifier_ctx *ctx;

    if (!ins) {
        return FLB_PROCESSOR_SUCCESS;
    }

    ctx = data;
    if (ctx) {
        cm_config_destroy(ctx);
    }

    return FLB_PROCESSOR_SUCCESS;
}

static int cb_process_logs(struct flb_processor_instance *ins,
                           void *chunk_data,
                           const char *tag,
                           int tag_len)
{
    int ret;
    struct content_modifier_ctx *ctx;
    struct flb_mp_chunk_cobj *chunk_cobj = (struct flb_mp_chunk_cobj *) chunk_data;

    if (!ins->context) {
        return FLB_PROCESSOR_FAILURE;
    }
    ctx = ins->context;

    ret = cm_logs_process(ins, ctx, chunk_cobj, tag, tag_len);
    return ret;

}

static int cb_process_traces(struct flb_processor_instance *ins,
                             struct ctrace *in_ctr,
                             struct ctrace **out_ctr,
                             const char *tag,
                             int tag_len)
{
    int ret;
    struct content_modifier_ctx *ctx;

    if (!ins->context) {
        return FLB_PROCESSOR_FAILURE;
    }
    ctx = ins->context;

    ret = cm_traces_process(ins, ctx, in_ctr, out_ctr, tag, tag_len);
    return ret;

}

static int cb_process_metrics(struct flb_processor_instance *ins,
                              struct cmt *in_cmt,
                              struct cmt **out_cmt,
                              const char *tag,
                              int tag_len)
{
    int ret;
    struct content_modifier_ctx *ctx;

    if (!ins->context) {
        return FLB_PROCESSOR_FAILURE;
    }
    ctx = ins->context;

    ret = cm_metrics_process(ins, ctx, in_cmt, out_cmt, tag, tag_len);
    return ret;
}

static struct flb_config_map config_map[] = {
    {
        FLB_CONFIG_MAP_STR, "context", NULL,
        0, FLB_TRUE, offsetof(struct content_modifier_ctx, context_str),
        "Context where the action will be applied."
    },

    {
        FLB_CONFIG_MAP_STR, "action", NULL,
        0, FLB_TRUE, offsetof(struct content_modifier_ctx, action_str),
        "Action to perform over the content: insert, upsert, delete, rename or hash."
    },

    {
        FLB_CONFIG_MAP_STR, "key", NULL,
        0, FLB_TRUE, offsetof(struct content_modifier_ctx, key),
        "Key to apply the action."
    },

    {
        FLB_CONFIG_MAP_STR, "value", NULL,
        0, FLB_TRUE, offsetof(struct content_modifier_ctx, value),
        "Value to apply the action."
    },

    {
        FLB_CONFIG_MAP_STR, "pattern", NULL,
        0, FLB_TRUE, offsetof(struct content_modifier_ctx, pattern),
        "Pattern used to create a regular expression."
    },

    {
        FLB_CONFIG_MAP_STR, "converted_type", NULL,
        0, FLB_TRUE, offsetof(struct content_modifier_ctx, converted_type_str),
        "Specify the data type to convert to, allowed values are: int, double or string."
    },

    /* EOF */
    {0}
};

struct flb_processor_plugin processor_content_modifier_plugin = {
    .name               = "content_modifier",
    .description        = "Modify the content of Logs, Metrics and Traces",
    .cb_init            = cb_init,
    .cb_process_logs    = cb_process_logs,
    .cb_process_metrics = cb_process_metrics,
    .cb_process_traces  = cb_process_traces,
    .cb_exit            = cb_exit,
    .config_map         = config_map,
    .flags              = 0
};
