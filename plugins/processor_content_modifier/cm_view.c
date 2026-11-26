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
#include <fluent-bit/flb_log_view.h>

#include "cm.h"

/*
 * EXPERIMENTAL: the same edits cm_logs.c applies to a cfl_kvlist, expressed
 * on a CFL map view. Keys and values come from the instance context,
 * which outlives every batch.
 */
int cm_logs_view_maps(struct flb_processor_instance *ins)
{
    struct content_modifier_ctx *ctx;

    ctx = ins->context;
    if (ctx != NULL && ctx->context_type == CM_CONTEXT_OTEL_LOG_ATTR &&
        (ctx->action_type == CM_ACTION_INSERT || ctx->action_type == CM_ACTION_UPSERT ||
         ctx->action_type == CM_ACTION_DELETE || ctx->action_type == CM_ACTION_RENAME)) {
        return FLB_LOG_VIEW_OTEL_LOG_ATTRIBUTES;
    }

    return 0;
}

int cm_logs_process_view(struct flb_processor_instance *ins, struct flb_log_view *record,
                         const char *tag, int tag_len)
{
    int ret;
    int64_t match;
    struct cfl_view *view;
    struct content_modifier_ctx *ctx;

    (void) tag;
    (void) tag_len;
    ctx = ins->context;
    view = record->otel_log_attributes;
    if (view == NULL) {
        return FLB_PROCESSOR_SUCCESS;
    }

    ret = 0;
    match = cfl_view_find(view, ctx->key, cfl_sds_len(ctx->key));
    if (ctx->action_type == CM_ACTION_INSERT) {
        /* insert requires the key to be missing, it is silent otherwise */
        if (match < 0) {
            ret = cfl_view_append_string(view, ctx->key, cfl_sds_len(ctx->key),
                                             ctx->value, cfl_sds_len(ctx->value));
        }
    }
    else if (ctx->action_type == CM_ACTION_UPSERT) {
        if (match >= 0) {
            cfl_view_remove_at(view, (size_t) match);
        }
        ret = cfl_view_append_string(view, ctx->key, cfl_sds_len(ctx->key),
                                         ctx->value, cfl_sds_len(ctx->value));
    }
    else if (ctx->action_type == CM_ACTION_DELETE) {
        if (match >= 0) {
            ret = cfl_view_remove_at(view, (size_t) match);
        }
    }
    else if (ctx->action_type == CM_ACTION_RENAME) {
        if (match >= 0) {
            ret = cfl_view_rename_at(view, (size_t) match, ctx->value,
                                         cfl_sds_len(ctx->value));
        }
    }

    return ret == 0 ? FLB_PROCESSOR_SUCCESS : FLB_PROCESSOR_FAILURE;
}
