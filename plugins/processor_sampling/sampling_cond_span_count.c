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
#include <fluent-bit/flb_regex.h>

#include "sampling.h"
#include "sampling_cond_attribute.h"

struct cond_span_count {
    int min_spans;
    int max_spans;
};

int cond_span_count_check(struct sampling_condition *sampling_condition,
                          struct trace_entry *trace_entry, struct ctrace_span *span)
{
    int span_count = 0;
    struct cond_span_count *ctx;

    ctx = sampling_condition->type_context;
    span_count = cfl_list_size(&trace_entry->span_list);

    if (span_count >= ctx->min_spans && span_count <= ctx->max_spans) {
        return FLB_TRUE;
    }

    return FLB_FALSE;
}

struct sampling_condition *cond_span_count_create(struct sampling *ctx,
                                                  struct sampling_conditions *sampling_conditions,
                                                  struct cfl_variant *settings)
{
    struct cfl_variant *var;
    struct cond_span_count *cond;
    struct sampling_condition *sampling_condition;

    cond = flb_calloc(1, sizeof(struct cond_span_count));
    if (!cond) {
        flb_errno();
        return NULL;
    }

    /* min_spans */
    var = cfl_kvlist_fetch(settings->data.as_kvlist, "min_spans");
    if (var) {
        if (var->type != CFL_VARIANT_INT && var->type != CFL_VARIANT_UINT) {
            flb_plg_error(ctx->ins, "'min_spans' must be an integer");
            flb_free(cond);
            return NULL;
        }

        if (var->type == CFL_VARIANT_INT) {
            cond->min_spans = var->data.as_int64;
        }
        else {
            cond->min_spans = (int64_t) var->data.as_uint64;
        }
    }
    else {
        flb_plg_error(ctx->ins, "missing 'min_spans' in condition");
        flb_free(cond);
        return NULL;
    }


    /* max_spans */
    var = cfl_kvlist_fetch(settings->data.as_kvlist, "max_spans");
    if (var) {
        if (var->type != CFL_VARIANT_INT && var->type != CFL_VARIANT_UINT) {
            flb_plg_error(ctx->ins, "'max_spans' must be an integer");
            flb_free(cond);
            return NULL;
        }

        if (var->type == CFL_VARIANT_INT) {
            cond->max_spans = var->data.as_int64;
        }
        else {
            cond->max_spans = (int64_t) var->data.as_uint64;
        }
    }
    else {
        flb_plg_error(ctx->ins, "missing 'max_spans' in condition");
        flb_free(cond);
        return NULL;
    }

    if (cond->min_spans > cond->max_spans) {
        flb_plg_error(ctx->ins, "'min_spans' must be less than 'max_spans'");
        flb_free(cond);
        return NULL;
    }

    sampling_condition = flb_calloc(1, sizeof(struct sampling_condition));
    if (!sampling_condition) {
        flb_errno();
        flb_free(cond);
        return NULL;
    }
    sampling_condition->type = SAMPLING_COND_SPAN_COUNT;
    sampling_condition->type_context = cond;
    cfl_list_add(&sampling_condition->_head, &sampling_conditions->list);

    return sampling_condition;

}

void cond_span_count_destroy(struct sampling_condition *sampling_condition)
{
    struct cond_span_count *ctx = sampling_condition->type_context;
    flb_free(ctx);
}
