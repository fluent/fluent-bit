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
#include "sampling.h"

/* condition: status_code */
struct cond_status_code {
    int status_unset;
    int status_ok;
    int status_error;
};

int cond_status_codes_check(struct sampling_condition *sampling_condition, struct ctrace_span *span)
{
    struct cond_status_code *ctx = sampling_condition->type_context;

    if (span->status.code == CTRACE_SPAN_STATUS_CODE_UNSET) {
        if (ctx->status_unset == FLB_TRUE) {
            return FLB_TRUE;
        }
    }
    else if (span->status.code == CTRACE_SPAN_STATUS_CODE_OK) {
        if (ctx->status_ok == FLB_TRUE) {
            return FLB_TRUE;
        }
    }
    else if (span->status.code == CTRACE_SPAN_STATUS_CODE_ERROR) {
        if (ctx->status_error == FLB_TRUE) {
            return FLB_TRUE;
        }
    }

    return FLB_FALSE;
}

struct sampling_condition *cond_status_codes_create(struct sampling *ctx,
                                                    struct sampling_conditions *sampling_conditions,
                                                    struct cfl_variant *settings)
{
    int i;
    struct cond_status_code *cond;
    struct cfl_variant *var;
    struct cfl_variant *status_code;
    struct sampling_condition *sampling_condition;

    cond = flb_calloc(1, sizeof(struct cond_status_code));
    if (!cond) {
        flb_errno();
        return NULL;
    }

    /* get option status_codes */
    var = cfl_kvlist_fetch(settings->data.as_kvlist, "status_codes");
    if (!var) {
        flb_plg_error(ctx->ins, "missing 'status_codes' in condition");
        flb_free(cond);
        return NULL;
    }

    if (var->type != CFL_VARIANT_ARRAY) {
        flb_plg_error(ctx->ins, "status_codes must be an array");
        flb_free(cond);
        return NULL;
    }

    /* iterate status codes */
    for (i = 0; i < var->data.as_array->entry_count; i++) {
        status_code = var->data.as_array->entries[i];
        if (status_code->type != CFL_VARIANT_STRING) {
            flb_plg_error(ctx->ins, "status code must be an string");
            flb_free(cond);
            return NULL;
        }

        if (strcasecmp(status_code->data.as_string, "UNSET") == 0) {
            cond->status_unset = FLB_TRUE;
        }
        else if (strcasecmp(status_code->data.as_string, "OK") == 0) {
            cond->status_ok = FLB_TRUE;
        }
        else if (strcasecmp(status_code->data.as_string, "ERROR") == 0) {
            cond->status_error = FLB_TRUE;
        }
        else {
            flb_plg_error(ctx->ins, "invalid status code '%s'", status_code->data.as_string);
            flb_free(cond);
            return NULL;
        }
    }

    sampling_condition = flb_calloc(1, sizeof(struct sampling_condition));
    if (!sampling_condition) {
        flb_errno();
        flb_free(cond);
        return NULL;
    }
    sampling_condition->type = SAMPLING_COND_STATUS_CODE;
    sampling_condition->type_context = cond;
    cfl_list_add(&sampling_condition->_head, &sampling_conditions->list);

    return sampling_condition;
}

void cond_status_codes_destroy(struct sampling_condition *sampling_condition)
{
    struct cond_status_code *cond = sampling_condition->type_context;
    flb_free(cond);
}
