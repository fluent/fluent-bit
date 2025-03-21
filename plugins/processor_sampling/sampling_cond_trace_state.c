/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2025 The Fluent Bit Authors
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
#include <fluent-bit/flb_slist.h>

#include "sampling.h"

struct cond_state_entry {
    cfl_sds_t kv;
    struct cfl_list _head;
};

struct cond_trace_state {
    struct cfl_list list_states;
};

static inline int slist_entry_compare(struct flb_slist_entry *entry, cfl_sds_t kv)
{
    if (flb_sds_len(entry->str) != cfl_sds_len(kv)) {
        return FLB_FALSE;
    }

    if (strncmp(entry->str, kv, flb_sds_len(kv)) == 0) {
        return FLB_TRUE;
    }

    return FLB_FALSE;
}

static inline int slist_check(struct mk_list *list, cfl_sds_t kv)
{
    struct mk_list *head;
    struct flb_slist_entry *entry;

    mk_list_foreach(head, list) {
        entry = mk_list_entry(head, struct flb_slist_entry, _head);
        if (slist_entry_compare(entry, kv) == FLB_TRUE) {
            return FLB_TRUE;
        }
    }

    return FLB_FALSE;
}

int cond_trace_state_check(struct sampling_condition *sampling_condition, struct ctrace_span *span)
{
    int ret;
    struct mk_list list;
    struct cfl_list *head;
    struct cond_trace_state *ctx;
    struct cond_state_entry *entry;

    ctx = sampling_condition->type_context;

    if (!span->trace_state) {
        return FLB_FALSE;
    }

    if (cfl_sds_len(span->trace_state) == 0) {
        return FLB_FALSE;
    }

    flb_slist_create(&list);
    ret = flb_slist_split_string(&list, span->trace_state, ',', 0);
    if (ret == -1) {
        return FLB_FALSE;
    }

    cfl_list_foreach(head, &ctx->list_states) {
        entry = cfl_list_entry(head, struct cond_state_entry, _head);

        ret = slist_check(&list, entry->kv);
        if (ret == FLB_TRUE) {
            flb_slist_destroy(&list);
            return FLB_TRUE;
        }
    }
    flb_slist_destroy(&list);

    /* no matches */
    return FLB_FALSE;
}

static int read_values_from_variant(struct sampling *ctx, struct cond_trace_state *cond, struct cfl_variant *var)
{
    int i;
    struct cfl_variant *value;
    struct cond_state_entry *entry;

    for (i = 0; i < var->data.as_array->entry_count; i++) {
        value = var->data.as_array->entries[i];
        if (value->type != CFL_VARIANT_STRING) {
            return -1;
        }

        entry = flb_calloc(1, sizeof(struct cond_state_entry));
        if (!entry) {
            flb_errno();
            return -1;
        }

        entry->kv = cfl_sds_create_len(value->data.as_string, flb_sds_len(value->data.as_string));
        if (!entry->kv) {
            flb_free(entry);
            return -1;
        }
        cfl_list_add(&entry->_head, &cond->list_states);
    }

    return 0;
}

struct sampling_condition *cond_trace_state_create(struct sampling *ctx,
                                                   struct sampling_conditions *sampling_conditions,
                                                   struct cfl_variant *settings)
{
    int ret;
    struct cfl_variant *var = NULL;
    struct cond_trace_state *cond;
    struct sampling_condition *sampling_condition;

    cond = flb_calloc(1, sizeof(struct cond_trace_state));
    if (!cond) {
        flb_errno();
        return NULL;
    }
    cfl_list_init(&cond->list_states);

    /* values */
    var = cfl_kvlist_fetch(settings->data.as_kvlist, "values");
    if (var) {
        if (var->type != CFL_VARIANT_ARRAY) {
            flb_plg_error(ctx->ins, "'values' must be an array");
            flb_free(cond);
            return NULL;
        }
    }
    else {
        flb_plg_error(ctx->ins, "missing 'values' in condition");
        flb_free(cond);
        return NULL;
    }

    ret = read_values_from_variant(ctx, cond, var);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "failed to read values from variant");

        return NULL;
    }

    sampling_condition = flb_calloc(1, sizeof(struct sampling_condition));
    if (!sampling_condition) {
        flb_errno();
        flb_free(cond);
        return NULL;
    }
    sampling_condition->type = SAMPLING_COND_TRACE_STATE;
    sampling_condition->type_context = cond;
    cfl_list_add(&sampling_condition->_head, &sampling_conditions->list);

    return sampling_condition;

}

void cond_trace_state_destroy(struct sampling_condition *sampling_condition)
{
    struct cfl_list *tmp;
    struct cfl_list *head;
    struct cond_state_entry *entry;
    struct cond_trace_state *ctx = sampling_condition->type_context;

    /* destroy states */
    cfl_list_foreach_safe(head, tmp, &ctx->list_states) {
        entry = cfl_list_entry(head, struct cond_state_entry, _head);
        cfl_sds_destroy(entry->kv);
        cfl_list_del(&entry->_head);
        flb_free(entry);
    }

    flb_free(ctx);
}
