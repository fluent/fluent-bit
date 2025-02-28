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

#include "sampling.h"
#include "sampling_span_registry.h"

struct sampling_span_registry *sampling_span_registry_create()
{
    struct sampling_span_registry *reg;

    reg = flb_calloc(1, sizeof(struct sampling_span_registry));
    if (!reg) {
        flb_errno();
        return NULL;
    }

    reg->ht = flb_hash_table_create(FLB_HASH_TABLE_EVICT_NONE, 1024, 0);
    if (!reg->ht) {
        flb_free(reg);
        return NULL;
    }
    cfl_list_init(&reg->trace_list);

    return reg;
}

void sampling_span_registry_destroy(struct sampling_span_registry *reg)
{
    if (!reg) {
        return;
    }

    if (reg->ht) {
        flb_hash_table_destroy(reg->ht);
    }

    flb_free(reg);
}

int sampling_span_registry_add_span(struct sampling *ctx, struct sampling_span_registry *reg, struct ctrace_span *span)
{
    int ret;
    size_t out_size = 0;
    cfl_sds_t trace_id;
    struct trace_entry *t_entry;
    struct trace_span *t_span;

    /* convert trace_id to readable format */
    if (!span->trace_id) {
        flb_plg_error(ctx->ins, "trace_id is missing in span %s", span->name);
        return -1;
    }

    if (!span->span_id) {
        flb_plg_error(ctx->ins, "span_id is missing in span %s", span->name);
        return -1;
    }


    /* check if the trace_id exists or not in the trace_buffer hash table */
    ret = flb_hash_table_get(reg->ht,
                             ctr_id_get_buf(span->trace_id),
                             ctr_id_get_len(span->trace_id),
                             (void **) &t_entry, &out_size);
    if (ret == -1) {
        /* create a new trace_entry for the trace_id in question */
        t_entry = flb_calloc(1, sizeof(struct trace_entry));
        if (!t_entry) {
            flb_errno();
            return -1;
        }

        t_entry->ts_created = cfl_time_now();
        t_entry->ts_last_updated = t_entry->ts_created;

        cfl_list_init(&t_entry->span_list);

        trace_id = ctr_id_to_lower_base16(span->trace_id);
        if (!trace_id) {
            flb_plg_error(ctx->ins, "failed to convert trace_id to readable format");
            flb_free(t_entry);
            return -1;
        }
        t_entry->trace_id = trace_id;
        cfl_list_add(&t_entry->_head, &reg->trace_list);

        ret = flb_hash_table_add(reg->ht,
                                 ctr_id_get_buf(span->trace_id),
                                 ctr_id_get_len(span->trace_id),
                                 t_entry, 0);
        if (ret == -1) {
            flb_plg_error(ctx->ins, "failed to add trace entry to buffer");
            flb_free(t_entry);
            return -1;
        }
    }

    /* add the span to the trace_entry */
    t_span = flb_calloc(1, sizeof(struct trace_span));
    if (!t_span) {
        flb_errno();
        return -1;
    }
    t_span->span = span;
    cfl_list_add(&t_span->_head, &t_entry->span_list);

    /* update timestamp */
    t_entry->ts_last_updated = cfl_time_now();
    return 0;
}

int sampling_span_registry_add_trace(struct sampling *ctx, struct sampling_span_registry *reg, struct ctrace *ctr)
{
    int ret;
    struct cfl_list *head;
    struct ctrace_span *span;

    /* iterate spans */
    cfl_list_foreach(head, &ctr->span_list) {
        span = cfl_list_entry(head, struct ctrace_span, _head_global);
        ret = sampling_span_registry_add_span(ctx, reg, span);
        if (ret != 0) {
            flb_plg_error(ctx->ins, "failed to process span: %s", span->name);
            return -1;
        }
    }

    return 0;
}

int sampling_span_registry_print(struct sampling *ctx, struct sampling_span_registry *reg, char *title)
{
    struct cfl_list *head;
    struct cfl_list *head_span;
    struct trace_entry *t_entry;
    struct trace_span *t_span;
    cfl_sds_t span_id;

    printf("\n");
    printf("🔍 %s\n", title);
    cfl_list_foreach(head, &reg->trace_list) {
        t_entry = cfl_list_entry(head, struct trace_entry, _head);
        printf("   ┌─────────────────────────────────────────────────────────────────┐\n");
        printf("   │ trace_id=%s                       │\n", t_entry->trace_id);
        printf("   ├─────────────────────────────────────────────────────────────────┤\n");
        printf("   │ spans:                                                          │\n");

        /* iterate spans */
        cfl_list_foreach(head_span, &t_entry->span_list) {
            t_span = cfl_list_entry(head_span, struct trace_span, _head);

            span_id = ctr_id_to_lower_base16(t_span->span->span_id);
            if (!span_id) {
                flb_plg_error(ctx->ins, "failed to convert span_id to readable format");
                return -1;
            }
            printf("   │   ├── id=%s name=%-32s │\n", span_id, t_span->span->name);

            cfl_sds_destroy(span_id);
        }
        printf("   └─────────────────────────────────────────────────────────────────┘\n\n");
    }

    return 0;
}

