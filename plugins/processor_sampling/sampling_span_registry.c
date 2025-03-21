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

struct sampling_span_registry *sampling_span_registry_create(uint64_t max_traces)
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
    cfl_list_init(&reg->trace_list_complete);
    cfl_list_init(&reg->trace_list_incomplete);

    reg->max_traces = max_traces;

    return reg;
}

static void sampling_span_registry_delete_traces(struct sampling *ctx, struct sampling_span_registry *reg)
{
    struct cfl_list *head;
    struct cfl_list *tmp;
    struct trace_entry *t_entry;

    cfl_list_foreach_safe(head, tmp, &reg->trace_list) {
        t_entry = cfl_list_entry(head, struct trace_entry, _head);
        cfl_list_del(&t_entry->_head);
        cfl_list_del(&t_entry->_head_complete);

        /* free the trace_entry */
        cfl_sds_destroy(t_entry->hex_trace_id);

        ctr_id_destroy(t_entry->trace_id);
        flb_free(t_entry);
    }
}

void sampling_span_registry_destroy(struct sampling_span_registry *reg)
{
    if (!reg) {
        return;
    }

    sampling_span_registry_delete_traces(NULL, reg);

    if (reg->ht) {
        flb_hash_table_destroy(reg->ht);
    }
    flb_free(reg);
}

int sampling_span_registry_delete_entry(struct sampling *ctx, struct sampling_span_registry *reg,
                                        struct trace_entry *t_entry, int delete_spans)
{
    int ret;
    struct cfl_list *head_span;
    struct cfl_list *tmp_span;
    struct trace_span *t_span;

    /* remove from the hash table */
    ret = flb_hash_table_del_ptr(reg->ht, ctr_id_get_buf(t_entry->trace_id), ctr_id_get_len(t_entry->trace_id), t_entry);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "failed to delete trace entry from buffer");
        return -1;
    }

    /* remove from the linked list */
    cfl_list_del(&t_entry->_head);
    cfl_list_del(&t_entry->_head_complete);

    /* free the trace_entry */
    cfl_sds_destroy(t_entry->hex_trace_id);

    ctr_id_destroy(t_entry->trace_id);

    /* delete trace spans (this don't delete spans!) */
    cfl_list_foreach_safe(head_span, tmp_span, &t_entry->span_list) {
        t_span = cfl_list_entry(head_span, struct trace_span, _head);
        if (delete_spans) {
            ctr_span_destroy(t_span->span);
        }

        cfl_list_del(&t_span->_head);
        flb_free(t_span);
    }

    flb_free(t_entry);

    reg->count_traces--;

    return 0;
}

int sampling_span_registry_add_span(struct sampling *ctx, struct sampling_span_registry *reg, struct ctrace_span *span)
{
    int ret;
    size_t out_size = 0;
    cfl_sds_t hex_trace_id;
    struct cfl_list *head;
    struct trace_entry *t_entry;
    struct trace_entry *t_entry_delete;
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
        t_entry->ts_created = time(NULL);
        t_entry->ts_last_updated = t_entry->ts_created;
        cfl_list_init(&t_entry->span_list);

        /* trace_id */
        t_entry->trace_id = ctr_id_create(ctr_id_get_buf(span->trace_id), ctr_id_get_len(span->trace_id));
        if (!t_entry->trace_id) {
            flb_plg_error(ctx->ins, "failed to create trace_id");
            flb_free(t_entry);
            return -1;
        }

        /* hex trace id (for test/dev purposes mostly) */
        hex_trace_id = ctr_id_to_lower_base16(span->trace_id);
        if (!hex_trace_id) {
            flb_plg_error(ctx->ins, "failed to convert trace_id to readable format");
            flb_free(t_entry);
            return -1;
        }
        t_entry->hex_trace_id = hex_trace_id;
        cfl_list_add(&t_entry->_head, &reg->trace_list);

        /* always add a new trace into the incomplete list */
        cfl_list_add(&t_entry->_head_complete, &reg->trace_list_incomplete);

        /* add to the hash table */
        ret = flb_hash_table_add(reg->ht,
                                 ctr_id_get_buf(span->trace_id),
                                 ctr_id_get_len(span->trace_id),
                                 t_entry, 0);
        if (ret == -1) {
            flb_plg_error(ctx->ins, "failed to add trace entry to buffer");
            cfl_list_del(&t_entry->_head);
            cfl_list_del(&t_entry->_head_complete);
            flb_free(t_entry);
            return -1;
        }

        reg->count_traces++;
    }

    /* update if the trace is completed */
    if (!span->parent_span_id) {
        t_entry->is_trace_complete = FLB_TRUE;

        /* move entry to the complete list */
        cfl_list_del(&t_entry->_head_complete);
        cfl_list_add(&t_entry->_head_complete, &reg->trace_list_complete);
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

    /* if the new number of traces exceeds max_traces, delete the oldest one */
    if (reg->count_traces > reg->max_traces) {
        cfl_list_foreach(head, &reg->trace_list) {
            t_entry_delete = cfl_list_entry(head, struct trace_entry, _head);

            /* delete the first entry from the list */
            sampling_span_registry_delete_entry(ctx, reg, t_entry_delete, FLB_TRUE);
            break;
        }
    }
    return 0;
}

int sampling_span_registry_add_trace(struct sampling *ctx, struct sampling_span_registry *reg, struct ctrace *ctr)
{
    int ret;
    struct cfl_list *tmp;
    struct cfl_list *head;
    struct ctrace_span *span;

    /* iterate spans */
    cfl_list_foreach_safe(head, tmp, &ctr->span_list) {
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
        printf("   │ trace_id=%s                       │\n", t_entry->hex_trace_id);
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

