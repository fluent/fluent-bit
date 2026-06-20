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

#ifndef FLB_PROCESSOR_SAMPLING_SPAN_REGISTRY_H
#define FLB_PROCESSOR_SAMPLING_SPAN_REGISTRY_H

#include <fluent-bit/flb_processor_plugin.h>

struct sampling_span_registry {
    struct flb_hash_table *ht;

    uint64_t count_traces;
    uint64_t max_traces;

    /* linked lists of trace_entries inside the hash table (ht) using the _head node */
    struct cfl_list trace_list;

    /* the following two lists puts the trace into a complete or incomplete status */
    struct cfl_list trace_list_complete;
    struct cfl_list trace_list_incomplete;
};

struct sampling_span_registry *sampling_span_registry_create(uint64_t max_traces);
void sampling_span_registry_destroy(struct sampling_span_registry *reg);
int sampling_span_registry_delete_entry(struct sampling *ctx, struct sampling_span_registry *reg,
                                        struct trace_entry *t_entry, int delete_spans);
int sampling_span_registry_add_trace(struct sampling *ctx, struct sampling_span_registry *reg, struct ctrace *ctr);
int sampling_span_registry_print(struct sampling *ctx, struct sampling_span_registry *reg, char *title);

#endif
