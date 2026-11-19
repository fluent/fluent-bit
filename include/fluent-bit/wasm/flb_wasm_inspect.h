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

#ifndef FLB_WASM_INSPECT_H
#define FLB_WASM_INSPECT_H

/*
 * Browser SDK inspection: reports routing decisions, it never changes them.
 * Everything here exists only in Emscripten builds; in any other build the
 * trace macro expands to nothing.
 */
#ifdef __EMSCRIPTEN__

#include <stddef.h>

struct flb_config;
struct flb_route;
struct flb_input_instance;
struct flb_filter_instance;
struct flb_output_instance;

/*
 * Results are JSON documents in a malloc(3) buffer owned by the caller.
 * Return 0 on success. On -1 no buffer is returned.
 */

/*
 * Evaluate one route condition against sample log records.
 *
 *   in:  {"condition": {...}, "records": [{...}], "metadata": [{...}]}
 *   out: {"matched": [true, false]}  or  {"error": "reason"}
 *
 * 'metadata' is optional and parallel to 'records'.
 */
int flb_wasm_inspect_condition(const char *json, size_t size,
                               char **out, size_t *out_size);

/* Connections the engine made for a loaded configuration. */
int flb_wasm_inspect_topology(struct flb_config *config,
                              char **out, size_t *out_size);

/* Per-record trace. Disabled until flb_wasm_trace_set(FLB_TRUE). */
extern int flb_wasm_trace_active;

void flb_wasm_trace_set(int enabled);
/* out: {"events": [...], "dropped": N}; the buffer is emptied. */
int flb_wasm_trace_take(char **out, size_t *out_size);

void flb_wasm_trace_append(struct flb_input_instance *ins,
                           const char *tag, size_t tag_len, size_t records);
void flb_wasm_trace_route(struct flb_input_instance *ins, size_t record,
                          struct flb_route *route, int is_default);
void flb_wasm_trace_unrouted(struct flb_input_instance *ins, size_t record);
void flb_wasm_trace_filter(struct flb_filter_instance *filter,
                           struct flb_input_instance *ins,
                           const char *tag, size_t tag_len,
                           size_t records_in, size_t records_out, int modified);
void flb_wasm_trace_output(struct flb_output_instance *output,
                           struct flb_input_instance *ins,
                           const char *tag, size_t tag_len, size_t records);
void flb_wasm_trace_undelivered(struct flb_input_instance *ins,
                                const char *tag, size_t tag_len, size_t records);

/* One predictable branch while tracing is off. */
#define FLB_WASM_TRACE(call) do { if (flb_wasm_trace_active) { call; } } while (0)

#else

#define FLB_WASM_TRACE(call) do { } while (0)

#endif /* __EMSCRIPTEN__ */

#endif
