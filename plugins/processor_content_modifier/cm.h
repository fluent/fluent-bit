/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2024 The Fluent Bit Authors
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

#ifndef FLB_PROCESSOR_CONTENT_MODIFIER_H
#define FLB_PROCESSOR_CONTENT_MODIFIER_H

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_mp_chunk.h>

enum {
    CM_TELEMETRY_LOGS = 1,
    CM_TELEMETRY_METRICS,
    CM_TELEMETRY_TRACES
};

/* Actions that can be applied */
enum {
    CM_ACTION_INSERT = 1,
    CM_ACTION_UPSERT,
    CM_ACTION_DELETE,
    CM_ACTION_RENAME,
    CM_ACTION_HASH,
    CM_ACTION_EXTRACT,
    CM_ACTION_CONVERT
};

/* Telemetry contexts */
enum {
    CM_CONTEXT_UNDEFINED = 0,

    /* Logs */
    CM_CONTEXT_LOG_METADATA,
    CM_CONTEXT_LOG_BODY,

    CM_CONTEXT_OTEL_RESOURCE_ATTR,
    CM_CONTEXT_OTEL_SCOPE_NAME,
    CM_CONTEXT_OTEL_SCOPE_VERSION,
    CM_CONTEXT_OTEL_SCOPE_ATTR,

    /* Metrics */
    CM_CONTEXT_METRIC_NAME,
    CM_CONTEXT_METRIC_DESCRIPTION,
    CM_CONTEXT_METRIC_LABELS,

    /* Traces */
    CM_CONTEXT_TRACE_SPAN_NAME,
    CM_CONTEXT_TRACE_SPAN_KIND,
    CM_CONTEXT_TRACE_SPAN_STATUS,
    CM_CONTEXT_TRACE_SPAN_ATTRIBUTES,
};

struct cm_actions {
    /*
     * Based on the type, we either register a key/value pair or a
     * single string value
     */
    union {
        struct cfl_kv *kv;
        cfl_sds_t str;
    } value;

    /* Link to struct proc_attr_rules->rules */
    struct cfl_list _head;
};

struct content_modifier_ctx {
    int telemetry_type;

    /* Type of action (e.g. ..._ACTION_DELETE, ..._ACTION_INSERT )*/
    int action_type;

    /* Context where the action is applied */
    int context_type;

    /* CFL_VARIANT numerical type representation of converted_type_str */
    int converted_type;

    /* public configuration properties */
    flb_sds_t action_str;          /* converted to action_type  */
    flb_sds_t context_str;         /* converted to context_type */
    flb_sds_t pattern;             /* pattern to create 'regex' context */
    flb_sds_t converted_type_str;  /* converted_type */
    flb_sds_t key;                 /* target key */
    flb_sds_t value;               /* used for any value */
    struct flb_regex *regex;       /* regular expression context created from 'pattern' */

    /* processor instance reference */
    struct flb_processor_instance *ins;
};

/* Export telemetry functions */
int cm_logs_process(struct flb_processor_instance *ins,
                    struct content_modifier_ctx *ctx,
                    struct flb_mp_chunk_cobj *chunk_cobj,
                    const char *tag,
                    int tag_len);

int cm_traces_process(struct flb_processor_instance *ins,
                      struct content_modifier_ctx *ctx,
                      struct ctrace *traces_context,
                      struct ctrace **out_traces_context,
                      const char *tag, int tag_len);

int cm_metrics_process(struct flb_processor_instance *ins,
                       struct content_modifier_ctx *ctx,
                       struct cmt *in_cmt,
                       struct cmt **out_cmt,
                       const char *tag, int tag_len);

#endif
