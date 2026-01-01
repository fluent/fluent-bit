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

#ifndef FLB_PROCESSOR_SAMPLING_H
#define FLB_PROCESSOR_SAMPLING_H

#include <fluent-bit/flb_processor_plugin.h>
#include <ctraces/ctraces.h>

enum {
    SAMPLING_TYPE_PROBABILISTIC = 0,
    SAMPLING_TYPE_TAIL,

    /* unused: for dev/test purposes only */
    SAMPLING_TYPE_TEST,
};

struct trace_span {
    struct ctrace_span *span;

    /* link to struct trace_entry->span_list */
    struct cfl_list _head;
};

struct trace_entry {
    /* binary trace_id (this wraps a cfl_sds_t) */
    struct ctrace_id *trace_id;

    /* trace_id in hex format */
    cfl_sds_t hex_trace_id;

    /* describe if the root span has been received */
    int is_trace_complete;

    /* Linked list of spans */
    struct cfl_list span_list;

    uint64_t ts_created;
    uint64_t ts_last_updated;

    /* link to struct sampling->trace_list */
    struct cfl_list _head;

    /* link to struct sampling->trace_list_complete or trace_list_incomplete */
    struct cfl_list _head_complete;
};

enum {
    SAMPLING_COND_STATUS_CODE = 0,
    SAMPLING_COND_LATENCY,
    SAMPLING_COND_STRING_ATTRIBUTE,
    SAMPLING_COND_NUMERIC_ATTRIBUTE,
    SAMPLING_COND_BOOLEAN_ATTRIBUTE,
    SAMPLING_COND_SPAN_COUNT,
    SAMPLING_COND_TRACE_STATE,
};

struct sampling_condition {
    int type;
    void *type_context;
    struct cfl_list _head;
};

struct sampling_conditions {
    struct cfl_list list;
};

struct sampling {
    /* config map properties */
    flb_sds_t type_str;
    bool debug_mode;
    struct cfl_variant *sampling_settings;
    struct cfl_variant *conditions;

    /*
     * Internal
     * --------
     */
    int type;  /* sampling type */

    struct cfl_list plugins;

    struct sampling_conditions *sampling_conditions;

    /* plugin registration structure */
    struct sampling_plugin *plugin;

    /* Lists for config map and rule properties: this list is created dinamically */
    void *plugin_context;
    struct mk_list plugin_settings_properties;
    struct mk_list *plugin_config_map;

    /* Processor instance */
    struct flb_processor_instance *ins;

    /* Parent input plugin instance */
    struct flb_input_instance *input_ins;
};

/* Common structure for all sampling mechanisms */
struct sampling_plugin {
    char *name;
    int type;
    struct flb_config_map *config_map;
    int (*cb_init) (struct flb_config *config, struct sampling *ctx);
    int (*cb_do_sampling) (struct sampling *ctx, void *context,
                           struct ctrace *in_trace, struct ctrace **out_trace);
    int (*cb_exit) (struct flb_config *config, void *context);
    struct cfl_list _head;
};

/* Plugins registration */
extern struct sampling_plugin sampling_test_plugin;
extern struct sampling_plugin sampling_probabilistic_plugin;
extern struct sampling_plugin sampling_tail_plugin;

static inline void sampling_set_context(struct sampling *ctx, void *plugin_context)
{
    ctx->plugin_context = plugin_context;
}

/* sampling_conf */
int sampling_config_process_rules(struct flb_config *config, struct sampling *ctx);

int sampling_config_map_set(struct flb_config *config, struct sampling *ctx, void *plugin_ctx, struct flb_config_map *map);

struct sampling *sampling_config_create(struct flb_processor_instance *processor_instance,
                                        struct flb_config *config);
void sampling_config_destroy(struct flb_config *config, struct sampling *ctx);

/* conditions */
struct sampling_conditions *sampling_conditions_create(struct sampling *ctx, struct cfl_variant *conditions);
int sampling_conditions_check(struct sampling *ctx, struct sampling_conditions *sampling_conditions,
                              struct trace_entry *trace_entry, struct ctrace_span *span);

void sampling_conditions_destroy(struct sampling_conditions *sampling_conditions);

/*
 * conditions types
 * ----------------
 */

/* condition: status_codes_check */
struct sampling_condition *cond_status_codes_create(struct sampling *ctx,
                                                    struct sampling_conditions *sampling_conditions,
                                                    struct cfl_variant *settings);
int cond_status_codes_check(struct sampling_condition *sampling_condition, struct ctrace_span *span);
void cond_status_codes_destroy(struct sampling_condition *sampling_condition);

/* condition: latency */
struct sampling_condition *cond_latency_create(struct sampling *ctx,
                                               struct sampling_conditions *sampling_conditions,
                                               struct cfl_variant *settings);
int cond_latency_check(struct sampling_condition *sampling_condition, struct ctrace_span *span);
void cond_latency_destroy(struct sampling_condition *sampling_condition);

/* condition: string_attribute */
struct sampling_condition *cond_string_attr_create(struct sampling *ctx,
                                                   struct sampling_conditions *sampling_conditions,
                                                   struct cfl_variant *settings);
int cond_string_attr_check(struct sampling_condition *sampling_condition, struct ctrace_span *span);
void cond_string_attr_destroy(struct sampling_condition *sampling_condition);

/* condition: numeric_attribute */
struct sampling_condition *cond_numeric_attr_create(struct sampling *ctx,
                                                    struct sampling_conditions *sampling_conditions,
                                                    struct cfl_variant *settings);
void cond_numeric_attr_destroy(struct sampling_condition *sampling_condition);


/* condition: boolean_attribute */
struct sampling_condition *cond_boolean_attr_create(struct sampling *ctx,
                                                    struct sampling_conditions *sampling_conditions,
                                                    struct cfl_variant *settings);
void cond_boolean_attr_destroy(struct sampling_condition *sampling_condition);

/* condition: span_count */
int cond_span_count_check(struct sampling_condition *sampling_condition, struct trace_entry *trace_entry, struct ctrace_span *span);

struct sampling_condition *cond_span_count_create(struct sampling *ctx,
                                                  struct sampling_conditions *sampling_conditions,
                                                  struct cfl_variant *settings);
void cond_span_count_destroy(struct sampling_condition *sampling_condition);

/* condition: trace_state */
int cond_trace_state_check(struct sampling_condition *sampling_condition, struct ctrace_span *span);
struct sampling_condition *cond_trace_state_create(struct sampling *ctx,
                                                   struct sampling_conditions *sampling_conditions,
                                                   struct cfl_variant *settings);
void cond_trace_state_destroy(struct sampling_condition *sampling_condition);

#endif