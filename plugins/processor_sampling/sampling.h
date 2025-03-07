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

#ifndef FLB_PROCESSOR_SAMPLING_H
#define FLB_PROCESSOR_SAMPLING_H

#include <fluent-bit/flb_processor_plugin.h>
#include <ctraces/ctraces.h>

enum {
    SAMPLING_TYPE_TEST = 0,
    SAMPLING_TYPE_PROBABILISTIC,
    SAMPLING_TYPE_RATE_LIMITING,
    SAMPLING_TYPE_DYNAMIC,
};

struct trace_span {
    struct ctrace_span *span;

    /* link to struct trace_entry->span_list */
    struct cfl_list _head;
};

struct trace_entry {
    /* trace_id in hex format */
    cfl_sds_t trace_id;

    /* Linked list of spans */
    struct cfl_list span_list;

    uint64_t ts_created;
    uint64_t ts_last_updated;

    /* link to struct sampling->trace_list */
    struct cfl_list _head;
};

struct sampling {
    /* config map properties */
    flb_sds_t type_str;
    bool debug_mode;
    struct cfl_variant *rules;

    /*
     * Internal
     * --------
     */
    int type;  /* sampling type */

    struct cfl_list plugins;

    /* plugin registration structure */
    struct sampling_plugin *plugin;

    /* Lists for config map and rule properties: this list is created dinamically */
    void *plugin_context;
    struct mk_list plugin_rules_properties;
    struct mk_list *plugin_config_map;

    /* Processor instance */
    struct flb_processor_instance *ins;
};

/* Common structure for all sampling mechanisms */
struct sampling_plugin {
    char *name;
    int type;
    struct flb_config_map *config_map;
    int (*cb_init) (struct flb_config *config, struct sampling *ctx);
    int (*cb_do_sampling) (struct sampling *ctx, void *context, struct ctrace *trace);
    int (*cb_exit) (struct flb_config *config, void *context);
    struct cfl_list _head;
};

/* Plugins registration */
extern struct sampling_plugin sampling_test_plugin;
extern struct sampling_plugin sampling_probabilistic_plugin;

static inline void sampling_set_context(struct sampling *ctx, void *plugin_context)
{
    ctx->plugin_context = plugin_context;
}

/* sampling_conf */
int sampling_config_process_rules(struct flb_config *config, struct sampling *ctx);

int sampling_config_map_set(struct flb_config *config, struct sampling *ctx, void *plugin_ctx, struct flb_config_map *map);

//char *sampling_config_type_str(int type);
struct sampling *sampling_config_create(struct flb_processor_instance *processor_instance,
                                        struct flb_config *config);
void sampling_config_destroy(struct flb_config *config, struct sampling *ctx);

#endif