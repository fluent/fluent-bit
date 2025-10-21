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

#ifndef FLB_ROUTER_H
#define FLB_ROUTER_H

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_event.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_conditionals.h>
#include <cfl/cfl.h>
#include <monkey/mk_core.h>

struct flb_mp_chunk_cobj;
struct flb_log_event_encoder;
struct flb_log_event_decoder;

struct flb_router_chunk_context {
    struct flb_mp_chunk_cobj *chunk_cobj;
    struct flb_log_event_encoder *log_encoder;
    struct flb_log_event_decoder *log_decoder;
};

struct flb_router_path {
    struct flb_output_instance *ins;
    struct flb_route *route;
    struct mk_list _head;
};

static inline int flb_router_match_type(int in_event_type,
                                        struct flb_output_instance *o_ins)
{
    if (in_event_type == FLB_INPUT_LOGS &&
        !(o_ins->event_type & FLB_OUTPUT_LOGS)) {
        return FLB_FALSE;
    }
    else if (in_event_type == FLB_INPUT_METRICS &&
             !(o_ins->event_type & FLB_OUTPUT_METRICS)) {
        return FLB_FALSE;
    }
    else if (in_event_type == FLB_INPUT_TRACES &&
             !(o_ins->event_type & FLB_OUTPUT_TRACES)) {
        return FLB_FALSE;
    }
    else if (in_event_type == FLB_INPUT_PROFILES &&
             !(o_ins->event_type & FLB_OUTPUT_PROFILES)) {
        return FLB_FALSE;
    }
    else if (in_event_type == FLB_INPUT_BLOBS &&
             !(o_ins->event_type & FLB_OUTPUT_BLOBS)) {
        return FLB_FALSE;
    }

    return FLB_TRUE;
}

enum flb_router_signal {
    FLB_ROUTER_SIGNAL_LOGS    = (1U << 0),
    FLB_ROUTER_SIGNAL_METRICS = (1U << 1),
    FLB_ROUTER_SIGNAL_TRACES  = (1U << 2),
    FLB_ROUTER_SIGNAL_ANY     = (FLB_ROUTER_SIGNAL_LOGS |
                                 FLB_ROUTER_SIGNAL_METRICS |
                                 FLB_ROUTER_SIGNAL_TRACES)
};

struct flb_route_condition_rule {
    flb_sds_t field;
    flb_sds_t op;
    flb_sds_t value;
    flb_sds_t *values;
    size_t values_count;
    struct cfl_list _head;
};

struct flb_route_condition {
    struct cfl_list rules;
    int is_default;
    enum flb_condition_operator op;
    struct flb_condition *compiled;
    int compiled_status;
};

struct flb_route_output {
    flb_sds_t name;
    flb_sds_t fallback;
    struct cfl_list _head;
};

struct flb_route_processor_property {
    flb_sds_t key;
    flb_sds_t value;
    struct cfl_list _head;
};

struct flb_route_processor {
    flb_sds_t name;
    struct cfl_list properties;
    struct cfl_list _head;
};

struct flb_route {
    flb_sds_t name;
    uint32_t signals;
    struct flb_route_condition *condition;
    struct cfl_list outputs;
    struct cfl_list processors;
    struct cfl_list _head;
};

struct flb_input_routes {
    flb_sds_t input_name;
    struct cfl_list processors;
    struct cfl_list routes;
    struct cfl_list _head;
};

int flb_router_connect(struct flb_input_instance *in,
                       struct flb_output_instance *out);
int flb_router_connect_direct(struct flb_input_instance *in,
                              struct flb_output_instance *out);

int flb_router_match(const char *tag, int tag_len,
                     const char *match, void *match_regex);
int flb_router_io_set(struct flb_config *config);
void flb_router_exit(struct flb_config *config);

uint32_t flb_router_signal_from_chunk(struct flb_event_chunk *chunk);

int flb_router_chunk_context_init(struct flb_router_chunk_context *context);
void flb_router_chunk_context_reset(struct flb_router_chunk_context *context);
void flb_router_chunk_context_destroy(struct flb_router_chunk_context *context);
int flb_router_chunk_context_prepare_logs(struct flb_router_chunk_context *context,
                                          struct flb_event_chunk *chunk);

int flb_route_condition_eval(struct flb_event_chunk *chunk,
                             struct flb_router_chunk_context *context,
                             struct flb_route *route);
int flb_condition_eval_logs(struct flb_event_chunk *chunk,
                            struct flb_router_chunk_context *context,
                            struct flb_route *route);
int flb_condition_eval_metrics(struct flb_event_chunk *chunk,
                               struct flb_router_chunk_context *context,
                               struct flb_route *route);
int flb_condition_eval_traces(struct flb_event_chunk *chunk,
                              struct flb_router_chunk_context *context,
                              struct flb_route *route);
int flb_router_path_should_route(struct flb_event_chunk *chunk,
                                 struct flb_router_chunk_context *context,
                                 struct flb_router_path *path);

struct flb_condition *flb_router_route_get_condition(struct flb_route *route);

struct flb_cf;

int flb_router_config_parse(struct flb_cf *cf,
                            struct cfl_list *input_routes,
                            struct flb_config *config);
void flb_router_routes_destroy(struct cfl_list *input_routes);
int flb_router_apply_config(struct flb_config *config);

#endif

