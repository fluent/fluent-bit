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

#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_router.h>
#include <fluent-bit/flb_conditionals.h>
#include <fluent-bit/flb_log_event_decoder.h>
#include <fluent-bit/flb_mp.h>
#include <fluent-bit/flb_mp_chunk.h>

#define FLB_ROUTE_CONDITION_COMPILED_SUCCESS  1
#define FLB_ROUTE_CONDITION_COMPILED_FAILURE -1

static struct flb_condition *route_condition_get_compiled(struct flb_route_condition *condition);
static void route_condition_record_destroy(struct flb_mp_chunk_record *record);

uint32_t flb_router_signal_from_chunk(struct flb_event_chunk *chunk)
{
    if (!chunk) {
        return 0;
    }

    switch (chunk->type) {
    case FLB_EVENT_TYPE_LOGS:
        return FLB_ROUTER_SIGNAL_LOGS;
    case FLB_EVENT_TYPE_METRICS:
        return FLB_ROUTER_SIGNAL_METRICS;
    case FLB_EVENT_TYPE_TRACES:
        return FLB_ROUTER_SIGNAL_TRACES;
    default:
        break;
    }

    return 0;
}

int flb_condition_eval_logs(struct flb_event_chunk *chunk,
                            struct flb_route *route)
{
    int ret;
    int result = FLB_FALSE;
    struct flb_route_condition *condition;
    struct flb_condition *compiled;
    struct flb_log_event_decoder decoder;
    struct flb_log_event event;
    struct flb_mp_chunk_record record;

    if (!chunk || !route || !route->condition) {
        return FLB_FALSE;
    }

    if (!chunk->data || chunk->size == 0) {
        return FLB_FALSE;
    }

    condition = route->condition;

    compiled = route_condition_get_compiled(condition);
    if (!compiled) {
        return FLB_FALSE;
    }

    ret = flb_log_event_decoder_init(&decoder, chunk->data, chunk->size);
    if (ret != FLB_EVENT_DECODER_SUCCESS) {
        return FLB_FALSE;
    }

    flb_log_event_decoder_read_groups(&decoder, FLB_TRUE);

    while ((ret = flb_log_event_decoder_next(&decoder, &event)) == FLB_EVENT_DECODER_SUCCESS) {
        memset(&record, 0, sizeof(record));
        record.event = event;

        if (event.metadata) {
            record.cobj_metadata = flb_mp_object_to_cfl(event.metadata);
            if (!record.cobj_metadata) {
                route_condition_record_destroy(&record);
                break;
            }
        }

        if (event.body) {
            record.cobj_record = flb_mp_object_to_cfl(event.body);
            if (!record.cobj_record) {
                route_condition_record_destroy(&record);
                break;
            }
        }

        if (flb_condition_evaluate(compiled, &record) == FLB_TRUE) {
            result = FLB_TRUE;
            route_condition_record_destroy(&record);
            break;
        }

        route_condition_record_destroy(&record);
    }

    flb_log_event_decoder_destroy(&decoder);

    return result;
}

int flb_condition_eval_metrics(struct flb_event_chunk *chunk,
                               struct flb_route *route)
{
    (void) chunk;
    (void) route;

    return FLB_FALSE;
}

int flb_condition_eval_traces(struct flb_event_chunk *chunk,
                              struct flb_route *route)
{
    (void) chunk;
    (void) route;

    return FLB_FALSE;
}

int flb_route_condition_eval(struct flb_event_chunk *chunk,
                             struct flb_route *route)
{
    uint32_t signal;

    if (!route) {
        return FLB_FALSE;
    }

    if (!route->condition) {
        return FLB_TRUE;
    }

    signal = flb_router_signal_from_chunk(chunk);
    if (signal == 0) {
        return FLB_FALSE;
    }

    if ((route->signals != 0) && (route->signals != FLB_ROUTER_SIGNAL_ANY) && ((route->signals & signal) == 0)) {
        return FLB_FALSE;
    }

    if (route->condition->is_default) {
        return FLB_TRUE;
    }

    switch (signal) {
    case FLB_ROUTER_SIGNAL_LOGS:
        return flb_condition_eval_logs(chunk, route);
    case FLB_ROUTER_SIGNAL_METRICS:
        return flb_condition_eval_metrics(chunk, route);
    case FLB_ROUTER_SIGNAL_TRACES:
        return flb_condition_eval_traces(chunk, route);
    default:
        break;
    }

    return FLB_FALSE;
}

int flb_router_path_should_route(struct flb_event_chunk *chunk,
                                 struct flb_router_path *path)
{
    if (!path) {
        return FLB_FALSE;
    }

    if (!path->route) {
        return FLB_TRUE;
    }

    return flb_route_condition_eval(chunk, path->route);
}

static int parse_rule_operator(const flb_sds_t op_str,
                               enum flb_rule_operator *out)
{
    if (!op_str || !out) {
        return -1;
    }

    if (strcasecmp(op_str, "eq") == 0) {
        *out = FLB_RULE_OP_EQ;
    }
    else if (strcasecmp(op_str, "neq") == 0) {
        *out = FLB_RULE_OP_NEQ;
    }
    else if (strcasecmp(op_str, "gt") == 0) {
        *out = FLB_RULE_OP_GT;
    }
    else if (strcasecmp(op_str, "lt") == 0) {
        *out = FLB_RULE_OP_LT;
    }
    else if (strcasecmp(op_str, "gte") == 0) {
        *out = FLB_RULE_OP_GTE;
    }
    else if (strcasecmp(op_str, "lte") == 0) {
        *out = FLB_RULE_OP_LTE;
    }
    else if (strcasecmp(op_str, "regex") == 0) {
        *out = FLB_RULE_OP_REGEX;
    }
    else if (strcasecmp(op_str, "not_regex") == 0) {
        *out = FLB_RULE_OP_NOT_REGEX;
    }
    else if (strcasecmp(op_str, "in") == 0) {
        *out = FLB_RULE_OP_IN;
    }
    else if (strcasecmp(op_str, "not_in") == 0) {
        *out = FLB_RULE_OP_NOT_IN;
    }
    else {
        return -1;
    }

    return 0;
}

static int parse_numeric_value(flb_sds_t value, double *out)
{
    char *endptr = NULL;
    double result;

    if (!value || !out) {
        return -1;
    }

    errno = 0;
    result = strtod(value, &endptr);
    if (errno == ERANGE || endptr == value || (endptr && *endptr != '\0')) {
        return -1;
    }

    *out = result;
    return 0;
}

static struct flb_condition *route_condition_compile(struct flb_route_condition *condition)
{
    int ret;
    double numeric_value;
    enum flb_rule_operator op;
    struct cfl_list *head;
    struct flb_condition *compiled;
    struct flb_route_condition_rule *rule;

    compiled = flb_condition_create(condition->op);
    if (!compiled) {
        return NULL;
    }

    cfl_list_foreach(head, &condition->rules) {
        rule = cfl_list_entry(head, struct flb_route_condition_rule, _head);

        if (!rule->field || !rule->op) {
            flb_condition_destroy(compiled);
            return NULL;
        }

        if (parse_rule_operator(rule->op, &op) != 0) {
            flb_condition_destroy(compiled);
            return NULL;
        }

        switch (op) {
        case FLB_RULE_OP_EQ:
        case FLB_RULE_OP_NEQ:
        case FLB_RULE_OP_REGEX:
        case FLB_RULE_OP_NOT_REGEX:
            if (!rule->value) {
                flb_condition_destroy(compiled);
                return NULL;
            }
            ret = flb_condition_add_rule(compiled, rule->field, op,
                                         rule->value, 1, RECORD_CONTEXT_BODY);
            break;
        case FLB_RULE_OP_GT:
        case FLB_RULE_OP_LT:
        case FLB_RULE_OP_GTE:
        case FLB_RULE_OP_LTE:
            if (!rule->value) {
                flb_condition_destroy(compiled);
                return NULL;
            }
            if (parse_numeric_value(rule->value, &numeric_value) != 0) {
                flb_condition_destroy(compiled);
                return NULL;
            }
            ret = flb_condition_add_rule(compiled, rule->field, op,
                                         &numeric_value, 1, RECORD_CONTEXT_BODY);
            break;
        case FLB_RULE_OP_IN:
        case FLB_RULE_OP_NOT_IN:
            if (!rule->values || rule->values_count == 0) {
                flb_condition_destroy(compiled);
                return NULL;
            }
            ret = flb_condition_add_rule(compiled, rule->field, op,
                                         rule->values,
                                         (int) rule->values_count,
                                         RECORD_CONTEXT_BODY);
            break;
        default:
            flb_condition_destroy(compiled);
            return NULL;
        }

        if (ret != FLB_TRUE) {
            flb_condition_destroy(compiled);
            return NULL;
        }
    }

    return compiled;
}

static struct flb_condition *route_condition_get_compiled(struct flb_route_condition *condition)
{
    if (!condition) {
        return NULL;
    }

    if (condition->compiled_status == FLB_ROUTE_CONDITION_COMPILED_FAILURE) {
        return NULL;
    }

    if (condition->compiled_status == FLB_ROUTE_CONDITION_COMPILED_SUCCESS &&
        condition->compiled) {
        return condition->compiled;
    }

    condition->compiled = route_condition_compile(condition);
    if (!condition->compiled) {
        condition->compiled_status = FLB_ROUTE_CONDITION_COMPILED_FAILURE;
        return NULL;
    }

    condition->compiled_status = FLB_ROUTE_CONDITION_COMPILED_SUCCESS;
    return condition->compiled;
}

static void route_condition_record_destroy(struct flb_mp_chunk_record *record)
{
    if (!record) {
        return;
    }

    if (record->cobj_record) {
        cfl_object_destroy(record->cobj_record);
        record->cobj_record = NULL;
    }

    if (record->cobj_metadata) {
        cfl_object_destroy(record->cobj_metadata);
        record->cobj_metadata = NULL;
    }
}

