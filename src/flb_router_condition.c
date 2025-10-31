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
#include <fluent-bit/flb_log_event_encoder.h>
#include <fluent-bit/flb_log_event_decoder.h>
#include <fluent-bit/flb_mp_chunk.h>
#include <cfl/cfl_kvlist.h>

#define FLB_ROUTE_CONDITION_COMPILED_SUCCESS  1
#define FLB_ROUTE_CONDITION_COMPILED_FAILURE -1

static struct flb_condition *route_condition_get_compiled(struct flb_route_condition *condition);

static inline struct cfl_variant *get_object_variant(struct cfl_object *object)
{
    if (!object) {
        return NULL;
    }

    return object->variant;
}

static inline struct cfl_variant *get_body_variant(struct flb_mp_chunk_record *record)
{
    if (!record || !record->cobj_record) {
        return NULL;
    }

    return record->cobj_record->variant;
}

static struct cfl_variant *get_otel_container_variant(struct flb_mp_chunk_record *record,
                                                      const char *key,
                                                      int use_group_attributes)
{
    struct cfl_variant *source;
    struct cfl_variant *container;

    /* For OTLP, resource/scope attributes are in group_attributes, not body */
    if (use_group_attributes && record->cobj_group_attributes && record->cobj_group_attributes->variant) {
        source = record->cobj_group_attributes->variant;
    }
    else {
        source = get_body_variant(record);
    }

    if (!source || source->type != CFL_VARIANT_KVLIST) {
        return NULL;
    }

    container = cfl_kvlist_fetch(source->data.as_kvlist, key);
    if (!container || container->type != CFL_VARIANT_KVLIST) {
        return NULL;
    }

    return container;
}

static struct cfl_variant *get_otel_attributes_variant(struct flb_mp_chunk_record *record,
                                                       enum record_context_type context_type)
{
    struct cfl_variant *container;
    const char *container_key = NULL;

    if (context_type == RECORD_CONTEXT_OTEL_RESOURCE_ATTRIBUTES) {
        container_key = "resource";
    }
    else if (context_type == RECORD_CONTEXT_OTEL_SCOPE_ATTRIBUTES) {
        container_key = "scope";
    }
    else {
        return NULL;
    }

    /* For OTLP resource/scope attributes, look in group_attributes first */
    container = get_otel_container_variant(record, container_key, 1);
    if (!container) {
        return NULL;
    }

    container = cfl_kvlist_fetch(container->data.as_kvlist, "attributes");
    if (!container || container->type != CFL_VARIANT_KVLIST) {
        return NULL;
    }

    return container;
}

static struct cfl_variant *get_otel_scope_metadata_variant(struct flb_mp_chunk_record *record)
{
    struct cfl_variant *scope;

    /* For OTLP scope metadata, also check group_attributes first */
    scope = get_otel_container_variant(record, "scope", 1);
    if (!scope || scope->type != CFL_VARIANT_KVLIST) {
        return NULL;
    }

    return scope;
}

static struct cfl_variant *route_logs_get_variant(struct flb_condition_rule *rule,
                                                  void *ctx)
{
    struct flb_mp_chunk_record *record = (struct flb_mp_chunk_record *) ctx;

    if (!rule || !record) {
        return NULL;
    }

    switch (rule->context) {
    case RECORD_CONTEXT_METADATA:
        return get_object_variant(record->cobj_metadata);
    case RECORD_CONTEXT_BODY:
        return get_body_variant(record);
    case RECORD_CONTEXT_GROUP_METADATA:
        return get_object_variant(record->cobj_group_metadata);
    case RECORD_CONTEXT_GROUP_ATTRIBUTES:
        return get_object_variant(record->cobj_group_attributes);
    case RECORD_CONTEXT_OTEL_RESOURCE_ATTRIBUTES:
    case RECORD_CONTEXT_OTEL_SCOPE_ATTRIBUTES:
        return get_otel_attributes_variant(record, rule->context);
    case RECORD_CONTEXT_OTEL_SCOPE_METADATA:
        return get_otel_scope_metadata_variant(record);
    default:
        break;
    }

    return NULL;
}

int flb_router_chunk_context_init(struct flb_router_chunk_context *context)
{
    if (!context) {
        return -1;
    }

    context->chunk_cobj = NULL;
    context->log_encoder = NULL;
    context->log_decoder = NULL;

    return 0;
}

void flb_router_chunk_context_reset(struct flb_router_chunk_context *context)
{
    if (!context) {
        return;
    }

    if (context->chunk_cobj) {
        flb_mp_chunk_cobj_destroy(context->chunk_cobj);
        context->chunk_cobj = NULL;
    }

    if (context->log_decoder) {
        flb_log_event_decoder_destroy(context->log_decoder);
        context->log_decoder = NULL;
    }

    if (context->log_encoder) {
        flb_log_event_encoder_destroy(context->log_encoder);
        context->log_encoder = NULL;
    }
}

void flb_router_chunk_context_destroy(struct flb_router_chunk_context *context)
{
    flb_router_chunk_context_reset(context);
}

int flb_router_chunk_context_prepare_logs(struct flb_router_chunk_context *context,
                                          struct flb_event_chunk *chunk)
{
    int ret;
    struct flb_mp_chunk_record *record;

    if (!context || !chunk) {
        return -1;
    }

    if (chunk->type != FLB_EVENT_TYPE_LOGS) {
        return 0;
    }

    if (context->chunk_cobj) {
        return 0;
    }

    if (!chunk->data || chunk->size == 0) {
        return -1;
    }

    if (!context->log_encoder) {
        context->log_encoder = flb_log_event_encoder_create(FLB_LOG_EVENT_FORMAT_DEFAULT);
        if (!context->log_encoder) {
            return -1;
        }
    }

    if (!context->log_decoder) {
        context->log_decoder = flb_log_event_decoder_create(NULL, 0);
        if (!context->log_decoder) {
            flb_router_chunk_context_reset(context);
            return -1;
        }
        flb_log_event_decoder_read_groups(context->log_decoder, FLB_TRUE);
    }

    flb_log_event_decoder_reset(context->log_decoder, chunk->data, chunk->size);

    context->chunk_cobj = flb_mp_chunk_cobj_create(context->log_encoder,
                                                   context->log_decoder);
    if (!context->chunk_cobj) {
        flb_router_chunk_context_reset(context);
        return -1;
    }

    while ((ret = flb_mp_chunk_cobj_record_next(context->chunk_cobj, &record)) ==
           FLB_MP_CHUNK_RECORD_OK) {
        continue;
    }

    if (ret != FLB_MP_CHUNK_RECORD_EOF) {
        flb_router_chunk_context_reset(context);
        return -1;
    }

    context->chunk_cobj->record_pos = NULL;
    context->chunk_cobj->condition = NULL;

    return 0;
}

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
                            struct flb_router_chunk_context *context,
                            struct flb_route *route)
{
    int result = FLB_FALSE;
    struct flb_route_condition *condition;
    struct flb_condition *compiled;
    struct flb_mp_chunk_record *record;
    struct cfl_list *head;

    if (!chunk || !context || !route || !route->condition) {
        return FLB_FALSE;
    }

    condition = route->condition;

    compiled = route_condition_get_compiled(condition);
    if (!compiled) {
        return FLB_FALSE;
    }

    if (flb_router_chunk_context_prepare_logs(context, chunk) != 0) {
        return FLB_FALSE;
    }

    if (!context->chunk_cobj) {
        return FLB_FALSE;
    }

    cfl_list_foreach(head, &context->chunk_cobj->records) {
        record = cfl_list_entry(head, struct flb_mp_chunk_record, _head);

        if (flb_condition_evaluate_ex(compiled, record, route_logs_get_variant) == FLB_TRUE) {
            result = FLB_TRUE;
            break;
        }
    }

    return result;
}

int flb_condition_eval_metrics(struct flb_event_chunk *chunk,
                               struct flb_router_chunk_context *context,
                               struct flb_route *route)
{
    (void) chunk;
    (void) context;
    (void) route;

    return FLB_FALSE;
}

int flb_condition_eval_traces(struct flb_event_chunk *chunk,
                              struct flb_router_chunk_context *context,
                              struct flb_route *route)
{
    (void) chunk;
    (void) context;
    (void) route;

    return FLB_FALSE;
}

int flb_route_condition_eval(struct flb_event_chunk *chunk,
                             struct flb_router_chunk_context *context,
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
        return flb_condition_eval_logs(chunk, context, route);
    case FLB_ROUTER_SIGNAL_METRICS:
        return flb_condition_eval_metrics(chunk, context, route);
    case FLB_ROUTER_SIGNAL_TRACES:
        return flb_condition_eval_traces(chunk, context, route);
    default:
        break;
    }

    return FLB_FALSE;
}

int flb_router_path_should_route(struct flb_event_chunk *chunk,
                                 struct flb_router_chunk_context *context,
                                 struct flb_router_path *path)
{
    if (!path) {
        return FLB_FALSE;
    }

    if (!path->route) {
        return FLB_TRUE;
    }

    if (chunk && chunk->type == FLB_EVENT_TYPE_LOGS) {
        if (!context) {
            return FLB_FALSE;
        }

        if (flb_router_chunk_context_prepare_logs(context, chunk) != 0) {
            return FLB_FALSE;
        }
    }

    return flb_route_condition_eval(chunk, context, path->route);
}

struct flb_condition *flb_router_route_get_condition(struct flb_route *route)
{
    if (!route || !route->condition) {
        return NULL;
    }

    return route_condition_get_compiled(route->condition);
}

int flb_router_condition_evaluate_record(struct flb_route *route,
                                         struct flb_mp_chunk_record *record)
{
    struct flb_condition *compiled;

    if (!route || !record) {
        return FLB_FALSE;
    }

    if (!route->condition) {
        return FLB_TRUE;
    }

    compiled = flb_router_route_get_condition(route);
    if (!compiled) {
        if (route->condition->is_default) {
            return FLB_TRUE;
        }

        return FLB_FALSE;
    }

    return flb_condition_evaluate_ex(compiled, record, route_logs_get_variant);
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
                                         rule->value, 1, rule->context);
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
                                         &numeric_value, 1, rule->context);
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
                                         rule->context);
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

