/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2024 The Fluent Bit Authors
 *
 *  Licensed under the Apache License, Version 2.0 (the \"License\");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an \"AS IS\" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#include <ctype.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#ifndef _WIN32
#include <strings.h>
#endif

#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_router.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/config_format/flb_cf.h>

#include <cfl/cfl_array.h>
#include <cfl/cfl_kvlist.h>
#include <cfl/cfl_list.h>
#include <cfl/cfl_variant.h>

static flb_sds_t copy_from_cfl_sds(cfl_sds_t value)
{
    if (!value) {
        return NULL;
    }

    return flb_sds_create_len(value, cfl_sds_len(value));
}

static flb_sds_t variant_to_sds(struct cfl_variant *var)
{
    char tmp[64];
    int len;

    if (!var) {
        return NULL;
    }

    switch (var->type) {
    case CFL_VARIANT_STRING:
        return copy_from_cfl_sds(var->data.as_string);
    case CFL_VARIANT_INT:
        len = snprintf(tmp, sizeof(tmp), \"%\" PRId64, var->data.as_int64);
        if (len < 0) {
            return NULL;
        }
        return flb_sds_create_len(tmp, len);
    case CFL_VARIANT_UINT:
        len = snprintf(tmp, sizeof(tmp), \"%\" PRIu64, var->data.as_uint64);
        if (len < 0) {
            return NULL;
        }
        return flb_sds_create_len(tmp, len);
    case CFL_VARIANT_DOUBLE:
        len = snprintf(tmp, sizeof(tmp), \"%.*g\", 17, var->data.as_double);
        if (len < 0) {
            return NULL;
        }
        return flb_sds_create_len(tmp, len);
    case CFL_VARIANT_BOOL:
        return flb_sds_create(var->data.as_bool ? \"true\" : \"false\");
    default:
        break;
    }

    return NULL;
}

static int variant_to_bool(struct cfl_variant *var, int *out)
{
    if (!var || !out) {
        return -1;
    }

    if (var->type == CFL_VARIANT_BOOL) {
        *out = var->data.as_bool != 0;
        return 0;
    }
    else if (var->type == CFL_VARIANT_STRING && var->data.as_string) {
        const char *val = var->data.as_string;

        if (strcasecmp(val, \"true\") == 0) {
            *out = FLB_TRUE;
            return 0;
        }
        else if (strcasecmp(val, \"false\") == 0) {
            *out = FLB_FALSE;
            return 0;
        }
    }

    return -1;
}

static int field_allowed_for_logs(const char *field)
{
    if (!field) {
        return FLB_FALSE;
    }

    if (strncmp(field, \"$metric.\", 8) == 0) {
        return FLB_FALSE;
    }
    if (strncmp(field, \"$span.\", 6) == 0) {
        return FLB_FALSE;
    }
    if (strncmp(field, \"$scope.\", 7) == 0) {
        return FLB_FALSE;
    }

    return FLB_TRUE;
}

static int field_allowed_for_metrics(const char *field)
{
    if (!field) {
        return FLB_FALSE;
    }

    if (strncmp(field, \"$metric.\", 8) == 0) {
        return FLB_TRUE;
    }
    if (strncmp(field, \"$resource[\", 10) == 0) {
        return FLB_TRUE;
    }
    if (strncmp(field, \"$attributes[\", 12) == 0) {
        return FLB_TRUE;
    }

    return FLB_FALSE;
}

static int field_allowed_for_traces(const char *field)
{
    if (!field) {
        return FLB_FALSE;
    }

    if (strncmp(field, \"$span.\", 6) == 0) {
        return FLB_TRUE;
    }
    if (strncmp(field, \"$resource[\", 10) == 0) {
        return FLB_TRUE;
    }
    if (strncmp(field, \"$scope[\", 7) == 0) {
        return FLB_TRUE;
    }

    return FLB_FALSE;
}

static int validate_rule_field(const char *field, uint32_t signals)
{
    int ok = FLB_FALSE;

    if (!field) {
        return FLB_FALSE;
    }

    if (signals == FLB_ROUTER_SIGNAL_ANY) {
        signals = FLB_ROUTER_SIGNAL_LOGS |
                  FLB_ROUTER_SIGNAL_METRICS |
                  FLB_ROUTER_SIGNAL_TRACES;
    }

    if (signals & FLB_ROUTER_SIGNAL_LOGS) {
        if (field_allowed_for_logs(field)) {
            ok = FLB_TRUE;
        }
        else {
            return FLB_FALSE;
        }
    }

    if (signals & FLB_ROUTER_SIGNAL_METRICS) {
        if (field_allowed_for_metrics(field)) {
            ok = FLB_TRUE;
        }
        else {
            return FLB_FALSE;
        }
    }

    if (signals & FLB_ROUTER_SIGNAL_TRACES) {
        if (field_allowed_for_traces(field)) {
            ok = FLB_TRUE;
        }
        else {
            return FLB_FALSE;
        }
    }

    return ok;
}

static uint32_t parse_signal_key(const char *key)
{
    const char *cursor;
    uint32_t mask = 0;

    if (!key) {
        return 0;
    }

    cursor = key;
    while (*cursor) {
        const char *start;
        size_t len;

        while (*cursor && (isspace((unsigned char) *cursor) ||
                           *cursor == ',' || *cursor == '|' || *cursor == '+')) {
            cursor++;
        }

        if (*cursor == '\0') {
            break;
        }

        start = cursor;
        while (*cursor && !isspace((unsigned char) *cursor) &&
               *cursor != ',' && *cursor != '|' && *cursor != '+') {
            cursor++;
        }

        len = cursor - start;
        if (len == 0) {
            continue;
        }

        if (len == 4 && strncasecmp(start, "logs", len) == 0) {
            mask |= FLB_ROUTER_SIGNAL_LOGS;
        }
        else if (len == 7 && strncasecmp(start, "metrics", len) == 0) {
            mask |= FLB_ROUTER_SIGNAL_METRICS;
        }
        else if (len == 6 && strncasecmp(start, "traces", len) == 0) {
            mask |= FLB_ROUTER_SIGNAL_TRACES;
        }
        else if (len == 3 && strncasecmp(start, "any", len) == 0) {
            mask |= FLB_ROUTER_SIGNAL_ANY;
        }
        else {
            return 0;
        }
    }

    return mask;
}

static void route_condition_destroy(struct flb_route_condition *condition)
{
    struct cfl_list *tmp;
    struct cfl_list *head;

    if (!condition) {
        return;
    }

    cfl_list_foreach_safe(head, tmp, &condition->rules) {
        struct flb_route_condition_rule *rule;

        rule = cfl_list_entry(head, struct flb_route_condition_rule, _head);
        cfl_list_del(&rule->_head);

        if (rule->field) {
            flb_sds_destroy(rule->field);
        }
        if (rule->op) {
            flb_sds_destroy(rule->op);
        }
        if (rule->value) {
            flb_sds_destroy(rule->value);
        }

        flb_free(rule);
    }

    flb_free(condition);
}

static void route_outputs_destroy(struct flb_route *route)
{
    struct cfl_list *tmp;
    struct cfl_list *head;

    cfl_list_foreach_safe(head, tmp, &route->outputs) {
        struct flb_route_output *output;

        output = cfl_list_entry(head, struct flb_route_output, _head);
        cfl_list_del(&output->_head);

        if (output->name) {
            flb_sds_destroy(output->name);
        }
        if (output->fallback) {
            flb_sds_destroy(output->fallback);
        }
        flb_free(output);
    }
}

static void route_processors_destroy(struct cfl_list *processors)
{
    struct cfl_list *tmp;
    struct cfl_list *head;

    if (!processors) {
        return;
    }

    cfl_list_foreach_safe(head, tmp, processors) {
        struct flb_route_processor *processor;
        struct cfl_list *p_head;
        struct cfl_list *p_tmp;

        processor = cfl_list_entry(head, struct flb_route_processor, _head);
        cfl_list_del(&processor->_head);

        cfl_list_foreach_safe(p_head, p_tmp, &processor->properties) {
            struct flb_route_processor_property *prop;

            prop = cfl_list_entry(p_head, struct flb_route_processor_property, _head);
            cfl_list_del(&prop->_head);

            if (prop->key) {
                flb_sds_destroy(prop->key);
            }
            if (prop->value) {
                flb_sds_destroy(prop->value);
            }
            flb_free(prop);
        }

        if (processor->name) {
            flb_sds_destroy(processor->name);
        }
        flb_free(processor);
    }
}

void flb_router_routes_destroy(struct cfl_list *input_routes)
{
    struct cfl_list *head;
    struct cfl_list *tmp;

    if (!input_routes) {
        return;
    }

    cfl_list_foreach_safe(head, tmp, input_routes) {
        struct flb_input_routes *routes;
        struct cfl_list *r_head;
        struct cfl_list *r_tmp;

        routes = cfl_list_entry(head, struct flb_input_routes, _head);
        cfl_list_del(&routes->_head);

        route_processors_destroy(&routes->processors);

        cfl_list_foreach_safe(r_head, r_tmp, &routes->routes) {
            struct flb_route *route;

            route = cfl_list_entry(r_head, struct flb_route, _head);
            cfl_list_del(&route->_head);

            if (route->condition) {
                route_condition_destroy(route->condition);
            }

            route_outputs_destroy(route);
            route_processors_destroy(&route->processors);

            if (route->name) {
                flb_sds_destroy(route->name);
            }
            flb_free(route);
        }

        if (routes->input_name) {
            flb_sds_destroy(routes->input_name);
        }

        flb_free(routes);
    }
}

static int add_processor_properties(struct flb_route_processor *processor,
                                    struct cfl_kvlist *kvlist)
{
    struct cfl_list *head;

    if (!processor || !kvlist) {
        return -1;
    }

    cfl_list_foreach(head, &kvlist->list) {
        struct cfl_kvpair *pair;
        struct flb_route_processor_property *prop;

        pair = cfl_list_entry(head, struct cfl_kvpair, _head);
        if (strcmp(pair->key, \"name\") == 0) {
            continue;
        }

        prop = flb_calloc(1, sizeof(struct flb_route_processor_property));
        if (!prop) {
            flb_errno();
            return -1;
        }

        cfl_list_init(&prop->_head);

        prop->key = flb_sds_create_len(pair->key, cfl_sds_len(pair->key));
        if (!prop->key) {
            flb_free(prop);
            return -1;
        }

        prop->value = variant_to_sds(pair->val);
        if (!prop->value) {
            flb_sds_destroy(prop->key);
            flb_free(prop);
            return -1;
        }

        cfl_list_add(&prop->_head, &processor->properties);
    }

    return 0;
}

static int parse_processors(struct cfl_variant *variant,
                            struct cfl_list *out_list,
                            struct flb_config *config)
{
    size_t idx;
    struct cfl_array *array;

    (void) config;

    if (!variant || !out_list) {
        return -1;
    }

    if (variant->type != CFL_VARIANT_ARRAY) {
        return -1;
    }

    array = variant->data.as_array;
    for (idx = 0; idx < cfl_array_size(array); idx++) {
        struct cfl_variant *entry;
        struct cfl_kvlist *kvlist;
        struct cfl_variant *name_var;
        struct flb_route_processor *processor;

        entry = cfl_array_fetch_by_index(array, idx);
        if (!entry || entry->type != CFL_VARIANT_KVLIST) {
            return -1;
        }

        kvlist = entry->data.as_kvlist;
        name_var = cfl_kvlist_fetch(kvlist, \"name\");
        if (!name_var || name_var->type != CFL_VARIANT_STRING) {
            return -1;
        }

        processor = flb_calloc(1, sizeof(struct flb_route_processor));
        if (!processor) {
            flb_errno();
            return -1;
        }
        cfl_list_init(&processor->_head);
        cfl_list_init(&processor->properties);

        processor->name = copy_from_cfl_sds(name_var->data.as_string);
        if (!processor->name) {
            flb_free(processor);
            return -1;
        }

        if (add_processor_properties(processor, kvlist) != 0) {
            route_processors_destroy(&processor->properties);
            if (processor->name) {
                flb_sds_destroy(processor->name);
            }
            flb_free(processor);
            return -1;
        }

        cfl_list_add(&processor->_head, out_list);
    }

    return 0;
}

static struct flb_route_condition_rule *parse_condition_rule(struct cfl_variant *variant)
{
    struct flb_route_condition_rule *rule;
    struct cfl_kvlist *kvlist;
    struct cfl_variant *field_var;
    struct cfl_variant *op_var;
    struct cfl_variant *value_var;

    if (!variant || variant->type != CFL_VARIANT_KVLIST) {
        return NULL;
    }

    kvlist = variant->data.as_kvlist;
    field_var = cfl_kvlist_fetch(kvlist, \"field\");
    op_var = cfl_kvlist_fetch(kvlist, \"op\");
    value_var = cfl_kvlist_fetch(kvlist, \"value\");

    if (!field_var || field_var->type != CFL_VARIANT_STRING) {
        return NULL;
    }
    if (!op_var || op_var->type != CFL_VARIANT_STRING) {
        return NULL;
    }

    rule = flb_calloc(1, sizeof(struct flb_route_condition_rule));
    if (!rule) {
        flb_errno();
        return NULL;
    }
    cfl_list_init(&rule->_head);

    rule->field = copy_from_cfl_sds(field_var->data.as_string);
    if (!rule->field) {
        flb_free(rule);
        return NULL;
    }

    rule->op = copy_from_cfl_sds(op_var->data.as_string);
    if (!rule->op) {
        flb_sds_destroy(rule->field);
        flb_free(rule);
        return NULL;
    }

    if (value_var) {
        rule->value = variant_to_sds(value_var);
        if (!rule->value && strcmp(rule->op, \"exists\") != 0) {
            flb_sds_destroy(rule->op);
            flb_sds_destroy(rule->field);
            flb_free(rule);
            return NULL;
        }
    }

    return rule;
}

static struct flb_route_condition *parse_condition(struct cfl_variant *variant,
                                                   uint32_t signals)
{
    struct flb_route_condition *condition;
    struct cfl_variant *rules_var;
    struct cfl_variant *default_var;
    struct cfl_array *rules_array;
    size_t idx;

    if (!variant || variant->type != CFL_VARIANT_KVLIST) {
        return NULL;
    }

    condition = flb_calloc(1, sizeof(struct flb_route_condition));
    if (!condition) {
        flb_errno();
        return NULL;
    }
    cfl_list_init(&condition->rules);

    rules_var = cfl_kvlist_fetch(variant->data.as_kvlist, \"rules\");
    default_var = cfl_kvlist_fetch(variant->data.as_kvlist, \"default\");

    if (default_var) {
        int val;

        if (variant_to_bool(default_var, &val) != 0) {
            route_condition_destroy(condition);
            return NULL;
        }
        condition->is_default = val;
    }

    if (rules_var) {
        if (rules_var->type != CFL_VARIANT_ARRAY) {
            route_condition_destroy(condition);
            return NULL;
        }

        rules_array = rules_var->data.as_array;
        for (idx = 0; idx < cfl_array_size(rules_array); idx++) {
            struct cfl_variant *entry;
            struct flb_route_condition_rule *rule;

            entry = cfl_array_fetch_by_index(rules_array, idx);
            rule = parse_condition_rule(entry);
            if (!rule) {
                route_condition_destroy(condition);
                return NULL;
            }

            if (!validate_rule_field(rule->field, signals)) {
                route_condition_destroy(condition);
                return NULL;
            }

            cfl_list_add(&rule->_head, &condition->rules);
        }
    }

    if (!condition->is_default && cfl_list_is_empty(&condition->rules) == 1) {
        route_condition_destroy(condition);
        return NULL;
    }

    return condition;
}

static int add_output_from_variant(struct flb_route *route,
                                   struct cfl_variant *variant)
{
    struct flb_route_output *output;

    if (!route || !variant) {
        return -1;
    }

    output = flb_calloc(1, sizeof(struct flb_route_output));
    if (!output) {
        flb_errno();
        return -1;
    }
    cfl_list_init(&output->_head);

    if (variant->type == CFL_VARIANT_STRING) {
        output->name = copy_from_cfl_sds(variant->data.as_string);
        if (!output->name) {
            flb_free(output);
            return -1;
        }
    }
    else if (variant->type == CFL_VARIANT_KVLIST) {
        struct cfl_variant *name_var;
        struct cfl_variant *fallback_var;

        name_var = cfl_kvlist_fetch(variant->data.as_kvlist, \"name\");
        if (!name_var || name_var->type != CFL_VARIANT_STRING) {
            flb_free(output);
            return -1;
        }
        output->name = copy_from_cfl_sds(name_var->data.as_string);
        if (!output->name) {
            flb_free(output);
            return -1;
        }

        fallback_var = cfl_kvlist_fetch(variant->data.as_kvlist, \"fallback\");
        if (fallback_var) {
            if (fallback_var->type != CFL_VARIANT_STRING) {
                flb_sds_destroy(output->name);
                flb_free(output);
                return -1;
            }
            output->fallback = copy_from_cfl_sds(fallback_var->data.as_string);
            if (!output->fallback) {
                flb_sds_destroy(output->name);
                flb_free(output);
                return -1;
            }
        }
    }
    else {
        flb_free(output);
        return -1;
    }

    cfl_list_add(&output->_head, &route->outputs);
    return 0;
}

static int parse_outputs(struct cfl_variant *variant, struct flb_route *route)
{
    size_t idx;

    if (!variant || !route) {
        return -1;
    }

    if (variant->type == CFL_VARIANT_ARRAY) {
        struct cfl_array *array = variant->data.as_array;

        if (cfl_array_size(array) == 0) {
            return -1;
        }

        for (idx = 0; idx < cfl_array_size(array); idx++) {
            struct cfl_variant *entry;

            entry = cfl_array_fetch_by_index(array, idx);
            if (!entry) {
                return -1;
            }

            if (add_output_from_variant(route, entry) != 0) {
                return -1;
            }
        }

        return 0;
    }

    if (add_output_from_variant(route, variant) != 0) {
        return -1;
    }

    return 0;
}

static int route_name_exists(struct cfl_list *routes, flb_sds_t name)
{
    struct cfl_list *head;

    if (!routes || !name) {
        return FLB_FALSE;
    }

    cfl_list_foreach(head, routes) {
        struct flb_route *route;

        route = cfl_list_entry(head, struct flb_route, _head);
        if (route->name && strcmp(route->name, name) == 0) {
            return FLB_TRUE;
        }
    }

    return FLB_FALSE;
}

static int parse_route(struct cfl_variant *variant,
                       struct flb_input_routes *input,
                       struct flb_config *config,
                       uint32_t signals)
{
    struct flb_route *route;
    struct cfl_kvlist *kvlist;
    struct cfl_variant *name_var;
    struct cfl_variant *condition_var;
    struct cfl_variant *processors_var;
    struct cfl_variant *to_var;
    struct cfl_variant *outputs_var;

    (void) config;

    if (!variant || variant->type != CFL_VARIANT_KVLIST) {
        return -1;
    }

    if (signals == 0) {
        return -1;
    }

    kvlist = variant->data.as_kvlist;

    name_var = cfl_kvlist_fetch(kvlist, \"name\");
    if (!name_var || name_var->type != CFL_VARIANT_STRING) {
        return -1;
    }

    route = flb_calloc(1, sizeof(struct flb_route));
    if (!route) {
        flb_errno();
        return -1;
    }
    cfl_list_init(&route->_head);
    cfl_list_init(&route->outputs);
    cfl_list_init(&route->processors);
    route->signals = signals;

    route->name = copy_from_cfl_sds(name_var->data.as_string);
    if (!route->name) {
        flb_free(route);
        return -1;
    }

    if (route_name_exists(&input->routes, route->name)) {
        flb_sds_destroy(route->name);
        flb_free(route);
        return -1;
    }


    condition_var = cfl_kvlist_fetch(kvlist, \"condition\");
    if (condition_var) {
        route->condition = parse_condition(condition_var, route->signals);
        if (!route->condition) {
            flb_sds_destroy(route->name);
            flb_free(route);
            return -1;
        }
    }

    processors_var = cfl_kvlist_fetch(kvlist, \"processors\");
    if (processors_var) {
        if (parse_processors(processors_var, &route->processors, config) != 0) {
            if (route->condition) {
                route_condition_destroy(route->condition);
            }
            flb_sds_destroy(route->name);
            flb_free(route);
            return -1;
        }
    }

    to_var = cfl_kvlist_fetch(kvlist, \"to\");
    if (!to_var) {
        if (route->condition) {
            route_condition_destroy(route->condition);
        }
        route_processors_destroy(&route->processors);
        flb_sds_destroy(route->name);
        flb_free(route);
        return -1;
    }

    if (to_var->type == CFL_VARIANT_KVLIST) {
        outputs_var = cfl_kvlist_fetch(to_var->data.as_kvlist, \"outputs\");
    }
    else {
        outputs_var = to_var;
    }

    if (!outputs_var || parse_outputs(outputs_var, route) != 0 ||
        cfl_list_is_empty(&route->outputs) == 1) {
        if (route->condition) {
            route_condition_destroy(route->condition);
        }
        route_processors_destroy(&route->processors);
        route_outputs_destroy(route);
        flb_sds_destroy(route->name);
        flb_free(route);
        return -1;
    }

    cfl_list_add(&route->_head, &input->routes);
    return 0;
}

static int parse_routes_block(struct cfl_variant *variant,
                              struct flb_input_routes *input,
                              struct flb_config *config,
                              uint32_t signals)
{
    struct cfl_array *array;
    size_t idx;

    if (!variant) {
        return -1;
    }

    if (variant->type == CFL_VARIANT_ARRAY) {
        array = variant->data.as_array;
        if (cfl_array_size(array) == 0) {
            return -1;
        }

        for (idx = 0; idx < cfl_array_size(array); idx++) {
            struct cfl_variant *entry;

            entry = cfl_array_fetch_by_index(array, idx);
            if (!entry) {
                return -1;
            }

            if (parse_route(entry, input, config, signals) != 0) {
                return -1;
            }
        }

        return 0;
    }

    if (variant->type == CFL_VARIANT_KVLIST) {
        if (parse_route(variant, input, config, signals) != 0) {
            return -1;
        }
        return 0;
    }

    return -1;
}

static int parse_input_section(struct flb_cf_section *section,
                               struct cfl_list *input_routes,
                               struct flb_config *config)
{
    struct flb_input_routes *input;
    struct cfl_kvlist *kvlist;
    struct cfl_variant *name_var;
    struct cfl_variant *processors_var;
    struct cfl_variant *routes_var;
    struct cfl_kvlist *routes_kvlist;
    struct cfl_list *head;
    struct cfl_kvpair *pair;
    uint32_t mask;
    size_t before_count;

    if (!section || !input_routes) {
        return -1;
    }

    kvlist = section->properties;
    if (!kvlist) {
        return -1;
    }

    name_var = cfl_kvlist_fetch(kvlist, "name");
    if (!name_var || name_var->type != CFL_VARIANT_STRING) {
        return -1;
    }

    input = flb_calloc(1, sizeof(struct flb_input_routes));
    if (!input) {
        flb_errno();
        return -1;
    }

    cfl_list_init(&input->_head);
    cfl_list_init(&input->processors);
    cfl_list_init(&input->routes);

    input->input_name = copy_from_cfl_sds(name_var->data.as_string);
    if (!input->input_name) {
        flb_free(input);
        return -1;
    }

    processors_var = cfl_kvlist_fetch(kvlist, "processors");
    if (processors_var) {
        if (parse_processors(processors_var, &input->processors, config) != 0) {
            goto error;
        }
    }

    routes_var = cfl_kvlist_fetch(kvlist, "routes");
    if (!routes_var || routes_var->type != CFL_VARIANT_KVLIST) {
        goto error;
    }

    routes_kvlist = routes_var->data.as_kvlist;
    if (cfl_list_is_empty(&routes_kvlist->list) == 1) {
        goto error;
    }

    cfl_list_foreach(head, &routes_kvlist->list) {
        pair = cfl_list_entry(head, struct cfl_kvpair, _head);
        if (!pair || !pair->key) {
            goto error;
        }

        mask = parse_signal_key(pair->key);
        if (mask == 0) {
            goto error;
        }

        if (!pair->val) {
            goto error;
        }

        before_count = cfl_list_size(&input->routes);
        if (parse_routes_block(pair->val, input, config, mask) != 0 ||
            cfl_list_size(&input->routes) == before_count) {
            goto error;
        }
    }

    if (cfl_list_is_empty(&input->routes) == 1) {
        goto error;
    }

    cfl_list_add(&input->_head, input_routes);
    return 0;

error:
    flb_router_routes_destroy(&input->routes);
    route_processors_destroy(&input->processors);
    if (input->input_name) {
        flb_sds_destroy(input->input_name);
    }
    flb_free(input);
    return -1;
}

int flb_router_config_parse(struct flb_cf *cf,
                            struct cfl_list *input_routes,
                            struct flb_config *config)
{
    struct mk_list *head;
    struct flb_cf_section *section;

    if (!cf || !input_routes) {
        return -1;
    }

    cfl_list_init(input_routes);

    mk_list_foreach(head, &cf->inputs) {
        section = mk_list_entry(head, struct flb_cf_section, _head_section);
        if (parse_input_section(section, input_routes, config) != 0) {
            flb_router_routes_destroy(input_routes);
            cfl_list_init(input_routes);
            return -1;
        }
    }

    if (cfl_list_is_empty(input_routes) == 1) {
        flb_router_routes_destroy(input_routes);
        cfl_list_init(input_routes);
        return -1;
    }

    return 0;
}

