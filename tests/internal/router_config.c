/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <string.h>

#include <fluent-bit/flb_config_format.h>
#include <fluent-bit/flb_router.h>
#include <fluent-bit/config_format/flb_cf.h>

#include <cfl/cfl_array.h>
#include <cfl/cfl_kvlist.h>
#include <cfl/cfl_variant.h>
#include <cfl/cfl_sds.h>

#include "flb_tests_internal.h"

#ifdef _WIN32
#define FLB_ROUTER_TEST_FILE(name) \
    FLB_TESTS_DATA_PATH "\\data\\config_format\\yaml\\routing\\" name
#else
#define FLB_ROUTER_TEST_FILE(name) \
    FLB_TESTS_DATA_PATH "/data/config_format/yaml/routing/" name
#endif

static struct cfl_variant *clone_variant(struct cfl_variant *var);

static struct cfl_array *clone_array(struct cfl_array *array)
{
    struct cfl_array *copy;
    struct cfl_variant *entry;
    struct cfl_variant *entry_copy;
    size_t idx;

    if (!array) {
        return NULL;
    }

    copy = cfl_array_create(cfl_array_size(array));
    if (!copy) {
        return NULL;
    }

    for (idx = 0; idx < cfl_array_size(array); idx++) {
        entry = cfl_array_fetch_by_index(array, idx);
        entry_copy = clone_variant(entry);
        if (!entry_copy) {
            cfl_array_destroy(copy);
            return NULL;
        }

        if (cfl_array_append(copy, entry_copy) != 0) {
            cfl_variant_destroy(entry_copy);
            cfl_array_destroy(copy);
            return NULL;
        }
    }

    return copy;
}

static struct cfl_kvlist *clone_kvlist(struct cfl_kvlist *kvlist)
{
    struct cfl_kvlist *copy;
    struct cfl_list *head;
    struct cfl_kvpair *pair;
    struct cfl_variant *value_copy;

    if (!kvlist) {
        return NULL;
    }

    copy = cfl_kvlist_create();
    if (!copy) {
        return NULL;
    }

    cfl_list_foreach(head, &kvlist->list) {
        pair = cfl_list_entry(head, struct cfl_kvpair, _head);
        value_copy = clone_variant(pair->val);
        if (!value_copy) {
            cfl_kvlist_destroy(copy);
            return NULL;
        }

        if (cfl_kvlist_insert_s(copy,
                                pair->key,
                                cfl_sds_len(pair->key),
                                value_copy) != 0) {
            cfl_variant_destroy(value_copy);
            cfl_kvlist_destroy(copy);
            return NULL;
        }
    }

    return copy;
}

static struct cfl_variant *clone_variant(struct cfl_variant *var)
{
    if (!var) {
        return NULL;
    }

    switch (var->type) {
    case CFL_VARIANT_STRING:
        return cfl_variant_create_from_string_s(var->data.as_string,
                                                cfl_sds_len(var->data.as_string),
                                                CFL_FALSE);
    case CFL_VARIANT_BOOL:
        return cfl_variant_create_from_bool(var->data.as_bool);
    case CFL_VARIANT_INT:
        return cfl_variant_create_from_int64(var->data.as_int64);
    case CFL_VARIANT_UINT:
        return cfl_variant_create_from_uint64(var->data.as_uint64);
    case CFL_VARIANT_DOUBLE:
        return cfl_variant_create_from_double(var->data.as_double);
    case CFL_VARIANT_NULL:
        return cfl_variant_create_from_null();
    case CFL_VARIANT_ARRAY: {
        struct cfl_array *copy = clone_array(var->data.as_array);
        if (!copy) {
            return NULL;
        }
        return cfl_variant_create_from_array(copy);
    }
    case CFL_VARIANT_KVLIST: {
        struct cfl_kvlist *copy = clone_kvlist(var->data.as_kvlist);
        if (!copy) {
            return NULL;
        }
        return cfl_variant_create_from_kvlist(copy);
    }
    default:
        break;
    }

    return NULL;
}

static struct flb_cf *cf_from_inputs_variant(struct cfl_variant *inputs)
{
    struct flb_cf *cf;
    struct cfl_array *array;
    size_t idx;

    if (!inputs || inputs->type != CFL_VARIANT_ARRAY) {
        return NULL;
    }

    cf = flb_cf_create();
    if (!cf) {
        return NULL;
    }

    array = inputs->data.as_array;
    for (idx = 0; idx < cfl_array_size(array); idx++) {
        struct cfl_variant *entry;
        struct cfl_kvlist *copy;
        struct flb_cf_section *section;

        entry = cfl_array_fetch_by_index(array, idx);
        if (!entry || entry->type != CFL_VARIANT_KVLIST) {
            flb_cf_destroy(cf);
            return NULL;
        }

        copy = clone_kvlist(entry->data.as_kvlist);
        if (!copy) {
            flb_cf_destroy(cf);
            return NULL;
        }

        section = flb_cf_section_create(cf, "input", 5);
        if (!section) {
            cfl_kvlist_destroy(copy);
            flb_cf_destroy(cf);
            return NULL;
        }

        cfl_kvlist_destroy(section->properties);
        section->properties = copy;
    }

    return cf;
}

static struct flb_cf *load_cf_from_yaml(const char *path)
{
    return flb_cf_yaml_create(NULL, (char *) path, NULL, 0);
}

static struct cfl_variant *create_inputs_variant()
{
    struct cfl_array *inputs;
    struct cfl_kvlist *input;
    struct cfl_array *processors;
    struct cfl_kvlist *proc;
    struct cfl_kvlist *routes;
    struct cfl_array *log_routes;
    struct cfl_kvlist *route;
    struct cfl_kvlist *condition;
    struct cfl_array *rules;
    struct cfl_kvlist *rule_kv;
    struct cfl_variant *rule_variant;
    struct cfl_array *outputs;
    struct cfl_kvlist *to;
    struct cfl_kvlist *output_obj;
    struct cfl_kvlist *default_condition;
    struct cfl_variant *inputs_variant;

    inputs = cfl_array_create(1);
    TEST_CHECK(inputs != NULL);
    if (!inputs) {
        return NULL;
    }

    input = cfl_kvlist_create();
    TEST_CHECK(input != NULL);
    if (!input) {
        cfl_array_destroy(inputs);
        return NULL;
    }

    TEST_CHECK(cfl_kvlist_insert_string(input, "name", "opentelemetry") == 0);

    processors = cfl_array_create(1);
    TEST_CHECK(processors != NULL);
    proc = cfl_kvlist_create();
    TEST_CHECK(proc != NULL);
    TEST_CHECK(cfl_kvlist_insert_string(proc, "name", "parser") == 0);
    TEST_CHECK(cfl_kvlist_insert_string(proc, "parser", "json") == 0);
    TEST_CHECK(cfl_array_append(processors, cfl_variant_create_from_kvlist(proc)) == 0);
    TEST_CHECK(cfl_kvlist_insert_array(input, "processors", processors) == 0);

    routes = cfl_kvlist_create();
    TEST_CHECK(routes != NULL);
    log_routes = cfl_array_create(2);
    TEST_CHECK(log_routes != NULL);

    /* error_logs route */
    route = cfl_kvlist_create();
    TEST_CHECK(route != NULL);
    TEST_CHECK(cfl_kvlist_insert_string(route, "name", "error_logs") == 0);

    condition = cfl_kvlist_create();
    TEST_CHECK(condition != NULL);
    rules = cfl_array_create(1);
    TEST_CHECK(rules != NULL);

    rule_kv = cfl_kvlist_create();
    TEST_CHECK(rule_kv != NULL);
    TEST_CHECK(cfl_kvlist_insert_string(rule_kv, "field", "$level") == 0);
    TEST_CHECK(cfl_kvlist_insert_string(rule_kv, "op", "eq") == 0);
    TEST_CHECK(cfl_kvlist_insert_string(rule_kv, "value", "error") == 0);
    rule_variant = cfl_variant_create_from_kvlist(rule_kv);
    TEST_CHECK(rule_variant != NULL);
    TEST_CHECK(cfl_array_append(rules, rule_variant) == 0);

    TEST_CHECK(cfl_kvlist_insert_array(condition, "rules", rules) == 0);
    TEST_CHECK(cfl_kvlist_insert_kvlist(route, "condition", condition) == 0);

    outputs = cfl_array_create(1);
    TEST_CHECK(outputs != NULL);
    TEST_CHECK(cfl_array_append_string(outputs, "loki") == 0);
    to = cfl_kvlist_create();
    TEST_CHECK(to != NULL);
    TEST_CHECK(cfl_kvlist_insert_array(to, "outputs", outputs) == 0);
    TEST_CHECK(cfl_kvlist_insert_kvlist(route, "to", to) == 0);

    TEST_CHECK(cfl_array_append(log_routes, cfl_variant_create_from_kvlist(route)) == 0);

    /* default route */
    route = cfl_kvlist_create();
    TEST_CHECK(route != NULL);
    TEST_CHECK(cfl_kvlist_insert_string(route, "name", "default") == 0);

    default_condition = cfl_kvlist_create();
    TEST_CHECK(default_condition != NULL);
    TEST_CHECK(cfl_kvlist_insert_bool(default_condition, "default", 1) == 0);
    TEST_CHECK(cfl_kvlist_insert_kvlist(route, "condition", default_condition) == 0);

    outputs = cfl_array_create(1);
    TEST_CHECK(outputs != NULL);
    output_obj = cfl_kvlist_create();
    TEST_CHECK(output_obj != NULL);
    TEST_CHECK(cfl_kvlist_insert_string(output_obj, "name", "elasticsearch") == 0);
    TEST_CHECK(cfl_kvlist_insert_string(output_obj, "fallback", "s3_backup") == 0);
    TEST_CHECK(cfl_array_append(outputs, cfl_variant_create_from_kvlist(output_obj)) == 0);

    to = cfl_kvlist_create();
    TEST_CHECK(to != NULL);
    TEST_CHECK(cfl_kvlist_insert_array(to, "outputs", outputs) == 0);
    TEST_CHECK(cfl_kvlist_insert_kvlist(route, "to", to) == 0);

    TEST_CHECK(cfl_array_append(log_routes, cfl_variant_create_from_kvlist(route)) == 0);

    TEST_CHECK(cfl_kvlist_insert_array(routes, "logs", log_routes) == 0);
    TEST_CHECK(cfl_kvlist_insert_kvlist(input, "routes", routes) == 0);
    TEST_CHECK(cfl_array_append(inputs, cfl_variant_create_from_kvlist(input)) == 0);

    inputs_variant = cfl_variant_create_from_array(inputs);
    TEST_CHECK(inputs_variant != NULL);

    return inputs_variant;
}
static struct cfl_variant *create_duplicate_route_inputs()
{
    struct cfl_array *inputs;
    struct cfl_kvlist *input;
    struct cfl_kvlist *routes;
    struct cfl_array *log_routes;
    struct cfl_kvlist *route;
    struct cfl_kvlist *condition;
    struct cfl_kvlist *to;
    struct cfl_array *outputs;
    int idx;

    inputs = cfl_array_create(1);
    TEST_CHECK(inputs != NULL);
    if (!inputs) {
        return NULL;
    }

    input = cfl_kvlist_create();
    TEST_CHECK(input != NULL);
    if (!input) {
        cfl_array_destroy(inputs);
        return NULL;
    }

    TEST_CHECK(cfl_kvlist_insert_string(input, "name", "duplicate") == 0);

    routes = cfl_kvlist_create();
    TEST_CHECK(routes != NULL);
    log_routes = cfl_array_create(2);
    TEST_CHECK(log_routes != NULL);

    for (idx = 0; idx < 2; idx++) {
        route = cfl_kvlist_create();
        TEST_CHECK(route != NULL);
        TEST_CHECK(cfl_kvlist_insert_string(route, "name", "dup") == 0);

        condition = cfl_kvlist_create();
        TEST_CHECK(condition != NULL);
        TEST_CHECK(cfl_kvlist_insert_bool(condition, "default", 1) == 0);
        TEST_CHECK(cfl_kvlist_insert_kvlist(route, "condition", condition) == 0);

        outputs = cfl_array_create(1);
        TEST_CHECK(outputs != NULL);
        if (idx == 0) {
            TEST_CHECK(cfl_array_append_string(outputs, "primary") == 0);
        }
        else {
            TEST_CHECK(cfl_array_append_string(outputs, "secondary") == 0);
        }

        to = cfl_kvlist_create();
        TEST_CHECK(to != NULL);
        TEST_CHECK(cfl_kvlist_insert_array(to, "outputs", outputs) == 0);
        TEST_CHECK(cfl_kvlist_insert_kvlist(route, "to", to) == 0);

        TEST_CHECK(cfl_array_append(log_routes, cfl_variant_create_from_kvlist(route)) == 0);
    }

    TEST_CHECK(cfl_kvlist_insert_array(routes, "logs", log_routes) == 0);
    TEST_CHECK(cfl_kvlist_insert_kvlist(input, "routes", routes) == 0);
    TEST_CHECK(cfl_array_append(inputs, cfl_variant_create_from_kvlist(input)) == 0);

    return cfl_variant_create_from_array(inputs);
}
void test_router_config_parse_basic()
{
    struct cfl_list routes;
    struct cfl_variant *inputs;
    struct flb_cf *cf;
    struct flb_input_routes *input_routes;
    struct flb_route *first_route;
    struct flb_route *second_route;
    struct flb_route_output *output;
    struct cfl_list *head;
    struct cfl_list *route_head;
    int ret;

    cfl_list_init(&routes);

    inputs = create_inputs_variant();
    TEST_CHECK(inputs != NULL);
    if (!inputs) {
        return;
    }

    cf = cf_from_inputs_variant(inputs);
    TEST_CHECK(cf != NULL);
    if (!cf) {
        cfl_variant_destroy(inputs);
        return;
    }

    ret = flb_router_config_parse(cf, &routes, NULL);
    TEST_CHECK(ret == 0);
    if (ret == 0) {
        TEST_CHECK(cfl_list_size(&routes) == 1);
        head = routes.next;
        input_routes = cfl_list_entry(head, struct flb_input_routes, _head);
        TEST_CHECK(strcmp(input_routes->input_name, "opentelemetry") == 0);
        TEST_CHECK(cfl_list_size(&input_routes->processors) == 1);
        TEST_CHECK(cfl_list_size(&input_routes->routes) == 2);

        route_head = input_routes->routes.next;
        first_route = cfl_list_entry(route_head, struct flb_route, _head);
        TEST_CHECK(strcmp(first_route->name, "error_logs") == 0);
        TEST_CHECK(first_route->signals == FLB_ROUTER_SIGNAL_LOGS);
        TEST_CHECK(first_route->condition != NULL);
        TEST_CHECK(cfl_list_size(&first_route->outputs) == 1);
        output = cfl_list_entry(first_route->outputs.next,
                                struct flb_route_output, _head);
        TEST_CHECK(strcmp(output->name, "loki") == 0);

        route_head = route_head->next;
        second_route = cfl_list_entry(route_head, struct flb_route, _head);
        TEST_CHECK(second_route->condition != NULL);
        TEST_CHECK(second_route->condition->is_default == FLB_TRUE);
        TEST_CHECK(cfl_list_size(&second_route->outputs) == 1);
        TEST_CHECK(second_route->signals == FLB_ROUTER_SIGNAL_LOGS);
        output = cfl_list_entry(second_route->outputs.next,
                                struct flb_route_output, _head);
        TEST_CHECK(strcmp(output->fallback, "s3_backup") == 0);

        flb_router_routes_destroy(&routes);
    }

    if (ret != 0) {
        cfl_list_init(&routes);
    }

    flb_cf_destroy(cf);
    cfl_variant_destroy(inputs);
}

void test_router_config_duplicate_route()
{
    struct cfl_list routes;
    struct cfl_variant *inputs;
    struct flb_cf *cf;
    int ret;

    cfl_list_init(&routes);

    inputs = create_duplicate_route_inputs();
    TEST_CHECK(inputs != NULL);
    if (!inputs) {
        return;
    }

    cf = cf_from_inputs_variant(inputs);
    TEST_CHECK(cf != NULL);
    if (!cf) {
        cfl_variant_destroy(inputs);
        return;
    }

    ret = flb_router_config_parse(cf, &routes, NULL);
    TEST_CHECK(ret != 0);
    TEST_CHECK(cfl_list_is_empty(&routes) == 1);

    flb_cf_destroy(cf);
    cfl_variant_destroy(inputs);
}

void test_router_config_parse_file_basic()
{
    struct cfl_list routes;
    struct flb_cf *cf;
    struct flb_input_routes *input_routes;
    struct cfl_list *routes_head;
    struct cfl_list *route_head;
    struct flb_route *route;
    struct flb_route_output *output;
    int seen_error;
    int seen_metrics;
    int seen_default;
    int ret;

    cf = load_cf_from_yaml(FLB_ROUTER_TEST_FILE("basic.yaml"));
    TEST_CHECK(cf != NULL);
    if (!cf) {
        return;
    }

    cfl_list_init(&routes);
    seen_error = FLB_FALSE;
    seen_metrics = FLB_FALSE;
    seen_default = FLB_FALSE;

    ret = flb_router_config_parse(cf, &routes, NULL);
    TEST_CHECK(ret == 0);
    if (ret == 0) {
        routes_head = routes.next;
        input_routes = cfl_list_entry(routes_head, struct flb_input_routes, _head);
        TEST_CHECK(strcmp(input_routes->input_name, "opentelemetry") == 0);
        TEST_CHECK(cfl_list_size(&input_routes->routes) == 3);

        cfl_list_foreach(route_head, &input_routes->routes) {
            route = cfl_list_entry(route_head, struct flb_route, _head);
            if (strcmp(route->name, "error_logs") == 0) {
                seen_error = FLB_TRUE;
                TEST_CHECK(route->signals == FLB_ROUTER_SIGNAL_LOGS);
                output = cfl_list_entry(route->outputs.next,
                                        struct flb_route_output, _head);
                TEST_CHECK(strcmp(output->name, "loki") == 0);
                TEST_CHECK(strcmp(output->fallback, "s3_backup") == 0);
            }
            else if (strcmp(route->name, "metrics_above_threshold") == 0) {
                seen_metrics = FLB_TRUE;
                TEST_CHECK(route->signals == FLB_ROUTER_SIGNAL_METRICS);
            }
            else if (strcmp(route->name, "default") == 0) {
                seen_default = FLB_TRUE;
                TEST_CHECK(route->condition != NULL);
                TEST_CHECK(route->signals == FLB_ROUTER_SIGNAL_LOGS);
                TEST_CHECK(route->condition->is_default == FLB_TRUE);
                output = cfl_list_entry(route->outputs.next,
                                        struct flb_route_output, _head);
                TEST_CHECK(strcmp(output->name, "elasticsearch") == 0);
            }
        }

        TEST_CHECK(seen_error == FLB_TRUE);
        TEST_CHECK(seen_metrics == FLB_TRUE);
        TEST_CHECK(seen_default == FLB_TRUE);

        flb_router_routes_destroy(&routes);
    }

    flb_cf_destroy(cf);
}

void test_router_config_parse_file_multi_signal()
{
    struct cfl_list routes;
    struct flb_cf *cf;
    struct flb_input_routes *input_routes;
    struct flb_route *route;
    struct flb_route_output *output;
    struct cfl_list *route_head;
    struct cfl_list *output_head;
    int seen_multi;
    int seen_default;
    int outputs;
    int ret;

    cf = load_cf_from_yaml(FLB_ROUTER_TEST_FILE("multi_signal.yaml"));
    TEST_CHECK(cf != NULL);
    if (!cf) {
        return;
    }

    cfl_list_init(&routes);
    seen_multi = FLB_FALSE;
    seen_default = FLB_FALSE;

    ret = flb_router_config_parse(cf, &routes, NULL);
    TEST_CHECK(ret == 0);
    if (ret == 0) {
        input_routes = cfl_list_entry(routes.next, struct flb_input_routes, _head);
        TEST_CHECK(strcmp(input_routes->input_name, "telemetry") == 0);

        cfl_list_foreach(route_head, &input_routes->routes) {
            route = cfl_list_entry(route_head, struct flb_route, _head);
            if (strcmp(route->name, "service_checkout") == 0) {
                seen_multi = FLB_TRUE;
                TEST_CHECK(route->signals ==
                           (FLB_ROUTER_SIGNAL_LOGS | FLB_ROUTER_SIGNAL_TRACES));
            }
            else if (strcmp(route->name, "catch_all") == 0) {
                seen_default = FLB_TRUE;
                TEST_CHECK(route->condition != NULL &&
                           route->condition->is_default == FLB_TRUE);
                TEST_CHECK(route->signals == FLB_ROUTER_SIGNAL_LOGS);

                outputs = 0;
                cfl_list_foreach(output_head, &route->outputs) {
                    output = cfl_list_entry(output_head, struct flb_route_output, _head);
                    outputs++;
                    if (strcmp(output->name, "s3_archive") == 0) {
                        TEST_CHECK(strcmp(output->fallback, "glacier") == 0);
                    }
                }
                TEST_CHECK(outputs == 2);
            }
        }

        TEST_CHECK(seen_multi == FLB_TRUE);
        TEST_CHECK(seen_default == FLB_TRUE);

        flb_router_routes_destroy(&routes);
    }

    flb_cf_destroy(cf);
}

void test_router_config_parse_file_metrics()
{
    struct cfl_list routes;
    struct flb_cf *cf;
    struct flb_input_routes *input_routes;
    struct flb_route *route;
    struct flb_route_output *output;
    int ret;

    cf = load_cf_from_yaml(FLB_ROUTER_TEST_FILE("metrics.yaml"));
    TEST_CHECK(cf != NULL);
    if (!cf) {
        return;
    }

    cfl_list_init(&routes);

    ret = flb_router_config_parse(cf, &routes, NULL);
    TEST_CHECK(ret == 0);
    if (ret == 0) {
        input_routes = cfl_list_entry(routes.next, struct flb_input_routes, _head);
        TEST_CHECK(strcmp(input_routes->input_name, "metrics") == 0);
        TEST_CHECK(cfl_list_size(&input_routes->routes) == 1);

        route = cfl_list_entry(input_routes->routes.next,
                               struct flb_route, _head);
        TEST_CHECK(strcmp(route->name, "cpu_hot") == 0);
        TEST_CHECK(route->signals == FLB_ROUTER_SIGNAL_METRICS);

        output = cfl_list_entry(route->outputs.next,
                                struct flb_route_output, _head);
        TEST_CHECK(strcmp(output->name, "prometheus_remote") == 0);
        TEST_CHECK(strcmp(output->fallback, "s3_backup") == 0);

        flb_router_routes_destroy(&routes);
    }

    flb_cf_destroy(cf);
}

TEST_LIST = {
    { "parse_basic", test_router_config_parse_basic },
    { "duplicate_route", test_router_config_duplicate_route },
    { "parse_basic_file", test_router_config_parse_file_basic },
    { "parse_multi_signal_file", test_router_config_parse_file_multi_signal },
    { "parse_metrics_file", test_router_config_parse_file_metrics },
    { 0 }
};
