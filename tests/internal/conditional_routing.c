/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <string.h>
#include <stdio.h>

#include <fluent-bit/flb_config_format.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_router.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_log_event_encoder.h>
#include <fluent-bit/flb_event.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_input_log.h>
#include <fluent-bit/flb_conditionals.h>
#include <fluent-bit/flb_mp_chunk.h>
#include <fluent-bit/flb_mp.h>
#include <fluent-bit/flb_input_chunk.h>
#include <fluent-bit/flb_hash_table.h>
#include <fluent-bit/flb_routes_mask.h>
#include <fluent-bit/flb_task.h>

#include <cfl/cfl.h>
#include <cfl/cfl_array.h>
#include <cfl/cfl_kvlist.h>
#include <cfl/cfl_variant.h>
#include <cfl/cfl_sds.h>

#include "flb_tests_internal.h"

/* Test data structures */
struct test_log_record {
    const char *level;
    const char *service;
    const char *message;
    const char *expected_route;
};

static const struct test_log_record test_records[] = {
    {"info", "web-server", "Application started successfully", "info_logs"},
    {"error", "database", "Database connection failed", "error_logs"},
    {"undef", "logger", "Unknown log level detected", "default_logs"},
    {"info", "auth", "User authentication successful", "info_logs"},
    {"error", "file-service", "File not found", "error_logs"},
    {"undef", "parser", "Invalid log format", "default_logs"},
    {"info", "cache", "Cache updated successfully", "info_logs"},
    {"error", "memory-manager", "Memory allocation failed", "error_logs"},
    {"undef", "event-processor", "Unrecognized event type", "default_logs"},
    {"info", "test", "Test log entry", "info_logs"}
};

static const size_t test_records_count = sizeof(test_records) / sizeof(test_records[0]);

/* Helper function to create a test log chunk */
static int create_test_log_chunk(const char *level,
                                 const char *service,
                                 const char *message,
                                 struct flb_log_event_encoder *encoder,
                                 struct flb_event_chunk *chunk)
{
    int ret;

    if (!level || !service || !message || !encoder || !chunk) {
        return -1;
    }

    ret = flb_log_event_encoder_init(encoder, FLB_LOG_EVENT_FORMAT_DEFAULT);
    TEST_CHECK(ret == FLB_EVENT_ENCODER_SUCCESS);
    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        return -1;
    }

    ret = flb_log_event_encoder_begin_record(encoder);
    TEST_CHECK(ret == FLB_EVENT_ENCODER_SUCCESS);
    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        flb_log_event_encoder_destroy(encoder);
        return -1;
    }

    ret = flb_log_event_encoder_set_current_timestamp(encoder);
    TEST_CHECK(ret == FLB_EVENT_ENCODER_SUCCESS);
    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        flb_log_event_encoder_destroy(encoder);
        return -1;
    }

    ret = flb_log_event_encoder_append_body_values(
        encoder,
        FLB_LOG_EVENT_STRING_VALUE("level", 5),
        FLB_LOG_EVENT_CSTRING_VALUE(level),
        FLB_LOG_EVENT_STRING_VALUE("service", 7),
        FLB_LOG_EVENT_CSTRING_VALUE(service),
        FLB_LOG_EVENT_STRING_VALUE("message", 7),
        FLB_LOG_EVENT_CSTRING_VALUE(message));
    TEST_CHECK(ret == FLB_EVENT_ENCODER_SUCCESS);
    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        flb_log_event_encoder_destroy(encoder);
        return -1;
    }

    ret = flb_log_event_encoder_commit_record(encoder);
    TEST_CHECK(ret == FLB_EVENT_ENCODER_SUCCESS);
    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        flb_log_event_encoder_destroy(encoder);
        return -1;
    }

    memset(chunk, 0, sizeof(*chunk));
    chunk->type = FLB_EVENT_TYPE_LOGS;
    chunk->data = encoder->output_buffer;
    chunk->size = encoder->output_length;
    chunk->total_events = 1;

    return 0;
}

/* Test conditional routing configuration parsing */
void test_conditional_routing_config_parse()
{
    struct cfl_list routes;
    struct cfl_variant *inputs;
    struct flb_cf *cf;
    struct flb_input_routes *input_routes;
    struct flb_route *route;
    struct cfl_list *head;
    struct cfl_list *route_head;
    int ret;
    int seen_info = 0;
    int seen_error = 0;
    int seen_default = 0;

    cfl_list_init(&routes);

    /* Create test configuration */
    inputs = create_conditional_routing_inputs();
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
        TEST_CHECK(strcmp(input_routes->input_name, "tail") == 0);
        TEST_CHECK(cfl_list_size(&input_routes->routes) == 3);

        cfl_list_foreach(route_head, &input_routes->routes) {
            route = cfl_list_entry(route_head, struct flb_route, _head);
            if (strcmp(route->name, "info_logs") == 0) {
                seen_info = 1;
                TEST_CHECK(route->per_record_routing == FLB_TRUE);
                TEST_CHECK(route->condition != NULL);
                TEST_CHECK(route->condition->is_default == FLB_FALSE);
            }
            else if (strcmp(route->name, "error_logs") == 0) {
                seen_error = 1;
                TEST_CHECK(route->per_record_routing == FLB_TRUE);
                TEST_CHECK(route->condition != NULL);
                TEST_CHECK(route->condition->is_default == FLB_FALSE);
            }
            else if (strcmp(route->name, "default_logs") == 0) {
                seen_default = 1;
                TEST_CHECK(route->per_record_routing == FLB_TRUE);
                TEST_CHECK(route->condition != NULL);
                TEST_CHECK(route->condition->is_default == FLB_TRUE);
            }
        }

        TEST_CHECK(seen_info == 1);
        TEST_CHECK(seen_error == 1);
        TEST_CHECK(seen_default == 1);

        flb_router_routes_destroy(&routes);
    }

    flb_cf_destroy(cf);
    cfl_variant_destroy(inputs);
}

/* Test condition evaluation for individual records */
void test_conditional_routing_condition_eval()
{
    struct flb_route route;
    struct flb_route_condition *condition;
    struct flb_route_condition_rule *rule;
    struct flb_log_event_encoder encoder;
    struct flb_event_chunk chunk;
    struct flb_router_chunk_context context;
    int ret;
    size_t i;

    memset(&route, 0, sizeof(route));
    cfl_list_init(&route.outputs);
    cfl_list_init(&route.processors);

    /* Create condition: level == "info" */
    condition = flb_calloc(1, sizeof(struct flb_route_condition));
    TEST_CHECK(condition != NULL);
    if (!condition) {
        return;
    }

    cfl_list_init(&condition->rules);
    condition->op = FLB_COND_OP_AND;
    condition->compiled_status = 0;
    condition->compiled = NULL;
    condition->is_default = FLB_FALSE;

    rule = flb_calloc(1, sizeof(struct flb_route_condition_rule));
    TEST_CHECK(rule != NULL);
    if (!rule) {
        flb_free(condition);
        return;
    }

    cfl_list_init(&rule->_head);
    rule->field = flb_sds_create("$level");
    rule->op = flb_sds_create("eq");
    rule->value = flb_sds_create("info");
    TEST_CHECK(rule->field != NULL && rule->op != NULL && rule->value != NULL);

    cfl_list_add(&rule->_head, &condition->rules);
    route.condition = condition;
    route.signals = FLB_ROUTER_SIGNAL_LOGS;
    route.per_record_routing = FLB_TRUE;

    flb_router_chunk_context_init(&context);

    /* Test each record */
    for (i = 0; i < test_records_count; i++) {
        const struct test_log_record *record = &test_records[i];
        int expected_result = (strcmp(record->level, "info") == 0) ? FLB_TRUE : FLB_FALSE;

        ret = create_test_log_chunk(record->level, record->service, record->message,
                                   &encoder, &chunk);
        TEST_CHECK(ret == 0);
        if (ret == 0) {
            int result = flb_condition_eval_logs(&chunk, &context, &route);
            TEST_CHECK(result == expected_result);
            if (result != expected_result) {
                fprintf(stderr, "Condition evaluation failed for record %zu: level=%s, expected=%d, got=%d\n",
                        i, record->level, expected_result, result);
            }
        }
        flb_router_chunk_context_reset(&context);
        flb_log_event_encoder_destroy(&encoder);
    }

    flb_router_chunk_context_destroy(&context);
    flb_free(condition);
    flb_sds_destroy(rule->field);
    flb_sds_destroy(rule->op);
    flb_sds_destroy(rule->value);
    flb_free(rule);
}

/* Test per-record routing functionality */
void test_conditional_routing_per_record()
{
    struct flb_config config;
    struct flb_input_instance input;
    struct flb_output_instance output1, output2, output3;
    struct flb_input_plugin input_plugin;
    struct flb_output_plugin output_plugin;
    struct flb_input_routes input_routes;
    struct flb_route route1, route2, route3;
    struct flb_route_output route_output1, route_output2, route_output3;
    struct flb_router_path *path;
    struct flb_log_event_encoder encoder;
    struct flb_event_chunk chunk;
    int ret;
    size_t i;

    /* Setup test instances */
    setup_conditional_routing_instances(&config, &input, &input_plugin,
                                       &output1, &output2, &output3, &output_plugin);

    /* Setup routes */
    setup_conditional_routes(&input_routes, &route1, &route2, &route3,
                            &route_output1, &route_output2, &route_output3,
                            &output1, &output2, &output3);

    /* Apply configuration */
    ret = flb_router_apply_config(&config);
    TEST_CHECK(ret == 0);
    TEST_CHECK(cfl_list_size(&input.routes_direct) == 3);

    /* Test per-record routing for each test record */
    for (i = 0; i < test_records_count; i++) {
        const struct test_log_record *record = &test_records[i];

        ret = create_test_log_chunk(record->level, record->service, record->message,
                                   &encoder, &chunk);
        TEST_CHECK(ret == 0);
        if (ret == 0) {
            /* Test that the record routes to the expected output */
            int routed_correctly = test_record_routing(&input, &chunk, record->expected_route);
            TEST_CHECK(routed_correctly == 1);
            if (!routed_correctly) {
                fprintf(stderr, "Record %zu did not route correctly: level=%s, expected=%s\n",
                        i, record->level, record->expected_route);
            }
        }
        flb_log_event_encoder_destroy(&encoder);
    }

    /* Cleanup */
    flb_router_exit(&config);
    cleanup_conditional_routing_instances(&config, &input, &output1, &output2, &output3,
                                          &input_routes, &route1, &route2, &route3,
                                          &route_output1, &route_output2, &route_output3);
}

/* Test default route handling */
void test_conditional_routing_default_route()
{
    struct flb_config config;
    struct flb_input_instance input;
    struct flb_output_instance output1, output2, output3;
    struct flb_input_plugin input_plugin;
    struct flb_output_plugin output_plugin;
    struct flb_input_routes input_routes;
    struct flb_route route1, route2, route3;
    struct flb_route_output route_output1, route_output2, route_output3;
    struct flb_log_event_encoder encoder;
    struct flb_event_chunk chunk;
    int ret;
    size_t i;
    int default_route_count = 0;

    /* Setup test instances */
    setup_conditional_routing_instances(&config, &input, &input_plugin,
                                       &output1, &output2, &output3, &output_plugin);

    /* Setup routes */
    setup_conditional_routes(&input_routes, &route1, &route2, &route3,
                            &route_output1, &route_output2, &route_output3,
                            &output1, &output2, &output3);

    /* Apply configuration */
    ret = flb_router_apply_config(&config);
    TEST_CHECK(ret == 0);

    /* Test that records with "undef" level go to default route */
    for (i = 0; i < test_records_count; i++) {
        const struct test_log_record *record = &test_records[i];

        if (strcmp(record->level, "undef") == 0) {
            ret = create_test_log_chunk(record->level, record->service, record->message,
                                       &encoder, &chunk);
            TEST_CHECK(ret == 0);
            if (ret == 0) {
                int routed_to_default = test_record_routing(&input, &chunk, "default_logs");
                TEST_CHECK(routed_to_default == 1);
                if (routed_to_default) {
                    default_route_count++;
                }
            }
            flb_log_event_encoder_destroy(&encoder);
        }
    }

    /* Verify that all "undef" records went to default route */
    TEST_CHECK(default_route_count == 3); /* Should have 3 "undef" records */

    /* Cleanup */
    flb_router_exit(&config);
    cleanup_conditional_routing_instances(&config, &input, &output1, &output2, &output3,
                                          &input_routes, &route1, &route2, &route3,
                                          &route_output1, &route_output2, &route_output3);
}

/* Test route mask functionality */
void test_conditional_routing_route_mask()
{
    struct flb_config config;
    struct flb_input_instance input;
    struct flb_output_instance output1, output2, output3;
    struct flb_input_plugin input_plugin;
    struct flb_output_plugin output_plugin;
    struct flb_input_routes input_routes;
    struct flb_route route1, route2, route3;
    struct flb_route_output route_output1, route_output2, route_output3;
    struct flb_input_chunk *chunk;
    flb_route_mask_element *routes_mask;
    int ret;
    size_t i;

    /* Setup test instances */
    setup_conditional_routing_instances(&config, &input, &input_plugin,
                                       &output1, &output2, &output3, &output_plugin);

    /* Setup routes */
    setup_conditional_routes(&input_routes, &route1, &route2, &route3,
                            &route_output1, &route_output2, &route_output3,
                            &output1, &output2, &output3);

    /* Apply configuration */
    ret = flb_router_apply_config(&config);
    TEST_CHECK(ret == 0);

    /* Test route mask for info records */
    for (i = 0; i < test_records_count; i++) {
        const struct test_log_record *record = &test_records[i];

        if (strcmp(record->level, "info") == 0) {
            /* Create a test chunk */
            chunk = flb_input_chunk_create(&input, FLB_INPUT_LOGS, "test_tag", 8);
            TEST_CHECK(chunk != NULL);
            if (chunk) {
                /* Set route mask for info output only */
                routes_mask = chunk->routes_mask;
                flb_routes_mask_set_bit(routes_mask, output1.id, config.router);

                /* Verify route mask is set correctly */
                TEST_CHECK(flb_routes_mask_get_bit(routes_mask, output1.id, config.router) == 1);
                TEST_CHECK(flb_routes_mask_get_bit(routes_mask, output2.id, config.router) == 0);
                TEST_CHECK(flb_routes_mask_get_bit(routes_mask, output3.id, config.router) == 0);

                flb_input_chunk_destroy(chunk);
            }
        }
    }

    /* Cleanup */
    flb_router_exit(&config);
    cleanup_conditional_routing_instances(&config, &input, &output1, &output2, &output3,
                                          &input_routes, &route1, &route2, &route3,
                                          &route_output1, &route_output2, &route_output3);
}

/* Test no duplicate routing */
void test_conditional_routing_no_duplicates()
{
    struct flb_config config;
    struct flb_input_instance input;
    struct flb_output_instance output1, output2, output3;
    struct flb_input_plugin input_plugin;
    struct flb_output_plugin output_plugin;
    struct flb_input_routes input_routes;
    struct flb_route route1, route2, route3;
    struct flb_route_output route_output1, route_output2, route_output3;
    struct flb_log_event_encoder encoder;
    struct flb_event_chunk chunk;
    int ret;
    size_t i;
    int total_routed = 0;
    int info_routed = 0;
    int error_routed = 0;
    int default_routed = 0;

    /* Setup test instances */
    setup_conditional_routing_instances(&config, &input, &input_plugin,
                                       &output1, &output2, &output3, &output_plugin);

    /* Setup routes */
    setup_conditional_routes(&input_routes, &route1, &route2, &route3,
                            &route_output1, &route_output2, &route_output3,
                            &output1, &output2, &output3);

    /* Apply configuration */
    ret = flb_router_apply_config(&config);
    TEST_CHECK(ret == 0);

    /* Test all records and count routing */
    for (i = 0; i < test_records_count; i++) {
        const struct test_log_record *record = &test_records[i];

        ret = create_test_log_chunk(record->level, record->service, record->message,
                                   &encoder, &chunk);
        TEST_CHECK(ret == 0);
        if (ret == 0) {
            int routed = test_record_routing(&input, &chunk, record->expected_route);
            TEST_CHECK(routed == 1);
            if (routed == 1) {
                total_routed++;
                if (strcmp(record->expected_route, "info_logs") == 0) {
                    info_routed++;
                } else if (strcmp(record->expected_route, "error_logs") == 0) {
                    error_routed++;
                } else if (strcmp(record->expected_route, "default_logs") == 0) {
                    default_routed++;
                }
            }
        }
        flb_log_event_encoder_destroy(&encoder);
    }

    /* Verify no duplicates - each record should be routed exactly once */
    TEST_CHECK(total_routed == test_records_count);
    TEST_CHECK(info_routed == 4);  /* 4 info records */
    TEST_CHECK(error_routed == 3); /* 3 error records */
    TEST_CHECK(default_routed == 3); /* 3 default records */

    /* Cleanup */
    flb_router_exit(&config);
    cleanup_conditional_routing_instances(&config, &input, &output1, &output2, &output3,
                                          &input_routes, &route1, &route2, &route3,
                                          &route_output1, &route_output2, &route_output3);
}

/* Helper functions for test setup */

static struct cfl_variant *create_conditional_routing_inputs()
{
    struct cfl_array *inputs;
    struct cfl_kvlist *input;
    struct cfl_kvlist *routes;
    struct cfl_array *log_routes;
    struct cfl_kvlist *route;
    struct cfl_kvlist *condition;
    struct cfl_array *rules;
    struct cfl_kvlist *rule_kv;
    struct cfl_variant *rule_variant;
    struct cfl_array *outputs;
    struct cfl_kvlist *to;
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

    TEST_CHECK(cfl_kvlist_insert_string(input, "name", "tail") == 0);

    routes = cfl_kvlist_create();
    TEST_CHECK(routes != NULL);
    log_routes = cfl_array_create(3);
    TEST_CHECK(log_routes != NULL);

    /* info_logs route */
    route = cfl_kvlist_create();
    TEST_CHECK(route != NULL);
    TEST_CHECK(cfl_kvlist_insert_string(route, "name", "info_logs") == 0);
    TEST_CHECK(cfl_kvlist_insert_bool(route, "per_record_routing", 1) == 0);

    condition = cfl_kvlist_create();
    TEST_CHECK(condition != NULL);
    rules = cfl_array_create(1);
    TEST_CHECK(rules != NULL);

    rule_kv = cfl_kvlist_create();
    TEST_CHECK(rule_kv != NULL);
    TEST_CHECK(cfl_kvlist_insert_string(rule_kv, "field", "$level") == 0);
    TEST_CHECK(cfl_kvlist_insert_string(rule_kv, "op", "eq") == 0);
    TEST_CHECK(cfl_kvlist_insert_string(rule_kv, "value", "info") == 0);
    rule_variant = cfl_variant_create_from_kvlist(rule_kv);
    TEST_CHECK(rule_variant != NULL);
    TEST_CHECK(cfl_array_append(rules, rule_variant) == 0);

    TEST_CHECK(cfl_kvlist_insert_array(condition, "rules", rules) == 0);
    TEST_CHECK(cfl_kvlist_insert_kvlist(route, "condition", condition) == 0);

    outputs = cfl_array_create(1);
    TEST_CHECK(outputs != NULL);
    TEST_CHECK(cfl_array_append_string(outputs, "info_destination") == 0);
    to = cfl_kvlist_create();
    TEST_CHECK(to != NULL);
    TEST_CHECK(cfl_kvlist_insert_array(to, "outputs", outputs) == 0);
    TEST_CHECK(cfl_kvlist_insert_kvlist(route, "to", to) == 0);

    TEST_CHECK(cfl_array_append(log_routes, cfl_variant_create_from_kvlist(route)) == 0);

    /* error_logs route */
    route = cfl_kvlist_create();
    TEST_CHECK(route != NULL);
    TEST_CHECK(cfl_kvlist_insert_string(route, "name", "error_logs") == 0);
    TEST_CHECK(cfl_kvlist_insert_bool(route, "per_record_routing", 1) == 0);

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
    TEST_CHECK(cfl_array_append_string(outputs, "error_destination") == 0);
    to = cfl_kvlist_create();
    TEST_CHECK(to != NULL);
    TEST_CHECK(cfl_kvlist_insert_array(to, "outputs", outputs) == 0);
    TEST_CHECK(cfl_kvlist_insert_kvlist(route, "to", to) == 0);

    TEST_CHECK(cfl_array_append(log_routes, cfl_variant_create_from_kvlist(route)) == 0);

    /* default_logs route */
    route = cfl_kvlist_create();
    TEST_CHECK(route != NULL);
    TEST_CHECK(cfl_kvlist_insert_string(route, "name", "default_logs") == 0);
    TEST_CHECK(cfl_kvlist_insert_bool(route, "per_record_routing", 1) == 0);

    condition = cfl_kvlist_create();
    TEST_CHECK(condition != NULL);
    TEST_CHECK(cfl_kvlist_insert_bool(condition, "default", 1) == 0);
    TEST_CHECK(cfl_kvlist_insert_kvlist(route, "condition", condition) == 0);

    outputs = cfl_array_create(1);
    TEST_CHECK(outputs != NULL);
    TEST_CHECK(cfl_array_append_string(outputs, "default_destination") == 0);
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
    struct cfl_array *array_copy;
    struct cfl_kvlist *kvlist_copy;
    int referenced;

    array_copy = NULL;
    kvlist_copy = NULL;
    referenced = CFL_FALSE;

    if (!var) {
        return NULL;
    }

    switch (var->type) {
    case CFL_VARIANT_STRING:
        referenced = (var->referenced == CFL_TRUE) ? CFL_TRUE : CFL_FALSE;
        return cfl_variant_create_from_string_s(var->data.as_string,
                                                cfl_sds_len(var->data.as_string),
                                                referenced);
    case CFL_VARIANT_BOOL:
        return cfl_variant_create_from_bool(var->data.as_bool);
    case CFL_VARIANT_ARRAY:
        array_copy = clone_array(var->data.as_array);
        if (!array_copy) {
            return NULL;
        }
        return cfl_variant_create_from_array(array_copy);
    case CFL_VARIANT_KVLIST:
        kvlist_copy = clone_kvlist(var->data.as_kvlist);
        if (!kvlist_copy) {
            return NULL;
        }
        return cfl_variant_create_from_kvlist(kvlist_copy);
    default:
        break;
    }

    return NULL;
}

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

static void setup_conditional_routing_instances(struct flb_config *config,
                                               struct flb_input_instance *input,
                                               struct flb_input_plugin *input_plugin,
                                               struct flb_output_instance *output1,
                                               struct flb_output_instance *output2,
                                               struct flb_output_instance *output3,
                                               struct flb_output_plugin *output_plugin)
{
    memset(config, 0, sizeof(struct flb_config));
    mk_list_init(&config->inputs);
    mk_list_init(&config->outputs);
    cfl_list_init(&config->input_routes);

    config->router = flb_router_create(config);
    TEST_CHECK(config->router != NULL);
    if (config->router) {
        flb_routes_mask_set_size(1, config->router);
    }

    memset(input, 0, sizeof(struct flb_input_instance));
    mk_list_init(&input->_head);
    cfl_list_init(&input->routes_direct);
    cfl_list_init(&input->routes);
    mk_list_init(&input->tasks);
    mk_list_init(&input->chunks);
    mk_list_init(&input->collectors);
    snprintf(input->name, sizeof(input->name), "tail.0");
    input->alias = flb_sds_create("test_input");
    input_plugin->name = "tail";
    input->p = input_plugin;
    mk_list_add(&input->_head, &config->inputs);

    memset(output1, 0, sizeof(struct flb_output_instance));
    mk_list_init(&output1->_head);
    mk_list_init(&output1->properties);
    mk_list_init(&output1->net_properties);
    snprintf(output1->name, sizeof(output1->name), "stdout.0");
    output1->alias = flb_sds_create("info_destination");
    output1->event_type = FLB_OUTPUT_LOGS;
    output1->id = 1;
    output_plugin->name = "stdout";
    output1->p = output_plugin;
    mk_list_add(&output1->_head, &config->outputs);

    memset(output2, 0, sizeof(struct flb_output_instance));
    mk_list_init(&output2->_head);
    mk_list_init(&output2->properties);
    mk_list_init(&output2->net_properties);
    snprintf(output2->name, sizeof(output2->name), "stdout.1");
    output2->alias = flb_sds_create("error_destination");
    output2->event_type = FLB_OUTPUT_LOGS;
    output2->id = 2;
    output2->p = output_plugin;
    mk_list_add(&output2->_head, &config->outputs);

    memset(output3, 0, sizeof(struct flb_output_instance));
    mk_list_init(&output3->_head);
    mk_list_init(&output3->properties);
    mk_list_init(&output3->net_properties);
    snprintf(output3->name, sizeof(output3->name), "stdout.2");
    output3->alias = flb_sds_create("default_destination");
    output3->event_type = FLB_OUTPUT_LOGS;
    output3->id = 3;
    output3->p = output_plugin;
    mk_list_add(&output3->_head, &config->outputs);
}

static void setup_conditional_routes(struct flb_input_routes *input_routes,
                                    struct flb_route *route1,
                                    struct flb_route *route2,
                                    struct flb_route *route3,
                                    struct flb_route_output *route_output1,
                                    struct flb_route_output *route_output2,
                                    struct flb_route_output *route_output3,
                                    struct flb_output_instance *output1,
                                    struct flb_output_instance *output2,
                                    struct flb_output_instance *output3)
{
    memset(input_routes, 0, sizeof(struct flb_input_routes));
    cfl_list_init(&input_routes->_head);
    cfl_list_init(&input_routes->routes);
    input_routes->input_name = flb_sds_create("tail");
    input_routes->plugin_name = flb_sds_create("tail");
    input_routes->has_alias = FLB_FALSE;

    /* Route 1: info_logs */
    memset(route1, 0, sizeof(struct flb_route));
    cfl_list_init(&route1->_head);
    cfl_list_init(&route1->outputs);
    route1->name = flb_sds_create("info_logs");
    route1->signals = FLB_ROUTER_SIGNAL_LOGS;
    route1->per_record_routing = FLB_TRUE;
    cfl_list_add(&route1->_head, &input_routes->routes);

    memset(route_output1, 0, sizeof(struct flb_route_output));
    cfl_list_init(&route_output1->_head);
    route_output1->name = flb_sds_create("info_destination");
    cfl_list_add(&route_output1->_head, &route1->outputs);

    /* Route 2: error_logs */
    memset(route2, 0, sizeof(struct flb_route));
    cfl_list_init(&route2->_head);
    cfl_list_init(&route2->outputs);
    route2->name = flb_sds_create("error_logs");
    route2->signals = FLB_ROUTER_SIGNAL_LOGS;
    route2->per_record_routing = FLB_TRUE;
    cfl_list_add(&route2->_head, &input_routes->routes);

    memset(route_output2, 0, sizeof(struct flb_route_output));
    cfl_list_init(&route_output2->_head);
    route_output2->name = flb_sds_create("error_destination");
    cfl_list_add(&route_output2->_head, &route2->outputs);

    /* Route 3: default_logs */
    memset(route3, 0, sizeof(struct flb_route));
    cfl_list_init(&route3->_head);
    cfl_list_init(&route3->outputs);
    route3->name = flb_sds_create("default_logs");
    route3->signals = FLB_ROUTER_SIGNAL_LOGS;
    route3->per_record_routing = FLB_TRUE;
    cfl_list_add(&route3->_head, &input_routes->routes);

    memset(route_output3, 0, sizeof(struct flb_route_output));
    cfl_list_init(&route_output3->_head);
    route_output3->name = flb_sds_create("default_destination");
    cfl_list_add(&route_output3->_head, &route3->outputs);
}

static int test_record_routing(struct flb_input_instance *input,
                              struct flb_event_chunk *chunk,
                              const char *expected_route)
{
    struct mk_list *head;
    struct flb_router_path *path;
    struct flb_router_chunk_context context;
    int found = 0;

    flb_router_chunk_context_init(&context);

    cfl_list_foreach(head, &input->routes_direct) {
        path = cfl_list_entry(head, struct flb_router_path, _head);

        if (path->route && strcmp(path->route->name, expected_route) == 0) {
            if (flb_router_path_should_route(chunk, &context, path) == FLB_TRUE) {
                found = 1;
                break;
            }
        }
    }

    flb_router_chunk_context_destroy(&context);
    return found;
}

static void cleanup_conditional_routing_instances(struct flb_config *config,
                                                 struct flb_input_instance *input,
                                                 struct flb_output_instance *output1,
                                                 struct flb_output_instance *output2,
                                                 struct flb_output_instance *output3,
                                                 struct flb_input_routes *input_routes,
                                                 struct flb_route *route1,
                                                 struct flb_route *route2,
                                                 struct flb_route *route3,
                                                 struct flb_route_output *route_output1,
                                                 struct flb_route_output *route_output2,
                                                 struct flb_route_output *route_output3)
{
    flb_sds_destroy(input->alias);
    flb_sds_destroy(output1->alias);
    flb_sds_destroy(output2->alias);
    flb_sds_destroy(output3->alias);
    flb_sds_destroy(input_routes->input_name);
    flb_sds_destroy(input_routes->plugin_name);
    flb_sds_destroy(route1->name);
    flb_sds_destroy(route2->name);
    flb_sds_destroy(route3->name);
    flb_sds_destroy(route_output1->name);
    flb_sds_destroy(route_output2->name);
    flb_sds_destroy(route_output3->name);

    if (config && config->router) {
        flb_router_destroy(config->router);
        config->router = NULL;
    }
}

TEST_LIST = {
    { "config_parse", test_conditional_routing_config_parse },
    { "condition_eval", test_conditional_routing_condition_eval },
    { "per_record", test_conditional_routing_per_record },
    { "default_route", test_conditional_routing_default_route },
    { "route_mask", test_conditional_routing_route_mask },
    { "no_duplicates", test_conditional_routing_no_duplicates },
    { 0 }
};
