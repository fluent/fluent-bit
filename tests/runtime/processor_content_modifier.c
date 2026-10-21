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

#include <fluent-bit.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_log_event_decoder.h>
#include <fluent-bit/flb_pack.h>
#include <cmetrics/cmetrics.h>
#include <ctraces/ctraces.h>
#include <msgpack.h>
#include "flb_tests_runtime.h"
#include "../../plugins/processor_content_modifier/cm.h"

struct processor_test {
    flb_ctx_t *flb;    /* Fluent Bit library context */
    int i_ffd;         /* Input fd  */
    int f_ffd;         /* Filter fd */
    int o_ffd;         /* Output fd */
    int type; /* logs/metrics/traces */
    struct flb_processor *proc;
    struct flb_processor_unit *pu;
};

struct expect_str {
    char *str;
    int  found;
};


/* Callback to check expected results */
static int cb_check_result(void *record, size_t size, void *data)
{
    char *p;
    char *result;
    struct expect_str *expected;

    expected = (struct expect_str*)data;
    result = (char *) record;

    if (!TEST_CHECK(expected != NULL)) {
        flb_error("expected is NULL");
    }
    if (!TEST_CHECK(result != NULL)) {
        flb_error("result is NULL");
    }

    while(expected != NULL && expected->str != NULL) {
        if (expected->found == FLB_TRUE) {
            p = strstr(result, expected->str);
            if(!TEST_CHECK(p != NULL)) {
                flb_error("Expected to find: '%s' in result '%s'",
                          expected->str, result);
            }
        }
        else {
            p = strstr(result, expected->str);
            if(!TEST_CHECK(p == NULL)) {
                flb_error("'%s' should be removed in result '%s'",
                          expected->str, result);
            }
        }

        /*
         * If you want to debug your test
         *
         * printf("Expect: '%s' in result '%s'", expected, result);
         */

        expected++;
    }

    flb_free(record);
    return 0;
}

static int cb_check_metadata_result(void *record, size_t size, void *data)
{
    int ret;
    char *p;
    flb_sds_t result;
    size_t result_size = 1024;
    struct expect_str *expected;
    struct flb_log_event event;
    struct flb_log_event_decoder decoder;

    expected = (struct expect_str *) data;
    result = NULL;

    ret = flb_log_event_decoder_init(&decoder, (char *) record, size);
    if (!TEST_CHECK(ret == FLB_EVENT_DECODER_SUCCESS)) {
        return -1;
    }

    flb_log_event_decoder_read_groups(&decoder, FLB_TRUE);

    ret = flb_log_event_decoder_next(&decoder, &event);
    if (!TEST_CHECK(ret == FLB_EVENT_DECODER_SUCCESS)) {
        flb_log_event_decoder_destroy(&decoder);
        return -1;
    }

    result = flb_sds_create_size(result_size);
    if (!TEST_CHECK(result != NULL)) {
        flb_log_event_decoder_destroy(&decoder);
        return -1;
    }

    ret = flb_msgpack_to_json(result, result_size, event.metadata, FLB_TRUE);
    if (!TEST_CHECK(ret >= 0)) {
        flb_sds_destroy(result);
        flb_log_event_decoder_destroy(&decoder);
        return -1;
    }

    while(expected != NULL && expected->str != NULL) {
        if (expected->found == FLB_TRUE) {
            p = strstr(result, expected->str);
            if(!TEST_CHECK(p != NULL)) {
                flb_error("Expected to find: '%s' in metadata '%s'",
                          expected->str, result);
            }
        }
        else {
            p = strstr(result, expected->str);
            if(!TEST_CHECK(p == NULL)) {
                flb_error("'%s' should be removed from metadata '%s'",
                          expected->str, result);
            }
        }

        expected++;
    }

    flb_sds_destroy(result);
    flb_log_event_decoder_destroy(&decoder);

    return 0;
}

static int init_logs(struct processor_test *ctx, struct flb_lib_out_cb *data)
{
    int i_ffd;
    int o_ffd;
    int ret;

    /* Input */
    i_ffd = flb_input(ctx->flb, (char *) "lib", NULL);
    if(!TEST_CHECK(i_ffd >= 0)) {
        TEST_MSG("flb_input failed");
        return -1;
    }
    flb_input_set(ctx->flb, i_ffd, "tag", "test", NULL);
    ctx->i_ffd = i_ffd;

    /* Output */
    o_ffd = flb_output(ctx->flb, (char *) "lib", (void *) data);
    if(!TEST_CHECK(o_ffd >= 0)) {
        TEST_MSG("flb_output failed");
        return -1;
    }
    flb_output_set(ctx->flb, o_ffd,
                   "match", "test",
                   NULL);
    ctx->o_ffd = o_ffd;

    ctx->pu = flb_processor_unit_create(ctx->proc, ctx->type, "content_modifier");
    if(!TEST_CHECK(ctx->pu != NULL)) {
        TEST_MSG("flb_processor_unit_create failed");
        return -1;
    }

    ret = flb_input_set_processor(ctx->flb, i_ffd, ctx->proc);
    if(!TEST_CHECK(ret == 0)) {
        TEST_MSG("flb_input_set_processor faild");
        return -1;
    }

    return 0;
}

static struct processor_test *processor_test_create(int type, struct flb_lib_out_cb *data)
{
    struct processor_test *ctx;
    int ret = -1;

    ctx = flb_malloc(sizeof(struct processor_test));
    if (!ctx) {
        flb_errno();
        return NULL;
    }
    ctx->proc = NULL;
    ctx->i_ffd = -1;
    ctx->f_ffd = -1;

    /* Service config */
    ctx->flb = flb_create();
    flb_service_set(ctx->flb,
                    "Flush", "0.200000000",
                    "Grace", "1",
                    "Log_Level", "error",
                    NULL);

    ctx->proc = flb_processor_create(ctx->flb->config, "unit_test", NULL, 0);
    if (!TEST_CHECK(ctx->proc != NULL)) {
        TEST_MSG("flb_processor_create failed");
        flb_destroy(ctx->flb);
        flb_free(ctx);
        return NULL;
    }

    ctx->type = type;
    switch (type) {
    case FLB_PROCESSOR_LOGS:
        ret = init_logs(ctx, data);
        break;
    default:
        flb_error("not implemented");
    }


    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("init failed");
        flb_destroy(ctx->flb);
        flb_free(ctx);
        return NULL;
    }

    return ctx;
}

static void processor_test_destroy(struct processor_test *ctx)
{
    sleep(1);
    flb_stop(ctx->flb);
    flb_destroy(ctx->flb);
    flb_free(ctx);
}

static int run_content_modifier_direct(int type,
                                       char *action_name,
                                       char *context_name,
                                       char **key_names,
                                       size_t key_count,
                                       char *value_string,
                                       char *converted_type_string,
                                       void *data)
{
    int ret;
    size_t index;
    size_t out_size;
    void *out_buf;
    struct cfl_array *array;
    struct cfl_variant *key;
    struct cfl_variant scalar_key;
    struct flb_config *config;
    struct flb_processor *processor;
    struct flb_processor_unit *unit;
    struct cfl_variant action = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = action_name,
    };
    struct cfl_variant context = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = context_name,
    };
    struct cfl_variant value = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = value_string,
    };
    struct cfl_variant converted_type = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = converted_type_string,
    };

    ret = -1;
    out_buf = NULL;
    out_size = 0;
    processor = NULL;

    flb_init_env();
    config = flb_config_init();
    if (config == NULL) {
        return -1;
    }

    processor = flb_processor_create(config, "unit_test", NULL, 0);
    if (processor == NULL) {
        goto cleanup;
    }

    unit = flb_processor_unit_create(processor, type, "content_modifier");
    if (unit == NULL) {
        goto cleanup;
    }

    if (flb_processor_unit_set_property(unit, "action", &action) != 0 ||
        flb_processor_unit_set_property(unit, "context", &context) != 0) {
        goto cleanup;
    }

    if (key_count == 1) {
        scalar_key.type = CFL_VARIANT_STRING;
        scalar_key.data.as_string = key_names[0];

        if (flb_processor_unit_set_property(unit, "key", &scalar_key) != 0) {
            goto cleanup;
        }
    }
    else {
        array = cfl_array_create(key_count);
        if (array == NULL) {
            goto cleanup;
        }

        for (index = 0; index < key_count; index++) {
            if (cfl_array_append_string(array, key_names[index]) != 0) {
                cfl_array_destroy(array);
                goto cleanup;
            }
        }

        key = cfl_variant_create_from_array(array);
        if (key == NULL) {
            cfl_array_destroy(array);
            goto cleanup;
        }

        ret = flb_processor_unit_set_property(unit, "key", key);
        cfl_variant_destroy(key);
        if (ret != 0) {
            goto cleanup;
        }
    }

    if (value_string != NULL &&
        flb_processor_unit_set_property(unit, "value", &value) != 0) {
        goto cleanup;
    }

    if (converted_type_string != NULL &&
        flb_processor_unit_set_property(unit, "converted_type", &converted_type) != 0) {
        goto cleanup;
    }

    ret = flb_processor_init(processor);
    if (ret != 0) {
        goto cleanup;
    }

    ret = flb_processor_run(processor, 0, type, "test", 4,
                            data, 0, &out_buf, &out_size);
    if (ret == 0 && out_buf != data) {
        ret = -1;
    }

cleanup:
    if (processor != NULL) {
        flb_processor_destroy(processor);
    }
    flb_config_exit(config);

    return ret;
}

static struct cfl_kvlist *create_metrics_resource_attributes(struct cmt *context)
{
    struct cfl_kvlist *resource;
    struct cfl_kvlist *attributes;

    if (cfl_kvlist_insert_string(context->internal_metadata,
                                 "producer", "opentelemetry") != 0) {
        return NULL;
    }

    resource = cfl_kvlist_create();
    if (resource == NULL) {
        return NULL;
    }

    attributes = cfl_kvlist_create();
    if (attributes == NULL) {
        cfl_kvlist_destroy(resource);
        return NULL;
    }

    if (cfl_kvlist_insert_kvlist(resource, "attributes", attributes) != 0) {
        cfl_kvlist_destroy(attributes);
        cfl_kvlist_destroy(resource);
        return NULL;
    }

    if (cfl_kvlist_insert_kvlist(context->external_metadata,
                                 "resource", resource) != 0) {
        cfl_kvlist_destroy(resource);
        return NULL;
    }

    return attributes;
}

static int string_attribute_equals(struct cfl_kvlist *attributes,
                                   char *name, char *expected)
{
    struct cfl_variant *value;

    value = cfl_kvlist_fetch(attributes, name);
    if (value == NULL || value->type != CFL_VARIANT_STRING) {
        return FLB_FALSE;
    }

    return strcmp(value->data.as_string, expected) == 0;
}

static void assert_metrics_crud_action(char *action_name, int use_key_list)
{
    int ret;
    char *value;
    char *keys[] = {"foo", "bar", "missing"};
    char *scalar_key;
    char **selected_keys;
    size_t key_count;
    struct cmt *context;
    struct cfl_kvlist *attributes;

    context = cmt_create();
    TEST_CHECK(context != NULL);
    if (context == NULL) {
        return;
    }

    attributes = create_metrics_resource_attributes(context);
    TEST_CHECK(attributes != NULL);
    if (attributes == NULL) {
        cmt_destroy(context);
        return;
    }

    TEST_CHECK(cfl_kvlist_insert_string(attributes, "foo", "old") == 0);
    TEST_CHECK(cfl_kvlist_insert_string(attributes, "keep", "unchanged") == 0);
    if (strcmp(action_name, "delete") == 0) {
        TEST_CHECK(cfl_kvlist_insert_string(attributes, "bar", "old") == 0);
        value = NULL;
    }
    else {
        value = "new";
    }

    if (use_key_list == FLB_TRUE) {
        selected_keys = keys;
        key_count = 3;
    }
    else {
        if (strcmp(action_name, "insert") == 0) {
            scalar_key = "bar";
        }
        else {
            scalar_key = "foo";
        }
        selected_keys = &scalar_key;
        key_count = 1;
    }

    ret = run_content_modifier_direct(FLB_PROCESSOR_METRICS,
                                      action_name,
                                      "otel_resource_attributes",
                                      selected_keys, key_count, value, NULL, context);
    TEST_CHECK(ret == 0);

    if (strcmp(action_name, "insert") == 0) {
        TEST_CHECK(string_attribute_equals(attributes, "foo", "old") == FLB_TRUE);
        TEST_CHECK(string_attribute_equals(attributes, "bar", "new") == FLB_TRUE);
        if (use_key_list == FLB_TRUE) {
            TEST_CHECK(string_attribute_equals(attributes, "missing", "new") == FLB_TRUE);
        }
        else {
            TEST_CHECK(cfl_kvlist_contains(attributes, "missing") == FLB_FALSE);
        }
    }
    else if (strcmp(action_name, "upsert") == 0) {
        TEST_CHECK(string_attribute_equals(attributes, "foo", "new") == FLB_TRUE);
        if (use_key_list == FLB_TRUE) {
            TEST_CHECK(string_attribute_equals(attributes, "bar", "new") == FLB_TRUE);
            TEST_CHECK(string_attribute_equals(attributes, "missing", "new") == FLB_TRUE);
        }
        else {
            TEST_CHECK(cfl_kvlist_contains(attributes, "bar") == FLB_FALSE);
            TEST_CHECK(cfl_kvlist_contains(attributes, "missing") == FLB_FALSE);
        }
    }
    else {
        TEST_CHECK(cfl_kvlist_contains(attributes, "foo") == FLB_FALSE);
        if (use_key_list == FLB_TRUE) {
            TEST_CHECK(cfl_kvlist_contains(attributes, "bar") == FLB_FALSE);
        }
        else {
            TEST_CHECK(string_attribute_equals(attributes, "bar", "old") == FLB_TRUE);
        }
        TEST_CHECK(cfl_kvlist_contains(attributes, "missing") == FLB_FALSE);
    }

    TEST_CHECK(string_attribute_equals(attributes, "keep", "unchanged") == FLB_TRUE);
    cmt_destroy(context);
}

static void flb_metrics_action_insert()
{
    assert_metrics_crud_action("insert", FLB_FALSE);
}

static void flb_metrics_action_upsert()
{
    assert_metrics_crud_action("upsert", FLB_FALSE);
}

static void flb_metrics_action_delete()
{
    assert_metrics_crud_action("delete", FLB_FALSE);
}

static void flb_metrics_action_insert_key_list()
{
    assert_metrics_crud_action("insert", FLB_TRUE);
}

static void flb_metrics_action_upsert_key_list()
{
    assert_metrics_crud_action("upsert", FLB_TRUE);
}

static void flb_metrics_action_delete_key_list()
{
    assert_metrics_crud_action("delete", FLB_TRUE);
}

static void flb_metrics_action_convert_key_list_atomic()
{
    int ret;
    char *keys[] = {"foo", "bar"};
    struct cmt *context;
    struct cfl_kvlist *attributes;

    context = cmt_create();
    TEST_CHECK(context != NULL);
    if (context == NULL) {
        return;
    }

    attributes = create_metrics_resource_attributes(context);
    TEST_CHECK(attributes != NULL);
    if (attributes == NULL) {
        cmt_destroy(context);
        return;
    }

    TEST_CHECK(cfl_kvlist_insert_string(attributes, "foo", "1") == 0);
    TEST_CHECK(cfl_kvlist_insert_string(attributes, "bar", "invalid") == 0);

    ret = run_content_modifier_direct(FLB_PROCESSOR_METRICS,
                                      "convert", "otel_resource_attributes",
                                      keys, 2, NULL, "int", context);
    TEST_CHECK(ret != 0);
    TEST_CHECK(string_attribute_equals(attributes, "foo", "1") == FLB_TRUE);
    TEST_CHECK(string_attribute_equals(attributes, "bar", "invalid") == FLB_TRUE);

    cmt_destroy(context);
}

static void flb_metrics_action_convert_key_list_missing_key()
{
    int ret;
    char *keys[] = {"missing", "foo"};
    struct cmt *context;
    struct cfl_kvlist *attributes;
    struct cfl_variant *value;

    context = cmt_create();
    TEST_CHECK(context != NULL);
    if (context == NULL) {
        return;
    }

    attributes = create_metrics_resource_attributes(context);
    TEST_CHECK(attributes != NULL);
    if (attributes == NULL) {
        cmt_destroy(context);
        return;
    }

    TEST_CHECK(cfl_kvlist_insert_string(attributes, "foo", "1") == 0);

    ret = run_content_modifier_direct(FLB_PROCESSOR_METRICS,
                                      "convert", "otel_resource_attributes",
                                      keys, 2, NULL, "int", context);
    TEST_CHECK(ret == 0);

    value = cfl_kvlist_fetch(attributes, "foo");
    TEST_CHECK(value != NULL);
    if (value != NULL) {
        TEST_CHECK(value->type == CFL_VARIANT_INT);
        TEST_CHECK(value->data.as_int64 == 1);
    }
    TEST_CHECK(cfl_kvlist_contains(attributes, "missing") == FLB_FALSE);

    cmt_destroy(context);
}

struct traces_fixture {
    struct ctrace_opts opts;
    struct ctrace *context;
    struct ctrace_span *first_span;
    struct ctrace_span *second_span;
};

static int traces_fixture_create(struct traces_fixture *fixture)
{
    struct ctrace_resource_span *resource_span;
    struct ctrace_scope_span *scope_span;

    memset(fixture, 0, sizeof(struct traces_fixture));
    ctr_opts_init(&fixture->opts);

    fixture->context = ctr_create(&fixture->opts);
    if (fixture->context == NULL) {
        ctr_opts_exit(&fixture->opts);
        return -1;
    }

    resource_span = ctr_resource_span_create(fixture->context);
    if (resource_span == NULL) {
        return -1;
    }

    scope_span = ctr_scope_span_create(resource_span);
    if (scope_span == NULL) {
        return -1;
    }

    fixture->first_span = ctr_span_create(fixture->context, scope_span,
                                          "first", NULL);
    fixture->second_span = ctr_span_create(fixture->context, scope_span,
                                           "second", NULL);
    if (fixture->first_span == NULL || fixture->second_span == NULL) {
        return -1;
    }

    return 0;
}

static void traces_fixture_destroy(struct traces_fixture *fixture)
{
    if (fixture->context != NULL) {
        ctr_destroy(fixture->context);
    }
    ctr_opts_exit(&fixture->opts);
}

static int span_attribute_equals(struct ctrace_span *span,
                                 char *name, char *expected)
{
    if (span->attr == NULL) {
        return FLB_FALSE;
    }

    return string_attribute_equals(span->attr->kv, name, expected);
}

static int span_contains_key(struct ctrace_span *span, char *name)
{
    if (span->attr == NULL) {
        return FLB_FALSE;
    }

    return cfl_kvlist_contains(span->attr->kv, name);
}

static void assert_traces_crud_action(char *action_name, int use_key_list)
{
    int ret;
    char *value;
    size_t index;
    char *keys[] = {"foo", "bar", "missing"};
    char *scalar_key;
    char **selected_keys;
    size_t key_count;
    struct ctrace_span *spans[2];
    struct traces_fixture fixture;

    ret = traces_fixture_create(&fixture);
    TEST_CHECK(ret == 0);
    if (ret != 0) {
        traces_fixture_destroy(&fixture);
        return;
    }

    spans[0] = fixture.first_span;
    spans[1] = fixture.second_span;

    for (index = 0; index < 2; index++) {
        TEST_CHECK(ctr_span_set_attribute_string(spans[index], "foo", "old") == 0);
        TEST_CHECK(ctr_span_set_attribute_string(spans[index],
                                                 "keep", "unchanged") == 0);
        if (strcmp(action_name, "delete") == 0) {
            TEST_CHECK(ctr_span_set_attribute_string(spans[index], "bar", "old") == 0);
        }
    }

    if (strcmp(action_name, "delete") == 0) {
        value = NULL;
    }
    else {
        value = "new";
    }

    if (use_key_list == FLB_TRUE) {
        selected_keys = keys;
        key_count = 3;
    }
    else {
        if (strcmp(action_name, "insert") == 0) {
            scalar_key = "bar";
        }
        else {
            scalar_key = "foo";
        }
        selected_keys = &scalar_key;
        key_count = 1;
    }

    ret = run_content_modifier_direct(FLB_PROCESSOR_TRACES,
                                      action_name,
                                      "span_attributes",
                                      selected_keys, key_count, value, NULL, fixture.context);
    TEST_CHECK(ret == 0);

    for (index = 0; index < 2; index++) {
        if (strcmp(action_name, "insert") == 0) {
            TEST_CHECK(span_attribute_equals(spans[index], "foo", "old") == FLB_TRUE);
            TEST_CHECK(span_attribute_equals(spans[index], "bar", "new") == FLB_TRUE);
            if (use_key_list == FLB_TRUE) {
                TEST_CHECK(span_attribute_equals(spans[index],
                                                 "missing", "new") == FLB_TRUE);
            }
            else {
                TEST_CHECK(span_contains_key(spans[index], "missing") == FLB_FALSE);
            }
        }
        else if (strcmp(action_name, "upsert") == 0) {
            TEST_CHECK(span_attribute_equals(spans[index], "foo", "new") == FLB_TRUE);
            if (use_key_list == FLB_TRUE) {
                TEST_CHECK(span_attribute_equals(spans[index], "bar", "new") == FLB_TRUE);
                TEST_CHECK(span_attribute_equals(spans[index],
                                                 "missing", "new") == FLB_TRUE);
            }
            else {
                TEST_CHECK(span_contains_key(spans[index], "bar") == FLB_FALSE);
                TEST_CHECK(span_contains_key(spans[index], "missing") == FLB_FALSE);
            }
        }
        else {
            TEST_CHECK(span_contains_key(spans[index], "foo") == FLB_FALSE);
            if (use_key_list == FLB_TRUE) {
                TEST_CHECK(span_contains_key(spans[index], "bar") == FLB_FALSE);
            }
            else {
                TEST_CHECK(span_attribute_equals(spans[index],
                                                 "bar", "old") == FLB_TRUE);
            }
            TEST_CHECK(span_contains_key(spans[index], "missing") == FLB_FALSE);
        }

        TEST_CHECK(span_attribute_equals(spans[index],
                                         "keep", "unchanged") == FLB_TRUE);
    }

    traces_fixture_destroy(&fixture);
}

static void flb_traces_action_insert()
{
    assert_traces_crud_action("insert", FLB_FALSE);
}

static void flb_traces_action_upsert()
{
    assert_traces_crud_action("upsert", FLB_FALSE);
}

static void flb_traces_action_delete()
{
    assert_traces_crud_action("delete", FLB_FALSE);
}

static void flb_traces_action_insert_key_list()
{
    assert_traces_crud_action("insert", FLB_TRUE);
}

static void flb_traces_action_upsert_key_list()
{
    assert_traces_crud_action("upsert", FLB_TRUE);
}

static void flb_traces_action_delete_key_list()
{
    assert_traces_crud_action("delete", FLB_TRUE);
}

static void flb_traces_action_convert_key_list_atomic()
{
    int ret;
    size_t index;
    char *keys[] = {"foo", "bar"};
    struct ctrace_span *spans[2];
    struct traces_fixture fixture;

    ret = traces_fixture_create(&fixture);
    TEST_CHECK(ret == 0);
    if (ret != 0) {
        traces_fixture_destroy(&fixture);
        return;
    }

    spans[0] = fixture.first_span;
    spans[1] = fixture.second_span;
    for (index = 0; index < 2; index++) {
        TEST_CHECK(ctr_span_set_attribute_string(spans[index], "foo", "1") == 0);
        TEST_CHECK(ctr_span_set_attribute_string(spans[index],
                                                 "bar", "invalid") == 0);
    }

    ret = run_content_modifier_direct(FLB_PROCESSOR_TRACES,
                                      "convert", "span_attributes",
                                      keys, 2, NULL, "int", fixture.context);
    TEST_CHECK(ret != 0);

    for (index = 0; index < 2; index++) {
        TEST_CHECK(span_attribute_equals(spans[index], "foo", "1") == FLB_TRUE);
        TEST_CHECK(span_attribute_equals(spans[index], "bar", "invalid") == FLB_TRUE);
    }

    traces_fixture_destroy(&fixture);
}

static void assert_otel_scope_context_key(char *context_name, char *expected_key)
{
    int ret;
    struct processor_test *ctx;
    struct flb_lib_out_cb cb_data = {0};
    struct cfl_variant action = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "upsert",
    };
    struct cfl_variant context = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = context_name,
    };
    struct cfl_variant value = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "new value",
    };
    struct flb_processor_instance *ins;
    struct content_modifier_ctx *cm_ctx;

    ctx = processor_test_create(FLB_PROCESSOR_LOGS, &cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("failed to create ctx");
        return;
    }

    ret = flb_processor_unit_set_property(ctx->pu, "action", &action);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(ctx->pu, "context", &context);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(ctx->pu, "value", &value);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx->flb);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("flb_start failed");
        processor_test_destroy(ctx);
        return;
    }

    ins = (struct flb_processor_instance *) ctx->pu->ctx;
    if (!TEST_CHECK(ins != NULL)) {
        TEST_MSG("processor instance is NULL");
        processor_test_destroy(ctx);
        return;
    }

    cm_ctx = (struct content_modifier_ctx *) ins->context;
    if (!TEST_CHECK(cm_ctx != NULL)) {
        TEST_MSG("content modifier context is NULL");
        processor_test_destroy(ctx);
        return;
    }

    TEST_CHECK(cm_ctx->key_is_autogenerated == FLB_TRUE);
    TEST_CHECK(strcmp(cm_ctx->key, expected_key) == 0);

    processor_test_destroy(ctx);
}

static void flb_logs_otel_scope_name_autogenerates_key()
{
    assert_otel_scope_context_key("otel_scope_name", "name");
}

static void flb_logs_otel_scope_version_autogenerates_key()
{
    assert_otel_scope_context_key("otel_scope_version", "version");
}

static void flb_logs_action_insert()
{
    struct processor_test *ctx;
    struct flb_lib_out_cb cb_data;
    int ret;
    char *p;
    int bytes;
    size_t len;
    struct expect_str expect[] = {
      {"\"new_key\":\"new_value\"", FLB_TRUE},
      {"\"k\":\"sample\"", FLB_TRUE},
      {NULL, FLB_TRUE}
    };

    struct cfl_variant action = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "insert",
    };
    struct cfl_variant context = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "message",
    };
    struct cfl_variant key = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "new_key",
    };
    struct cfl_variant value = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "new_value",
    };

    /* Prepare output callback with expected result */
    cb_data.cb = cb_check_result;
    cb_data.data = &expect;

    ctx = processor_test_create(FLB_PROCESSOR_LOGS, &cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("failed to create ctx");
        return;
    }

    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "format", "json",
                         NULL);
    TEST_CHECK(ret == 0);

    ret = flb_processor_unit_set_property(ctx->pu, "action", &action);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(ctx->pu, "context", &context);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(ctx->pu, "key", &key);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(ctx->pu, "value", &value);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx->flb);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("flb_start failed");
        return;
    }

    p = "[[0, {}], {\"k\":\"sample\"}]";
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);

    processor_test_destroy(ctx);
}

static void flb_logs_action_delete()
{
    struct processor_test *ctx;
    struct flb_lib_out_cb cb_data;
    int ret;
    char *p;
    int bytes;
    size_t len;
    struct expect_str expect[] = {
      {"\"key\":\"value\"", FLB_FALSE},
      {"\"k\":\"sample\"", FLB_TRUE},
      {NULL, FLB_TRUE}
    };

    struct cfl_variant action = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "delete",
    };
    struct cfl_variant context = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "message",
    };
    struct cfl_variant key = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "key",
    };
    struct cfl_variant value = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "value",
    };

    /* Prepare output callback with expected result */
    cb_data.cb = cb_check_result;
    cb_data.data = &expect;

    ctx = processor_test_create(FLB_PROCESSOR_LOGS, &cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("failed to create ctx");
        return;
    }

    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "format", "json",
                         NULL);
    TEST_CHECK(ret == 0);

    ret = flb_processor_unit_set_property(ctx->pu, "action", &action);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(ctx->pu, "context", &context);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(ctx->pu, "key", &key);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(ctx->pu, "value", &value);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx->flb);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("flb_start failed");
        return;
    }

    p = "[0, {\"k\":\"sample\", \"key\":\"value\"}]";
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);

    processor_test_destroy(ctx);
}

static void flb_logs_action_delete_key_list()
{
    int ret;
    int bytes;
    char *p;
    size_t len;
    struct cfl_array *keys;
    struct cfl_variant *key;
    struct processor_test *ctx;
    struct flb_lib_out_cb cb_data;
    struct expect_str expect[] = {
      {"\"foo\":\"one\"", FLB_FALSE},
      {"\"bar\":\"two\"", FLB_FALSE},
      {"\"keep\":\"three\"", FLB_TRUE},
      {NULL, FLB_TRUE}
    };
    struct cfl_variant action = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "delete",
    };
    struct cfl_variant context = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "message",
    };

    keys = cfl_array_create(3);
    TEST_CHECK(keys != NULL);
    TEST_CHECK(cfl_array_append_string(keys, "foo") == 0);
    TEST_CHECK(cfl_array_append_string(keys, "bar") == 0);
    TEST_CHECK(cfl_array_append_string(keys, "missing") == 0);

    key = cfl_variant_create_from_array(keys);
    TEST_CHECK(key != NULL);

    cb_data.cb = cb_check_result;
    cb_data.data = &expect;

    ctx = processor_test_create(FLB_PROCESSOR_LOGS, &cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        cfl_variant_destroy(key);
        return;
    }

    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "format", "json",
                         NULL);
    TEST_CHECK(ret == 0);

    ret = flb_processor_unit_set_property(ctx->pu, "action", &action);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(ctx->pu, "context", &context);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(ctx->pu, "key", key);
    TEST_CHECK(ret == 0);
    cfl_variant_destroy(key);

    ret = flb_start(ctx->flb);
    if (!TEST_CHECK(ret == 0)) {
        processor_test_destroy(ctx);
        return;
    }

    p = "[0, {\"foo\":\"one\", \"bar\":\"two\", \"keep\":\"three\"}]";
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);

    processor_test_destroy(ctx);
}

static void flb_logs_action_upsert_key_list()
{
    int ret;
    int bytes;
    char *p;
    size_t len;
    struct cfl_array *keys;
    struct cfl_variant *key;
    struct processor_test *ctx;
    struct flb_lib_out_cb cb_data;
    struct expect_str expect[] = {
      {"\"foo\":\"new\"", FLB_TRUE},
      {"\"bar\":\"new\"", FLB_TRUE},
      {"\"keep\":\"three\"", FLB_TRUE},
      {NULL, FLB_TRUE}
    };
    struct cfl_variant action = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "upsert",
    };
    struct cfl_variant context = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "message",
    };
    struct cfl_variant value = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "new",
    };

    keys = cfl_array_create(2);
    TEST_CHECK(keys != NULL);
    TEST_CHECK(cfl_array_append_string(keys, "foo") == 0);
    TEST_CHECK(cfl_array_append_string(keys, "bar") == 0);

    key = cfl_variant_create_from_array(keys);
    TEST_CHECK(key != NULL);

    cb_data.cb = cb_check_result;
    cb_data.data = &expect;

    ctx = processor_test_create(FLB_PROCESSOR_LOGS, &cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        cfl_variant_destroy(key);
        return;
    }

    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "format", "json",
                         NULL);
    TEST_CHECK(ret == 0);

    ret = flb_processor_unit_set_property(ctx->pu, "action", &action);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(ctx->pu, "context", &context);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(ctx->pu, "key", key);
    TEST_CHECK(ret == 0);
    cfl_variant_destroy(key);
    ret = flb_processor_unit_set_property(ctx->pu, "value", &value);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx->flb);
    if (!TEST_CHECK(ret == 0)) {
        processor_test_destroy(ctx);
        return;
    }

    p = "[0, {\"foo\":\"old\", \"keep\":\"three\"}]";
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);

    processor_test_destroy(ctx);
}

static void flb_logs_action_convert_key_list_atomic()
{
    int ret;
    int bytes;
    char *p;
    size_t len;
    struct cfl_array *keys;
    struct cfl_variant *key;
    struct processor_test *ctx;
    struct flb_lib_out_cb cb_data;
    struct expect_str expect[] = {
      {"\"foo\":\"1\"", FLB_TRUE},
      {"\"bar\":\"invalid\"", FLB_TRUE},
      {NULL, FLB_TRUE}
    };
    struct cfl_variant action = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "convert",
    };
    struct cfl_variant context = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "message",
    };
    struct cfl_variant converted_type = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "int",
    };

    keys = cfl_array_create(2);
    TEST_CHECK(keys != NULL);
    TEST_CHECK(cfl_array_append_string(keys, "foo") == 0);
    TEST_CHECK(cfl_array_append_string(keys, "bar") == 0);

    key = cfl_variant_create_from_array(keys);
    TEST_CHECK(key != NULL);

    cb_data.cb = cb_check_result;
    cb_data.data = &expect;

    ctx = processor_test_create(FLB_PROCESSOR_LOGS, &cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        cfl_variant_destroy(key);
        return;
    }

    ret = flb_output_set(ctx->flb, ctx->o_ffd, "format", "json", NULL);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(ctx->pu, "action", &action);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(ctx->pu, "context", &context);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(ctx->pu, "key", key);
    TEST_CHECK(ret == 0);
    cfl_variant_destroy(key);
    ret = flb_processor_unit_set_property(ctx->pu, "converted_type", &converted_type);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx->flb);
    if (!TEST_CHECK(ret == 0)) {
        processor_test_destroy(ctx);
        return;
    }

    p = "[0, {\"foo\":\"1\", \"bar\":\"invalid\"}]";
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);

    processor_test_destroy(ctx);
}

static void flb_logs_action_convert_key_list_missing_key()
{
    int ret;
    int bytes;
    char *p;
    size_t len;
    struct cfl_array *keys;
    struct cfl_variant *key;
    struct processor_test *ctx;
    struct flb_lib_out_cb cb_data;
    struct expect_str expect[] = {
      {"\"foo\":1", FLB_TRUE},
      {"\"keep\":\"unchanged\"", FLB_TRUE},
      {"\"missing\"", FLB_FALSE},
      {NULL, FLB_TRUE}
    };
    struct cfl_variant action = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "convert",
    };
    struct cfl_variant context = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "message",
    };
    struct cfl_variant converted_type = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "int",
    };

    keys = cfl_array_create(2);
    TEST_CHECK(keys != NULL);
    TEST_CHECK(cfl_array_append_string(keys, "missing") == 0);
    TEST_CHECK(cfl_array_append_string(keys, "foo") == 0);

    key = cfl_variant_create_from_array(keys);
    TEST_CHECK(key != NULL);

    cb_data.cb = cb_check_result;
    cb_data.data = &expect;

    ctx = processor_test_create(FLB_PROCESSOR_LOGS, &cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        cfl_variant_destroy(key);
        return;
    }

    ret = flb_output_set(ctx->flb, ctx->o_ffd, "format", "json", NULL);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(ctx->pu, "action", &action);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(ctx->pu, "context", &context);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(ctx->pu, "key", key);
    TEST_CHECK(ret == 0);
    cfl_variant_destroy(key);
    ret = flb_processor_unit_set_property(ctx->pu, "converted_type", &converted_type);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx->flb);
    if (!TEST_CHECK(ret == 0)) {
        processor_test_destroy(ctx);
        return;
    }

    p = "[0, {\"foo\":\"1\", \"keep\":\"unchanged\"}]";
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);

    processor_test_destroy(ctx);
}

static void flb_logs_action_rename()
{
    struct processor_test *ctx;
    struct flb_lib_out_cb cb_data;
    int ret;
    char *p;
    int bytes;
    size_t len;
    struct expect_str expect[] = {
      {"\"key\":\"value\"", FLB_FALSE},
      {"\"new_key\":\"value\"", FLB_TRUE},
      {"\"k\":\"sample\"", FLB_TRUE},
      {NULL, FLB_TRUE}
    };

    struct cfl_variant action = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "rename",
    };
    struct cfl_variant context = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "message",
    };
    struct cfl_variant key = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "key",
    };
    struct cfl_variant value = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "new_key",
    };

    /* Prepare output callback with expected result */
    cb_data.cb = cb_check_result;
    cb_data.data = &expect;

    ctx = processor_test_create(FLB_PROCESSOR_LOGS, &cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("failed to create ctx");
        return;
    }

    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "format", "json",
                         NULL);
    TEST_CHECK(ret == 0);

    ret = flb_processor_unit_set_property(ctx->pu, "action", &action);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(ctx->pu, "context", &context);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(ctx->pu, "key", &key);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(ctx->pu, "value", &value);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx->flb);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("flb_start failed");
        return;
    }

    p = "[0, {\"k\":\"sample\", \"key\":\"value\"}]";
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);

    processor_test_destroy(ctx);
}

static void flb_logs_action_upsert()
{
    struct processor_test *ctx;
    struct flb_lib_out_cb cb_data;
    int ret;
    char *p;
    int bytes;
    size_t len;
    struct expect_str expect[] = {
      {"\"key\":\"new_value\"", FLB_TRUE},
      {"\"k\":\"sample\"", FLB_TRUE},
      {NULL, FLB_TRUE}
    };

    struct cfl_variant action = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "upsert",
    };
    struct cfl_variant context = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "message",
    };
    struct cfl_variant key = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "key",
    };
    struct cfl_variant value = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "new_value",
    };

    /* Prepare output callback with expected result */
    cb_data.cb = cb_check_result;
    cb_data.data = &expect;

    ctx = processor_test_create(FLB_PROCESSOR_LOGS, &cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("failed to create ctx");
        return;
    }

    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "format", "json",
                         NULL);
    TEST_CHECK(ret == 0);

    ret = flb_processor_unit_set_property(ctx->pu, "action", &action);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(ctx->pu, "context", &context);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(ctx->pu, "key", &key);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(ctx->pu, "value", &value);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx->flb);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("flb_start failed");
        return;
    }

    p = "[0, {\"k\":\"sample\", \"key\":\"value\"}]";
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);

    processor_test_destroy(ctx);
}

static void flb_logs_action_hash()
{
    struct processor_test *ctx;
    struct flb_lib_out_cb cb_data;
    int ret;
    char *p;
    int bytes;
    size_t len;
    struct expect_str expect[] = {
      {"\"key\":\"value\"", FLB_FALSE},
      {"\"key\":\"cd42404d52ad55ccfa9aca4adc828aa5800ad9d385a0671fbcbf724118320619\"", FLB_TRUE},
      {"\"k\":\"sample\"", FLB_TRUE},
      {NULL, FLB_TRUE}
    };

    struct cfl_variant action = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "hash",
    };
    struct cfl_variant context = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "message",
    };
    struct cfl_variant key = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "key",
    };

    /* Prepare output callback with expected result */
    cb_data.cb = cb_check_result;
    cb_data.data = &expect;

    ctx = processor_test_create(FLB_PROCESSOR_LOGS, &cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("failed to create ctx");
        return;
    }

    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "format", "json",
                         NULL);
    TEST_CHECK(ret == 0);

    ret = flb_processor_unit_set_property(ctx->pu, "action", &action);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(ctx->pu, "context", &context);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(ctx->pu, "key", &key);
    TEST_CHECK(ret == 0);


    ret = flb_start(ctx->flb);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("flb_start failed");
        return;
    }

    p = "[0, {\"k\":\"sample\", \"key\":\"value\"}]";
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);

    processor_test_destroy(ctx);
}

static void flb_logs_action_extract()
{
    struct processor_test *ctx;
    struct flb_lib_out_cb cb_data;
    int ret;
    char *p;
    int bytes;
    size_t len;
    struct expect_str expect[] = {
      {"\"k\":\"sample\"", FLB_TRUE},
      {"\"log\":\"exception occurred\"", FLB_TRUE},
      {"\"date\":\"2024/03/15\"", FLB_TRUE},
      {NULL, FLB_TRUE}
    };

    struct cfl_variant action = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "extract",
    };
    struct cfl_variant context = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "message",
    };
    struct cfl_variant key = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "key",
    };
    struct cfl_variant pattern = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "/(?<date>\\d{4}\\/\\d{2}\\/\\d{2}) (?<log>.+)/",
    };

    /* Prepare output callback with expected result */
    cb_data.cb = cb_check_result;
    cb_data.data = &expect;

    ctx = processor_test_create(FLB_PROCESSOR_LOGS, &cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("failed to create ctx");
        return;
    }

    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "format", "json",
                         NULL);
    TEST_CHECK(ret == 0);

    ret = flb_processor_unit_set_property(ctx->pu, "action", &action);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(ctx->pu, "context", &context);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(ctx->pu, "key", &key);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(ctx->pu, "pattern", &pattern);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx->flb);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("flb_start failed");
        return;
    }

    p = "[0, {\"k\":\"sample\", \"key\":\"2024/03/15 exception occurred\"}]";
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);

    processor_test_destroy(ctx);
}

static void flb_logs_action_convert_from_string_to_int()
{
    struct processor_test *ctx;
    struct flb_lib_out_cb cb_data;
    int ret;
    char *p;
    int bytes;
    size_t len;
    struct expect_str expect[] = {
      {"\"str\":100", FLB_TRUE},
      {"\"k\":\"sample\"", FLB_TRUE},
      {NULL, FLB_TRUE}
    };

    struct cfl_variant action = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "convert",
    };
    struct cfl_variant context = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "message",
    };
    struct cfl_variant key = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "str",
    };
    struct cfl_variant converted_type = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "int",
    };

    /* Prepare output callback with expected result */
    cb_data.cb = cb_check_result;
    cb_data.data = &expect;

    ctx = processor_test_create(FLB_PROCESSOR_LOGS, &cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("failed to create ctx");
        return;
    }

    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "format", "json",
                         NULL);
    TEST_CHECK(ret == 0);

    ret = flb_processor_unit_set_property(ctx->pu, "action", &action);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(ctx->pu, "context", &context);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(ctx->pu, "key", &key);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(ctx->pu, "converted_type", &converted_type);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx->flb);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("flb_start failed");
        return;
    }

    p = "[0, {\"k\":\"sample\", \"str\":\"100\"}]";
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);

    processor_test_destroy(ctx);
}

static void flb_logs_action_convert_from_int_to_string()
{
    struct processor_test *ctx;
    struct flb_lib_out_cb cb_data;
    int ret;
    char *p;
    int bytes;
    size_t len;
    struct expect_str expect[] = {
      {"\"i_key\":\"-100\"", FLB_TRUE},
      {"\"k\":\"sample\"", FLB_TRUE},
      {NULL, FLB_TRUE}
    };

    struct cfl_variant action = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "convert",
    };
    struct cfl_variant context = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "message",
    };
    struct cfl_variant key = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "i_key",
    };
    struct cfl_variant converted_type = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "string",
    };

    /* Prepare output callback with expected result */
    cb_data.cb = cb_check_result;
    cb_data.data = &expect;

    ctx = processor_test_create(FLB_PROCESSOR_LOGS, &cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("failed to create ctx");
        return;
    }

    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "format", "json",
                         NULL);
    TEST_CHECK(ret == 0);

    ret = flb_processor_unit_set_property(ctx->pu, "action", &action);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(ctx->pu, "context", &context);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(ctx->pu, "key", &key);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(ctx->pu, "converted_type", &converted_type);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx->flb);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("flb_start failed");
        return;
    }

    p = "[0, {\"k\":\"sample\", \"i_key\":-100}]";
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);

    processor_test_destroy(ctx);
}

static void flb_logs_action_convert_from_string_to_double()
{
    struct processor_test *ctx;
    struct flb_lib_out_cb cb_data;
    int ret;
    char *p;
    int bytes;
    size_t len;
    struct expect_str expect[] = {
      {"\"str\":123.456", FLB_TRUE},
      {"\"k\":\"sample\"", FLB_TRUE},
      {NULL, FLB_TRUE}
    };

    struct cfl_variant action = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "convert",
    };
    struct cfl_variant context = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "message",
    };
    struct cfl_variant key = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "str",
    };
    struct cfl_variant converted_type = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "double",
    };

    /* Prepare output callback with expected result */
    cb_data.cb = cb_check_result;
    cb_data.data = &expect;

    ctx = processor_test_create(FLB_PROCESSOR_LOGS, &cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("failed to create ctx");
        return;
    }

    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "format", "json",
                         NULL);
    TEST_CHECK(ret == 0);

    ret = flb_processor_unit_set_property(ctx->pu, "action", &action);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(ctx->pu, "context", &context);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(ctx->pu, "key", &key);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(ctx->pu, "converted_type", &converted_type);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx->flb);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("flb_start failed");
        return;
    }

    p = "[0, {\"k\":\"sample\", \"str\":\"123.456\"}]";
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);

    processor_test_destroy(ctx);
}

static void flb_logs_action_convert_from_double_to_string()
{
    struct processor_test *ctx;
    struct flb_lib_out_cb cb_data;
    int ret;
    char *p;
    int bytes;
    size_t len;
    struct expect_str expect[] = {
      {"\"d_key\":\"123.456\"", FLB_TRUE},
      {"\"k\":\"sample\"", FLB_TRUE},
      {NULL, FLB_TRUE}
    };

    struct cfl_variant action = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "convert",
    };
    struct cfl_variant context = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "message",
    };
    struct cfl_variant key = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "d_key",
    };
    struct cfl_variant converted_type = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "string",
    };

    /* Prepare output callback with expected result */
    cb_data.cb = cb_check_result;
    cb_data.data = &expect;

    ctx = processor_test_create(FLB_PROCESSOR_LOGS, &cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("failed to create ctx");
        return;
    }

    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "format", "json",
                         NULL);
    TEST_CHECK(ret == 0);

    ret = flb_processor_unit_set_property(ctx->pu, "action", &action);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(ctx->pu, "context", &context);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(ctx->pu, "key", &key);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(ctx->pu, "converted_type", &converted_type);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx->flb);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("flb_start failed");
        return;
    }

    p = "[0, {\"k\":\"sample\", \"d_key\":123.456}]";
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);

    processor_test_destroy(ctx);
}

static void flb_logs_action_convert_from_string_to_boolean()
{
    struct processor_test *ctx;
    struct flb_lib_out_cb cb_data;
    int ret;
    char *p;
    int bytes;
    size_t len;
    struct expect_str expect[] = {
      {"\"str\":false", FLB_TRUE},
      {"\"k\":\"sample\"", FLB_TRUE},
      {NULL, FLB_TRUE}
    };

    struct cfl_variant action = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "convert",
    };
    struct cfl_variant context = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "message",
    };
    struct cfl_variant key = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "str",
    };
    struct cfl_variant converted_type = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "boolean",
    };

    /* Prepare output callback with expected result */
    cb_data.cb = cb_check_result;
    cb_data.data = &expect;

    ctx = processor_test_create(FLB_PROCESSOR_LOGS, &cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("failed to create ctx");
        return;
    }

    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "format", "json",
                         NULL);
    TEST_CHECK(ret == 0);

    ret = flb_processor_unit_set_property(ctx->pu, "action", &action);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(ctx->pu, "context", &context);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(ctx->pu, "key", &key);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(ctx->pu, "converted_type", &converted_type);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx->flb);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("flb_start failed");
        return;
    }

    p = "[0, {\"k\":\"sample\", \"str\":\"false\"}]";
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);

    processor_test_destroy(ctx);
}

static void flb_logs_action_convert_from_int_to_boolean()
{
    struct processor_test *ctx;
    struct flb_lib_out_cb cb_data;
    int ret;
    char *p;
    int bytes;
    size_t len;
    struct expect_str expect[] = {
      {"\"i_key\":true", FLB_TRUE},
      {"\"k\":\"sample\"", FLB_TRUE},
      {NULL, FLB_TRUE}
    };

    struct cfl_variant action = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "convert",
    };
    struct cfl_variant context = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "message",
    };
    struct cfl_variant key = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "i_key",
    };
    struct cfl_variant converted_type = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "boolean",
    };

    /* Prepare output callback with expected result */
    cb_data.cb = cb_check_result;
    cb_data.data = &expect;

    ctx = processor_test_create(FLB_PROCESSOR_LOGS, &cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("failed to create ctx");
        return;
    }

    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "format", "json",
                         NULL);
    TEST_CHECK(ret == 0);

    ret = flb_processor_unit_set_property(ctx->pu, "action", &action);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(ctx->pu, "context", &context);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(ctx->pu, "key", &key);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(ctx->pu, "converted_type", &converted_type);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx->flb);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("flb_start failed");
        return;
    }

    p = "[0, {\"k\":\"sample\", \"i_key\":-100}]";
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);

    processor_test_destroy(ctx);
}

static void flb_logs_action_convert_from_int_to_double()
{
    struct processor_test *ctx;
    struct flb_lib_out_cb cb_data;
    int ret;
    char *p;
    int bytes;
    size_t len;
    struct expect_str expect[] = {
      {"\"i_key\":-100.0", FLB_TRUE},
      {"\"k\":\"sample\"", FLB_TRUE},
      {NULL, FLB_TRUE}
    };

    struct cfl_variant action = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "convert",
    };
    struct cfl_variant context = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "message",
    };
    struct cfl_variant key = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "i_key",
    };
    struct cfl_variant converted_type = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "double",
    };

    /* Prepare output callback with expected result */
    cb_data.cb = cb_check_result;
    cb_data.data = &expect;

    ctx = processor_test_create(FLB_PROCESSOR_LOGS, &cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("failed to create ctx");
        return;
    }

    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "format", "json",
                         NULL);
    TEST_CHECK(ret == 0);

    ret = flb_processor_unit_set_property(ctx->pu, "action", &action);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(ctx->pu, "context", &context);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(ctx->pu, "key", &key);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(ctx->pu, "converted_type", &converted_type);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx->flb);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("flb_start failed");
        return;
    }

    p = "[0, {\"k\":\"sample\", \"i_key\":-100}]";
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);

    processor_test_destroy(ctx);
}

static void flb_logs_action_convert_from_double_to_int()
{
    struct processor_test *ctx;
    struct flb_lib_out_cb cb_data;
    int ret;
    char *p;
    int bytes;
    size_t len;
    struct expect_str expect[] = {
      {"\"d_key\":123", FLB_TRUE},
      {"\"d_key\":123.", FLB_FALSE},
      {"\"k\":\"sample\"", FLB_TRUE},
      {NULL, FLB_TRUE}
    };

    struct cfl_variant action = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "convert",
    };
    struct cfl_variant context = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "message",
    };
    struct cfl_variant key = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "d_key",
    };
    struct cfl_variant converted_type = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "int",
    };

    /* Prepare output callback with expected result */
    cb_data.cb = cb_check_result;
    cb_data.data = &expect;

    ctx = processor_test_create(FLB_PROCESSOR_LOGS, &cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("failed to create ctx");
        return;
    }

    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "format", "json",
                         NULL);
    TEST_CHECK(ret == 0);

    ret = flb_processor_unit_set_property(ctx->pu, "action", &action);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(ctx->pu, "context", &context);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(ctx->pu, "key", &key);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(ctx->pu, "converted_type", &converted_type);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx->flb);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("flb_start failed");
        return;
    }

    p = "[0, {\"k\":\"sample\", \"d_key\":123.456}]";
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);

    processor_test_destroy(ctx);
}

static void flb_logs_action_convert_from_double_to_boolean()
{
    struct processor_test *ctx;
    struct flb_lib_out_cb cb_data;
    int ret;
    char *p;
    int bytes;
    size_t len;
    struct expect_str expect[] = {
      {"\"d_key\":true", FLB_TRUE},
      {"\"k\":\"sample\"", FLB_TRUE},
      {NULL, FLB_TRUE}
    };

    struct cfl_variant action = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "convert",
    };
    struct cfl_variant context = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "message",
    };
    struct cfl_variant key = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "d_key",
    };
    struct cfl_variant converted_type = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "boolean",
    };

    /* Prepare output callback with expected result */
    cb_data.cb = cb_check_result;
    cb_data.data = &expect;

    ctx = processor_test_create(FLB_PROCESSOR_LOGS, &cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("failed to create ctx");
        return;
    }

    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "format", "json",
                         NULL);
    TEST_CHECK(ret == 0);

    ret = flb_processor_unit_set_property(ctx->pu, "action", &action);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(ctx->pu, "context", &context);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(ctx->pu, "key", &key);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(ctx->pu, "converted_type", &converted_type);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx->flb);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("flb_start failed");
        return;
    }

    p = "[0, {\"k\":\"sample\", \"d_key\":123.456}]";
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);

    processor_test_destroy(ctx);
}

static void flb_logs_action_convert_from_null_to_string()
{
    struct processor_test *ctx;
    struct flb_lib_out_cb cb_data;
    int ret;
    char *p;
    int bytes;
    size_t len;
    struct expect_str expect[] = {
      {"\"n_key\":\"null\"", FLB_TRUE},
      {"\"k\":\"sample\"", FLB_TRUE},
      {NULL, FLB_TRUE}
    };

    struct cfl_variant action = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "convert",
    };
    struct cfl_variant context = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "message",
    };
    struct cfl_variant key = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "n_key",
    };
    struct cfl_variant converted_type = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "string",
    };

    /* Prepare output callback with expected result */
    cb_data.cb = cb_check_result;
    cb_data.data = &expect;

    ctx = processor_test_create(FLB_PROCESSOR_LOGS, &cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("failed to create ctx");
        return;
    }

    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "format", "json",
                         NULL);
    TEST_CHECK(ret == 0);

    ret = flb_processor_unit_set_property(ctx->pu, "action", &action);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(ctx->pu, "context", &context);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(ctx->pu, "key", &key);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(ctx->pu, "converted_type", &converted_type);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx->flb);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("flb_start failed");
        return;
    }

    p = "[0, {\"k\":\"sample\", \"n_key\":null}]";
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);

    processor_test_destroy(ctx);
}

static void flb_logs_action_convert_from_null_to_int()
{
    struct processor_test *ctx;
    struct flb_lib_out_cb cb_data;
    int ret;
    char *p;
    int bytes;
    size_t len;
    struct expect_str expect[] = {
      {"\"n_key\":0", FLB_TRUE},
      {"\"k\":\"sample\"", FLB_TRUE},
      {NULL, FLB_TRUE}
    };

    struct cfl_variant action = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "convert",
    };
    struct cfl_variant context = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "message",
    };
    struct cfl_variant key = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "n_key",
    };
    struct cfl_variant converted_type = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "int",
    };

    /* Prepare output callback with expected result */
    cb_data.cb = cb_check_result;
    cb_data.data = &expect;

    ctx = processor_test_create(FLB_PROCESSOR_LOGS, &cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("failed to create ctx");
        return;
    }

    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "format", "json",
                         NULL);
    TEST_CHECK(ret == 0);

    ret = flb_processor_unit_set_property(ctx->pu, "action", &action);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(ctx->pu, "context", &context);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(ctx->pu, "key", &key);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(ctx->pu, "converted_type", &converted_type);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx->flb);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("flb_start failed");
        return;
    }

    p = "[0, {\"k\":\"sample\", \"n_key\":null}]";
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);

    processor_test_destroy(ctx);
}

static void flb_logs_action_convert_from_null_to_double()
{
    struct processor_test *ctx;
    struct flb_lib_out_cb cb_data;
    int ret;
    char *p;
    int bytes;
    size_t len;
    struct expect_str expect[] = {
      {"\"n_key\":0.0", FLB_TRUE},
      {"\"k\":\"sample\"", FLB_TRUE},
      {NULL, FLB_TRUE}
    };

    struct cfl_variant action = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "convert",
    };
    struct cfl_variant context = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "message",
    };
    struct cfl_variant key = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "n_key",
    };
    struct cfl_variant converted_type = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "double",
    };

    /* Prepare output callback with expected result */
    cb_data.cb = cb_check_result;
    cb_data.data = &expect;

    ctx = processor_test_create(FLB_PROCESSOR_LOGS, &cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("failed to create ctx");
        return;
    }

    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "format", "json",
                         NULL);
    TEST_CHECK(ret == 0);

    ret = flb_processor_unit_set_property(ctx->pu, "action", &action);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(ctx->pu, "context", &context);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(ctx->pu, "key", &key);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(ctx->pu, "converted_type", &converted_type);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx->flb);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("flb_start failed");
        return;
    }

    p = "[0, {\"k\":\"sample\", \"n_key\":null}]";
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);

    processor_test_destroy(ctx);
}

static void flb_logs_otel_log_attributes_insert()
{
    struct processor_test *ctx;
    struct flb_lib_out_cb cb_data;
    int ret;
    char *p;
    int bytes;
    size_t len;
    struct expect_str expect[] = {
      {"\"otlp\":{\"attributes\":{\"my_otlp_attr\":\"my_otlp_value\"}}", FLB_TRUE},
      {NULL, FLB_TRUE}
    };

    struct cfl_variant action = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "insert",
    };
    struct cfl_variant context = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "otel_log_attributes",
    };
    struct cfl_variant key = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "my_otlp_attr",
    };
    struct cfl_variant value = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "my_otlp_value",
    };

    cb_data.cb = cb_check_metadata_result;
    cb_data.data = &expect;

    ctx = processor_test_create(FLB_PROCESSOR_LOGS, &cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("failed to create ctx");
        return;
    }

    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "data_mode", "chunk",
                         NULL);
    TEST_CHECK(ret == 0);

    ret = flb_processor_unit_set_property(ctx->pu, "action", &action);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(ctx->pu, "context", &context);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(ctx->pu, "key", &key);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(ctx->pu, "value", &value);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx->flb);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("flb_start failed");
        return;
    }

    p = "[[0, {}], {\"k\":\"sample\"}]";
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);

    processor_test_destroy(ctx);
}

static void flb_logs_otel_log_attributes_upsert()
{
    struct processor_test *ctx;
    struct flb_lib_out_cb cb_data;
    struct flb_processor_unit *pu_upsert;
    int ret;
    char *p;
    int bytes;
    size_t len;
    struct expect_str expect[] = {
      {"\"my_otlp_attr\":\"old_value\"", FLB_FALSE},
      {"\"my_otlp_attr\":\"new_value\"", FLB_TRUE},
      {NULL, FLB_TRUE}
    };

    struct cfl_variant action_insert = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "insert",
    };
    struct cfl_variant action_upsert = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "upsert",
    };
    struct cfl_variant context = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "otel_log_attributes",
    };
    struct cfl_variant key = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "my_otlp_attr",
    };
    struct cfl_variant value_insert = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "old_value",
    };
    struct cfl_variant value_upsert = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "new_value",
    };

    cb_data.cb = cb_check_metadata_result;
    cb_data.data = &expect;

    ctx = processor_test_create(FLB_PROCESSOR_LOGS, &cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("failed to create ctx");
        return;
    }

    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "data_mode", "chunk",
                         NULL);
    TEST_CHECK(ret == 0);

    ret = flb_processor_unit_set_property(ctx->pu, "action", &action_insert);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(ctx->pu, "context", &context);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(ctx->pu, "key", &key);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(ctx->pu, "value", &value_insert);
    TEST_CHECK(ret == 0);

    pu_upsert = flb_processor_unit_create(ctx->proc, ctx->type, "content_modifier");
    if (!TEST_CHECK(pu_upsert != NULL)) {
        TEST_MSG("failed to create second processor unit");
        processor_test_destroy(ctx);
        return;
    }

    ret = flb_processor_unit_set_property(pu_upsert, "action", &action_upsert);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(pu_upsert, "context", &context);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(pu_upsert, "key", &key);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(pu_upsert, "value", &value_upsert);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx->flb);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("flb_start failed");
        return;
    }

    p = "[[0, {}], {\"k\":\"sample\"}]";
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);

    processor_test_destroy(ctx);
}

static void flb_logs_otel_log_attributes_delete()
{
    struct processor_test *ctx;
    struct flb_lib_out_cb cb_data;
    struct flb_processor_unit *pu_delete;
    int ret;
    char *p;
    int bytes;
    size_t len;
    struct expect_str expect[] = {
      {"\"my_otlp_attr\"", FLB_FALSE},
      {"\"otlp\":{\"attributes\":{}}", FLB_TRUE},
      {NULL, FLB_TRUE}
    };

    struct cfl_variant action_insert = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "insert",
    };
    struct cfl_variant action_delete = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "delete",
    };
    struct cfl_variant context = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "otel_log_attributes",
    };
    struct cfl_variant key = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "my_otlp_attr",
    };
    struct cfl_variant value_insert = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "my_otlp_value",
    };

    cb_data.cb = cb_check_metadata_result;
    cb_data.data = &expect;

    ctx = processor_test_create(FLB_PROCESSOR_LOGS, &cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("failed to create ctx");
        return;
    }

    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "data_mode", "chunk",
                         NULL);
    TEST_CHECK(ret == 0);

    ret = flb_processor_unit_set_property(ctx->pu, "action", &action_insert);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(ctx->pu, "context", &context);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(ctx->pu, "key", &key);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(ctx->pu, "value", &value_insert);
    TEST_CHECK(ret == 0);

    pu_delete = flb_processor_unit_create(ctx->proc, ctx->type, "content_modifier");
    if (!TEST_CHECK(pu_delete != NULL)) {
        TEST_MSG("failed to create second processor unit");
        processor_test_destroy(ctx);
        return;
    }

    ret = flb_processor_unit_set_property(pu_delete, "action", &action_delete);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(pu_delete, "context", &context);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(pu_delete, "key", &key);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx->flb);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("flb_start failed");
        return;
    }

    p = "[[0, {}], {\"k\":\"sample\"}]";
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);

    processor_test_destroy(ctx);
}

static void flb_logs_otel_log_attributes_invalid_otlp_metadata()
{
    struct processor_test *ctx;
    struct flb_lib_out_cb cb_data;
    int ret;
    char *p;
    int bytes;
    size_t len;
    struct expect_str expect[] = {
      {"\"otlp\":\"broken\"", FLB_TRUE},
      {"\"my_otlp_attr\"", FLB_FALSE},
      {NULL, FLB_TRUE}
    };

    struct cfl_variant action = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "insert",
    };
    struct cfl_variant context = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "otel_log_attributes",
    };
    struct cfl_variant key = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "my_otlp_attr",
    };
    struct cfl_variant value = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = "my_otlp_value",
    };

    cb_data.cb = cb_check_metadata_result;
    cb_data.data = &expect;

    ctx = processor_test_create(FLB_PROCESSOR_LOGS, &cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("failed to create ctx");
        return;
    }

    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "data_mode", "chunk",
                         NULL);
    TEST_CHECK(ret == 0);

    ret = flb_processor_unit_set_property(ctx->pu, "action", &action);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(ctx->pu, "context", &context);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(ctx->pu, "key", &key);
    TEST_CHECK(ret == 0);
    ret = flb_processor_unit_set_property(ctx->pu, "value", &value);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx->flb);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("flb_start failed");
        return;
    }

    p = "[[0, {\"otlp\":\"broken\"}], {\"k\":\"sample\"}]";
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);

    processor_test_destroy(ctx);
}

TEST_LIST = {
    {"logs.action.insert"           , flb_logs_action_insert },
    {"logs.action.delete"           , flb_logs_action_delete },
    {"logs.action.delete_key_list"  , flb_logs_action_delete_key_list },
    {"logs.action.upsert_key_list"  , flb_logs_action_upsert_key_list },
    {"logs.action.convert_key_list_atomic", flb_logs_action_convert_key_list_atomic },
    {"logs.action.convert_key_list_missing_key",
     flb_logs_action_convert_key_list_missing_key },
    {"metrics.action.insert"        , flb_metrics_action_insert },
    {"metrics.action.delete"        , flb_metrics_action_delete },
    {"metrics.action.upsert"        , flb_metrics_action_upsert },
    {"metrics.action.insert_key_list", flb_metrics_action_insert_key_list },
    {"metrics.action.upsert_key_list", flb_metrics_action_upsert_key_list },
    {"metrics.action.delete_key_list", flb_metrics_action_delete_key_list },
    {"metrics.action.convert_key_list_atomic", flb_metrics_action_convert_key_list_atomic },
    {"metrics.action.convert_key_list_missing_key",
     flb_metrics_action_convert_key_list_missing_key },
    {"traces.action.insert"         , flb_traces_action_insert },
    {"traces.action.delete"         , flb_traces_action_delete },
    {"traces.action.upsert"         , flb_traces_action_upsert },
    {"traces.action.insert_key_list", flb_traces_action_insert_key_list },
    {"traces.action.upsert_key_list", flb_traces_action_upsert_key_list },
    {"traces.action.delete_key_list", flb_traces_action_delete_key_list },
    {"traces.action.convert_key_list_atomic", flb_traces_action_convert_key_list_atomic },
    {"logs.action.rename"           , flb_logs_action_rename },
    {"logs.action.upsert"           , flb_logs_action_upsert },
    {"logs.action.hash"             , flb_logs_action_hash },
    {"logs.action.extract"          , flb_logs_action_extract },
    {"logs.otel_scope_name.autogenerated_key" , flb_logs_otel_scope_name_autogenerates_key },
    {"logs.otel_scope_version.autogenerated_key" , flb_logs_otel_scope_version_autogenerates_key },
    {"logs.action.convert_from_string_to_int" , flb_logs_action_convert_from_string_to_int },
    {"logs.action.convert_from_int_to_string" , flb_logs_action_convert_from_int_to_string },
    {"logs.action.convert_from_string_to_double" , flb_logs_action_convert_from_string_to_double },
    {"logs.action.convert_from_double_to_string" , flb_logs_action_convert_from_double_to_string },
    {"logs.action.convert_from_string_to_boolean" , flb_logs_action_convert_from_string_to_boolean },
    {"logs.action.convert_from_int_to_boolean" , flb_logs_action_convert_from_int_to_boolean },
    {"logs.action.convert_from_int_to_double" , flb_logs_action_convert_from_int_to_double },
    {"logs.action.convert_from_double_to_int" , flb_logs_action_convert_from_double_to_int },
    {"logs.action.convert_from_double_to_boolean" , flb_logs_action_convert_from_double_to_boolean },
    {"logs.action.convert_from_null_to_string" , flb_logs_action_convert_from_null_to_string },
    {"logs.action.convert_from_null_to_int" , flb_logs_action_convert_from_null_to_int },
    {"logs.action.convert_from_null_to_double" , flb_logs_action_convert_from_null_to_double },
    {"logs.otel_log_attributes.insert" , flb_logs_otel_log_attributes_insert },
    {"logs.otel_log_attributes.upsert" , flb_logs_otel_log_attributes_upsert },
    {"logs.otel_log_attributes.delete" , flb_logs_otel_log_attributes_delete },
    {"logs.otel_log_attributes.invalid_otlp_metadata",
     flb_logs_otel_log_attributes_invalid_otlp_metadata },
    {NULL, NULL}
};
