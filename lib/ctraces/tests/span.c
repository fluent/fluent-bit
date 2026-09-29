/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  CTraces
 *  =======
 *  Copyright 2022 The CTraces Authors
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

#include <ctraces/ctraces.h>
#include <ctraces/ctr_span.h>

#include <cfl/cfl.h>
#include <cfl/cfl_array.h>
#include <cfl/cfl_kvlist.h>

#include "ctr_tests.h"

void test_span()
{
    int ret;
    struct ctrace *ctx;
    struct ctrace_span *span_root;
    struct ctrace_span *span_child;
    struct ctrace_resource_span *resource_span;
    struct ctrace_scope_span *scope_span;
    struct ctrace_id *id;
    struct cfl_array *array;
    struct cfl_kvlist *kvlist;

    ctx = ctr_create(NULL);

    resource_span = ctr_resource_span_create(ctx);
    scope_span = ctr_scope_span_create(resource_span);

    /* create root span */
    span_root = ctr_span_create(ctx, scope_span, "main", NULL);
    TEST_CHECK(span_root != NULL);
    TEST_CHECK(span_root->kind == CTRACE_SPAN_INTERNAL);

    /* set the span root a random id */
    id = ctr_id_create_random(CTR_ID_OTEL_SPAN_SIZE);
    TEST_CHECK(id != NULL);
    ctr_span_set_span_id_with_cid(span_root, id);

    /* id is not longer needed */
    ctr_id_destroy(id);

    span_child = ctr_span_create(ctx, scope_span, "do-work", span_root);
    TEST_CHECK(span_child != NULL);

    /* set span kind */
    ret = ctr_span_kind_set(span_child, CTRACE_SPAN_CONSUMER);
    TEST_CHECK(ret == 0);
    TEST_CHECK(span_child->kind == CTRACE_SPAN_CONSUMER);

    /* parent id check */
    ret = ctr_id_cmp(span_child->parent_span_id, span_root->span_id);
    TEST_CHECK(ret == 0);

    /* add attributes to span_child */
    ctr_span_set_attribute_string(span_child, "agent", "fluent bit");
    ctr_span_set_attribute_bool(span_child, "bool_t", 1);
    ctr_span_set_attribute_bool(span_child, "bool_f", 0);
    ctr_span_set_attribute_int64(span_child, "integer", 123456789);
    ctr_span_set_attribute_double(span_child, "double", 1.5);

    array = cfl_array_create(128);
    TEST_CHECK(array != NULL);
    ctr_span_set_attribute_array(span_child, "array", array);

    kvlist = cfl_kvlist_create();
    TEST_CHECK(kvlist != NULL);
    ctr_span_set_attribute_kvlist(span_child, "kvlist", kvlist);

    ctr_destroy(ctx);
}

void test_resource_span_direct_destroy()
{
    struct ctrace *ctx;
    struct ctrace_resource_span *resource_span;

    ctx = ctr_create(NULL);
    TEST_CHECK(ctx != NULL);

    resource_span = ctr_resource_span_create(ctx);
    TEST_CHECK(resource_span != NULL);

    ctr_resource_span_destroy(resource_span);
    TEST_CHECK(cfl_list_is_empty(&ctx->resource_spans));

    /* Preserve compatibility with Fluent Bit's historical manual unlink. */
    resource_span = ctr_resource_span_create(ctx);
    TEST_CHECK(resource_span != NULL);
    cfl_list_del(&resource_span->_head);
    ctr_resource_span_destroy(resource_span);

    /* Must not traverse the resource span that was already destroyed. */
    ctr_destroy(ctx);
}

void test_random_id_length()
{
    struct ctrace_id *id;

    id = ctr_id_create_random(CTR_ID_OTEL_TRACE_SIZE);
    TEST_CHECK(id != NULL);
    TEST_CHECK(ctr_id_get_len(id) == CTR_ID_OTEL_TRACE_SIZE);
    ctr_id_destroy(id);
}

void test_event_integer_api()
{
    struct ctrace *ctx;
    struct ctrace_resource_span *rs;
    struct ctrace_scope_span *ss;
    struct ctrace_span *span;
    struct ctrace_span_event *event;
    struct cfl_variant *value;

    ctx = ctr_create(NULL);
    rs = ctr_resource_span_create(ctx);
    ss = ctr_scope_span_create(rs);
    span = ctr_span_create(ctx, ss, "event", NULL);
    event = ctr_span_event_add(span, "integer");
    TEST_ASSERT(event != NULL);

    TEST_CHECK(ctr_span_event_set_attribute_int(event, "int", 42) == 0);
    TEST_CHECK(ctr_span_event_set_attribute_int64(event, "int64", INT64_MAX) == 0);
    value = cfl_kvlist_fetch(event->attr->kv, "int64");
    TEST_ASSERT(value != NULL);
    TEST_CHECK(value->data.as_int64 == INT64_MAX);

    ctr_destroy(ctx);
}

void test_text_encoder_optional_and_long_strings()
{
    char long_value[2048];
    cfl_sds_t text;
    struct ctrace *ctx;
    struct ctrace_resource_span *rs;
    struct ctrace_scope_span *ss;
    struct ctrace_instrumentation_scope *scope;
    struct ctrace_span *span;
    struct ctrace_link *link;

    memset(long_value, 'x', sizeof(long_value) - 1);
    long_value[sizeof(long_value) - 1] = '\0';

    ctx = ctr_create(NULL);
    rs = ctr_resource_span_create(ctx);
    ss = ctr_scope_span_create(rs);
    scope = ctr_instrumentation_scope_create(NULL, NULL, 0, NULL);
    ctr_scope_span_set_instrumentation_scope(ss, scope);
    span = ctr_span_create(ctx, ss, "text", NULL);
    link = ctr_link_create(span, NULL, 0, NULL, 0);
    TEST_ASSERT(link != NULL);
    TEST_CHECK(ctr_span_set_attribute_string(span, "long", long_value) == 0);

    text = ctr_encode_text_create(ctx);
    TEST_ASSERT(text != NULL);
    TEST_CHECK(strstr(text, long_value) != NULL);

    ctr_encode_text_destroy(text);
    ctr_destroy(ctx);
}

void test_owner_self_assignment()
{
    struct ctrace *ctx;
    struct ctrace_resource_span *rs;
    struct ctrace_scope_span *ss;
    struct ctrace_instrumentation_scope *scope;
    struct ctrace_span *span;
    struct ctrace_span_event *event;

    ctx = ctr_create(NULL);
    rs = ctr_resource_span_create(ctx);
    ss = ctr_scope_span_create(rs);
    scope = ctr_instrumentation_scope_create("scope", "1", 0, NULL);
    ctr_scope_span_set_instrumentation_scope(ss, scope);
    span = ctr_span_create(ctx, ss, "self", NULL);
    event = ctr_span_event_add(span, "self");

    TEST_CHECK(ctr_span_set_attributes(span, span->attr) == 0);
    TEST_CHECK(ctr_span_event_set_attributes(event, event->attr) == 0);
    ctr_scope_span_set_instrumentation_scope(ss, ss->instrumentation_scope);
    TEST_CHECK(strcmp(ss->instrumentation_scope->name, "scope") == 0);

    ctr_destroy(ctx);
}

void test_reject_cross_context_span()
{
    struct ctrace *ctx_a;
    struct ctrace *ctx_b;
    struct ctrace_resource_span *rs;
    struct ctrace_scope_span *ss;

    ctx_a = ctr_create(NULL);
    ctx_b = ctr_create(NULL);
    rs = ctr_resource_span_create(ctx_a);
    ss = ctr_scope_span_create(rs);

    TEST_CHECK(ctr_span_create(ctx_b, ss, "invalid", NULL) == NULL);
    TEST_CHECK(cfl_list_is_empty(&ctx_b->span_list));
    TEST_CHECK(cfl_list_is_empty(&ss->spans));

    ctr_destroy(ctx_b);
    ctr_destroy(ctx_a);
}

void test_reject_invalid_span_enums()
{
    struct ctrace *ctx;
    struct ctrace_resource_span *rs;
    struct ctrace_scope_span *ss;
    struct ctrace_span *span;

    ctx = ctr_create(NULL);
    rs = ctr_resource_span_create(ctx);
    ss = ctr_scope_span_create(rs);
    span = ctr_span_create(ctx, ss, "enums", NULL);

    TEST_CHECK(ctr_span_kind_set(span, CTRACE_SPAN_CONSUMER + 1) != 0);
    TEST_CHECK(span->kind == CTRACE_SPAN_INTERNAL);
    TEST_CHECK(ctr_span_set_status(span, CTRACE_SPAN_STATUS_CODE_ERROR + 1,
                                   "invalid") != 0);
    TEST_CHECK(span->status.code == CTRACE_SPAN_STATUS_CODE_UNSET);
    TEST_CHECK(span->status.message == NULL);

    ctr_destroy(ctx);
}

TEST_LIST = {
    {"span", test_span},
    {"resource_span_direct_destroy", test_resource_span_direct_destroy},
    {"random_id_length", test_random_id_length},
    {"event_integer_api", test_event_integer_api},
    {"text_encoder_optional_and_long_strings", test_text_encoder_optional_and_long_strings},
    {"owner_self_assignment", test_owner_self_assignment},
    {"reject_cross_context_span", test_reject_cross_context_span},
    {"reject_invalid_span_enums", test_reject_invalid_span_enums},
    { 0 }
};
