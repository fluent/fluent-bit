/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  CMetrics
 *  ========
 *  Copyright 2021 Eduardo Silva <eduardo@calyptia.com>
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
#ifdef __GNUC__
#define _GNU_SOURCE
#endif

#include <ctraces/ctraces.h>
#include <ctraces/ctr_encode_msgpack.h>
#include <ctraces/ctr_decode_msgpack.h>
#include <ctraces/ctr_encode_text.h>
#include "ctr_tests.h"

static int generate_dummy_array_attribute_set(struct cfl_array **out_array, size_t current_depth, size_t max_depth);
static int generate_dummy_kvlist_attribute_set(struct cfl_kvlist **out_kvlist, size_t current_depth, size_t max_depth);

struct cfl_kvlist *get_or_create_external_metadata_kvlist(
    struct cfl_kvlist *root, char *key)
{
    struct cfl_variant *entry_variant;
    struct cfl_kvlist  *entry_kvlist;
    int                 result;

    entry_variant = cfl_kvlist_fetch(root, key);

    if (entry_variant == NULL) {
        entry_kvlist = cfl_kvlist_create();

        if (entry_kvlist == NULL) {
            return NULL;
        }

        result = cfl_kvlist_insert_kvlist(root,
                                          key,
                                          entry_kvlist);

        if (result != 0) {
            cfl_kvlist_destroy(entry_kvlist);

            return NULL;
        }
    }
    else {
        entry_kvlist = entry_variant->data.as_kvlist;
    }

    return entry_kvlist;
}

static int generate_dummy_array_attribute_set(struct cfl_array **out_array, size_t current_depth, size_t max_depth)
{
    struct cfl_array  *inner_array;
    int                result;
    struct cfl_kvlist *kvlist;
    struct cfl_array  *array;

    if (*out_array == NULL) {
        array = cfl_array_create(10);
    }
    else {
        array = *out_array;
    }

    if (array == NULL) {
        return -1;
    }

    cfl_array_append_string(array, "string value");
    cfl_array_append_bytes(array, "\xFF\xEE\xFF\xEE\xCA\xFE", 6);
    cfl_array_append_bool(array, CTR_TRUE);
    cfl_array_append_int64(array, 303456);
    cfl_array_append_double(array, 1.23456);

    if (current_depth < max_depth) {
        kvlist = NULL;

        result = generate_dummy_kvlist_attribute_set(&kvlist, current_depth + 1, max_depth);

        if (result != 0) {
            return -2;
        }

        result = cfl_array_append_kvlist(array, kvlist);

        if (result != 0) {
            return -3;
        }

        inner_array = NULL;

        result = generate_dummy_array_attribute_set(&inner_array, current_depth + 1, max_depth);

        if (result != 0) {
            return -4;
        }

        result = cfl_array_append_array(array, inner_array);

        if (result != 0) {
            return -5;
        }
    }

    *out_array = array;

    return 0;
}

static int generate_dummy_kvlist_attribute_set(struct cfl_kvlist **out_kvlist, size_t current_depth, size_t max_depth)
{
    struct cfl_kvlist *inner_kvlist;
    int                result;
    struct cfl_kvlist *kvlist;
    struct cfl_array  *array;

    if (*out_kvlist == NULL) {
        kvlist = cfl_kvlist_create();
    }
    else {
        kvlist = *out_kvlist;
    }

    if (kvlist == NULL) {
        return -1;
    }

    result = cfl_kvlist_insert_string(kvlist, "string value", "test value 1");

    if (result != 0) {
        return -1;
    }


    result = cfl_kvlist_insert_int64(kvlist, "integer value", 789);

    if (result != 0) {
        return -2;
    }

    result = cfl_kvlist_insert_double(kvlist, "double value", 0.9825);

    if (result != 0) {
        return -3;
    }

    result = cfl_kvlist_insert_bool(kvlist, "bool value", 0);

    if (result != 0) {
        return -3;
    }

    result = cfl_kvlist_insert_bytes(kvlist, "bytes value", "\xFE\xEE\xFF\xEE\xCA\xFE", 6);

    if (result != 0) {
        return -3;
    }

    if (current_depth < max_depth) {
        array = NULL;

        result = generate_dummy_array_attribute_set(&array, current_depth + 1, max_depth);

        if (result != 0) {
            return -3;
        }

        result = cfl_kvlist_insert_array(kvlist, "array value", array);

        if (result != 0) {
            return -3;
        }

        inner_kvlist = NULL;

        result = generate_dummy_kvlist_attribute_set(&inner_kvlist, current_depth + 1, max_depth);

        if (result != 0) {
            return -3;
        }

        result = cfl_kvlist_insert_kvlist(kvlist, "kvlist value", inner_kvlist);

        if (result != 0) {
            return -3;
        }
    }

    *out_kvlist = kvlist;

    return 0;
}

static int generate_sample_resource_attributes(struct ctrace_resource *resource)
{
    struct ctrace_attributes *attributes;
    int                       result;

    attributes = ctr_attributes_create();

    if (attributes == NULL) {
        return -1;
    }

    result = generate_dummy_kvlist_attribute_set(&attributes->kv, 0, 2);

    if (result != 0) {
        ctr_attributes_destroy(attributes);

        return -2;
    }

    result = ctr_resource_set_attributes(resource, attributes);

    if (result != 0) {
        ctr_attributes_destroy(attributes);

        return -3;
    }

    return 0;
}

static int generate_sample_link_attributes(struct ctrace_link *link)
{
    struct ctrace_attributes *attributes;
    int                       result;

    attributes = ctr_attributes_create();

    if (attributes == NULL) {
        return -1;
    }

    result = generate_dummy_kvlist_attribute_set(&attributes->kv, 0, 2);

    if (result != 0) {
        ctr_attributes_destroy(attributes);

        return -2;
    }

    result = ctr_link_set_attributes(link, attributes);

    if (result != 0) {
        ctr_attributes_destroy(attributes);

        return -3;
    }

    return 0;
}

int generate_sample_instrumentation_scope(struct ctrace_scope_span *scope_span)
{
    struct ctrace_instrumentation_scope *instrumentation_scope;
    struct ctrace_attributes            *attributes;
    int                                  result;

    attributes = ctr_attributes_create();

    if (attributes == NULL) {
        return -1;
    }

    result = generate_dummy_kvlist_attribute_set(&attributes->kv, 0, 2);

    if (result != 0) {
        ctr_attributes_destroy(attributes);

        return -2;
    }

    instrumentation_scope = ctr_instrumentation_scope_create("sample instrumentation scope",
                                                             "0.0.1",
                                                             123,
                                                             attributes);

    if (instrumentation_scope == NULL) {
        ctr_attributes_destroy(attributes);

        return -3;
    }

    ctr_scope_span_set_instrumentation_scope(scope_span, instrumentation_scope);

    return 0;
}



static struct ctrace *generate_encoder_test_data()
{
    struct ctrace_resource_span *resource_span;
    struct ctrace_scope_span    *scope_span;
    struct ctrace               *context;
    int                          result;
    struct ctrace_span_event    *event;
    struct ctrace_span          *span;
    struct ctrace_link          *link;

    context = ctr_create(NULL);

    if (context == NULL) {
        return NULL;
    }

    resource_span = ctr_resource_span_create(context);

    if (resource_span == NULL) {
        ctr_destroy(context);

        return NULL;
    }

    ctr_resource_span_set_schema_url(resource_span, "http://resource_1.schema.url:9999/spec.json");
    ctr_resource_set_dropped_attr_count(resource_span->resource, 123);

    result = generate_sample_resource_attributes(resource_span->resource);

    if (result != 0) {
        ctr_destroy(context);

        return NULL;
    }

    scope_span = ctr_scope_span_create(resource_span);

    if (scope_span == NULL) {
        ctr_destroy(context);

        return NULL;
    }

    ctr_scope_span_set_schema_url(scope_span, "http://scope_span_1.schema.url:8888/spec.json");

    result = generate_sample_instrumentation_scope(scope_span);

    if (result != 0) {
        ctr_destroy(context);

        return NULL;
    }

    span = ctr_span_create(context, scope_span, "sample span 1", NULL);

    if (span == NULL) {
        ctr_destroy(context);

        return NULL;
    }

    ctr_span_set_status(span, CTRACE_SPAN_STATUS_CODE_OK, "TEST STATE 1");
    ctr_span_set_trace_id(span, "CTR_TRACE_000001", 16);
    ctr_span_set_span_id(span, "SPAN_001", 8);
    ctr_span_set_parent_span_id(span, "SPAN_801", 8);
    ctr_span_kind_set(span, CTRACE_SPAN_INTERNAL);
    ctr_span_start_ts(context, span, 1000000);
    ctr_span_end_ts(context, span, 2000000);

    result = generate_dummy_kvlist_attribute_set(&span->attr->kv, 0, 2);

    if (result != 0) {
        ctr_destroy(context);

        return NULL;
    }

    ctr_span_set_dropped_events_count(span, 555);

    event = ctr_span_event_add_ts(span, "span_1_event_1", 0x7357);

    if (event == NULL) {
        ctr_destroy(context);

        return NULL;
    }

    ctr_span_event_set_dropped_attributes_count(event, 999);

    result = generate_dummy_kvlist_attribute_set(&event->attr->kv, 0, 2);

    if (result != 0) {
        ctr_destroy(context);

        return NULL;
    }

    // ctr_span_event_set_attribute_string(event, "event_attribute_1", "TEST STRING attribute value");
    // ctr_span_event_set_attribute_int(event,  "event_attribute_2", 987);
    // ctr_span_event_set_attribute_double(event, "event_attribute_2", 9.21);
    ctr_span_event_set_dropped_attributes_count(event, 888);

    link = ctr_link_create(span,
                           "CTR_TRACE_800000", 16,
                           "SPAN_801", 8);

    if (link == NULL) {
        ctr_destroy(context);

        return NULL;
    }

    ctr_link_set_trace_state(link, "TEST STATE 2");
    ctr_link_set_dropped_attr_count(link, 987);

    result = generate_sample_link_attributes(link);

    if (result != 0) {
        ctr_destroy(context);

        return NULL;
    }

    return context;
}

/*
 * perform the following and then compare text buffers
 *
 * CMT +-> MSGPACK -> CMT -> TEXT
 *     +-> TEXT                |
 *          |                  |
 *          |---> compare <----|
 */

void test_msgpack_to_cmt()
{
    char          *validation_text_buffer;
    char          *referece_text_buffer;
    char          *msgpack_text_buffer;
    size_t         msgpack_text_size;
    struct ctrace *decoded_context;
    struct ctrace *context;
    size_t         offset;
    int            result;

    offset = 0;

    context = generate_encoder_test_data();
    TEST_ASSERT(context != NULL);

    referece_text_buffer = ctr_encode_text_create(context);
    TEST_ASSERT(referece_text_buffer != NULL);

    result = ctr_encode_msgpack_create(context, &msgpack_text_buffer, &msgpack_text_size);
    TEST_ASSERT(result == 0);

    result = ctr_decode_msgpack_create(&decoded_context, msgpack_text_buffer, msgpack_text_size, &offset);
    TEST_ASSERT(result == 0);

    validation_text_buffer = ctr_encode_text_create(context);
    TEST_ASSERT(validation_text_buffer != NULL);

    TEST_ASSERT(strcmp(referece_text_buffer, validation_text_buffer) == 0);

    ctr_encode_msgpack_destroy(msgpack_text_buffer);
    ctr_encode_text_destroy(validation_text_buffer);
    ctr_encode_text_destroy(referece_text_buffer);

    ctr_destroy(decoded_context);
    ctr_destroy(context);
}


TEST_LIST = {
    {"cmt_msgpack",      test_msgpack_to_cmt},
    { 0 }
};
