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
#include <ctraces/ctr_mpack_utils.h>
#include <ctraces/ctr_variant_utils.h>
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
    cfl_array_append_bytes(array, "\xFF\xEE\xFF\xEE\xCA\xFE", 6, CFL_FALSE);
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

    result = cfl_kvlist_insert_bytes(kvlist, "bytes value", "\xFE\xEE\xFF\xEE\xCA\xFE", 6, CFL_FALSE);

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

static int generate_sample_resource_minimal_attributes(struct ctrace_resource *resource)
{
    struct ctrace_attributes *attributes;
    int                       result;

    attributes = ctr_attributes_create();

    if (attributes == NULL) {
        return -1;
    }

    result = ctr_attributes_set_string(attributes, "receiver.tool", "ctraces");

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

static struct ctrace *generate_encoder_test_data_with_empty_spans()
{
    struct ctrace_resource_span *resource_span;
    struct ctrace_scope_span    *scope_span;
    struct ctrace               *context;
    int                          result;

    context = ctr_create(NULL);

    if (context == NULL) {
        return NULL;
    }

    resource_span = ctr_resource_span_create(context);

    if (resource_span == NULL) {
        ctr_destroy(context);

        return NULL;
    }

    ctr_resource_span_set_schema_url(resource_span, "");
    ctr_resource_set_dropped_attr_count(resource_span->resource, 0);

    result = generate_sample_resource_minimal_attributes(resource_span->resource);

    if (result != 0) {
        ctr_destroy(context);

        return NULL;
    }

    scope_span = ctr_scope_span_create(resource_span);

    if (scope_span == NULL) {
        ctr_destroy(context);

        return NULL;
    }

    ctr_scope_span_set_schema_url(scope_span, "");

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

static void msgpack_encode_decode_and_compare(struct ctrace *context)
{
    char          *validation_text_buffer;
    char          *referece_text_buffer;
    char          *msgpack_text_buffer;
    size_t         msgpack_text_size;
    struct ctrace *decoded_context;
    size_t         offset;
    int            result;

    offset = 0;

    referece_text_buffer = ctr_encode_text_create(context);
    TEST_ASSERT(referece_text_buffer != NULL);

    result = ctr_encode_msgpack_create(context, &msgpack_text_buffer, &msgpack_text_size);
    TEST_ASSERT(result == 0);

    result = ctr_decode_msgpack_create(&decoded_context, msgpack_text_buffer, msgpack_text_size, &offset);
    TEST_ASSERT(result == 0);

    validation_text_buffer = ctr_encode_text_create(decoded_context);
    TEST_ASSERT(validation_text_buffer != NULL);

    TEST_ASSERT(strcmp(referece_text_buffer, validation_text_buffer) == 0);

    ctr_encode_msgpack_destroy(msgpack_text_buffer);
    ctr_encode_text_destroy(validation_text_buffer);
    ctr_encode_text_destroy(referece_text_buffer);

    ctr_destroy(decoded_context);
}

void test_msgpack_to_cmt()
{
    struct ctrace *context;

    context = generate_encoder_test_data();
    TEST_ASSERT(context != NULL);

    msgpack_encode_decode_and_compare(context);

    ctr_destroy(context);
}

void test_msgpack_to_ctr_with_empty_spans()
{
    struct ctrace *context;
    char          *referece_text_buffer;

    context = generate_encoder_test_data_with_empty_spans();
    TEST_ASSERT(context != NULL);

    referece_text_buffer = ctr_encode_text_create(context);
    TEST_ASSERT(referece_text_buffer != NULL);

    printf("%s\n", referece_text_buffer);
    msgpack_encode_decode_and_compare(context);

    ctr_encode_text_destroy(referece_text_buffer);
    ctr_destroy(context);
}

void test_msgpack_preserves_flags()
{
    char *buffer;
    size_t size;
    size_t offset;
    struct ctrace *ctx;
    struct ctrace *decoded;
    struct ctrace_resource_span *rs;
    struct ctrace_scope_span *ss;
    struct ctrace_span *span;
    struct ctrace_link *link;
    int result;

    ctx = ctr_create(NULL);
    rs = ctr_resource_span_create(ctx);
    ss = ctr_scope_span_create(rs);
    span = ctr_span_create(ctx, ss, "flags", NULL);
    link = ctr_link_create(span, NULL, 0, NULL, 0);
    TEST_ASSERT(link != NULL);

    ctr_span_set_flags(span, 0x301);
    ctr_span_set_dropped_links_count(span, 17);
    ctr_link_set_flags(link, 0x201);

    result = ctr_encode_msgpack_create(ctx, &buffer, &size);
    TEST_ASSERT(result == 0);

    offset = 0;
    result = ctr_decode_msgpack_create(&decoded, buffer, size, &offset);
    TEST_ASSERT(result == 0);
    TEST_ASSERT(decoded != NULL);

    rs = cfl_list_entry(decoded->resource_spans.next,
                        struct ctrace_resource_span, _head);
    ss = cfl_list_entry(rs->scope_spans.next, struct ctrace_scope_span, _head);
    span = cfl_list_entry(ss->spans.next, struct ctrace_span, _head);
    link = cfl_list_entry(span->links.next, struct ctrace_link, _head);

    TEST_CHECK(span->flags == 0x301);
    TEST_CHECK(span->dropped_links_count == 17);
    TEST_CHECK(link->flags == 0x201);

    ctr_destroy(decoded);
    ctr_encode_msgpack_destroy(buffer);
    ctr_destroy(ctx);
}

void test_msgpack_invalid_offset()
{
    char data[] = {0x80};
    size_t offset;
    struct ctrace *decoded;
    int result;

    offset = sizeof(data) + 1;
    decoded = (struct ctrace *) 0x1;
    result = ctr_decode_msgpack_create(&decoded, data, sizeof(data), &offset);
    TEST_CHECK(result == CTR_DECODE_MSGPACK_INSUFFICIENT_DATA);
    TEST_CHECK(decoded == NULL);
}

void test_msgpack_integer_ranges()
{
    char negative[] = {(char) 0xff};
    char overflow_u32[] = {(char) 0xcf, 0x00, 0x00, 0x00, 0x01,
                           0x00, 0x00, 0x00, 0x00};
    char overflow_i32[] = {(char) 0xce, (char) 0x80, 0x00, 0x00, 0x00};
    mpack_reader_t reader;
    uint64_t u64;
    uint32_t u32;
    int32_t i32;

    mpack_reader_init_data(&reader, negative, sizeof(negative));
    TEST_CHECK(ctr_mpack_consume_uint64_tag(&reader, &u64) ==
               CTR_MPACK_CORRUPT_INPUT_DATA_ERROR);
    mpack_reader_destroy(&reader);

    mpack_reader_init_data(&reader, overflow_u32, sizeof(overflow_u32));
    TEST_CHECK(ctr_mpack_consume_uint32_tag(&reader, &u32) ==
               CTR_MPACK_CORRUPT_INPUT_DATA_ERROR);
    mpack_reader_destroy(&reader);

    mpack_reader_init_data(&reader, overflow_i32, sizeof(overflow_i32));
    TEST_CHECK(ctr_mpack_consume_int32_tag(&reader, &i32) ==
               CTR_MPACK_CORRUPT_INPUT_DATA_ERROR);
    mpack_reader_destroy(&reader);
}

void test_msgpack_long_attribute_key()
{
    char key[512];
    char *buffer;
    size_t size;
    size_t offset;
    struct ctrace *ctx;
    struct ctrace *decoded;
    struct ctrace_resource_span *rs;
    struct ctrace_scope_span *ss;
    struct ctrace_span *span;
    struct cfl_variant *null_value;
    struct cfl_variant *value;
    int result;

    memset(key, 'k', sizeof(key) - 1);
    key[sizeof(key) - 1] = '\0';

    ctx = ctr_create(NULL);
    rs = ctr_resource_span_create(ctx);
    ss = ctr_scope_span_create(rs);
    span = ctr_span_create(ctx, ss, "long-key", NULL);
    TEST_ASSERT(ctr_span_set_attribute_string(span, key, "value") == 0);
    TEST_ASSERT(cfl_kvlist_insert_uint64(span->attr->kv, "uint", UINT64_MAX) == 0);
    null_value = cfl_variant_create_from_null();
    TEST_ASSERT(null_value != NULL);
    TEST_ASSERT(cfl_kvlist_insert(span->attr->kv, "null", null_value) == 0);
    TEST_ASSERT(ctr_encode_msgpack_create(ctx, &buffer, &size) == 0);

    offset = 0;
    result = ctr_decode_msgpack_create(&decoded, buffer, size, &offset);
    TEST_ASSERT(result == 0);
    rs = cfl_list_entry(decoded->resource_spans.next,
                        struct ctrace_resource_span, _head);
    ss = cfl_list_entry(rs->scope_spans.next, struct ctrace_scope_span, _head);
    span = cfl_list_entry(ss->spans.next, struct ctrace_span, _head);
    TEST_CHECK(cfl_kvlist_fetch(span->attr->kv, key) != NULL);
    value = cfl_kvlist_fetch(span->attr->kv, "uint");
    TEST_ASSERT(value != NULL);
    TEST_CHECK(value->type == CFL_VARIANT_UINT);
    TEST_CHECK(value->data.as_uint64 == UINT64_MAX);
    value = cfl_kvlist_fetch(span->attr->kv, "null");
    TEST_ASSERT(value != NULL);
    TEST_CHECK(value->type == CFL_VARIANT_NULL);

    ctr_destroy(decoded);
    ctr_encode_msgpack_destroy(buffer);
    ctr_destroy(ctx);
}

static void check_variant_nesting_limit(int use_maps, size_t nesting_depth,
                                        int expected_result)
{
    char *buffer;
    size_t size;
    size_t index;
    int result;
    mpack_writer_t writer;
    mpack_reader_t reader;
    struct cfl_variant *variant;

    buffer = NULL;
    size = 0;
    variant = NULL;
    mpack_writer_init_growable(&writer, &buffer, &size);

    for (index = 0; index < nesting_depth; index++) {
        if (use_maps) {
            mpack_start_map(&writer, 1);
            mpack_write_cstr(&writer, "key");
        }
        else {
            mpack_start_array(&writer, 1);
        }
    }

    mpack_write_i64(&writer, 1);

    for (index = 0; index < nesting_depth; index++) {
        if (use_maps) {
            mpack_finish_map(&writer);
        }
        else {
            mpack_finish_array(&writer);
        }
    }

    TEST_ASSERT(mpack_writer_destroy(&writer) == mpack_ok);

    mpack_reader_init_data(&reader, buffer, size);
    result = unpack_cfl_variant(&reader, &variant);
    TEST_CHECK((result == 0) == (expected_result == 0));

    if (variant != NULL) {
        cfl_variant_destroy(variant);
    }

    mpack_reader_destroy(&reader);
    free(buffer);
}

void test_msgpack_variant_limits()
{
    char *buffer;
    size_t size;
    int result;
    mpack_writer_t writer;
    mpack_reader_t reader;
    struct cfl_variant *variant;
    struct cfl_kvlist *kvlist;

    check_variant_nesting_limit(CFL_FALSE,
                                CFL_VARIANT_UTILS_MAXIMUM_NESTING_DEPTH, 0);
    check_variant_nesting_limit(CFL_FALSE,
                                CFL_VARIANT_UTILS_MAXIMUM_NESTING_DEPTH + 1, -1);
    check_variant_nesting_limit(CFL_TRUE,
                                CFL_VARIANT_UTILS_MAXIMUM_NESTING_DEPTH, 0);
    check_variant_nesting_limit(CFL_TRUE,
                                CFL_VARIANT_UTILS_MAXIMUM_NESTING_DEPTH + 1, -1);

    mpack_writer_init_growable(&writer, &buffer, &size);
    mpack_start_map(&writer, 1);
    mpack_write_cstr(&writer, "overflow");
    mpack_write_u64(&writer, UINT64_MAX);
    mpack_finish_map(&writer);
    TEST_ASSERT(mpack_writer_destroy(&writer) == mpack_ok);

    mpack_reader_init_data(&reader, buffer, size);
    result = unpack_cfl_kvlist(&reader, &kvlist);
    TEST_ASSERT(result == 0);
    variant = cfl_kvlist_fetch(kvlist, "overflow");
    TEST_ASSERT(variant != NULL);
    TEST_CHECK(variant->type == CFL_VARIANT_UINT);
    TEST_CHECK(variant->data.as_uint64 == UINT64_MAX);
    cfl_kvlist_destroy(kvlist);
    mpack_reader_destroy(&reader);
    free(buffer);
}

void test_msgpack_rejects_reference()
{
    char *buffer;
    size_t size;
    struct ctrace *ctx;
    struct ctrace_resource_span *rs;
    struct ctrace_scope_span *ss;
    struct ctrace_span *span;

    ctx = ctr_create(NULL);
    rs = ctr_resource_span_create(ctx);
    ss = ctr_scope_span_create(rs);
    span = ctr_span_create(ctx, ss, "reference", NULL);
    TEST_ASSERT(cfl_kvlist_insert_reference(span->attr->kv, "opaque", span) == 0);

    buffer = (char *) 0x1;
    size = 123;
    TEST_CHECK(ctr_encode_msgpack_create(ctx, &buffer, &size) != 0);
    TEST_CHECK(buffer == NULL);
    TEST_CHECK(size == 0);

    ctr_destroy(ctx);
}

void test_msgpack_rejects_duplicate_fields()
{
    char *buffer;
    size_t size;
    size_t offset;
    mpack_writer_t writer;
    struct ctrace *decoded;
    int result;

    mpack_writer_init_growable(&writer, &buffer, &size);
    mpack_start_map(&writer, 2);
    mpack_write_cstr(&writer, "resourceSpans");
    mpack_start_array(&writer, 0);
    mpack_finish_array(&writer);
    mpack_write_cstr(&writer, "resourceSpans");
    mpack_start_array(&writer, 0);
    mpack_finish_array(&writer);
    mpack_finish_map(&writer);
    TEST_ASSERT(mpack_writer_destroy(&writer) == mpack_ok);

    offset = 0;
    decoded = NULL;
    result = ctr_decode_msgpack_create(&decoded, buffer, size, &offset);
    TEST_CHECK(result == CTR_MPACK_CORRUPT_INPUT_DATA_ERROR);
    TEST_CHECK(decoded == NULL);

    free(buffer);
}

void test_simple_to_msgpack_and_back()
{
    struct ctrace *ctx;
    struct ctrace_opts opts;
    struct ctrace_span *span_root;
    struct ctrace_span *span_child;
    struct ctrace_span_event *event;
    struct ctrace_resource_span *resource_span;
    struct ctrace_resource *resource;
    struct ctrace_scope_span *scope_span;
    struct ctrace_instrumentation_scope *instrumentation_scope;
    struct ctrace_link *link;
    struct ctrace_id *span_id;
    struct ctrace_id *trace_id;
    struct cfl_array *array;
    struct cfl_array *sub_array;
    struct cfl_kvlist *kv;

    /*
     * create an options context: this is used to initialize a CTrace context only,
     * it's not mandatory and you can pass a NULL instead on context creation.
     *
     * note: not used.
     */
    ctr_opts_init(&opts);

    /* ctrace context */
    ctx = ctr_create(&opts);
    TEST_ASSERT(ctx != NULL);

    /* resource span */
    resource_span = ctr_resource_span_create(ctx);
    ctr_resource_span_set_schema_url(resource_span, "https://ctraces/resource_span_schema_url");

    /* create a 'resource' for the 'resource span' in question */
    resource = ctr_resource_span_get_resource(resource_span);
    ctr_resource_set_dropped_attr_count(resource, 5);

    /* scope span */
    scope_span = ctr_scope_span_create(resource_span);
    ctr_scope_span_set_schema_url(scope_span, "https://ctraces/scope_span_schema_url");

    /* create an optional instrumentation scope */
    instrumentation_scope = ctr_instrumentation_scope_create("ctrace", "a.b.c", 3, NULL);
    TEST_ASSERT(instrumentation_scope != NULL);

    ctr_scope_span_set_instrumentation_scope(scope_span, instrumentation_scope);

    /* generate a random trace_id */
    trace_id = ctr_id_create_random(CTR_ID_OTEL_TRACE_SIZE);
    TEST_ASSERT(trace_id != NULL);

    /* generate a random ID for the new span */
    span_id = ctr_id_create_random(CTR_ID_OTEL_SPAN_SIZE);
    TEST_ASSERT(span_id != NULL);

    /* Create a root span */
    span_root = ctr_span_create(ctx, scope_span, "main", NULL);
    TEST_ASSERT(span_root != NULL);

    /* assign the random ID */
    ctr_span_set_span_id_with_cid(span_root, span_id);

    /* set random trace_id */
    ctr_span_set_trace_id_with_cid(span_root, trace_id);

    /* add some attributes to the span */
    ctr_span_set_attribute_string(span_root, "agent", "Fluent Bit");
    ctr_span_set_attribute_int64(span_root, "year", 2022);
    ctr_span_set_attribute_bool(span_root, "open_source", CTR_TRUE);
    ctr_span_set_attribute_double(span_root, "temperature", 25.5);

    /* pack an array: create an array context by using the CFL api */
    array = cfl_array_create(4);
    TEST_ASSERT(array != NULL);
    cfl_array_append_string(array, "first");
    cfl_array_append_double(array, 2.0);
    cfl_array_append_bool(array, CFL_FALSE);

    sub_array = cfl_array_create(3);
    TEST_ASSERT(sub_array != NULL);
    cfl_array_append_double(sub_array, 3.1);
    cfl_array_append_double(sub_array, 5.2);
    cfl_array_append_double(sub_array, 6.3);
    cfl_array_append_array(array, sub_array);

    /* add array to the attribute list */
    ctr_span_set_attribute_array(span_root, "my_array", array);

    /* event: add one event and set attributes to it */
    event = ctr_span_event_add(span_root, "connect to remote server");
    TEST_ASSERT(event != NULL);

    ctr_span_event_set_attribute_string(event, "syscall 1", "open()");
    ctr_span_event_set_attribute_string(event, "syscall 2", "connect()");
    ctr_span_event_set_attribute_string(event, "syscall 3", "write()");

    /* add a key/value pair list */
    kv = cfl_kvlist_create();
    TEST_ASSERT(kv != NULL);
    cfl_kvlist_insert_string(kv, "language", "c");

    ctr_span_set_attribute_kvlist(span_root, "my-list", kv);

    /* create a child span */
    span_child = ctr_span_create(ctx, scope_span, "do-work", span_root);
    TEST_ASSERT(span_child != NULL);

    /* set trace_id */
    ctr_span_set_trace_id_with_cid(span_child, trace_id);

    /* use span_root ID as parent_span_id */
    ctr_span_set_parent_span_id_with_cid(span_child, span_id);

    /* delete old span id and generate a new one */
    ctr_id_destroy(span_id);
    span_id = ctr_id_create_random(CTR_ID_OTEL_SPAN_SIZE);
    TEST_ASSERT(span_id != NULL);
    ctr_span_set_span_id_with_cid(span_child, span_id);

    /* destroy the IDs since is not longer needed */
    ctr_id_destroy(span_id);
    ctr_id_destroy(trace_id);

    /* change span kind to client */
    ctr_span_kind_set(span_child, CTRACE_SPAN_CLIENT);

    /* create a Link (no valid IDs of course) */
    trace_id = ctr_id_create_random(CTR_ID_OTEL_TRACE_SIZE);
    TEST_ASSERT(trace_id != NULL);

    span_id = ctr_id_create_random(CTR_ID_OTEL_SPAN_SIZE);
    TEST_ASSERT(span_id != NULL);

    link = ctr_link_create_with_cid(span_child, trace_id, span_id);
    TEST_ASSERT(link != NULL);

    ctr_link_set_trace_state(link, "aaabbbccc");
    ctr_link_set_dropped_attr_count(link, 2);

    /* delete IDs */
    ctr_id_destroy(span_id);
    ctr_id_destroy(trace_id);

    msgpack_encode_decode_and_compare(ctx);

    /* destroy the context */
    ctr_destroy(ctx);

    /* exit options (it release resources allocated) */
    ctr_opts_exit(&opts);
}


TEST_LIST = {
    {"cmt_simple_to_msgpack_and_back", test_simple_to_msgpack_and_back},
    {"cmt_msgpack",                    test_msgpack_to_cmt},
    {"empty_spans",                    test_msgpack_to_ctr_with_empty_spans},
    {"msgpack_preserves_flags",         test_msgpack_preserves_flags},
    {"msgpack_invalid_offset",          test_msgpack_invalid_offset},
    {"msgpack_integer_ranges",          test_msgpack_integer_ranges},
    {"msgpack_long_attribute_key",      test_msgpack_long_attribute_key},
    {"msgpack_variant_limits",          test_msgpack_variant_limits},
    {"msgpack_rejects_reference",       test_msgpack_rejects_reference},
    {"msgpack_rejects_duplicate_fields", test_msgpack_rejects_duplicate_fields},
    { 0 }
};
