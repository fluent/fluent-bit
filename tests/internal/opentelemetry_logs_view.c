/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2026 The Fluent Bit Authors
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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_log_view.h>
#include <fluent-bit/flb_opentelemetry.h>
#include <fluent-bit/flb_opentelemetry_view.h>
#include <fluent-bit/flb_log_event_encoder.h>
#include <msgpack.h>
#include <fluent-otel-proto/fluent-otel.h>

#include <errno.h>
#include <string.h>

#include "flb_tests_internal.h"

#define LOGS(name) opentelemetry__proto__collector__logs__v1__export_logs_service_request__##name

/* OTLP protobuf backend */

#define ATTRIBUTES 7

struct sample_request {
    Opentelemetry__Proto__Common__V1__AnyValue values[ATTRIBUTES];
    Opentelemetry__Proto__Common__V1__KeyValue pairs[ATTRIBUTES];
    Opentelemetry__Proto__Common__V1__KeyValue *pair_list[ATTRIBUTES];
    Opentelemetry__Proto__Common__V1__AnyValue nested_value;
    Opentelemetry__Proto__Common__V1__KeyValue nested_pair;
    Opentelemetry__Proto__Common__V1__KeyValue *nested_list[1];
    Opentelemetry__Proto__Common__V1__KeyValueList nested;
    Opentelemetry__Proto__Common__V1__AnyValue items[2];
    Opentelemetry__Proto__Common__V1__AnyValue *item_list[2];
    Opentelemetry__Proto__Common__V1__ArrayValue array;
    Opentelemetry__Proto__Common__V1__AnyValue body;
    Opentelemetry__Proto__Common__V1__AnyValue resource_value;
    Opentelemetry__Proto__Common__V1__KeyValue resource_pair;
    Opentelemetry__Proto__Common__V1__KeyValue *resource_pairs[1];
    Opentelemetry__Proto__Resource__V1__Resource resource;
    Opentelemetry__Proto__Common__V1__InstrumentationScope scope;
    Opentelemetry__Proto__Logs__V1__LogRecord records[3];
    Opentelemetry__Proto__Logs__V1__LogRecord *record_list[3];
    Opentelemetry__Proto__Logs__V1__ScopeLogs scope_logs;
    Opentelemetry__Proto__Logs__V1__ScopeLogs *scope_list[1];
    Opentelemetry__Proto__Logs__V1__ResourceLogs resource_logs;
    Opentelemetry__Proto__Logs__V1__ResourceLogs *resource_list[1];
    Opentelemetry__Proto__Collector__Logs__V1__ExportLogsServiceRequest request;
    ProtobufCMessageUnknownField unknown;
    uint8_t trace_id[16];
    uint8_t unknown_data[2];
};

static void set_string(Opentelemetry__Proto__Common__V1__AnyValue *value, char *text)
{
    opentelemetry__proto__common__v1__any_value__init(value);
    value->value_case = OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_STRING_VALUE;
    value->string_value = text;
}

/*
 * One resource, one scope and three records. The first record has every
 * attribute type and an unknown field, the second has no attributes and the
 * third only the exception type. 'filler' sizes one attribute of the first
 * record to move its length around varint boundaries.
 */
static void *sample_pack(struct sample_request *s, char *filler, size_t *size)
{
    static char *keys[ATTRIBUTES] = {"exception.type", "count", "enabled", "ratio",
                                     "payload", "labels", "tags"};
    void *buffer;
    int index;

    memset(s, 0, sizeof(*s));
    for (index = 0; index < ATTRIBUTES; index++) {
        opentelemetry__proto__common__v1__key_value__init(&s->pairs[index]);
        opentelemetry__proto__common__v1__any_value__init(&s->values[index]);
        s->pairs[index].key = keys[index];
        s->pairs[index].value = &s->values[index];
        s->pair_list[index] = &s->pairs[index];
    }
    set_string(&s->values[0], filler);
    s->values[1].value_case = OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_INT_VALUE;
    s->values[1].int_value = -42;
    s->values[2].value_case = OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_BOOL_VALUE;
    s->values[2].bool_value = 1;
    s->values[3].value_case = OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_DOUBLE_VALUE;
    s->values[3].double_value = 0.5;
    s->values[4].value_case = OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_BYTES_VALUE;
    s->values[4].bytes_value.data = (uint8_t *) "\x00\x01\x02";
    s->values[4].bytes_value.len = 3;

    set_string(&s->nested_value, "nested");
    opentelemetry__proto__common__v1__key_value__init(&s->nested_pair);
    s->nested_pair.key = "inner";
    s->nested_pair.value = &s->nested_value;
    s->nested_list[0] = &s->nested_pair;
    opentelemetry__proto__common__v1__key_value_list__init(&s->nested);
    s->nested.n_values = 1;
    s->nested.values = s->nested_list;
    s->values[5].value_case = OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_KVLIST_VALUE;
    s->values[5].kvlist_value = &s->nested;

    set_string(&s->items[0], "a");
    set_string(&s->items[1], "b");
    s->item_list[0] = &s->items[0];
    s->item_list[1] = &s->items[1];
    opentelemetry__proto__common__v1__array_value__init(&s->array);
    s->array.n_values = 2;
    s->array.values = s->item_list;
    s->values[6].value_case = OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_ARRAY_VALUE;
    s->values[6].array_value = &s->array;

    set_string(&s->body, "the log body");
    memset(s->trace_id, 0xab, sizeof(s->trace_id));
    for (index = 0; index < 3; index++) {
        opentelemetry__proto__logs__v1__log_record__init(&s->records[index]);
        s->records[index].time_unix_nano = 1700000000000000000ULL + index;
        s->records[index].severity_number = 9;
        s->records[index].severity_text = "INFO";
        s->records[index].body = &s->body;
        s->records[index].trace_id.data = s->trace_id;
        s->records[index].trace_id.len = sizeof(s->trace_id);
        s->record_list[index] = &s->records[index];
    }
    s->records[0].n_attributes = ATTRIBUTES;
    s->records[0].attributes = s->pair_list;
    s->records[2].n_attributes = 1;
    s->records[2].attributes = s->pair_list;

    /* field 99, varint 7: not part of the LogRecord schema */
    s->unknown.tag = 99;
    s->unknown.wire_type = PROTOBUF_C_WIRE_TYPE_VARINT;
    s->unknown_data[0] = 7;
    s->unknown.len = 1;
    s->unknown.data = s->unknown_data;
    s->records[0].base.n_unknown_fields = 1;
    s->records[0].base.unknown_fields = &s->unknown;

    set_string(&s->resource_value, "codec");
    opentelemetry__proto__common__v1__key_value__init(&s->resource_pair);
    s->resource_pair.key = "service.name";
    s->resource_pair.value = &s->resource_value;
    s->resource_pairs[0] = &s->resource_pair;
    opentelemetry__proto__resource__v1__resource__init(&s->resource);
    s->resource.n_attributes = 1;
    s->resource.attributes = s->resource_pairs;
    opentelemetry__proto__common__v1__instrumentation_scope__init(&s->scope);
    s->scope.name = "view-test";

    opentelemetry__proto__logs__v1__scope_logs__init(&s->scope_logs);
    s->scope_logs.scope = &s->scope;
    s->scope_logs.schema_url = "https://example.test/scope";
    s->scope_logs.n_log_records = 3;
    s->scope_logs.log_records = s->record_list;
    s->scope_list[0] = &s->scope_logs;
    opentelemetry__proto__logs__v1__resource_logs__init(&s->resource_logs);
    s->resource_logs.resource = &s->resource;
    s->resource_logs.n_scope_logs = 1;
    s->resource_logs.scope_logs = s->scope_list;
    s->resource_list[0] = &s->resource_logs;
    LOGS(init)(&s->request);
    s->request.n_resource_logs = 1;
    s->request.resource_logs = s->resource_list;

    *size = LOGS(get_packed_size)(&s->request);
    buffer = flb_malloc(*size);
    if (buffer != NULL) {
        LOGS(pack)(&s->request, buffer);
    }

    return buffer;
}

struct scan_state {
    size_t records;
    size_t found;
    size_t attributes;
    int materialized;
};

static int cb_scan(void *data, struct flb_log_view *record)
{
    struct scan_state *state = data;
    struct cfl_view *view = record->otel_log_attributes;
    struct cfl_view_value value;
    struct cfl_kvlist *kvlist;
    struct cfl_variant *variant;

    state->records++;
    state->attributes += cfl_view_count(view);
    if (cfl_view_get(view, "exception.type", 14, &value) == 1) {
        TEST_CHECK(value.type == CFL_VARIANT_STRING);
        TEST_CHECK(value.data.as_bytes.size == 9 &&
                   memcmp(value.data.as_bytes.data, "ValueFail", 9) == 0);
        state->found++;
    }
    if (cfl_view_count(view) != ATTRIBUTES) {
        return 0;
    }

    TEST_CHECK(cfl_view_get(view, "count", 5, &value) == 1);
    TEST_CHECK(value.type == CFL_VARIANT_INT && value.data.as_int64 == -42);
    TEST_CHECK(cfl_view_get(view, "enabled", 7, &value) == 1);
    TEST_CHECK(value.type == CFL_VARIANT_BOOL && value.data.as_bool);
    TEST_CHECK(cfl_view_get(view, "ratio", 5, &value) == 1);
    TEST_CHECK(value.type == CFL_VARIANT_DOUBLE && value.data.as_double == 0.5);
    TEST_CHECK(cfl_view_get(view, "payload", 7, &value) == 1);
    TEST_CHECK(value.type == CFL_VARIANT_BYTES && value.data.as_bytes.size == 3);
    TEST_CHECK(cfl_view_get(view, "labels", 6, &value) == 1);
    TEST_CHECK(value.type == CFL_VARIANT_KVLIST);
    TEST_CHECK(cfl_view_get(view, "tags", 4, &value) == 1);
    TEST_CHECK(value.type == CFL_VARIANT_ARRAY);

    /* compatibility exit: the whole map as native CFL */
    kvlist = cfl_view_materialize(view);
    TEST_CHECK(kvlist != NULL);
    if (kvlist != NULL) {
        TEST_CHECK(cfl_kvlist_count(kvlist) == ATTRIBUTES);
        variant = cfl_kvlist_fetch(kvlist, "labels");
        TEST_CHECK(variant != NULL && variant->type == CFL_VARIANT_KVLIST);
        if (variant != NULL && variant->type == CFL_VARIANT_KVLIST) {
            variant = cfl_kvlist_fetch(variant->data.as_kvlist, "inner");
            TEST_CHECK(variant != NULL && strcmp(variant->data.as_string, "nested") == 0);
        }
        variant = cfl_kvlist_fetch(kvlist, "tags");
        TEST_CHECK(variant != NULL && variant->type == CFL_VARIANT_ARRAY &&
                   variant->data.as_array->entry_count == 2);
        variant = cfl_kvlist_fetch(kvlist, "count");
        TEST_CHECK(variant != NULL && variant->data.as_int64 == -42);
        cfl_kvlist_destroy(kvlist);
        state->materialized = FLB_TRUE;
    }

    return 0;
}

static void test_protobuf_scan(void)
{
    struct sample_request sample;
    struct scan_state state = {0};
    struct flb_log_view_editor editor = {cb_scan, &state};
    size_t records = 0;
    size_t size;
    void *payload;

    payload = sample_pack(&sample, "ValueFail", &size);
    TEST_CHECK(payload != NULL);
    TEST_CHECK(flb_opentelemetry_logs_proto_view_scan(payload, size, &editor, &records) == 0);
    TEST_CHECK(records == 3 && state.records == 3);
    TEST_CHECK(state.found == 2);
    TEST_CHECK(state.attributes == ATTRIBUTES + 1);
    TEST_CHECK(state.materialized == FLB_TRUE);
    flb_free(payload);
}

static int cb_noop(void *data, struct flb_log_view *record)
{
    (void) data;
    (void) record;

    return 0;
}

static void test_protobuf_passthrough(void)
{
    struct sample_request sample;
    struct flb_log_view_editor editor = {cb_noop, NULL};
    size_t modified = 99;
    size_t records = 0;
    size_t out_size;
    size_t size;
    void *payload;
    void *out;

    payload = sample_pack(&sample, "ValueFail", &size);
    TEST_CHECK(flb_opentelemetry_logs_proto_view_transform(payload, size, &editor, &out,
                                                           &out_size, &records,
                                                           &modified) == 0);
    TEST_CHECK(records == 3 && modified == 0);
    TEST_CHECK(out_size == size && memcmp(out, payload, size) == 0);
    flb_free(out);
    flb_free(payload);
}

/* rename exception.type, remove 'count', insert a new string attribute */
static int cb_edit(void *data, struct flb_log_view *record)
{
    struct cfl_view *view = record->otel_log_attributes;
    int64_t index;

    (void) data;
    index = cfl_view_find(view, "exception.type", 14);
    if (index >= 0) {
        TEST_CHECK(cfl_view_rename_at(view, (size_t) index, "exception.kind", 14) == 0);
    }
    index = cfl_view_find(view, "count", 5);
    if (index >= 0) {
        TEST_CHECK(cfl_view_remove_at(view, (size_t) index) == 0);
    }
    if (cfl_view_find(view, "benchmark.enriched", 18) < 0) {
        TEST_CHECK(cfl_view_append_string(view, "benchmark.enriched", 18, "true", 4) == 0);
    }

    return 0;
}

static Opentelemetry__Proto__Common__V1__AnyValue *find_attribute(
        Opentelemetry__Proto__Logs__V1__LogRecord *record, const char *key)
{
    size_t index;

    for (index = 0; index < record->n_attributes; index++) {
        if (strcmp(record->attributes[index]->key, key) == 0) {
            return record->attributes[index]->value;
        }
    }

    return NULL;
}

static void check_edited(const void *out, size_t out_size, const char *filler)
{
    static const size_t counts[3] = {ATTRIBUTES, 1, 2};
    Opentelemetry__Proto__Collector__Logs__V1__ExportLogsServiceRequest *request;
    Opentelemetry__Proto__Logs__V1__ScopeLogs *scope;
    Opentelemetry__Proto__Logs__V1__LogRecord *record;
    Opentelemetry__Proto__Common__V1__AnyValue *value;
    size_t index;

    request = LOGS(unpack)(NULL, out_size, out);
    if (!TEST_CHECK(request != NULL)) {
        return;
    }
    TEST_CHECK(request->n_resource_logs == 1);
    TEST_CHECK(strcmp(request->resource_logs[0]->resource->attributes[0]->key,
                      "service.name") == 0);
    scope = request->resource_logs[0]->scope_logs[0];
    TEST_CHECK(strcmp(scope->scope->name, "view-test") == 0);
    TEST_CHECK(strcmp(scope->schema_url, "https://example.test/scope") == 0);
    TEST_CHECK(scope->n_log_records == 3);

    for (index = 0; index < scope->n_log_records; index++) {
        record = scope->log_records[index];
        TEST_CHECK(record->time_unix_nano == 1700000000000000000ULL + index);
        TEST_CHECK(record->severity_number == 9);
        TEST_CHECK(strcmp(record->severity_text, "INFO") == 0);
        TEST_CHECK(strcmp(record->body->string_value, "the log body") == 0);
        TEST_CHECK(record->trace_id.len == 16 && record->trace_id.data[15] == 0xab);
        TEST_CHECK_(record->n_attributes == counts[index], "record %zu: %zu attributes",
                    index, record->n_attributes);
        TEST_CHECK(find_attribute(record, "exception.type") == NULL);
        TEST_CHECK(find_attribute(record, "count") == NULL);
        value = find_attribute(record, "benchmark.enriched");
        TEST_CHECK(value != NULL && strcmp(value->string_value, "true") == 0);
        /* inserted pairs go last */
        TEST_CHECK(strcmp(record->attributes[record->n_attributes - 1]->key,
                          "benchmark.enriched") == 0);
        if (index != 1) {
            /* a renamed pair keeps its position and its value */
            TEST_CHECK(strcmp(record->attributes[0]->key, "exception.kind") == 0);
            TEST_CHECK(strcmp(record->attributes[0]->value->string_value, filler) == 0);
        }
    }

    record = scope->log_records[0];
    TEST_CHECK(find_attribute(record, "enabled")->bool_value == 1);
    TEST_CHECK(find_attribute(record, "ratio")->double_value == 0.5);
    TEST_CHECK(find_attribute(record, "payload")->bytes_value.len == 3);
    TEST_CHECK(strcmp(find_attribute(record, "labels")->kvlist_value->values[0]->key,
                      "inner") == 0);
    TEST_CHECK(find_attribute(record, "tags")->array_value->n_values == 2);
    /* the field outside the schema survives the rewrite */
    TEST_CHECK(record->base.n_unknown_fields == 1);
    if (record->base.n_unknown_fields == 1) {
        TEST_CHECK(record->base.unknown_fields[0].tag == 99 &&
                   record->base.unknown_fields[0].data[0] == 7);
    }
    LOGS(free_unpacked)(request, NULL);
}

static void test_protobuf_edit(void)
{
    struct sample_request sample;
    struct flb_log_view_editor editor = {cb_edit, NULL};
    char filler[400];
    size_t length;
    size_t modified;
    size_t records;
    size_t out_size;
    size_t size;
    void *payload;
    void *out;

    /* sweep the record and parent sizes across the one and two byte prefixes */
    for (length = 0; length < sizeof(filler) - 1; length++) {
        memset(filler, 'x', length);
        filler[length] = '\0';
        payload = sample_pack(&sample, filler, &size);
        if (!TEST_CHECK(payload != NULL)) {
            return;
        }
        out = NULL;
        if (TEST_CHECK_(flb_opentelemetry_logs_proto_view_transform(
                            payload, size, &editor, &out, &out_size, &records,
                            &modified) == 0, "filler %zu", length)) {
            TEST_CHECK(records == 3 && modified == 3);
            check_edited(out, out_size, filler);
        }
        flb_free(out);
        flb_free(payload);
    }
}

static int cb_fail(void *data, struct flb_log_view *record)
{
    (void) data;
    (void) record;

    return -1;
}

static void test_protobuf_errors(void)
{
    struct sample_request sample;
    struct flb_log_view_editor editor = {cb_edit, NULL};
    struct flb_log_view_editor failing = {cb_fail, NULL};
    size_t out_size;
    size_t size;
    size_t cut;
    void *payload;
    void *out;
    int result;

    payload = sample_pack(&sample, "ValueFail", &size);

    /* every truncation is rejected or still well formed, never read past */
    for (cut = 0; cut < size; cut++) {
        out = NULL;
        result = flb_opentelemetry_logs_proto_view_transform(payload, cut, &editor, &out,
                                                             &out_size, NULL, NULL);
        TEST_CHECK(result == 0 || result == EINVAL);
        TEST_CHECK((result == 0) == (out != NULL));
        flb_free(out);
    }

    out = NULL;
    TEST_CHECK(flb_opentelemetry_logs_proto_view_transform(payload, size, &failing, &out,
                                                           &out_size, NULL,
                                                           NULL) == ECANCELED);
    TEST_CHECK(out == NULL);
    flb_free(payload);
}

/*
 * Protobuf to MessagePack without unpacking. The unpacking decoder is the
 * reference: whenever the direct one accepts a request, both must produce
 * the same records.
 */
static msgpack_object *map_value(msgpack_object *map, const char *key)
{
    uint32_t index;

    if (map->type != MSGPACK_OBJECT_MAP) {
        return NULL;
    }
    for (index = 0; index < map->via.map.size; index++) {
        if (map->via.map.ptr[index].key.type == MSGPACK_OBJECT_STR &&
            map->via.map.ptr[index].key.via.str.size == strlen(key) &&
            memcmp(map->via.map.ptr[index].key.via.str.ptr, key, strlen(key)) == 0) {
            return &map->via.map.ptr[index].val;
        }
    }

    return NULL;
}

/* A record without any timestamp gets the current time: only then it may differ. */
static int same_records(const char *a, size_t a_size, const char *b, size_t b_size)
{
    msgpack_unpacked left;
    msgpack_unpacked right;
    msgpack_object *header_a;
    msgpack_object *header_b;
    msgpack_object *otlp;
    size_t offset_a = 0;
    size_t offset_b = 0;
    int same = FLB_TRUE;
    int more_a;
    int more_b;

    msgpack_unpacked_init(&left);
    msgpack_unpacked_init(&right);
    while (same) {
        if (offset_a == a_size || offset_b == b_size) {
            /* equal when both end here, cleanly */
            same = offset_a == a_size && offset_b == b_size;
            break;
        }
        more_a = msgpack_unpack_next(&left, a, a_size, &offset_a) == MSGPACK_UNPACK_SUCCESS;
        more_b = msgpack_unpack_next(&right, b, b_size, &offset_b) == MSGPACK_UNPACK_SUCCESS;
        if (!more_a || !more_b) {
            /* bytes left that are not a complete object */
            same = FLB_FALSE;
            break;
        }
        if (left.data.type != MSGPACK_OBJECT_ARRAY || left.data.via.array.size != 2 ||
            right.data.type != MSGPACK_OBJECT_ARRAY || right.data.via.array.size != 2) {
            same = FLB_FALSE;
            break;
        }
        header_a = &left.data.via.array.ptr[0];
        header_b = &right.data.via.array.ptr[0];
        if (header_a->type != MSGPACK_OBJECT_ARRAY || header_a->via.array.size != 2 ||
            header_b->type != MSGPACK_OBJECT_ARRAY || header_b->via.array.size != 2) {
            same = FLB_FALSE;
            break;
        }
        same = msgpack_object_equal(header_a->via.array.ptr[1], header_b->via.array.ptr[1]) &&
               msgpack_object_equal(left.data.via.array.ptr[1], right.data.via.array.ptr[1]);
        otlp = map_value(&header_a->via.array.ptr[1], "otlp");
        if (same && (otlp == NULL || map_value(otlp, "timestamp") != NULL ||
                     map_value(otlp, "observed_timestamp") != NULL)) {
            same = msgpack_object_equal(header_a->via.array.ptr[0], header_b->via.array.ptr[0]);
        }
    }
    msgpack_unpacked_destroy(&left);
    msgpack_unpacked_destroy(&right);

    return same;
}

/* Returns FLB_TRUE when the direct decoder took the request on. */
static int check_direct(const void *payload, size_t size, const char *body_key)
{
    struct flb_opentelemetry_logs_decode_options options = {
        .metadata_key = "otlp", .body_key = body_key, .output_limit = SIZE_MAX,
    };
    struct flb_opentelemetry_log_buffer direct = {0};
    struct flb_log_event_encoder *encoder;
    size_t records = 0;
    int reference;
    int result;

    result = flb_opentelemetry_logs_proto_view_to_msgpack(payload, size, &options, NULL,
                                                          &direct);
    if (result != 0) {
        TEST_CHECK(result == FLB_OTEL_LOGS_VIEW_FALLBACK);
        TEST_CHECK(direct.size == 0 && direct.records == 0);
        flb_free(direct.data);
        return FLB_FALSE;
    }

    encoder = flb_log_event_encoder_create(FLB_LOG_EVENT_FORMAT_FLUENT_BIT_V2);
    TEST_ASSERT(encoder != NULL);
    reference = flb_opentelemetry_logs_protobuf_to_msgpack(encoder, payload, size, &options,
                                                           &records);
    if (!TEST_CHECK(reference == 0)) {
        TEST_MSG("the unpacking decoder rejects a request the direct one accepted");
    }
    else {
        TEST_CHECK(records == direct.records);
        if (!TEST_CHECK(same_records(direct.data, direct.size, encoder->output_buffer,
                                     encoder->output_length))) {
            TEST_MSG("records differ, %zu and %zu bytes", direct.size,
                     encoder->output_length);
        }
    }
    flb_log_event_encoder_destroy(encoder);
    flb_free(direct.data);

    return FLB_TRUE;
}

static void *repack(struct sample_request *s, size_t *size)
{
    void *buffer;

    *size = LOGS(get_packed_size)(&s->request);
    buffer = flb_malloc(*size);
    TEST_ASSERT(buffer != NULL);
    LOGS(pack)(&s->request, buffer);

    return buffer;
}

static void test_protobuf_to_msgpack(void)
{
    static char text[] = "an event";
    struct sample_request s;
    uint8_t span_id[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    void *payload;
    size_t size;

    payload = sample_pack(&s, "value", &size);
    TEST_ASSERT(payload != NULL);
    TEST_CHECK(check_direct(payload, size, NULL) == FLB_TRUE);
    TEST_CHECK(check_direct(payload, size, "message") == FLB_TRUE);
    flb_free(payload);

    /* every optional record field, a map body, a missing body and no timestamps */
    s.records[0].observed_time_unix_nano = 1700000000000000999ULL;
    s.records[0].dropped_attributes_count = 3;
    s.records[0].flags = 0x1ff;
    s.records[0].span_id.data = span_id;
    s.records[0].span_id.len = sizeof(span_id);
    s.records[0].event_name = text;
    s.records[0].body = &s.values[5];
    s.records[1].body = NULL;
    s.records[1].severity_number = 99;
    s.records[1].severity_text = "";
    s.records[1].trace_id.len = 0;
    s.records[2].time_unix_nano = 0;
    s.records[2].body = &s.values[6];
    s.resource.dropped_attributes_count = 2;
    s.resource_logs.schema_url = "https://example.test/resource";
    s.scope.version = "1.2.3";
    s.scope.dropped_attributes_count = 1;
    s.scope.n_attributes = 2;
    s.scope.attributes = s.pair_list;
    payload = repack(&s, &size);
    TEST_CHECK(check_direct(payload, size, NULL) == FLB_TRUE);
    TEST_CHECK(check_direct(payload, size, "message") == FLB_TRUE);
    flb_free(payload);

    /* no resource, no scope and no scope schema URL */
    s.resource_logs.resource = NULL;
    s.scope_logs.scope = NULL;
    s.scope_logs.schema_url = "";
    payload = repack(&s, &size);
    TEST_CHECK(check_direct(payload, size, NULL) == FLB_TRUE);
    flb_free(payload);

    /* a scope without records is left to the unpacking decoder, an empty request is not */
    s.scope_logs.n_log_records = 0;
    payload = repack(&s, &size);
    TEST_CHECK(check_direct(payload, size, NULL) == FLB_FALSE);
    flb_free(payload);
    TEST_CHECK(check_direct("", 0, NULL) == FLB_TRUE);
}

#define MUTATION_ROUNDS 20000

/* Damaged requests: the direct decoder never accepts what the reference rejects. */
static void test_protobuf_to_msgpack_mutations(void)
{
    struct sample_request s;
    uint8_t *payload;
    uint8_t *copy;
    uint64_t seed = 0x9e3779b97f4a7c15ULL;
    size_t accepted = 0;
    size_t size;
    size_t length;
    int round;
    int change;

    payload = sample_pack(&s, "value", &size);
    TEST_ASSERT(payload != NULL);
    copy = flb_malloc(size);
    TEST_ASSERT(copy != NULL);
    for (round = 0; round < MUTATION_ROUNDS; round++) {
        memcpy(copy, payload, size);
        length = size;
        for (change = 0; change <= round % 3; change++) {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            copy[seed % size] = (uint8_t) (seed >> 32);
        }
        if (round % 5 == 0) {
            length = (seed >> 16) % (size + 1);
        }
        accepted += check_direct(copy, length, round % 2 ? "message" : NULL);
    }
    /* small changes inside strings leave a request both decoders take */
    TEST_CHECK(accepted > 0);
    TEST_MSG("accepted %zu of %d", accepted, MUTATION_ROUNDS);

    flb_free(copy);
    flb_free(payload);
}

/* With an editor the attributes map is always written, edits applied. */
static void test_protobuf_to_msgpack_views(void)
{
    struct flb_opentelemetry_logs_decode_options options = {
        .metadata_key = "otlp", .output_limit = SIZE_MAX,
    };
    struct flb_opentelemetry_log_buffer out = {0};
    struct flb_log_view_editor editor = {cb_edit, NULL};
    struct sample_request s;
    msgpack_unpacked record;
    msgpack_object *attributes;
    size_t offset = 0;
    size_t records = 0;
    size_t size;
    void *payload;

    payload = sample_pack(&s, "value", &size);
    TEST_ASSERT(payload != NULL);
    TEST_ASSERT(flb_opentelemetry_logs_proto_view_to_msgpack(payload, size, &options, &editor,
                                                             &out) == 0);
    TEST_CHECK(out.records == 3);

    msgpack_unpacked_init(&record);
    while (msgpack_unpack_next(&record, out.data, out.size, &offset) ==
           MSGPACK_UNPACK_SUCCESS) {
        attributes = map_value(&record.data.via.array.ptr[0].via.array.ptr[1], "otlp");
        if (attributes == NULL) {
            /* group markers */
            continue;
        }
        attributes = map_value(attributes, "attributes");
        if (!TEST_CHECK(attributes != NULL && attributes->type == MSGPACK_OBJECT_MAP)) {
            continue;
        }
        records++;
        /* cb_edit: rename exception.type, drop count, add an attribute */
        TEST_CHECK(map_value(attributes, "exception.type") == NULL);
        TEST_CHECK(map_value(attributes, "count") == NULL);
        TEST_CHECK(map_value(attributes, "benchmark.enriched") != NULL);
        if (records != 2) {
            TEST_CHECK(map_value(attributes, "exception.kind") != NULL);
        }
    }
    TEST_CHECK(records == 3);
    msgpack_unpacked_destroy(&record);
    flb_free(out.data);

    /* a consumer that fails cancels the request */
    editor.cb_record = cb_fail;
    memset(&out, 0, sizeof(out));
    TEST_CHECK(flb_opentelemetry_logs_proto_view_to_msgpack(payload, size, &options, &editor,
                                                            &out) ==
               FLB_OTEL_LOGS_VIEW_CANCELED);
    TEST_CHECK(out.size == 0);
    flb_free(out.data);
    flb_free(payload);
}

/* An editor never hides a malformed value by taking its attribute out. */
static void test_protobuf_to_msgpack_removed(void)
{
    static const char pattern[] = "\x05" "count" "\x12";
    struct flb_opentelemetry_logs_decode_options options = {
        .metadata_key = "otlp", .output_limit = SIZE_MAX,
    };
    struct flb_opentelemetry_log_buffer out = {0};
    struct flb_log_view_editor editor = {cb_noop, NULL};
    struct sample_request s;
    uint8_t *payload;
    size_t damaged = 0;
    size_t index;
    size_t size;

    payload = sample_pack(&s, "value", &size);
    TEST_ASSERT(payload != NULL);
    TEST_CHECK(flb_opentelemetry_logs_proto_view_to_msgpack(payload, size, &options, &editor,
                                                            &out) == 0);

    /* the int value of 'count' becomes a string longer than its message */
    for (index = 0; index + sizeof(pattern) + 1 < size; index++) {
        if (memcmp(payload + index, pattern, sizeof(pattern) - 1) == 0 &&
            payload[index + sizeof(pattern)] == 0x18) {
            payload[index + sizeof(pattern)] = 0x0a;
            damaged++;
        }
    }
    TEST_CHECK(damaged > 0);

    TEST_CHECK(flb_opentelemetry_logs_proto_view_to_msgpack(payload, size, &options, NULL,
                                                            &out) ==
               FLB_OTEL_LOGS_VIEW_FALLBACK);
    TEST_CHECK(flb_opentelemetry_logs_proto_view_to_msgpack(payload, size, &options, &editor,
                                                            &out) ==
               FLB_OTEL_LOGS_VIEW_FALLBACK);
    /* cb_edit removes 'count' */
    editor.cb_record = cb_edit;
    TEST_CHECK(flb_opentelemetry_logs_proto_view_to_msgpack(payload, size, &options, &editor,
                                                            &out) ==
               FLB_OTEL_LOGS_VIEW_FALLBACK);
    TEST_CHECK(out.size == 0 && out.records == 0);

    flb_free(out.data);
    flb_free(payload);
}

/* The size limit and the charge are about the records before the edits. */
static void test_protobuf_to_msgpack_charge(void)
{
    struct flb_opentelemetry_logs_decode_options options = {
        .metadata_key = "otlp", .output_limit = SIZE_MAX,
    };
    struct flb_opentelemetry_log_buffer out = {0};
    struct flb_log_view_editor editor = {cb_noop, NULL};
    struct sample_request s;
    size_t plain;
    size_t size;
    void *payload;

    payload = sample_pack(&s, "value", &size);
    TEST_ASSERT(payload != NULL);
    TEST_ASSERT(flb_opentelemetry_logs_proto_view_to_msgpack(payload, size, &options, NULL,
                                                             &out) == 0);
    plain = out.size;
    TEST_CHECK(out.charged == plain);

    /* with an editor, a record without attributes gets an empty map */
    TEST_ASSERT(flb_opentelemetry_logs_proto_view_to_msgpack(payload, size, &options, &editor,
                                                             &out) == 0);
    TEST_CHECK(out.size > plain && out.charged == plain);

    options.output_limit = plain - 1;
    TEST_CHECK(flb_opentelemetry_logs_proto_view_to_msgpack(payload, size, &options, &editor,
                                                            &out) ==
               FLB_OTEL_LOGS_VIEW_FALLBACK);

    /*
     * cb_edit renames a key, removes a pair and adds a longer one to each
     * record. The records no longer fit the limit, the request still does.
     */
    options.output_limit = plain;
    editor.cb_record = cb_edit;
    TEST_CHECK(flb_opentelemetry_logs_proto_view_to_msgpack(payload, size, &options, &editor,
                                                            &out) == 0);
    TEST_CHECK(out.size > plain);
    /* the old name of the renamed key and the removed pair are counted */
    TEST_CHECK(out.charged == plain);
    TEST_MSG("plain %zu, edited %zu, charged %zu", plain, out.size, out.charged);

    /* without the removed pairs the request would fit a smaller limit */
    options.output_limit = out.charged - 1;
    TEST_CHECK(flb_opentelemetry_logs_proto_view_to_msgpack(payload, size, &options, &editor,
                                                            &out) ==
               FLB_OTEL_LOGS_VIEW_FALLBACK);

    flb_free(out.data);
    flb_free(payload);
}

/* CFL objects an editor places in the view: replace 'enabled', add a map. */
static int cb_objects(void *data, struct flb_log_view *record)
{
    struct cfl_view *view = record->otel_log_attributes;
    struct cfl_variant *value;
    struct cfl_kvlist *map;
    struct cfl_array *list;
    int64_t index;

    (void) data;
    index = cfl_view_find(view, "enabled", 7);
    if (index >= 0) {
        value = cfl_variant_create_from_string("yes");
        TEST_ASSERT(value != NULL);
        TEST_CHECK(cfl_view_set_variant_at(view, (size_t) index, value) == 0);
    }

    map = cfl_kvlist_create();
    list = cfl_array_create(2);
    TEST_ASSERT(map != NULL && list != NULL);
    TEST_CHECK(cfl_array_append_int64(list, -7) == 0);
    TEST_CHECK(cfl_array_append_bool(list, CFL_TRUE) == 0);
    TEST_CHECK(cfl_kvlist_insert_string(map, "name", "view") == 0);
    TEST_CHECK(cfl_kvlist_insert_double(map, "ratio", 0.25) == 0);
    TEST_CHECK(cfl_kvlist_insert_array(map, "items", list) == 0);
    value = cfl_variant_create_from_kvlist(map);
    TEST_ASSERT(value != NULL);
    TEST_CHECK(cfl_view_append_variant(view, "object", 6, value) == 0);

    return 0;
}

static void test_protobuf_objects(void)
{
    struct flb_opentelemetry_logs_decode_options options = {
        .metadata_key = "otlp", .output_limit = SIZE_MAX,
    };
    Opentelemetry__Proto__Collector__Logs__V1__ExportLogsServiceRequest *request;
    Opentelemetry__Proto__Common__V1__KeyValueList *object;
    Opentelemetry__Proto__Common__V1__AnyValue *value;
    struct flb_opentelemetry_log_buffer out = {0};
    struct flb_log_view_editor editor = {cb_objects, NULL};
    struct sample_request s;
    msgpack_unpacked record;
    msgpack_object *attributes;
    msgpack_object *item;
    size_t offset = 0;
    size_t records = 0;
    size_t modified = 0;
    size_t out_size = 0;
    size_t size;
    void *payload;
    void *encoded = NULL;

    payload = sample_pack(&s, "value", &size);
    TEST_ASSERT(payload != NULL);

    /* as MessagePack records */
    TEST_ASSERT(flb_opentelemetry_logs_proto_view_to_msgpack(payload, size, &options, &editor,
                                                             &out) == 0);
    msgpack_unpacked_init(&record);
    while (msgpack_unpack_next(&record, out.data, out.size, &offset) ==
           MSGPACK_UNPACK_SUCCESS) {
        attributes = map_value(&record.data.via.array.ptr[0].via.array.ptr[1], "otlp");
        if (attributes == NULL) {
            continue;
        }
        attributes = map_value(attributes, "attributes");
        if (!TEST_CHECK(attributes != NULL)) {
            continue;
        }
        records++;
        if (records == 1) {
            item = map_value(attributes, "enabled");
            TEST_CHECK(item != NULL && item->type == MSGPACK_OBJECT_STR &&
                       item->via.str.size == 3 && memcmp(item->via.str.ptr, "yes", 3) == 0);
        }
        attributes = map_value(attributes, "object");
        if (!TEST_CHECK(attributes != NULL && attributes->type == MSGPACK_OBJECT_MAP &&
                        attributes->via.map.size == 3)) {
            continue;
        }
        item = map_value(attributes, "name");
        TEST_CHECK(item != NULL && item->type == MSGPACK_OBJECT_STR && item->via.str.size == 4);
        item = map_value(attributes, "ratio");
        TEST_CHECK(item != NULL && item->type == MSGPACK_OBJECT_FLOAT64 &&
                   item->via.f64 == 0.25);
        item = map_value(attributes, "items");
        TEST_CHECK(item != NULL && item->type == MSGPACK_OBJECT_ARRAY &&
                   item->via.array.size == 2 &&
                   item->via.array.ptr[0].type == MSGPACK_OBJECT_NEGATIVE_INTEGER &&
                   item->via.array.ptr[0].via.i64 == -7 &&
                   item->via.array.ptr[1].type == MSGPACK_OBJECT_BOOLEAN);
    }
    TEST_CHECK(records == 3);
    msgpack_unpacked_destroy(&record);
    flb_free(out.data);

    /* as an OTLP request */
    records = 0;
    TEST_ASSERT(flb_opentelemetry_logs_proto_view_transform(payload, size, &editor, &encoded,
                                                            &out_size, &records,
                                                            &modified) == 0);
    TEST_CHECK(records == 3 && modified == 3);
    request = LOGS(unpack)(NULL, out_size, encoded);
    if (TEST_CHECK(request != NULL)) {
        value = find_attribute(request->resource_logs[0]->scope_logs[0]->log_records[0],
                               "enabled");
        TEST_CHECK(value != NULL &&
                   value->value_case ==
                   OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_STRING_VALUE &&
                   strcmp(value->string_value, "yes") == 0);
        value = find_attribute(request->resource_logs[0]->scope_logs[0]->log_records[2],
                               "object");
        if (TEST_CHECK(value != NULL && value->kvlist_value != NULL &&
                       value->kvlist_value->n_values == 3)) {
            object = value->kvlist_value;
            TEST_CHECK(strcmp(object->values[0]->key, "name") == 0 &&
                       strcmp(object->values[0]->value->string_value, "view") == 0);
            TEST_CHECK(strcmp(object->values[1]->key, "ratio") == 0 &&
                       object->values[1]->value->double_value == 0.25);
            TEST_CHECK(strcmp(object->values[2]->key, "items") == 0 &&
                       object->values[2]->value->array_value->n_values == 2 &&
                       object->values[2]->value->array_value->values[0]->int_value == -7 &&
                       object->values[2]->value->array_value->values[1]->bool_value);
        }
        LOGS(free_unpacked)(request, NULL);
    }
    flb_free(encoded);
    flb_free(payload);
}

/* Wraps 'size' bytes at the end of 'buffer' in a length-delimited field. */
static size_t wrap_field(uint8_t *buffer, size_t capacity, size_t size, uint8_t tag,
                         const char *prefix, size_t prefix_size)
{
    uint8_t header[8];
    size_t length = size + prefix_size;
    size_t used = 0;

    header[used++] = tag;
    while (length >= 0x80) {
        header[used++] = (uint8_t) (length | 0x80);
        length >>= 7;
    }
    header[used++] = (uint8_t) length;

    TEST_ASSERT(size + prefix_size + used <= capacity);
    memcpy(buffer + capacity - size - prefix_size, prefix, prefix_size);
    memcpy(buffer + capacity - size - prefix_size - used, header, used);

    return size + prefix_size + used;
}

/*
 * A request with one record whose body, or whose only attribute, is an int
 * under 'steps' nested key and value lists. Built from the leaf outwards at
 * the end of 'buffer'; returns where the request starts.
 */
static uint8_t *nested_request(uint8_t *buffer, size_t capacity, int steps, int attribute,
                               size_t *size)
{
    size_t used = 2;
    int step;

    /* AnyValue { int_value: 1 } */
    buffer[capacity - 2] = 0x18;
    buffer[capacity - 1] = 0x01;
    for (step = 0; step < steps; step++) {
        /* KeyValue { key: "k", value }, KeyValueList { values }, AnyValue { kvlist } */
        used = wrap_field(buffer, capacity, used, 0x12, NULL, 0);
        used = wrap_field(buffer, capacity, used, 0x0a, "\x0a\x01k", 3);
        used = wrap_field(buffer, capacity, used, 0x32, NULL, 0);
    }
    if (attribute) {
        used = wrap_field(buffer, capacity, used, 0x12, NULL, 0);
        used = wrap_field(buffer, capacity, used, 0x32, "\x0a\x01k", 3);
    }
    else {
        used = wrap_field(buffer, capacity, used, 0x2a, NULL, 0);
    }
    /* ScopeLogs { log_records }, ResourceLogs { scope_logs }, the request */
    used = wrap_field(buffer, capacity, used, 0x12, NULL, 0);
    used = wrap_field(buffer, capacity, used, 0x12, NULL, 0);
    used = wrap_field(buffer, capacity, used, 0x0a, NULL, 0);
    *size = used;

    return buffer + capacity - used;
}

/* The reader takes on no nesting the request validation rejects. */
static void test_protobuf_to_msgpack_nesting(void)
{
    struct flb_opentelemetry_logs_decode_options options = {
        .metadata_key = "otlp", .output_limit = SIZE_MAX,
    };
    struct flb_opentelemetry_log_buffer out = {0};
    struct flb_log_view_editor editor = {cb_noop, NULL};
    uint8_t buffer[2048];
    uint8_t *payload;
    size_t size;
    int attribute;
    int edited;
    int steps;
    int valid;
    int ret;

    for (attribute = 0; attribute <= 1; attribute++) {
        for (steps = 29; steps <= 34; steps++) {
            payload = nested_request(buffer, sizeof(buffer), steps, attribute, &size);
            valid = flb_opentelemetry_protobuf_validate(&LOGS(descriptor), payload, size) == 0;
            TEST_CHECK(valid == (steps <= 31));
            for (edited = 0; edited <= 1; edited++) {
                ret = flb_opentelemetry_logs_proto_view_to_msgpack(payload, size, &options,
                                                                   edited ? &editor : NULL,
                                                                   &out);
                TEST_CHECK(ret == (valid ? 0 : FLB_OTEL_LOGS_VIEW_FALLBACK));
                TEST_MSG("attribute %d, steps %d, editor %d: valid %d, reader %d",
                         attribute, steps, edited, valid, ret);
            }
        }
    }

    flb_free(out.data);
}

TEST_LIST = {
    { "protobuf_scan", test_protobuf_scan },
    { "protobuf_passthrough", test_protobuf_passthrough },
    { "protobuf_edit", test_protobuf_edit },
    { "protobuf_errors", test_protobuf_errors },
    { "protobuf_to_msgpack", test_protobuf_to_msgpack },
    { "protobuf_to_msgpack_mutations", test_protobuf_to_msgpack_mutations },
    { "protobuf_to_msgpack_views", test_protobuf_to_msgpack_views },
    { "protobuf_to_msgpack_removed", test_protobuf_to_msgpack_removed },
    { "protobuf_to_msgpack_charge", test_protobuf_to_msgpack_charge },
    { "protobuf_objects", test_protobuf_objects },
    { "protobuf_to_msgpack_nesting", test_protobuf_to_msgpack_nesting },
    { 0 }
};
