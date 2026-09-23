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
#include <ctraces/ctr_encode_opentelemetry.h>
#include <ctraces/ctr_decode_opentelemetry.h>
#include <fluent-otel-proto/fluent-otel.h>
#include <string.h>
#include "ctr_tests.h"

/* build a non-trivial trace that exercises spans, events, links, status,
 * attributes (scalars/array/kvlist) and an instrumentation scope - the same
 * surface that triggered the encoder NULL-deref fixes.
 */
static struct ctrace *build_sample_trace()
{
    struct ctrace *ctx;
    struct ctrace_span *span_root;
    struct ctrace_span *span_child;
    struct ctrace_span_event *event;
    struct ctrace_resource_span *resource_span;
    struct ctrace_resource *resource;
    struct ctrace_scope_span *scope_span;
    struct ctrace_instrumentation_scope *scope;
    struct ctrace_link *link;
    struct ctrace_id *span_id;
    struct ctrace_id *trace_id;
    struct cfl_array *array;
    struct cfl_kvlist *kv;

    ctx = ctr_create(NULL);
    if (!ctx) {
        return NULL;
    }

    resource_span = ctr_resource_span_create(ctx);
    ctr_resource_span_set_schema_url(resource_span, "https://ctraces/rs");

    resource = ctr_resource_span_get_resource(resource_span);
    ctr_resource_set_dropped_attr_count(resource, 5);

    scope_span = ctr_scope_span_create(resource_span);
    ctr_scope_span_set_schema_url(scope_span, "https://ctraces/ss");

    scope = ctr_instrumentation_scope_create("ctrace", "1.2.3", 3, NULL);
    ctr_scope_span_set_instrumentation_scope(scope_span, scope);

    trace_id = ctr_id_create_random(CTR_ID_OTEL_TRACE_SIZE);
    span_id = ctr_id_create_random(CTR_ID_OTEL_SPAN_SIZE);

    span_root = ctr_span_create(ctx, scope_span, "main", NULL);
    ctr_span_set_trace_id_with_cid(span_root, trace_id);
    ctr_span_set_span_id_with_cid(span_root, span_id);
    ctr_span_set_status(span_root, CTRACE_SPAN_STATUS_CODE_OK, "all good");
    ctr_span_set_flags(span_root, 0x301);
    ctr_span_set_dropped_links_count(span_root, 11);

    ctr_span_set_attribute_string(span_root, "service.name", "ctraces");
    ctr_span_set_attribute_int64(span_root, "year", 2026);
    ctr_span_set_attribute_bool(span_root, "open_source", CTR_TRUE);
    ctr_span_set_attribute_double(span_root, "ratio", 0.42);

    array = cfl_array_create(3);
    cfl_array_append_string(array, "a");
    cfl_array_append_int64(array, 1);
    cfl_array_append_bool(array, CFL_FALSE);
    ctr_span_set_attribute_array(span_root, "list", array);

    kv = cfl_kvlist_create();
    cfl_kvlist_insert_string(kv, "language", "c");
    ctr_span_set_attribute_kvlist(span_root, "meta", kv);

    event = ctr_span_event_add(span_root, "connect");
    ctr_span_event_set_attribute_string(event, "host", "localhost");
    ctr_span_event_set_dropped_attributes_count(event, 1);

    span_child = ctr_span_create(ctx, scope_span, "do-work", span_root);
    ctr_span_set_trace_id_with_cid(span_child, trace_id);
    ctr_span_kind_set(span_child, CTRACE_SPAN_CLIENT);

    link = ctr_link_create_with_cid(span_child, trace_id, span_id);
    ctr_link_set_trace_state(link, "state=1");
    ctr_link_set_dropped_attr_count(link, 2);
    ctr_link_set_flags(link, 0x201);

    ctr_id_destroy(trace_id);
    ctr_id_destroy(span_id);

    return ctx;
}

/* count spans across the whole context, traversing the resource/scope tree
 * so we verify that the decoder rebuilt the structure end-to-end.
 */
static int count_spans(struct ctrace *ctx)
{
    int count = 0;
    struct cfl_list *rs_head;
    struct cfl_list *ss_head;
    struct ctrace_resource_span *rs;
    struct ctrace_scope_span *ss;

    cfl_list_foreach(rs_head, &ctx->resource_spans) {
        rs = cfl_list_entry(rs_head, struct ctrace_resource_span, _head);
        cfl_list_foreach(ss_head, &rs->scope_spans) {
            ss = cfl_list_entry(ss_head, struct ctrace_scope_span, _head);
            count += cfl_list_size(&ss->spans);
        }
    }

    return count;
}

void test_otlp_roundtrip()
{
    cfl_sds_t buf;
    size_t offset = 0;
    struct ctrace *ctx;
    struct ctrace *decoded;
    int ret;
    struct ctrace_resource_span *rs;
    struct ctrace_scope_span *ss;
    struct ctrace_span *span;
    struct ctrace_link *link;

    ctx = build_sample_trace();
    TEST_ASSERT(ctx != NULL);

    buf = ctr_encode_opentelemetry_create(ctx);
    TEST_ASSERT(buf != NULL);
    TEST_CHECK(cfl_sds_len(buf) > 0);

    ret = ctr_decode_opentelemetry_create(&decoded, buf, cfl_sds_len(buf), &offset);
    TEST_ASSERT(ret == CTR_DECODE_OPENTELEMETRY_SUCCESS);
    TEST_ASSERT(decoded != NULL);
    TEST_CHECK(count_spans(decoded) == 2);

    rs = cfl_list_entry(decoded->resource_spans.next,
                        struct ctrace_resource_span, _head);
    ss = cfl_list_entry(rs->scope_spans.next, struct ctrace_scope_span, _head);
    span = cfl_list_entry(ss->spans.next, struct ctrace_span, _head);
    TEST_CHECK(span->flags == 0x301);
    TEST_CHECK(span->dropped_links_count == 11);

    span = cfl_list_entry(span->_head.next, struct ctrace_span, _head);
    link = cfl_list_entry(span->links.next, struct ctrace_link, _head);
    TEST_CHECK(link->flags == 0x201);
    TEST_CHECK(strcmp(link->trace_state, "state=1") == 0);

    ctr_encode_opentelemetry_destroy(buf);
    ctr_destroy(decoded);
    ctr_destroy(ctx);
}

void test_otlp_decode_corrupted()
{
    struct ctrace *decoded = NULL;
    size_t offset = 0;
    /* not a valid protobuf payload */
    char garbage[] = "\xff\xff\xff\xff\xff\xff\xff\xff";
    int ret;

    ret = ctr_decode_opentelemetry_create(&decoded, garbage, sizeof(garbage) - 1, &offset);
    TEST_CHECK(ret != CTR_DECODE_OPENTELEMETRY_SUCCESS);

    /* offset past end of buffer must be reported as insufficient data,
     * not crash.
     */
    offset = 64;
    ret = ctr_decode_opentelemetry_create(&decoded, garbage, sizeof(garbage) - 1, &offset);
    TEST_CHECK(ret == CTR_DECODE_OPENTELEMETRY_INSUFFICIENT_DATA);
}

/* minimal trace: one span, no attributes, events, links, or instrumentation
 * scope. Exercises the encoder's empty-list paths and the decoder's
 * "optional fields not present" paths.
 */
void test_otlp_minimal_trace()
{
    cfl_sds_t buf;
    size_t offset = 0;
    struct ctrace *ctx;
    struct ctrace *decoded = NULL;
    struct ctrace_resource_span *rs;
    struct ctrace_scope_span *ss;
    struct ctrace_span *span;
    int ret;

    ctx = ctr_create(NULL);
    TEST_ASSERT(ctx != NULL);

    rs = ctr_resource_span_create(ctx);
    ss = ctr_scope_span_create(rs);
    span = ctr_span_create(ctx, ss, "bare", NULL);
    TEST_ASSERT(span != NULL);

    buf = ctr_encode_opentelemetry_create(ctx);
    TEST_ASSERT(buf != NULL);

    ret = ctr_decode_opentelemetry_create(&decoded, buf, cfl_sds_len(buf), &offset);
    TEST_ASSERT(ret == CTR_DECODE_OPENTELEMETRY_SUCCESS);
    TEST_CHECK(count_spans(decoded) == 1);

    ctr_encode_opentelemetry_destroy(buf);
    ctr_destroy(decoded);
    ctr_destroy(ctx);
}

void test_otlp_empty_context()
{
    cfl_sds_t buf;
    size_t offset;
    struct ctrace *ctx;
    struct ctrace *decoded;
    int ret;

    ctx = ctr_create(NULL);
    buf = ctr_encode_opentelemetry_create(ctx);
    TEST_ASSERT(buf != NULL);

    offset = 0;
    ret = ctr_decode_opentelemetry_create(&decoded, buf, cfl_sds_len(buf), &offset);
    TEST_ASSERT(ret == CTR_DECODE_OPENTELEMETRY_SUCCESS);
    TEST_CHECK(cfl_list_is_empty(&decoded->resource_spans));

    ctr_destroy(decoded);
    ctr_encode_opentelemetry_destroy(buf);
    ctr_destroy(ctx);
}

void test_otlp_empty_bytes_attribute()
{
    cfl_sds_t buf;
    struct ctrace *ctx;
    struct ctrace_resource_span *rs;
    struct ctrace_scope_span *ss;
    struct ctrace_span *span;

    ctx = ctr_create(NULL);
    rs = ctr_resource_span_create(ctx);
    ss = ctr_scope_span_create(rs);
    span = ctr_span_create(ctx, ss, "empty-bytes", NULL);
    TEST_ASSERT(cfl_kvlist_insert_bytes(span->attr->kv, "empty", "", 0,
                                        CFL_FALSE) == 0);

    buf = ctr_encode_opentelemetry_create(ctx);
    TEST_CHECK(buf != NULL);

    ctr_encode_opentelemetry_destroy(buf);
    ctr_destroy(ctx);
}

void test_otlp_rejects_invalid_variant()
{
    cfl_sds_t buf;
    struct ctrace *ctx;
    struct ctrace_resource_span *rs;
    struct ctrace_scope_span *ss;
    struct ctrace_span *span;
    struct cfl_variant *value;

    ctx = ctr_create(NULL);
    rs = ctr_resource_span_create(ctx);
    ss = ctr_scope_span_create(rs);
    span = ctr_span_create(ctx, ss, "invalid", NULL);
    value = cfl_variant_create();
    TEST_ASSERT(value != NULL);
    value->type = 999;
    TEST_ASSERT(cfl_kvlist_insert(span->attr->kv, "invalid", value) == 0);

    buf = ctr_encode_opentelemetry_create(ctx);
    TEST_CHECK(buf == NULL);

    ctr_destroy(ctx);
}

void test_otlp_rejects_opaque_reference()
{
    cfl_sds_t buf;
    struct ctrace *ctx;
    struct ctrace_resource_span *rs;
    struct ctrace_scope_span *ss;
    struct ctrace_span *span;

    ctx = ctr_create(NULL);
    rs = ctr_resource_span_create(ctx);
    ss = ctr_scope_span_create(rs);
    span = ctr_span_create(ctx, ss, "reference", NULL);
    TEST_ASSERT(cfl_kvlist_insert_reference(span->attr->kv, "opaque", span) == 0);

    buf = ctr_encode_opentelemetry_create(ctx);
    TEST_CHECK(buf == NULL);

    ctr_destroy(ctx);
}

/* attributes carry bytes only when wrapped in an array or kvlist
 * (convert_bytes_value rejects raw bytes at attribute top-level).
 * This exercises ctr_variant_binary_to_otlp_any_value end-to-end.
 */
void test_otlp_bytes_in_array()
{
    cfl_sds_t buf;
    size_t offset = 0;
    struct ctrace *ctx;
    struct ctrace *decoded = NULL;
    struct ctrace_resource_span *rs;
    struct ctrace_scope_span *ss;
    struct ctrace_span *span;
    struct cfl_array *array;
    int ret;

    ctx = ctr_create(NULL);
    rs = ctr_resource_span_create(ctx);
    ss = ctr_scope_span_create(rs);
    span = ctr_span_create(ctx, ss, "bytes", NULL);

    array = cfl_array_create(2);
    cfl_array_append_bytes(array, "\xDE\xAD\xBE\xEF", 4, CFL_FALSE);
    cfl_array_append_string(array, "tail");
    ctr_span_set_attribute_array(span, "blob", array);

    buf = ctr_encode_opentelemetry_create(ctx);
    TEST_ASSERT(buf != NULL);

    ret = ctr_decode_opentelemetry_create(&decoded, buf, cfl_sds_len(buf), &offset);
    TEST_ASSERT(ret == CTR_DECODE_OPENTELEMETRY_SUCCESS);
    TEST_CHECK(count_spans(decoded) == 1);

    ctr_encode_opentelemetry_destroy(buf);
    ctr_destroy(decoded);
    ctr_destroy(ctx);
}

void test_otlp_bytes_attribute()
{
    cfl_sds_t buf;
    size_t offset = 0;
    struct ctrace *ctx;
    struct ctrace *decoded = NULL;
    struct ctrace_resource_span *rs;
    struct ctrace_scope_span *ss;
    struct ctrace_span *span;
    struct cfl_variant *value;
    int ret;

    ctx = ctr_create(NULL);
    rs = ctr_resource_span_create(ctx);
    ss = ctr_scope_span_create(rs);
    span = ctr_span_create(ctx, ss, "bytes", NULL);
    TEST_ASSERT(span != NULL);
    TEST_ASSERT(cfl_kvlist_insert_bytes(span->attr->kv, "blob", "\xDE\xAD", 2,
                                        CFL_FALSE) == 0);

    buf = ctr_encode_opentelemetry_create(ctx);
    TEST_ASSERT(buf != NULL);
    ret = ctr_decode_opentelemetry_create(&decoded, buf, cfl_sds_len(buf), &offset);
    TEST_ASSERT(ret == CTR_DECODE_OPENTELEMETRY_SUCCESS);

    rs = cfl_list_entry(decoded->resource_spans.next,
                        struct ctrace_resource_span, _head);
    ss = cfl_list_entry(rs->scope_spans.next, struct ctrace_scope_span, _head);
    span = cfl_list_entry(ss->spans.next, struct ctrace_span, _head);
    value = cfl_kvlist_fetch(span->attr->kv, "blob");
    TEST_ASSERT(value != NULL);
    TEST_CHECK(value->type == CFL_VARIANT_BYTES);
    TEST_CHECK(cfl_sds_len(value->data.as_bytes) == 2);
    TEST_CHECK(memcmp(value->data.as_bytes, "\xDE\xAD", 2) == 0);

    ctr_encode_opentelemetry_destroy(buf);
    ctr_destroy(decoded);
    ctr_destroy(ctx);
}

/* multiple resource_spans, each with multiple scope_spans, each with
 * multiple spans - exercises every encoder/decoder outer loop including
 * the per-resource_span/per-scope_span/per-span destroy paths.
 */
void test_otlp_multiple_spans()
{
    cfl_sds_t buf;
    size_t offset = 0;
    struct ctrace *ctx;
    struct ctrace *decoded = NULL;
    struct ctrace_resource_span *rs;
    struct ctrace_scope_span *ss;
    int r;
    int s;
    int n;
    int ret;
    char name[32];

    ctx = ctr_create(NULL);

    for (r = 0; r < 2; r++) {
        rs = ctr_resource_span_create(ctx);
        for (s = 0; s < 2; s++) {
            ss = ctr_scope_span_create(rs);
            for (n = 0; n < 2; n++) {
                snprintf(name, sizeof(name), "span-%d-%d-%d", r, s, n);
                TEST_ASSERT(ctr_span_create(ctx, ss, name, NULL) != NULL);
            }
        }
    }

    buf = ctr_encode_opentelemetry_create(ctx);
    TEST_ASSERT(buf != NULL);

    ret = ctr_decode_opentelemetry_create(&decoded, buf, cfl_sds_len(buf), &offset);
    TEST_ASSERT(ret == CTR_DECODE_OPENTELEMETRY_SUCCESS);
    TEST_CHECK(count_spans(decoded) == 2 * 2 * 2);

    ctr_encode_opentelemetry_destroy(buf);
    ctr_destroy(decoded);
    ctr_destroy(ctx);
}

/* hand-build a protobuf payload that is well-formed wire-wise but
 * omits the required `resource` field on the ResourceSpans message.
 * The decoder must reject it without crashing or leaking.
 */
void test_otlp_decode_missing_resource()
{
    Opentelemetry__Proto__Collector__Trace__V1__ExportTraceServiceRequest req;
    Opentelemetry__Proto__Trace__V1__ResourceSpans rs;
    Opentelemetry__Proto__Trace__V1__ResourceSpans *rs_arr[1];
    uint8_t *wire;
    size_t wire_len;
    size_t offset = 0;
    struct ctrace *decoded = NULL;
    int ret;

    opentelemetry__proto__collector__trace__v1__export_trace_service_request__init(&req);
    opentelemetry__proto__trace__v1__resource_spans__init(&rs);

    /* explicitly leave rs.resource = NULL and rs.n_scope_spans = 0 */
    rs_arr[0] = &rs;
    req.resource_spans = rs_arr;
    req.n_resource_spans = 1;

    wire_len = opentelemetry__proto__collector__trace__v1__export_trace_service_request__get_packed_size(&req);
    wire = malloc(wire_len);
    TEST_ASSERT(wire != NULL);
    opentelemetry__proto__collector__trace__v1__export_trace_service_request__pack(&req, wire);

    ret = ctr_decode_opentelemetry_create(&decoded, (char *) wire, wire_len, &offset);
    TEST_CHECK(ret == CTR_DECODE_OPENTELEMETRY_INVALID_PAYLOAD);

    free(wire);
}

/* feed a valid payload truncated to half its length. Protobuf decoding
 * must fail with CORRUPTED_DATA rather than reading past the end.
 */
void test_otlp_decode_truncated()
{
    cfl_sds_t buf;
    size_t offset = 0;
    struct ctrace *ctx;
    struct ctrace *decoded = NULL;
    int ret;

    ctx = build_sample_trace();
    TEST_ASSERT(ctx != NULL);

    buf = ctr_encode_opentelemetry_create(ctx);
    TEST_ASSERT(buf != NULL);
    TEST_ASSERT(cfl_sds_len(buf) > 4);

    ret = ctr_decode_opentelemetry_create(&decoded, buf, cfl_sds_len(buf) / 2, &offset);
    TEST_CHECK(ret == CTR_DECODE_OPENTELEMETRY_CORRUPTED_DATA);
    TEST_CHECK(decoded == NULL);

    ctr_encode_opentelemetry_destroy(buf);
    ctr_destroy(ctx);
}

/* Helpers to build a malicious payload: a service_request containing
 * exactly one span with attributes/events/links chosen by the caller.
 * The returned wire buffer must be freed by the caller.
 */
static uint8_t *pack_one_span_payload(Opentelemetry__Proto__Trace__V1__Span *span,
                                      size_t *out_len)
{
    Opentelemetry__Proto__Collector__Trace__V1__ExportTraceServiceRequest req;
    Opentelemetry__Proto__Trace__V1__ResourceSpans rs;
    Opentelemetry__Proto__Trace__V1__ResourceSpans *rs_arr[1];
    Opentelemetry__Proto__Trace__V1__ScopeSpans ss;
    Opentelemetry__Proto__Trace__V1__ScopeSpans *ss_arr[1];
    Opentelemetry__Proto__Trace__V1__Span *span_arr[1];
    Opentelemetry__Proto__Resource__V1__Resource resource;
    size_t len;
    uint8_t *wire;

    opentelemetry__proto__collector__trace__v1__export_trace_service_request__init(&req);
    opentelemetry__proto__trace__v1__resource_spans__init(&rs);
    opentelemetry__proto__resource__v1__resource__init(&resource);
    opentelemetry__proto__trace__v1__scope_spans__init(&ss);

    rs.resource = &resource;
    ss_arr[0] = &ss;
    rs.scope_spans = ss_arr;
    rs.n_scope_spans = 1;

    span_arr[0] = span;
    ss.spans = span_arr;
    ss.n_spans = 1;

    rs_arr[0] = &rs;
    req.resource_spans = rs_arr;
    req.n_resource_spans = 1;

    len = opentelemetry__proto__collector__trace__v1__export_trace_service_request__get_packed_size(&req);
    wire = malloc(len);
    if (wire) {
        opentelemetry__proto__collector__trace__v1__export_trace_service_request__pack(&req, wire);
    }
    *out_len = len;
    return wire;
}

/* A KeyValue with no `value` field set unpacks to value=NULL. The decoder
 * must skip the entry instead of dereferencing it.
 */
void test_otlp_decode_attribute_null_value()
{
    Opentelemetry__Proto__Common__V1__KeyValue kv;
    Opentelemetry__Proto__Common__V1__KeyValue *kv_arr[1];
    Opentelemetry__Proto__Trace__V1__Span span;
    uint8_t *wire;
    size_t wire_len;
    size_t offset = 0;
    struct ctrace *decoded = NULL;
    int ret;

    opentelemetry__proto__trace__v1__span__init(&span);
    opentelemetry__proto__common__v1__key_value__init(&kv);
    kv.key = "bad-key";
    /* leave kv.value = NULL */

    kv_arr[0] = &kv;
    span.name = "victim";
    span.attributes = kv_arr;
    span.n_attributes = 1;

    wire = pack_one_span_payload(&span, &wire_len);
    TEST_ASSERT(wire != NULL);

    ret = ctr_decode_opentelemetry_create(&decoded, (char *) wire, wire_len, &offset);
    TEST_CHECK(ret == CTR_DECODE_OPENTELEMETRY_SUCCESS);
    TEST_CHECK(decoded != NULL);
    if (decoded != NULL) {
        TEST_CHECK(count_spans(decoded) == 1);
        ctr_destroy(decoded);
    }
    free(wire);
}

/* A nested AnyValue with VALUE_INT_VALUE but key=NULL would, before the
 * hardening, call strlen(NULL) inside cfl_kvlist_insert_int64. Build a
 * kvlist attribute containing an int entry with empty key (the closest
 * we can encode via protobuf-c, which forbids NULL on wire) plus a
 * KeyValue whose value field is absent - both must be handled safely.
 */
void test_otlp_decode_nested_malformed_kv()
{
    Opentelemetry__Proto__Common__V1__AnyValue any_int;
    Opentelemetry__Proto__Common__V1__KeyValue inner_good;
    Opentelemetry__Proto__Common__V1__KeyValue inner_bad;
    Opentelemetry__Proto__Common__V1__KeyValue *inner_arr[2];
    Opentelemetry__Proto__Common__V1__KeyValueList kvlist;
    Opentelemetry__Proto__Common__V1__AnyValue any_kv;
    Opentelemetry__Proto__Common__V1__KeyValue outer;
    Opentelemetry__Proto__Common__V1__KeyValue *outer_arr[1];
    Opentelemetry__Proto__Trace__V1__Span span;
    uint8_t *wire;
    size_t wire_len;
    size_t offset = 0;
    struct ctrace *decoded = NULL;
    int ret;

    opentelemetry__proto__trace__v1__span__init(&span);

    opentelemetry__proto__common__v1__any_value__init(&any_int);
    any_int.value_case = OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_INT_VALUE;
    any_int.int_value = 42;

    opentelemetry__proto__common__v1__key_value__init(&inner_good);
    inner_good.key = "k";
    inner_good.value = &any_int;

    opentelemetry__proto__common__v1__key_value__init(&inner_bad);
    inner_bad.key = "missing-value";
    /* leave inner_bad.value = NULL */

    inner_arr[0] = &inner_good;
    inner_arr[1] = &inner_bad;

    opentelemetry__proto__common__v1__key_value_list__init(&kvlist);
    kvlist.values = inner_arr;
    kvlist.n_values = 2;

    opentelemetry__proto__common__v1__any_value__init(&any_kv);
    any_kv.value_case = OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_KVLIST_VALUE;
    any_kv.kvlist_value = &kvlist;

    opentelemetry__proto__common__v1__key_value__init(&outer);
    outer.key = "nested";
    outer.value = &any_kv;
    outer_arr[0] = &outer;

    span.name = "victim";
    span.attributes = outer_arr;
    span.n_attributes = 1;

    wire = pack_one_span_payload(&span, &wire_len);
    TEST_ASSERT(wire != NULL);

    ret = ctr_decode_opentelemetry_create(&decoded, (char *) wire, wire_len, &offset);
    TEST_CHECK(ret == CTR_DECODE_OPENTELEMETRY_SUCCESS);
    TEST_CHECK(decoded != NULL);
    if (decoded != NULL) {
        ctr_destroy(decoded);
    }
    free(wire);
}

/* A span whose `name` field is absent on the wire unpacks with an
 * empty-string name (protobuf-c default). The decoder must accept it
 * gracefully, not crash on the empty key.
 */
void test_otlp_decode_span_empty_name()
{
    Opentelemetry__Proto__Trace__V1__Span span;
    uint8_t *wire;
    size_t wire_len;
    size_t offset = 0;
    struct ctrace *decoded = NULL;
    int ret;

    opentelemetry__proto__trace__v1__span__init(&span);
    /* span.name defaults to the empty-string sentinel */

    wire = pack_one_span_payload(&span, &wire_len);
    TEST_ASSERT(wire != NULL);

    ret = ctr_decode_opentelemetry_create(&decoded, (char *) wire, wire_len, &offset);
    TEST_CHECK(ret == CTR_DECODE_OPENTELEMETRY_SUCCESS);
    if (decoded != NULL) {
        TEST_CHECK(count_spans(decoded) == 1);
        ctr_destroy(decoded);
    }

    free(wire);
}

void test_otlp_decode_invalid_kind()
{
    Opentelemetry__Proto__Trace__V1__Span span;
    uint8_t *wire;
    size_t wire_len;
    size_t offset;
    struct ctrace *decoded;
    int ret;

    opentelemetry__proto__trace__v1__span__init(&span);
    span.name = "invalid-kind";
    span.kind = 99;
    wire = pack_one_span_payload(&span, &wire_len);
    TEST_ASSERT(wire != NULL);

    offset = 0;
    decoded = NULL;
    ret = ctr_decode_opentelemetry_create(&decoded, (char *) wire, wire_len, &offset);
    TEST_CHECK(ret != CTR_DECODE_OPENTELEMETRY_SUCCESS);
    TEST_CHECK(decoded == NULL);

    free(wire);
}


static void check_otlp_depth(size_t depth, int shape)
{
    struct ctrace *original;
    struct ctrace *decoded;
    struct ctrace_resource_span *resource;
    struct cfl_variant *value;
    struct cfl_variant *parent;
    struct cfl_kvlist *map;
    struct cfl_array *array;
    cfl_sds_t wire;
    size_t index;
    size_t offset;
    int result;

    original = build_sample_trace();
    TEST_ASSERT(original != NULL);
    resource = cfl_list_entry(original->resource_spans.next, struct ctrace_resource_span, _head);
    value = cfl_variant_create_from_string("leaf");
    TEST_ASSERT(value != NULL);
    for (index = 0; index < depth; index++) {
        if (shape == 0 || (shape == 2 && index % 2 == 0)) {
            map = cfl_kvlist_create();
            TEST_ASSERT(map != NULL);
            TEST_ASSERT(cfl_kvlist_insert(map, "k", value) == 0);
            parent = cfl_variant_create_from_kvlist(map);
        }
        else {
            array = cfl_array_create(1);
            TEST_ASSERT(array != NULL);
            TEST_ASSERT(cfl_array_append(array, value) == 0);
            parent = cfl_variant_create_from_array(array);
        }
        TEST_ASSERT(parent != NULL);
        value = parent;
    }
    TEST_ASSERT(cfl_kvlist_insert(resource->resource->attr->kv, "deep", value) == 0);
    wire = ctr_encode_opentelemetry_create(original);
    TEST_ASSERT(wire != NULL);
    ctr_destroy(original);
    decoded = NULL;
    offset = 0;
    result = ctr_decode_opentelemetry_create(&decoded,  wire,
                                               cfl_sds_len(wire), &offset);
    TEST_CHECK((result == 0) == (depth < 32));
    if (decoded != NULL) {
        ctr_destroy(decoded);
    }
    ctr_encode_opentelemetry_destroy(wire);
}

static void test_otlp_depth_boundary(void)
{
    int shape;

    for (shape = 0; shape < 3; shape++) {
        check_otlp_depth(8, shape);
        check_otlp_depth(31, shape);
        check_otlp_depth(32, shape);
        check_otlp_depth(400, shape);
    }
}

TEST_LIST = {
    {"otlp_depth_boundary", test_otlp_depth_boundary},
    {"otlp_roundtrip",                  test_otlp_roundtrip},
    {"otlp_minimal_trace",              test_otlp_minimal_trace},
    {"otlp_empty_context",              test_otlp_empty_context},
    {"otlp_empty_bytes_attribute",      test_otlp_empty_bytes_attribute},
    {"otlp_rejects_invalid_variant",     test_otlp_rejects_invalid_variant},
    {"otlp_rejects_opaque_reference",    test_otlp_rejects_opaque_reference},
    {"otlp_bytes_in_array",             test_otlp_bytes_in_array},
    {"otlp_bytes_attribute",            test_otlp_bytes_attribute},
    {"otlp_multiple_spans",             test_otlp_multiple_spans},
    {"otlp_decode_corrupted",           test_otlp_decode_corrupted},
    {"otlp_decode_missing_resource",    test_otlp_decode_missing_resource},
    {"otlp_decode_truncated",           test_otlp_decode_truncated},
    {"otlp_decode_attribute_null_value", test_otlp_decode_attribute_null_value},
    {"otlp_decode_nested_malformed_kv",  test_otlp_decode_nested_malformed_kv},
    {"otlp_decode_span_empty_name",      test_otlp_decode_span_empty_name},
    {"otlp_decode_invalid_kind",         test_otlp_decode_invalid_kind},
    { 0 }
};
