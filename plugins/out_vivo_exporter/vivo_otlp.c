/* Fluent Bit - Copyright (C) 2015-2026 The Fluent Bit Authors
 * SPDX-License-Identifier: Apache-2.0
 */
#include <inttypes.h>
#include <limits.h>
#include <math.h>
#include <ctype.h>
#include <fluent-bit/flb_base64.h>
#include <fluent-bit/flb_log_event_decoder.h>
#include <cmetrics/cmt_decode_msgpack.h>
#include <cmetrics/cmt_encode_opentelemetry.h>
#include <ctraces/ctr_decode_msgpack.h>
#include <ctraces/ctr_encode_opentelemetry.h>
#include <opentelemetry/proto/collector/trace/v1/trace_service.pb-c.h>
#include "vivo_otlp.h"

/* Keep the OTLP type information until the final JSON write. */
struct json_writer {
    flb_sds_t data;
    int error;
};

static void write_bytes(struct json_writer *writer, const char *data, size_t size)
{
    flb_sds_t grown;
    size_t growth;

    if (writer->error) {
        return;
    }
    if (size > INT_MAX || flb_sds_len(writer->data) > INT_MAX - size) {
        writer->error = FLB_TRUE;
        return;
    }
    if (flb_sds_avail(writer->data) < size) {
        growth = flb_sds_alloc(writer->data);
        if (growth < size) {
            growth = size;
        }
        grown = flb_sds_increase(writer->data, growth);
        if (!grown) {
            writer->error = FLB_TRUE;
            return;
        }
        writer->data = grown;
    }
    if (flb_sds_cat_safe(&writer->data, data, size) < 0) {
        writer->error = FLB_TRUE;
    }
}

static void write_text(struct json_writer *writer, const char *text)
{
    write_bytes(writer, text, strlen(text));
}

static void write_string(struct json_writer *writer, const char *text, size_t size)
{
    size_t index;
    size_t start = 0;
    unsigned char byte;
    char escape[7];

    write_text(writer, "\"");
    for (index = 0; index < size; index++) {
        byte = text[index];
        if (byte < 0x20 || byte == '"' || byte == '\\') {
            write_bytes(writer, text + start, index - start);
            if (byte < 0x20) {
                snprintf(escape, sizeof(escape), "\\u%04x", byte);
                write_text(writer, escape);
            }
            else {
                write_text(writer, "\\");
                write_bytes(writer, text + index, 1);
            }
            start = index + 1;
        }
    }
    if (start < size) {
        write_bytes(writer, text + start, size - start);
    }
    write_text(writer, "\"");
}

static void write_uint64(struct json_writer *writer, uint64_t value, int quoted)
{
    char number[32];

    snprintf(number, sizeof(number), "%" PRIu64, value);
    if (quoted) {
        write_string(writer, number, strlen(number));
    }
    else {
        write_text(writer, number);
    }
}

static void write_int64(struct json_writer *writer, int64_t value, int quoted)
{
    char number[32];

    snprintf(number, sizeof(number), "%" PRId64, value);
    if (quoted) {
        write_string(writer, number, strlen(number));
    }
    else {
        write_text(writer, number);
    }
}

static void write_double(struct json_writer *writer, double value)
{
    char number[32];

    if (isnan(value)) {
        write_text(writer, "\"NaN\"");
    }
    else if (isinf(value)) {
        write_text(writer, value < 0 ? "\"-Infinity\"" : "\"Infinity\"");
    }
    else if (value == 0.0 && signbit(value)) {
        write_text(writer, "-0.0");
    }
    else {
        snprintf(number, sizeof(number), "%.17g", value);
        write_text(writer, number);
    }
}

static void write_binary(struct json_writer *writer, const unsigned char *data, size_t size, int hex)
{
    unsigned char *encoded;
    size_t length;
    size_t index;
    char pair[3];

    if (hex) {
        write_text(writer, "\"");
        for (index = 0; index < size; index++) {
            snprintf(pair, sizeof(pair), "%02x", data[index]);
            write_text(writer, pair);
        }
        write_text(writer, "\"");
        return;
    }
    length = ((size + 2) / 3) * 4 + 1;
    encoded = flb_malloc(length);
    if (!encoded) {
        writer->error = FLB_TRUE;
        return;
    }
    if (flb_base64_encode(encoded, length, &length, data, size) != 0) {
        writer->error = FLB_TRUE;
    }
    else {
        write_string(writer, (char *) encoded, length);
    }
    flb_free(encoded);
}

static void write_field_name(struct json_writer *writer, const char *name)
{
    int uppercase = FLB_FALSE;
    char character;

    write_text(writer, "\"");
    while (*name) {
        if (*name == '_') {
            uppercase = FLB_TRUE;
        }
        else {
            character = uppercase ? toupper((unsigned char) *name) : *name;
            write_bytes(writer, &character, 1);
            uppercase = FLB_FALSE;
        }
        name++;
    }
    write_text(writer, "\":");
}

static size_t field_size(ProtobufCType type)
{
    switch (type) {
    case PROTOBUF_C_TYPE_INT64:
    case PROTOBUF_C_TYPE_SINT64:
    case PROTOBUF_C_TYPE_SFIXED64:
    case PROTOBUF_C_TYPE_UINT64:
    case PROTOBUF_C_TYPE_FIXED64:
    case PROTOBUF_C_TYPE_DOUBLE:
        return 8;
    case PROTOBUF_C_TYPE_STRING:
    case PROTOBUF_C_TYPE_MESSAGE:
        return sizeof(void *);
    case PROTOBUF_C_TYPE_BYTES:
        return sizeof(ProtobufCBinaryData);
    default:
        return 4;
    }
}

/* Omit proto3 defaults, but retain explicitly selected oneof/optional values. */
static int field_is_default(const ProtobufCFieldDescriptor *field, const void *value)
{
    switch (field->type) {
    case PROTOBUF_C_TYPE_STRING:
        return *(const char * const *) value == NULL || **(const char * const *) value == '\0';
    case PROTOBUF_C_TYPE_MESSAGE:
        return *(const void * const *) value == NULL;
    case PROTOBUF_C_TYPE_BYTES:
        return ((const ProtobufCBinaryData *) value)->len == 0;
    case PROTOBUF_C_TYPE_FLOAT:
        return *(const float *) value == 0.0f;
    case PROTOBUF_C_TYPE_DOUBLE:
        return *(const double *) value == 0.0;
    case PROTOBUF_C_TYPE_INT64:
    case PROTOBUF_C_TYPE_SINT64:
    case PROTOBUF_C_TYPE_SFIXED64:
    case PROTOBUF_C_TYPE_UINT64:
    case PROTOBUF_C_TYPE_FIXED64:
        return *(const uint64_t *) value == 0;
    default:
        return *(const uint32_t *) value == 0;
    }
}

static void write_message(struct json_writer *writer, const ProtobufCMessage *message, int depth);

static void write_field(struct json_writer *writer, const ProtobufCFieldDescriptor *field,
                        const void *value, int depth)
{
    const ProtobufCBinaryData *binary;
    const char *string;
    int hex;

    switch (field->type) {
    case PROTOBUF_C_TYPE_INT32:
    case PROTOBUF_C_TYPE_SINT32:
    case PROTOBUF_C_TYPE_SFIXED32:
    case PROTOBUF_C_TYPE_ENUM:
        write_int64(writer, *(const int32_t *) value, FLB_FALSE);
        break;
    case PROTOBUF_C_TYPE_UINT32:
    case PROTOBUF_C_TYPE_FIXED32:
        write_uint64(writer, *(const uint32_t *) value, FLB_FALSE);
        break;
    case PROTOBUF_C_TYPE_INT64:
    case PROTOBUF_C_TYPE_SINT64:
    case PROTOBUF_C_TYPE_SFIXED64:
        write_int64(writer, *(const int64_t *) value, FLB_TRUE);
        break;
    case PROTOBUF_C_TYPE_UINT64:
    case PROTOBUF_C_TYPE_FIXED64:
        write_uint64(writer, *(const uint64_t *) value, FLB_TRUE);
        break;
    case PROTOBUF_C_TYPE_BOOL:
        write_text(writer, *(const protobuf_c_boolean *) value ? "true" : "false");
        break;
    case PROTOBUF_C_TYPE_FLOAT:
        write_double(writer, *(const float *) value);
        break;
    case PROTOBUF_C_TYPE_DOUBLE:
        write_double(writer, *(const double *) value);
        break;
    case PROTOBUF_C_TYPE_STRING:
        string = *(const char * const *) value;
        write_string(writer, string, strlen(string));
        break;
    case PROTOBUF_C_TYPE_BYTES:
        binary = value;
        hex = strcmp(field->name, "trace_id") == 0 || strcmp(field->name, "span_id") == 0 ||
              strcmp(field->name, "parent_span_id") == 0;
        write_binary(writer, binary->data, binary->len, hex);
        break;
    case PROTOBUF_C_TYPE_MESSAGE:
        write_message(writer, *(const ProtobufCMessage * const *) value, depth + 1);
        break;
    }
}

/* Reflection over our compiled OTLP descriptors avoids a second hand-maintained
 * metrics/trace schema. Only OTLP messages (no protobuf well-known types) enter here. */
static void write_message(struct json_writer *writer, const ProtobufCMessage *message, int depth)
{
    const ProtobufCFieldDescriptor *field;
    const unsigned char *base;
    const unsigned char *value;
    const unsigned char *items;
    size_t count;
    size_t index;
    unsigned int field_index;
    int first = FLB_TRUE;

    if (!message || depth > 64) {
        writer->error = FLB_TRUE;
        return;
    }
    base = (const unsigned char *) message;
    write_text(writer, "{");
    for (field_index = 0; field_index < message->descriptor->n_fields; field_index++) {
        field = &message->descriptor->fields[field_index];
        value = base + field->offset;
        count = 1;
        if (field->label == PROTOBUF_C_LABEL_REPEATED) {
            count = *(const size_t *) (base + field->quantifier_offset);
            if (count == 0) {
                continue;
            }
        }
        else if (field->flags & PROTOBUF_C_FIELD_FLAG_ONEOF) {
            if (*(const uint32_t *) (base + field->quantifier_offset) != field->id) {
                continue;
            }
        }
        else if (field->quantifier_offset != 0 &&
                 !*(const protobuf_c_boolean *) (base + field->quantifier_offset)) {
            continue;
        }
        else if ((field->type == PROTOBUF_C_TYPE_MESSAGE || field->type == PROTOBUF_C_TYPE_STRING) &&
                 *(const void * const *) value == NULL) {
            continue;
        }
        if (field->label != PROTOBUF_C_LABEL_REPEATED &&
            !(field->flags & PROTOBUF_C_FIELD_FLAG_ONEOF) &&
            field->quantifier_offset == 0 && field_is_default(field, value)) {
            continue;
        }
        if (!first) {
            write_text(writer, ",");
        }
        first = FLB_FALSE;
        write_field_name(writer, field->name);
        if (field->label == PROTOBUF_C_LABEL_REPEATED) {
            items = *(const unsigned char * const *) value;
            write_text(writer, "[");
            for (index = 0; index < count; index++) {
                if (index) {
                    write_text(writer, ",");
                }
                write_field(writer, field, items + index * field_size(field->type), depth);
            }
            write_text(writer, "]");
        }
        else {
            write_field(writer, field, value, depth);
        }
    }
    write_text(writer, "}");
}

static msgpack_object *map_get(msgpack_object *map, const char *key)
{
    size_t index;
    msgpack_object_kv *pair;

    if (!map || map->type != MSGPACK_OBJECT_MAP) {
        return NULL;
    }
    for (index = 0; index < map->via.map.size; index++) {
        pair = &map->via.map.ptr[index];
        if (pair->key.type == MSGPACK_OBJECT_STR && pair->key.via.str.size == strlen(key) &&
            memcmp(pair->key.via.str.ptr, key, strlen(key)) == 0) {
            return &pair->val;
        }
    }
    return NULL;
}

static void write_any(struct json_writer *writer, msgpack_object *value, int depth);

static void write_attributes(struct json_writer *writer, msgpack_object *map, int depth)
{
    size_t index;
    msgpack_object_kv *pair;

    write_text(writer, "[");
    if (map && map->type == MSGPACK_OBJECT_MAP) {
        for (index = 0; index < map->via.map.size; index++) {
            pair = &map->via.map.ptr[index];
            if (pair->key.type != MSGPACK_OBJECT_STR) {
                writer->error = FLB_TRUE;
                break;
            }
            if (index) {
                write_text(writer, ",");
            }
            write_text(writer, "{\"key\":");
            write_string(writer, pair->key.via.str.ptr, pair->key.via.str.size);
            write_text(writer, ",\"value\":");
            write_any(writer, &pair->val, depth + 1);
            write_text(writer, "}");
        }
    }
    write_text(writer, "]");
}

static void write_any(struct json_writer *writer, msgpack_object *value, int depth)
{
    size_t index;

    if (depth > 64) {
        writer->error = FLB_TRUE;
        return;
    }
    write_text(writer, "{");
    if (value) {
        switch (value->type) {
        case MSGPACK_OBJECT_NIL:
            break;
        case MSGPACK_OBJECT_BOOLEAN:
            write_text(writer, value->via.boolean ? "\"boolValue\":true" : "\"boolValue\":false");
            break;
        case MSGPACK_OBJECT_POSITIVE_INTEGER:
            if (value->via.u64 > INT64_MAX) {
                /* OTLP AnyValue has no uint64 arm. Preserve the exact digits in a
                 * documented typed kvlist instead of wrapping a signed integer. */
                write_text(writer, "\"kvlistValue\":{\"values\":[{\"key\":\"fluentbit.type\","
                                   "\"value\":{\"stringValue\":\"uint64\"}},"
                                   "{\"key\":\"fluentbit.value\",\"value\":{\"stringValue\":");
                write_uint64(writer, value->via.u64, FLB_TRUE);
                write_text(writer, "}}]}");
            }
            else {
                write_text(writer, "\"intValue\":");
                write_uint64(writer, value->via.u64, FLB_TRUE);
            }
            break;
        case MSGPACK_OBJECT_NEGATIVE_INTEGER:
            write_text(writer, "\"intValue\":");
            write_int64(writer, value->via.i64, FLB_TRUE);
            break;
        case MSGPACK_OBJECT_FLOAT32:
        case MSGPACK_OBJECT_FLOAT64:
            write_text(writer, "\"doubleValue\":");
            write_double(writer, value->via.f64);
            break;
        case MSGPACK_OBJECT_STR:
            write_text(writer, "\"stringValue\":");
            write_string(writer, value->via.str.ptr, value->via.str.size);
            break;
        case MSGPACK_OBJECT_BIN:
            write_text(writer, "\"bytesValue\":");
            write_binary(writer, (const unsigned char *) value->via.bin.ptr, value->via.bin.size, FLB_FALSE);
            break;
        case MSGPACK_OBJECT_ARRAY:
            write_text(writer, "\"arrayValue\":{\"values\":[");
            for (index = 0; index < value->via.array.size; index++) {
                if (index) {
                    write_text(writer, ",");
                }
                write_any(writer, &value->via.array.ptr[index], depth + 1);
            }
            write_text(writer, "]}");
            break;
        case MSGPACK_OBJECT_MAP:
            write_text(writer, "\"kvlistValue\":{\"values\":");
            write_attributes(writer, value, depth + 1);
            write_text(writer, "}");
            break;
        default:
            writer->error = FLB_TRUE;
        }
    }
    write_text(writer, "}");
}

static void write_string_property(struct json_writer *writer, msgpack_object *map,
                                   const char *key, const char *name)
{
    msgpack_object *value;

    value = map_get(map, key);
    if (value && value->type == MSGPACK_OBJECT_STR) {
        write_text(writer, ",");
        write_field_name(writer, name);
        write_string(writer, value->via.str.ptr, value->via.str.size);
    }
}

static void write_number_property(struct json_writer *writer, msgpack_object *map,
                                   const char *key, const char *name, int quoted)
{
    msgpack_object *value;

    value = map_get(map, key);
    if (value && value->type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
        write_text(writer, ",");
        write_field_name(writer, name);
        write_uint64(writer, value->via.u64, quoted);
    }
}

static void write_log_id(struct json_writer *writer, msgpack_object *metadata, const char *key)
{
    msgpack_object *value;

    value = map_get(metadata, key);
    if (value && value->type == MSGPACK_OBJECT_BIN) {
        write_text(writer, ",");
        write_field_name(writer, key);
        write_binary(writer, (const unsigned char *) value->via.bin.ptr, value->via.bin.size, FLB_TRUE);
    }
    else {
        write_string_property(writer, metadata, key, key);
    }
}

static void write_log(struct json_writer *writer, struct flb_log_event *event, const char *body_key)
{
    msgpack_object *resource;
    msgpack_object *scope;
    msgpack_object *metadata;
    msgpack_object *body;
    msgpack_object *wrapped;

    resource = map_get(event->group_attributes, "resource");
    scope = map_get(event->group_attributes, "scope");
    metadata = map_get(event->metadata, "otlp");
    body = event->body;
    wrapped = map_get(body, body_key);
    if (metadata && wrapped && body->via.map.size == 1) {
        body = wrapped;
    }

    /* One resource/scope envelope per record is valid OTLP and avoids grouping
     * records by transient decoder pointers or discarding repeated identities. */
    write_text(writer, "{\"resource\":{\"attributes\":");
    write_attributes(writer, map_get(resource, "attributes"), 0);
    write_number_property(writer, resource, "dropped_attributes_count", "dropped_attributes_count", FLB_FALSE);
    write_text(writer, "}");
    write_string_property(writer, resource, "schema_url", "schema_url");
    write_text(writer, ",\"scopeLogs\":[{\"scope\":{\"attributes\":");
    write_attributes(writer, map_get(scope, "attributes"), 0);
    write_string_property(writer, scope, "name", "name");
    write_string_property(writer, scope, "version", "version");
    write_number_property(writer, scope, "dropped_attributes_count", "dropped_attributes_count", FLB_FALSE);
    write_text(writer, "}");
    write_string_property(writer, scope, "schema_url", "schema_url");
    write_text(writer, ",\"logRecords\":[{\"timeUnixNano\":");
    write_uint64(writer, flb_time_to_nanosec(&event->timestamp), FLB_TRUE);
    write_number_property(writer, metadata, "observed_timestamp", "observed_time_unix_nano", FLB_TRUE);
    write_number_property(writer, metadata, "severity_number", "severity_number", FLB_FALSE);
    write_number_property(writer, metadata, "trace_flags", "flags", FLB_FALSE);
    write_number_property(writer, metadata, "dropped_attributes_count", "dropped_attributes_count", FLB_FALSE);
    write_string_property(writer, metadata, "severity_text", "severity_text");
    write_string_property(writer, metadata, "event_name", "event_name");
    write_log_id(writer, metadata, "trace_id");
    write_log_id(writer, metadata, "span_id");
    write_text(writer, ",\"attributes\":");
    write_attributes(writer, metadata ? map_get(metadata, "attributes") : event->metadata, 0);
    write_text(writer, ",\"body\":");
    write_any(writer, body, 0);
    write_text(writer, "}]}]}");
}

static void write_metrics_resources(struct json_writer *writer, struct cmt *metrics, int *first)
{
    cfl_sds_t encoded;
    Opentelemetry__Proto__Metrics__V1__MetricsData *message;
    size_t index;

    encoded = cmt_encode_opentelemetry_create(metrics);
    if (!encoded) {
        writer->error = FLB_TRUE;
        return;
    }
    message = opentelemetry__proto__metrics__v1__metrics_data__unpack(NULL, cfl_sds_len(encoded),
                                                                   (unsigned char *) encoded);
    if (!message) {
        writer->error = FLB_TRUE;
    }
    else {
        for (index = 0; index < message->n_resource_metrics; index++) {
            if (!*first) {
                write_text(writer, ",");
            }
            *first = FLB_FALSE;
            write_message(writer, &message->resource_metrics[index]->base, 0);
        }
        opentelemetry__proto__metrics__v1__metrics_data__free_unpacked(message, NULL);
    }
    cmt_encode_opentelemetry_destroy(encoded);
}

static void write_trace_resources(struct json_writer *writer, struct ctrace *traces, int *first)
{
    cfl_sds_t encoded;
    Opentelemetry__Proto__Collector__Trace__V1__ExportTraceServiceRequest *message;
    size_t index;

    encoded = ctr_encode_opentelemetry_create(traces);
    if (!encoded) {
        writer->error = FLB_TRUE;
        return;
    }
    message = opentelemetry__proto__collector__trace__v1__export_trace_service_request__unpack(
        NULL, cfl_sds_len(encoded), (unsigned char *) encoded);
    if (!message) {
        writer->error = FLB_TRUE;
    }
    else {
        for (index = 0; index < message->n_resource_spans; index++) {
            if (!*first) {
                write_text(writer, ",");
            }
            *first = FLB_FALSE;
            write_message(writer, &message->resource_spans[index]->base, 0);
        }
        opentelemetry__proto__collector__trace__v1__export_trace_service_request__free_unpacked(message, NULL);
    }
    ctr_encode_opentelemetry_destroy(encoded);
}

static flb_sds_t finish_json(struct json_writer *writer)
{
    if (writer->error) {
        flb_sds_destroy(writer->data);
        return NULL;
    }
    return writer->data;
}

flb_sds_t vivo_otlp_metrics(struct cmt *metrics)
{
    struct json_writer writer;
    int first = FLB_TRUE;

    writer.data = flb_sds_create_size(1024);
    writer.error = writer.data == NULL;
    write_text(&writer, "{\"resourceMetrics\":[");
    write_metrics_resources(&writer, metrics, &first);
    write_text(&writer, "]}");
    return finish_json(&writer);
}

flb_sds_t vivo_otlp_chunk(struct flb_input_instance *source, struct flb_event_chunk *chunk)
{
    struct json_writer writer;
    struct flb_log_event_decoder decoder;
    struct flb_log_event event;
    struct cmt *metrics;
    struct ctrace *traces;
    size_t offset = 0;
    size_t previous;
    int first = FLB_TRUE;
    const char *body_key;
    const char *name;

    writer.data = flb_sds_create_size(1024);
    writer.error = writer.data == NULL;
    write_text(&writer, "{\"source\":{\"type\":");
    write_string(&writer, source->p->name, strlen(source->p->name));
    write_text(&writer, ",\"name\":");
    name = flb_input_name(source);
    write_string(&writer, name, strlen(name));
    write_text(&writer, ",\"tag\":");
    write_string(&writer, chunk->tag, flb_sds_len(chunk->tag));
    write_text(&writer, "},\"payload\":{");
    if (chunk->type == FLB_EVENT_TYPE_LOGS) {
        write_text(&writer, "\"resourceLogs\":[");
        body_key = flb_input_get_property("logs_body_key", source);
        if (!body_key) {
            body_key = "log";
        }
        if (flb_log_event_decoder_init(&decoder, (char *) chunk->data, chunk->size) !=
            FLB_EVENT_DECODER_SUCCESS) {
            writer.error = FLB_TRUE;
        }
        else {
            while (flb_log_event_decoder_next(&decoder, &event) == FLB_EVENT_DECODER_SUCCESS) {
                if (!first) {
                    write_text(&writer, ",");
                }
                first = FLB_FALSE;
                write_log(&writer, &event, body_key);
            }
            if (flb_log_event_decoder_get_last_result(&decoder) != FLB_EVENT_DECODER_SUCCESS) {
                writer.error = FLB_TRUE;
            }
            flb_log_event_decoder_destroy(&decoder);
        }
    }
    else {
        write_text(&writer, chunk->type == FLB_EVENT_TYPE_METRICS ? "\"resourceMetrics\":[" :
                                                                    "\"resourceSpans\":[");
        while (offset < chunk->size && !writer.error) {
            previous = offset;
            if (chunk->type == FLB_EVENT_TYPE_METRICS) {
                if (cmt_decode_msgpack_create(&metrics, (char *) chunk->data, chunk->size, &offset) != 0) {
                    writer.error = FLB_TRUE;
                    break;
                }
                write_metrics_resources(&writer, metrics, &first);
                cmt_decode_msgpack_destroy(metrics);
            }
            else {
                if (ctr_decode_msgpack_create(&traces, (char *) chunk->data, chunk->size, &offset) != 0) {
                    writer.error = FLB_TRUE;
                    break;
                }
                write_trace_resources(&writer, traces, &first);
                ctr_decode_msgpack_destroy(traces);
            }
            if (offset <= previous) {
                writer.error = FLB_TRUE;
            }
        }
    }
    write_text(&writer, "]}}");
    return finish_json(&writer);
}
