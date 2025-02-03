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

#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_pack.h>

#include <ctraces/ctraces.h>
#include <ctraces/ctr_encode_text.h>

#include "opentelemetry.h"
#include "opentelemetry_traces.h"
#include "opentelemetry_utils.h"

int opentelemetry_traces_process_protobuf(struct flb_opentelemetry *ctx,
                                          flb_sds_t tag,
                                          size_t tag_len,
                                          void *data, size_t size)
{
    struct ctrace *decoded_context;
    size_t         offset;
    int            result;

    offset = 0;
    result = ctr_decode_opentelemetry_create(&decoded_context,
                                             data, size,
                                             &offset);
    if (result == 0) {
        result = flb_input_trace_append(ctx->ins, tag, tag_len, decoded_context);
        ctr_decode_opentelemetry_destroy(decoded_context);
    }

    return result;
}

static int process_attribute(struct ctrace_attributes *attr,
                             msgpack_object *key, msgpack_object *value, int type)
{
    int ret;
    char *key_str;
    char *value_str;
    int64_t value_int;
    double value_double;
    int value_bool;

    if (key->type != MSGPACK_OBJECT_STR) {
        return -1;
    }

    /* temporary buffer for key since it needs to be NULL terminated */
    key_str = flb_sds_create_len(key->via.str.ptr, key->via.str.size);
    if (key_str == NULL) {
        return -1;
    }

    /*
     * the value of 'type' is set by the JSON wrapped value, we need to to convert it
     * since msgpack_object *value is always a string
     */
    switch (type) {
    case MSGPACK_OBJECT_STR:
        if (value->type != MSGPACK_OBJECT_STR) {
            flb_sds_destroy(key_str);
            return -1;
        }

        value_str = flb_sds_create_len(value->via.str.ptr, value->via.str.size);
        if (value_str == NULL) {
            flb_sds_destroy(key_str);
            return -1;
        }

        ret = ctr_attributes_set_string(attr, key_str, value_str);
        flb_sds_destroy(value_str);
        break;
    case MSGPACK_OBJECT_POSITIVE_INTEGER:
    case MSGPACK_OBJECT_NEGATIVE_INTEGER:
        if (value->type != MSGPACK_OBJECT_POSITIVE_INTEGER &&
            value->type != MSGPACK_OBJECT_NEGATIVE_INTEGER) {
            flb_sds_destroy(key_str);
            return -1;
        }

        value_int = value->via.i64;
        ret = ctr_attributes_set_int64(attr, key_str, value_int);
        break;
    case MSGPACK_OBJECT_FLOAT32:
    case MSGPACK_OBJECT_FLOAT64:
        if (value->type != MSGPACK_OBJECT_FLOAT32 &&
            value->type != MSGPACK_OBJECT_FLOAT64) {
            flb_sds_destroy(key_str);
            return -1;
        }

        value_double = value->via.f64;
        ret = ctr_attributes_set_double(attr, key_str, value_double);
        break;
    case MSGPACK_OBJECT_BOOLEAN:
        if (value->type != MSGPACK_OBJECT_BOOLEAN) {
            flb_sds_destroy(key_str);
            return -1;
        }

        value_bool = value->via.boolean;
        ret = ctr_attributes_set_bool(attr, key_str, value_bool);
        break;
    case MSGPACK_OBJECT_ARRAY:
        /*
         * The less fun part (OTel JSON encoding), the value can be an array and
         * only allows values such as string, bool, int64, double. I am glad this
         * don't support nested arrays or maps.
         */
        ret = 0;
        break;
    default:
        flb_sds_destroy(key_str);
        return -1;
    }

    flb_sds_destroy(key_str);
    return ret;
}

static int process_resource_unwrap_attribute(msgpack_object *attr,
                                             msgpack_object *out_key,
                                             msgpack_object *out_value, int *out_value_type)
{
    int ret;
    int type;
    msgpack_object key;
    msgpack_object val;
    msgpack_object *real_value;

    if (attr->type != MSGPACK_OBJECT_MAP) {
        return -1;
    }

    ret = find_map_entry_by_key(&attr->via.map, "key", 0, FLB_TRUE);
    if (ret == -1) {
        return -1;
    }

    key = attr->via.map.ptr[ret].val;
    if (key.type != MSGPACK_OBJECT_STR) {
        return -1;
    }

    ret = find_map_entry_by_key(&attr->via.map, "value", 0, FLB_TRUE);
    if (ret == -1) {
        return -1;
    }

    val = attr->via.map.ptr[ret].val;

    ret = json_payload_get_wrapped_value(&val, &real_value, &type);
    if (ret != 0) {
        return -1;
    }

    *out_key = key;
    *out_value = *real_value;
    *out_value_type = type;

    return 0;
}

/*
 * Convert a list of attributes in msgpack format to a cfl attributes by
 * unwrapping JSON encoded value types.
 */
static struct ctrace_attributes *convert_attributes(struct flb_opentelemetry *ctx,
                                                    msgpack_object *attributes,
                                                    char *log_context)
{
    int i;
    int ret;
    int value_type;
    msgpack_object key;
    msgpack_object value;
    struct ctrace_attributes *attr;

    attr = ctr_attributes_create();
    if (attr == NULL) {
        return NULL;
    }

    for (i = 0; i < attributes->via.array.size; i++) {
        ret = process_resource_unwrap_attribute(&attributes->via.array.ptr[i],
                                                &key, &value, &value_type);
        if (ret == -1) {
            flb_plg_warn(ctx->ins, "found invalid %s attribute, skipping",
                         log_context);
            continue;
        }

        /* set attribute */
        ret = process_attribute(attr, &key, &value, value_type);
        if (ret == -1) {
            flb_plg_warn(ctx->ins, "failed to set %s attribute, skipping",
                         log_context);
            continue;
        }
    }

    return attr;
}

static int process_resource_attributes(struct flb_opentelemetry *ctx,
                                       struct ctrace *ctr,
                                       struct ctrace_resource_span *resource_span,
                                       msgpack_object *attributes)

{
    struct ctrace_resource *resource;
    struct ctrace_attributes *attr;

    attr = convert_attributes(ctx, attributes, "trace resource");
    if (!attr) {
        return -1;
    }

    resource = ctr_resource_span_get_resource(resource_span);
    ctr_resource_set_attributes(resource, attr);

    return 0;
}

static int process_scope_attributes(struct flb_opentelemetry *ctx,
                                    struct ctrace *ctr,
                                    struct ctrace_scope_span *scope_span,
                                    msgpack_object *name,
                                    msgpack_object *version,
                                    msgpack_object *attributes,
                                    msgpack_object *dropped_attributes_count)

{
    int i;
    int ret;
    int value_type;
    int dropped = 0;
    msgpack_object key;
    msgpack_object value;
    cfl_sds_t name_str = NULL;
    cfl_sds_t version_str = NULL;
    struct ctrace_resource *resource;
    struct ctrace_attributes *attr = NULL;
    struct ctrace_instrumentation_scope *ins_scope;

    if (attributes) {
        attr = convert_attributes(ctx, attributes, "trace scope");
        if (!attr) {
            return -1;
        }
    }

    if (name) {
        name_str = cfl_sds_create_len(name->via.str.ptr, name->via.str.size);
    }
    if (version) {
        version_str = cfl_sds_create_len(version->via.str.ptr, version->via.str.size);
    }

    if (dropped_attributes_count) {
        dropped = dropped_attributes_count->via.u64;
    }

    ins_scope = ctr_instrumentation_scope_create(name_str, version_str, dropped, attr);
    if (!ins_scope) {
        if (name_str) {
            cfl_sds_destroy(name_str);
        }
        if (version_str) {
            cfl_sds_destroy(version_str);
        }
        if (attr) {
            ctr_attributes_destroy(attr);
        }
        return -1;
    }

    ctr_scope_span_set_instrumentation_scope(scope_span, ins_scope);
    return 0;
}

static int process_spans(struct flb_opentelemetry *ctx,
                         struct ctrace *ctr,
                         struct ctrace_scope_span *scope_span,
                         msgpack_object *spans)
{
    int i;
    int ret;
    cfl_sds_t name_str = NULL;
    msgpack_object span;
    msgpack_object *name = NULL;
    msgpack_object *attr = NULL;
    msgpack_object *status = NULL;
    msgpack_object *start_time = NULL;
    msgpack_object *end_time = NULL;
    struct ctrace_span *ctr_span = NULL;
    struct ctrace_attributes *ctr_attr = NULL;

    for (i = 0; i < spans->via.array.size; i++) {
        span = spans->via.array.ptr[i];
        if (span.type != MSGPACK_OBJECT_MAP) {
            flb_plg_error(ctx->ins, "unexpected span type");
            return -1;
        }

        /* name */
        ret = find_map_entry_by_key(&span.via.map, "name", 0, FLB_TRUE);
        if (ret >= 0 && span.via.map.ptr[ret].val.type == MSGPACK_OBJECT_STR) {
            name = &span.via.map.ptr[ret].val;
            name_str = cfl_sds_create_len(name->via.str.ptr, name->via.str.size);
        }

        /* create the span */
        ctr_span = ctr_span_create(ctr, scope_span, name_str, NULL);
        if (ctr_span == NULL) {
            return -1;
        }

        /* traceId */
        ret = find_map_entry_by_key(&span.via.map, "traceId", 0, FLB_TRUE);
        if (ret >= 0 && span.via.map.ptr[ret].val.type == MSGPACK_OBJECT_STR) {
            ctr_span_set_trace_id(ctr_span,
                                  span.via.map.ptr[ret].val.via.str.ptr,
                                  span.via.map.ptr[ret].val.via.str.size);
        }

        /* spanId */
        ret = find_map_entry_by_key(&span.via.map, "spanId", 0, FLB_TRUE);
        if (ret >= 0 && span.via.map.ptr[ret].val.type == MSGPACK_OBJECT_STR) {
            ctr_span_set_span_id(ctr_span,
                                 span.via.map.ptr[ret].val.via.str.ptr,
                                 span.via.map.ptr[ret].val.via.str.size);
        }

        /* parentSpanId */
        ret = find_map_entry_by_key(&span.via.map, "parentSpanId", 0, FLB_TRUE);
        if (ret >= 0 && span.via.map.ptr[ret].val.type == MSGPACK_OBJECT_STR) {
            ctr_span_set_parent_span_id(ctr_span,
                                        span.via.map.ptr[ret].val.via.str.ptr,
                                        span.via.map.ptr[ret].val.via.str.size);
        }

        /* start_time_unix_nano */
        ret = find_map_entry_by_key(&span.via.map, "startTimeUnixNano", 0, FLB_TRUE);
        if (ret >= 0 && span.via.map.ptr[ret].val.type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
            start_time = &span.via.map.ptr[ret].val;
            ctr_span_start_ts(ctr, ctr_span, start_time->via.u64);
        }

        /* end_time_unix_nano */
        ret = find_map_entry_by_key(&span.via.map, "endTimeUnixNano", 0, FLB_TRUE);
        if (ret >= 0 && span.via.map.ptr[ret].val.type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
            end_time = &span.via.map.ptr[ret].val;
            ctr_span_end_ts(ctr, ctr_span, end_time->via.u64);
        }

        /* kind */
        ret = find_map_entry_by_key(&span.via.map, "kind", 0, FLB_TRUE);
        if (ret >= 0 && span.via.map.ptr[ret].val.type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
            ctr_span_kind_set(ctr_span, span.via.map.ptr[ret].val.via.u64);
        }

        /* attributes */
        ret = find_map_entry_by_key(&span.via.map, "attributes", 0, FLB_TRUE);
        if (ret >= 0 && span.via.map.ptr[ret].val.type == MSGPACK_OBJECT_ARRAY) {
            attr = &span.via.map.ptr[ret].val;

            ctr_attr = convert_attributes(ctx, attr, "span");
            ctr_span->attr = ctr_attr;
        }
    }

}


static int process_scope_span(struct flb_opentelemetry *ctx,
                              struct ctrace *ctr,
                              struct ctrace_resource_span *resource_span,
                              msgpack_object *scope_spans)
{
    int ret;
    msgpack_object scope;
    msgpack_object *name;
    msgpack_object *attr;
    msgpack_object *version;
    msgpack_object *dropped_attr;
    msgpack_object *spans;
    struct ctrace_scope_span *scope_span;
    struct ctrace_attributes *ctr_attr;

    /* get 'scope' */
    ret = find_map_entry_by_key(&scope_spans->via.map, "scope", 0, FLB_TRUE);
    if (ret >= 0) {
        scope = scope_spans->via.map.ptr[ret].val;
        if (scope.type != MSGPACK_OBJECT_MAP) {
            flb_plg_error(ctx->ins, "unexpected scope type in scope span");
            return -1;
        }

        /* create the scope_span */
        scope_span = ctr_scope_span_create(resource_span);
        if (scope_span == NULL) {
            return -1;
        }

        /* instrumentation scope: name */
        name = NULL;
        ret = find_map_entry_by_key(&scope.via.map, "name", 0, FLB_TRUE);
        if (ret >= 0 && scope.via.map.ptr[ret].val.type == MSGPACK_OBJECT_STR) {
            name = &scope.via.map.ptr[ret].val;
        }

        /* instrumentation scope: version */
        version = NULL;
        ret = find_map_entry_by_key(&scope.via.map, "version", 0, FLB_TRUE);
        if (ret >= 0 && scope.via.map.ptr[ret].val.type == MSGPACK_OBJECT_STR) {
            version = &scope.via.map.ptr[ret].val;
        }

        /* instrumentation scope: attributes */
        attr = NULL;
        ret = find_map_entry_by_key(&scope.via.map, "attributes", 0, FLB_TRUE);
        if (ret >= 0 && scope.via.map.ptr[ret].val.type == MSGPACK_OBJECT_ARRAY) {
            attr = &scope.via.map.ptr[ret].val;
        }

        /* instrumentation scope: dropped_attributes_count */
        dropped_attr = NULL;
        ret = find_map_entry_by_key(&scope.via.map, "dropped_attributes_count", 0, FLB_TRUE);
        if (ret >= 0 && scope.via.map.ptr[ret].val.type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
            dropped_attr = &scope.via.map.ptr[ret].val;
        }

        ret = process_scope_attributes(ctx,
                                       ctr,
                                       scope_span,
                                       name, version, attr, dropped_attr);
        if (ret == -1) {
            flb_plg_warn(ctx->ins, "failed to process scope attributes");
        }
    }

    /* process the scope spans[] */
    ret = find_map_entry_by_key(&scope_spans->via.map, "spans", 0, FLB_TRUE);
    if (ret >= 0 && scope_spans->via.map.ptr[ret].val.type == MSGPACK_OBJECT_ARRAY) {
        spans = &scope_spans->via.map.ptr[ret].val;
        ret = process_spans(ctx, ctr, scope_span, spans);
        if (ret == -1) {
            flb_plg_warn(ctx->ins, "failed to process spans");
        }
    }

    return 0;
}

static int process_resource_span(struct flb_opentelemetry *ctx,
                                 msgpack_object *resource_spans)
{
    int i;
    int ret;
    cfl_sds_t url;
    struct ctrace *ctr;
    struct ctrace_resource_span *resource_span;
    msgpack_object resource;
    msgpack_object attr;
    msgpack_object scope_spans;
    msgpack_object schema_url;

    struct ctrace_attributes *ctr_attr;

    if (resource_spans->type != MSGPACK_OBJECT_MAP) {
        return -1;
    }

    /* get the resource */
    ret = find_map_entry_by_key(&resource_spans->via.map, "resource", 0, FLB_TRUE);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "resource missing");
        return -1;
    }

    resource = resource_spans->via.map.ptr[ret].val;
    if (resource.type != MSGPACK_OBJECT_MAP) {
        flb_plg_error(ctx->ins, "unexpected resource type in resource span");
        return -1;
    }

    /* Ctraces context */
    ctr = ctr_create(NULL);
    if (ctr == NULL) {
        return -1;
    }

    resource_span = ctr_resource_span_create(ctr);
    if (resource_span == NULL) {
        ctr_destroy(ctr);
        return -1;
    }

    /* Get resource attributes */
    ret = find_map_entry_by_key(&resource.via.map, "attributes", 0, FLB_TRUE);
    if (ret >= 0) {
        attr = resource.via.map.ptr[ret].val;
        if (attr.type == MSGPACK_OBJECT_ARRAY) {
            /* iterate and register attributes */
            ret = process_resource_attributes(ctx,
                                              ctr,
                                              resource_span,
                                              &attr);
            if (ret == -1) {
                flb_plg_warn(ctx->ins, "failed to process resource attributes");
            }
        }
    }

    /* schema_url */
    ret = find_map_entry_by_key(&resource.via.map, "schema_url", 0, FLB_TRUE);
    if (ret >= 0) {
        schema_url = resource.via.map.ptr[ret].val;
        if (schema_url.type == MSGPACK_OBJECT_STR) {
            url = cfl_sds_create_len(schema_url.via.str.ptr, schema_url.via.str.size);
            if (url) {
                ctr_resource_span_set_schema_url(resource_span, url);
            }
        }
    }

    /* scopeSpans */
    ret = find_map_entry_by_key(&resource_spans->via.map, "scopeSpans", 0, FLB_TRUE);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "scopeSpans missing");
        ctr_destroy(ctr);
        return -1;
    }
    scope_spans = resource_spans->via.map.ptr[ret].val;

    if (scope_spans.type != MSGPACK_OBJECT_ARRAY) {
        flb_plg_error(ctx->ins, "unexpected scopeSpans type");
        ctr_destroy(ctr);
        return -1;
    }

    for (i = 0; i < scope_spans.via.array.size; i++) {
        ret = process_scope_span(ctx,
                                 ctr,
                                 resource_span,
                                 &scope_spans.via.array.ptr[i]);
        if (ret == -1) {
            flb_plg_warn(ctx->ins, "failed to process scope span");
        }
    }

    cfl_sds_t t = ctr_encode_text_create(ctr);
    printf("%s\n", t);
    ctr_destroy(ctr);

    printf("------\n\n");
    msgpack_object_print(stdout, resource);

    return 0;
}

static int process_root_msgpack(struct flb_opentelemetry *ctx, msgpack_object *obj)
{
    int i;
    int ret;
    msgpack_object_array *resource_spans;

    if (obj->type != MSGPACK_OBJECT_MAP) {
        return -1;
    }

    ret = find_map_entry_by_key(&obj->via.map, "resourceSpans", 0, FLB_TRUE);
    if (ret == -1) {
        ret = find_map_entry_by_key(&obj->via.map, "resource_spans", 0, FLB_TRUE);
        if (ret == -1) {
            flb_plg_error(ctx->ins, "resourceSpans missing");
            return -1;
        }
    }

    if (obj->via.map.ptr[ret].val.type != MSGPACK_OBJECT_ARRAY) {
        flb_plg_error(ctx->ins, "unexpected resourceSpans type");
        return -1;
    }

    resource_spans = &obj->via.map.ptr[ret].val.via.array;
    ret = 0;

    for (i = 0; i < resource_spans->size; i++) {
        ret = process_resource_span(ctx, &resource_spans->ptr[i]);
    }

    return 0;
}

static int process_json(struct flb_opentelemetry *ctx,
                        const char *body,
                        size_t len)
{
    int              result = -1;
    int              root_type;
    char            *msgpack_body;
    size_t           msgpack_body_length;
    size_t           offset = 0;
    msgpack_unpacked unpacked_root;

    result = flb_pack_json(body, len, &msgpack_body, &msgpack_body_length,
                           &root_type, NULL);

    if (result != 0) {
        flb_plg_error(ctx->ins, "invalid JSON: msgpack conversion error");
        return -1;
    }

    msgpack_unpacked_init(&unpacked_root);

    result = msgpack_unpack_next(&unpacked_root,
                                 msgpack_body,
                                 msgpack_body_length,
                                 &offset);

    if (result != MSGPACK_UNPACK_SUCCESS) {
        return -1;
    }

    /* iterate msgpack and comppose a CTraces context */
    result = process_root_msgpack(ctx, &unpacked_root.data);

    msgpack_unpacked_destroy(&unpacked_root);
    flb_free(msgpack_body);

    return result;
}

static int opentelemetry_traces_process_json(struct flb_opentelemetry *ctx,
                                             flb_sds_t tag, size_t tag_len,
                                             char *data, size_t size)
{
    int ret;

    ret = process_json(ctx, data, size);

    return ret;
}

/*
 * This interface was the first approach to take traces in JSON and ingest them as logs,
 * we are not sure if it is still in use, but we are keeping it for now
 */
int opentelemetry_traces_process_raw_traces(struct flb_opentelemetry *ctx,
                                            flb_sds_t tag,
                                            size_t tag_len,
                                            void *data, size_t size)
{
    int ret;
    int root_type;
    char *out_buf = NULL;
    size_t out_size;

    msgpack_packer mp_pck;
    msgpack_sbuffer mp_sbuf;

    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    msgpack_pack_array(&mp_pck, 2);
    flb_pack_time_now(&mp_pck);

    /* Check if the incoming payload is a valid  message and convert it to msgpack */
    ret = flb_pack_json(data, size,
                        &out_buf, &out_size, &root_type, NULL);

    if (ret == 0 && root_type == JSMN_OBJECT) {
        /* JSON found, pack it msgpack representation */
        msgpack_sbuffer_write(&mp_sbuf, out_buf, out_size);
    }
    else {
        /* the content might be a binary payload or invalid JSON */
        msgpack_pack_map(&mp_pck, 1);
        msgpack_pack_str_with_body(&mp_pck, "trace", 5);
        msgpack_pack_str_with_body(&mp_pck, data, size);
    }

    /* release 'out_buf' if it was allocated */
    if (out_buf) {
        flb_free(out_buf);
    }

    flb_input_log_append(ctx->ins, tag, tag_len, mp_sbuf.data, mp_sbuf.size);
    msgpack_sbuffer_destroy(&mp_sbuf);

    return 0;
}

int opentelemetry_process_traces(struct flb_opentelemetry *ctx,
                                 flb_sds_t content_type,
                                 flb_sds_t tag,
                                 size_t tag_len,
                                 void *data, size_t size)
{
    int ret = -1;
    int is_proto = FLB_FALSE; /* default to JSON */
    char *buf;
    char *payload;
    size_t payload_size;

    buf = (char *) data;

    /* Detect the type of payload */
    if (content_type) {
        if (strcasecmp(content_type, "application/json") == 0) {
            if (buf[0] != '{') {
                flb_plg_error(ctx->ins, "Invalid JSON payload");
                return -1;
            }

            is_proto = FLB_FALSE;
        }
        else if (strcasecmp(content_type, "application/protobuf") == 0 ||
                 strcasecmp(content_type, "application/x-protobuf") == 0) {
            is_proto = FLB_TRUE;
        }
        else if (strcasecmp(content_type, "application/grpc") == 0) {
            if (size < 5) {
                return -1;
            }

            /* magic bytes: 0x00 or 0x01 */
            if (buf[0] != 0 && buf[0] != 1) {
                flb_plg_error(ctx->ins, "Invalid gRPC magic byte");
                return -1;
            }

            /* payload size */
            payload_size = (buf[1] << 24) | (buf[2] << 16) | (buf[3] << 8) | buf[4];
            if (size < payload_size + 5) {
                flb_plg_error(ctx->ins, "Invalid gRPC payload size");
                return -1;
            }

            /*
             * FIXME: implement compression support for the gRPC message, leaving on
             * hold for now.
             */

            /* skip the gRPC header bytes */
            payload = buf + 5;
            payload_size = size - 5;

            is_proto = FLB_TRUE;
        }
        else {
            flb_plg_error(ctx->ins, "Unsupported content type %s", content_type);
            return -1;
        }
    }

    if (is_proto == FLB_TRUE) {
        ret = opentelemetry_traces_process_protobuf(ctx,
                                                    tag, tag_len,
                                                    data, size);
    }
    else {
        if (ctx->raw_traces) {
            ret = opentelemetry_traces_process_raw_traces(ctx,
                                                          tag, tag_len,
                                                          data, size);
        }
        else {
            /* The content is likely OTel JSON */
            ret = opentelemetry_traces_process_json(ctx,
                                                    tag, tag_len,
                                                    data, size);
        }
    }

    return ret;
}
