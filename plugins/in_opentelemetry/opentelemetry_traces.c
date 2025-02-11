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
    int dropped = 0;
    cfl_sds_t name_str = NULL;
    cfl_sds_t version_str = NULL;
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

    if (name_str) {
        cfl_sds_destroy(name_str);
    }
    if (version_str) {
        cfl_sds_destroy(version_str);
    }

    ctr_scope_span_set_instrumentation_scope(scope_span, ins_scope);
    return 0;
}

static int process_events(struct flb_opentelemetry *ctx,
                          struct ctrace *ctr,
                          struct ctrace_span *span,
                          msgpack_object *events)
{
    int i;
    int ret;
    int len;
    uint64_t ts = 0;
    char tmp[64];
    cfl_sds_t name_str = NULL;
    msgpack_object event;
    msgpack_object *name = NULL;
    msgpack_object *attr = NULL;
    struct ctrace_span_event *ctr_event = NULL;
    struct ctrace_attributes *ctr_attr = NULL;

    for (i = 0; i < events->via.array.size; i++) {
        event = events->via.array.ptr[i];
        if (event.type != MSGPACK_OBJECT_MAP) {
            flb_plg_error(ctx->ins, "unexpected event type");
            return -1;
        }

        name_str = NULL;
        ts  = 0;

        /* name */
        ret = find_map_entry_by_key(&event.via.map, "name", 0, FLB_TRUE);
        if (ret >= 0 && event.via.map.ptr[ret].val.type == MSGPACK_OBJECT_STR) {
            name = &event.via.map.ptr[ret].val;
            name_str = cfl_sds_create_len(name->via.str.ptr, name->via.str.size);
            if (name_str == NULL) {
                return -1;
            }
        }

        if (!name_str) {
            flb_plg_warn(ctx->ins, "span event name is missing");
            return -1;
        }

        /* time_unix_nano */
        ret = find_map_entry_by_key(&event.via.map, "timeUnixNano", 0, FLB_TRUE);
        if (ret >= 0 && event.via.map.ptr[ret].val.type == MSGPACK_OBJECT_STR) {
            /* convert to uint64_t */
            len = event.via.map.ptr[ret].val.via.str.size;
            if (len > sizeof(tmp) - 1) {
                len = sizeof(tmp) - 1;
                memcpy(tmp, event.via.map.ptr[ret].val.via.str.ptr, len);
                tmp[len] = '\0';

                flb_plg_error(ctx->ins, "invalid timeUnixNano: '%s'", tmp);
                if (name_str) {
                    cfl_sds_destroy(name_str);
                }
                return -1;
            }

            memcpy(tmp, event.via.map.ptr[ret].val.via.str.ptr, len);
            tmp[len] = '\0';

            ts = strtoull(tmp, NULL, 10);
        }

        ctr_event = ctr_span_event_add_ts(span, name_str, ts);
        cfl_sds_destroy(name_str);
        if (ctr_event == NULL) {
            return -1;
        }

        /* attributes */
        ret = find_map_entry_by_key(&event.via.map, "attributes", 0, FLB_TRUE);
        if (ret >= 0 && event.via.map.ptr[ret].val.type == MSGPACK_OBJECT_ARRAY) {
            attr = &event.via.map.ptr[ret].val;
            ctr_attr = convert_attributes(ctx, attr, "span event");
            if (ctr_attr) {
                ctr_span_event_set_attributes(ctr_event, ctr_attr);
            }
        }

        /* dropped_attributes_count */
        ret = find_map_entry_by_key(&event.via.map, "droppedAttributesCount", 0, FLB_FALSE);
        if (ret >= 0 && event.via.map.ptr[ret].val.type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
            ctr_span_event_set_dropped_attributes_count(ctr_event, event.via.map.ptr[ret].val.via.u64);
        }
    }

    return 0;
}

static int process_links(struct flb_opentelemetry *ctx,
                         struct ctrace *ctr,
                         struct ctrace_span *span,
                         msgpack_object *links)
{
    int i;
    int ret;
    int len;
    char tmp[64];
    char trace_id_bin[16];
    char span_id_bin[8];
    cfl_sds_t buf;
    msgpack_object link;
    msgpack_object *trace_id = NULL;
    msgpack_object *span_id = NULL;
    msgpack_object *trace_state = NULL;
    msgpack_object *dropped_attr_count = NULL;
    msgpack_object *flags = NULL;
    msgpack_object *attr = NULL;

    struct ctrace_link *ctr_link = NULL;
    struct ctrace_attributes *ctr_attr = NULL;

    for (i = 0; i < links->via.array.size; i++) {
        link = links->via.array.ptr[i];
        if (link.type != MSGPACK_OBJECT_MAP) {
            flb_plg_error(ctx->ins, "unexpected link type");
            return -1;
        }

        trace_id = NULL;
        span_id = NULL;
        trace_state = NULL;
        dropped_attr_count = NULL;
        flags = NULL;
        ctr_attr = NULL;

        /* traceId */
        ret = find_map_entry_by_key(&link.via.map, "traceId", 0, FLB_TRUE);
        if (ret >= 0 && link.via.map.ptr[ret].val.type == MSGPACK_OBJECT_STR) {
            trace_id = &link.via.map.ptr[ret].val;

            /* trace_id is an hex of 32 bytes */
            if (trace_id->via.str.size != 32) {
                len = trace_id->via.str.size;
                if (len > sizeof(tmp) - 1) {
                    len = sizeof(tmp) - 1;
                }
                memcpy(tmp, trace_id->via.str.ptr, len);
                tmp[len] = '\0';

                flb_plg_error(ctx->ins, "invalid event traceId: '%s'", tmp);
                return -1;
            }

            /* decode the hex string (16 bytes) */
            hex_to_id((char *) trace_id->via.str.ptr, trace_id->via.str.size,
                      (unsigned char *) trace_id_bin, 16);
        }

        if (!trace_id) {
            flb_plg_error(ctx->ins, "link traceId is missing");
            return -1;
        }

        /* spanId */
        ret = find_map_entry_by_key(&link.via.map, "spanId", 0, FLB_TRUE);
        if (ret >= 0 && link.via.map.ptr[ret].val.type == MSGPACK_OBJECT_STR) {
            span_id = &link.via.map.ptr[ret].val;

            /* span_id is an hex of 16 bytes */
            if (span_id->via.str.size != 16) {
                len = span_id->via.str.size;
                if (len > sizeof(tmp) - 1) {
                    len = sizeof(tmp) - 1;
                }
                memcpy(tmp, span_id->via.str.ptr, len);
                tmp[len] = '\0';
                flb_plg_error(ctx->ins, "invalid spanId: '%s'", tmp);
                return -1;
            }

            /* decode the hex string (8 bytes) */
            memset(tmp, '\0', sizeof(tmp));
            hex_to_id((char *) span_id->via.str.ptr, span_id->via.str.size,
                      (unsigned char *) span_id_bin, 8);
        }

        if (!span_id) {
            flb_plg_error(ctx->ins, "link spanId is missing");
            return -1;
        }

        /* traceState */
        ret = find_map_entry_by_key(&link.via.map, "traceState", 0, FLB_FALSE);
        if (ret >= 0 && link.via.map.ptr[ret].val.type == MSGPACK_OBJECT_STR) {
            trace_state = &link.via.map.ptr[ret].val;
        }

        /* attributes */
        ret = find_map_entry_by_key(&link.via.map, "attributes", 0, FLB_FALSE);
        if (ret >= 0 && link.via.map.ptr[ret].val.type == MSGPACK_OBJECT_ARRAY) {
            attr = &link.via.map.ptr[ret].val;
            ctr_attr = convert_attributes(ctx, attr, "event link");
        }

        /* droped_attributes_count */
        ret = find_map_entry_by_key(&link.via.map, "droppedAttributesCount", 0, FLB_FALSE);
        if (ret >= 0 && link.via.map.ptr[ret].val.type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
            dropped_attr_count = &link.via.map.ptr[ret].val;
        }

        /* flags */
        ret = find_map_entry_by_key(&link.via.map, "flags", 0, FLB_FALSE);
        if (ret >= 0 && link.via.map.ptr[ret].val.type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
            flags = &link.via.map.ptr[ret].val;
        }

        ctr_link = ctr_link_create(span,
                                        trace_id_bin, 16,
                                        span_id_bin, 8);

        if (ctr_link == NULL) {
            if (ctr_attr) {
                ctr_attributes_destroy(ctr_attr);
            }
            return -1;
        }

        if (trace_state) {
            buf = cfl_sds_create_len(trace_state->via.str.ptr, trace_state->via.str.size);
            if (buf) {
                ctr_link_set_trace_state(ctr_link, buf);
                cfl_sds_destroy(buf);
            }
        }

        if (ctr_attr) {
            ctr_link_set_attributes(ctr_link, ctr_attr);
        }

        if (dropped_attr_count) {
            ctr_link_set_dropped_attr_count(ctr_link, dropped_attr_count->via.u64);
        }

        if (flags) {
            ctr_link_set_flags(ctr_link, flags->via.u64);
        }
    }

    return 0;
}

static int process_span_status(struct flb_opentelemetry *ctx,
                               struct ctrace *ctr,
                               struct ctrace_span *span,
                               msgpack_object *status)
{
    int ret;
    int code = 0;
    char *message = NULL;

    if (status->type != MSGPACK_OBJECT_MAP) {
        flb_plg_error(ctx->ins, "unexpected status type");
        return -1;
    }

    /* code */
    ret = find_map_entry_by_key(&status->via.map, "code", 0, FLB_TRUE);
    if (ret >= 0 && status->via.map.ptr[ret].val.type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
        code = status->via.map.ptr[ret].val.via.u64;
    }
    else {
        flb_plg_error(ctx->ins, "status code is missing");
        return -1;
    }

    /* message */
    ret = find_map_entry_by_key(&status->via.map, "message", 0, FLB_FALSE);
    if (ret >= 0 && status->via.map.ptr[ret].val.type == MSGPACK_OBJECT_STR) {
        message = flb_sds_create_len(status->via.map.ptr[ret].val.via.str.ptr,
                                     status->via.map.ptr[ret].val.via.str.size);
    }

    ctr_span_set_status(span, code, message);
    if (message) {
        flb_sds_destroy(message);
    }

    return 0;
}

static int process_spans(struct flb_opentelemetry *ctx,
                         struct ctrace *ctr,
                         struct ctrace_scope_span *scope_span,
                         msgpack_object *spans)
{
    int i;
    int ret;
    int len;
    uint64_t val;
    char tmp[64];
    cfl_sds_t val_str = NULL;
    msgpack_object span;
    msgpack_object *name = NULL;
    msgpack_object *attr = NULL;
    struct ctrace_span *ctr_span = NULL;
    struct ctrace_attributes *ctr_attr = NULL;

    for (i = 0; i < spans->via.array.size; i++) {
        span = spans->via.array.ptr[i];
        if (span.type != MSGPACK_OBJECT_MAP) {
            flb_plg_error(ctx->ins, "unexpected span type");
            return -1;
        }

        val_str = NULL;

        /* name */
        ret = find_map_entry_by_key(&span.via.map, "name", 0, FLB_TRUE);
        if (ret >= 0 && span.via.map.ptr[ret].val.type == MSGPACK_OBJECT_STR) {
            name = &span.via.map.ptr[ret].val;
            val_str = cfl_sds_create_len(name->via.str.ptr, name->via.str.size);
        }

        if (!val_str) {
            flb_plg_error(ctx->ins, "span name is missing");
            return -1;
        }

        /* create the span */
        ctr_span = ctr_span_create(ctr, scope_span, val_str, NULL);
        cfl_sds_destroy(val_str);

        if (ctr_span == NULL) {
            return -1;
        }

        /* traceId */
        ret = find_map_entry_by_key(&span.via.map, "traceId", 0, FLB_TRUE);
        if (ret >= 0 && span.via.map.ptr[ret].val.type == MSGPACK_OBJECT_STR) {
            /* trace_id is an hex of 32 bytes */
            if (span.via.map.ptr[ret].val.via.str.size != 32) {
                len = span.via.map.ptr[ret].val.via.str.size;
                if (len > sizeof(tmp) - 1) {
                    len = sizeof(tmp) - 1;
                }
                memcpy(tmp, span.via.map.ptr[ret].val.via.str.ptr, len);
                tmp[len] = '\0';

                flb_plg_error(ctx->ins, "invalid traceId: '%s'", tmp);
                return -1;
            }

            /* decode the hex string (16 bytes) */
            memset(tmp, '\0', sizeof(tmp));
            hex_to_id((char *) span.via.map.ptr[ret].val.via.str.ptr,
                      span.via.map.ptr[ret].val.via.str.size,
                      (unsigned char *) tmp, 16);
            ctr_span_set_trace_id(ctr_span, tmp, 16);
        }

        /* spanId */
        ret = find_map_entry_by_key(&span.via.map, "spanId", 0, FLB_TRUE);
        if (ret >= 0 && span.via.map.ptr[ret].val.type == MSGPACK_OBJECT_STR) {
            /* span_id is an hex of 16 bytes */
            if (span.via.map.ptr[ret].val.via.str.size != 16) {
                len = span.via.map.ptr[ret].val.via.str.size;
                if (len > sizeof(tmp) - 1) {
                    len = sizeof(tmp) - 1;
                }
                memcpy(tmp, span.via.map.ptr[ret].val.via.str.ptr, len);
                tmp[len] = '\0';
                flb_plg_error(ctx->ins, "invalid spanId: '%s'", tmp);
                return -1;
            }

            /* decode the hex string (8 bytes) */
            memset(tmp, '\0', sizeof(tmp));
            hex_to_id((char *) span.via.map.ptr[ret].val.via.str.ptr,
                      span.via.map.ptr[ret].val.via.str.size,
                      (unsigned char *) tmp, 8);
            ctr_span_set_span_id(ctr_span, tmp, 8);
        }

        /* traceState */
        ret = find_map_entry_by_key(&span.via.map, "traceState", 0, FLB_TRUE);
        if (ret >= 0 && span.via.map.ptr[ret].val.type == MSGPACK_OBJECT_STR) {
            val_str = cfl_sds_create_len(span.via.map.ptr[ret].val.via.str.ptr,
                                         span.via.map.ptr[ret].val.via.str.size);
            ctr_span->trace_state = val_str;
            val_str = NULL;
        }

        /* flags */
        ret = find_map_entry_by_key(&span.via.map, "flags", 0, FLB_TRUE);
        if (ret >= 0 && span.via.map.ptr[ret].val.type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
            /* unsupported in CTraces */
        }

        /* parentSpanId */
        ret = find_map_entry_by_key(&span.via.map, "parentSpanId", 0, FLB_TRUE);
        if (ret >= 0 &&
            span.via.map.ptr[ret].val.type == MSGPACK_OBJECT_STR &&
            span.via.map.ptr[ret].val.via.str.size > 0) {

            /* parent_span_id is an hex of 16 bytes */
            if (span.via.map.ptr[ret].val.via.str.size != 16) {
                len = span.via.map.ptr[ret].val.via.str.size;
                if (len > sizeof(tmp) - 1) {
                    len = sizeof(tmp) - 1;
                }
                memcpy(tmp, span.via.map.ptr[ret].val.via.str.ptr, len);
                tmp[len] = '\0';
                flb_plg_error(ctx->ins, "invalid parentSpanId: '%s'", tmp);
                return -1;
            }

            /* decode the hex string (8 bytes) */
            memset(tmp, '\0', sizeof(tmp));
            hex_to_id((char *) span.via.map.ptr[ret].val.via.str.ptr,
                      span.via.map.ptr[ret].val.via.str.size,
                      (unsigned char *) tmp, 8);
            ctr_span_set_parent_span_id(ctr_span, tmp, 8);
        }

        /* flags */
        ret = find_map_entry_by_key(&span.via.map, "flags", 0, FLB_TRUE);
        if (ret >= 0 && span.via.map.ptr[ret].val.type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
            ctr_span_set_flags(ctr_span, span.via.map.ptr[ret].val.via.u64);
        }

        /* start_time_unix_nano */
        ret = find_map_entry_by_key(&span.via.map, "startTimeUnixNano", 0, FLB_TRUE);
        if (ret >= 0 && span.via.map.ptr[ret].val.type == MSGPACK_OBJECT_STR) {
            /* convert string number to integer */
            val = convert_string_number_to_u64((char *) span.via.map.ptr[ret].val.via.str.ptr,
                                               span.via.map.ptr[ret].val.via.str.size);
            ctr_span_start_ts(ctr, ctr_span, val);
        }

        /* end_time_unix_nano */
        ret = find_map_entry_by_key(&span.via.map, "endTimeUnixNano", 0, FLB_TRUE);
        if (ret >= 0 && span.via.map.ptr[ret].val.type == MSGPACK_OBJECT_STR) {
            /* convert string number to integer */
            val = convert_string_number_to_u64((char *) span.via.map.ptr[ret].val.via.str.ptr,
                                               span.via.map.ptr[ret].val.via.str.size);
            ctr_span_end_ts(ctr, ctr_span, val);
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
            if (ctr_attr) {
                ctr_span_set_attributes(ctr_span, ctr_attr);
            }
        }

        /* dropped_attributes_count */
        ret = find_map_entry_by_key(&span.via.map, "droppedAttributesCount", 0, FLB_TRUE);
        if (ret >= 0 && span.via.map.ptr[ret].val.type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
            ctr_span_set_dropped_attributes_count(ctr_span, span.via.map.ptr[ret].val.via.u64);
        }

        /* events */
        ret = find_map_entry_by_key(&span.via.map, "events", 0, FLB_TRUE);
        if (ret >= 0 && span.via.map.ptr[ret].val.type == MSGPACK_OBJECT_ARRAY) {
            ret = process_events(ctx, ctr, ctr_span, &span.via.map.ptr[ret].val);
        }

        /* dropped_events_count */
        ret = find_map_entry_by_key(&span.via.map, "droppedEventsCount", 0, FLB_TRUE);
        if (ret >= 0 && span.via.map.ptr[ret].val.type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
            ctr_span_set_dropped_events_count(ctr_span, span.via.map.ptr[ret].val.via.u64);
        }

        /* dropped_links_count */
        ret = find_map_entry_by_key(&span.via.map, "droppedLinksCount", 0, FLB_TRUE);
        if (ret >= 0 && span.via.map.ptr[ret].val.type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
            ctr_span_set_dropped_links_count(ctr_span, span.via.map.ptr[ret].val.via.u64);
        }

        /* links */
        ret = find_map_entry_by_key(&span.via.map, "links", 0, FLB_TRUE);
        if (ret >= 0 && span.via.map.ptr[ret].val.type == MSGPACK_OBJECT_ARRAY) {
            ret = process_links(ctx, ctr, ctr_span, &span.via.map.ptr[ret].val);
        }

        /* schema_url */
        ret = find_map_entry_by_key(&span.via.map, "schemaUrl", 0, FLB_TRUE);
        if (ret >= 0 && span.via.map.ptr[ret].val.type == MSGPACK_OBJECT_STR) {
            val_str = cfl_sds_create_len(span.via.map.ptr[ret].val.via.str.ptr,
                                         span.via.map.ptr[ret].val.via.str.size);
            ctr_span_set_schema_url(ctr_span, val_str);
            cfl_sds_destroy(val_str);
            val_str = NULL;
        }

        /* status */
        ret = find_map_entry_by_key(&span.via.map, "status", 0, FLB_TRUE);
        if (ret >= 0 && span.via.map.ptr[ret].val.type == MSGPACK_OBJECT_MAP) {
            process_span_status(ctx, ctr, ctr_span, &span.via.map.ptr[ret].val);
        }
    }

    return 0;
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
    msgpack_object *schema_url;
    msgpack_object *dropped_attr;
    msgpack_object *spans;
    cfl_sds_t url = NULL;
    struct ctrace_scope_span *scope_span;

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
        ret = find_map_entry_by_key(&scope.via.map, "droppedAttributesCount", 0, FLB_TRUE);
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

    /* schema_url */
    ret = find_map_entry_by_key(&scope_spans->via.map, "schemaUrl", 0, FLB_TRUE);
    if (ret >= 0) {
        schema_url = &scope_spans->via.map.ptr[ret].val;
        if (schema_url->type == MSGPACK_OBJECT_STR) {
            /* set schema url */
            url = cfl_sds_create_len(schema_url->via.str.ptr, schema_url->via.str.size);
            if (url) {
                ctr_scope_span_set_schema_url(scope_span, url);
                cfl_sds_destroy(url);
            }
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
                                 struct ctrace *ctr,
                                 msgpack_object *resource_spans)
{
    int i;
    int ret;
    cfl_sds_t url;
    struct ctrace_resource *ctr_resource;
    struct ctrace_resource_span *resource_span;
    msgpack_object resource;
    msgpack_object attr;
    msgpack_object scope_spans;
    msgpack_object schema_url;

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


    resource_span = ctr_resource_span_create(ctr);
    if (resource_span == NULL) {
        return -1;
    }

    ctr_resource = ctr_resource_span_get_resource(resource_span);

    /* droppedAttributesCount */
    ret = find_map_entry_by_key(&resource.via.map, "droppedAttributesCount", 0, FLB_FALSE);
    if (ret >= 0 && resource.via.map.ptr[ret].val.type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
        ctr_resource_set_dropped_attr_count(ctr_resource, resource.via.map.ptr[ret].val.via.u64);
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

    /* scopeSpans */
    ret = find_map_entry_by_key(&resource_spans->via.map, "scopeSpans", 0, FLB_TRUE);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "scopeSpans missing");
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

    /* schema_url */
    ret = find_map_entry_by_key(&resource.via.map, "schemaUrl", 0, FLB_TRUE);
    if (ret >= 0) {
        schema_url = resource.via.map.ptr[ret].val;
        if (schema_url.type == MSGPACK_OBJECT_STR) {
            url = cfl_sds_create_len(schema_url.via.str.ptr, schema_url.via.str.size);
            if (url) {
                ctr_resource_span_set_schema_url(resource_span, url);
                cfl_sds_destroy(url);
            }
        }
    }

    return 0;
}

static struct ctrace *process_root_msgpack(struct flb_opentelemetry *ctx, msgpack_object *obj)
{
    int i;
    int ret;
    struct ctrace *ctr;
    msgpack_object_array *resource_spans;

    if (obj->type != MSGPACK_OBJECT_MAP) {
        return NULL;
    }

    ret = find_map_entry_by_key(&obj->via.map, "resourceSpans", 0, FLB_TRUE);
    if (ret == -1) {
        ret = find_map_entry_by_key(&obj->via.map, "resource_spans", 0, FLB_TRUE);
        if (ret == -1) {
            flb_plg_error(ctx->ins, "resourceSpans missing");
            return NULL;
        }
    }

    if (obj->via.map.ptr[ret].val.type != MSGPACK_OBJECT_ARRAY) {
        flb_plg_error(ctx->ins, "unexpected resourceSpans type");
        return NULL;
    }

    resource_spans = &obj->via.map.ptr[ret].val.via.array;
    ret = 0;

    ctr = ctr_create(NULL);
    if (!ctr) {
        return NULL;
    }

    for (i = 0; i < resource_spans->size; i++) {
        ret = process_resource_span(ctx, ctr,  &resource_spans->ptr[i]);
        if (ret == -1) {
            flb_plg_warn(ctx->ins, "failed to process resource span");

            ctr_destroy(ctr);
            return NULL;
        }
    }

    return ctr;
}

static int process_json(struct flb_opentelemetry *ctx,
                        char *tag, size_t tag_len,
                        const char *body, size_t len)
{
    int              result = -1;
    int              root_type;
    char            *msgpack_body;
    size_t           msgpack_body_length;
    size_t           offset = 0;
    msgpack_unpacked unpacked_root;
    struct ctrace   *ctr;

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
    ctr = process_root_msgpack(ctx, &unpacked_root.data);
    if (ctr) {
        result = flb_input_trace_append(ctx->ins, tag, tag_len, ctr);
        ctr_destroy(ctr);
    }

    msgpack_unpacked_destroy(&unpacked_root);
    flb_free(msgpack_body);

    return result;
}

static int opentelemetry_traces_process_json(struct flb_opentelemetry *ctx,
                                             flb_sds_t tag, size_t tag_len,
                                             char *data, size_t size)
{
    int ret;

    ret = process_json(ctx, tag, tag_len, data, size);

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
    uint64_t payload_size;

    buf = (char *) data;

    payload = buf;
    payload_size = size;

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

            if (buf[0] == 1) {
                flb_plg_error(ctx->ins, "gRPC compression is not supported");
                return -1;
            }
            /* payload size */
            payload_size = ((uint64_t) (uint8_t) buf[1] << 24) |
                           ((uint64_t) (uint8_t) buf[2] << 16) |
                           ((uint64_t) (uint8_t) buf[3] << 8)  |
                           ((uint64_t) (uint8_t) buf[4]);

            if (size < payload_size + 5) {
                flb_plg_error(ctx->ins, "Invalid gRPC payload size: received=%zu expected=%zu",
                              size, payload_size + 5);
                return -1;
            }

            /*
             * FIXME: implement compression support for the gRPC message, leaving on
             * hold for now.
             */

            /* skip the gRPC header bytes */
            payload = buf + 5;

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
                                                    payload, payload_size);
    }
    else {
        if (ctx->raw_traces) {
            ret = opentelemetry_traces_process_raw_traces(ctx,
                                                          tag, tag_len,
                                                          payload, payload_size);
        }
        else {
            /* The content is likely OTel JSON */
            ret = opentelemetry_traces_process_json(ctx,
                                                    tag, tag_len,
                                                    payload, payload_size);
        }
    }

    return ret;
}
