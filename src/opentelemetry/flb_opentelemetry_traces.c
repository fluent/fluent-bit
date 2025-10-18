/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2025 The Fluent Bit Authors
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
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_opentelemetry.h>

#include <ctraces/ctraces.h>

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
        if (value->type == MSGPACK_OBJECT_STR) {
            value_str = flb_sds_create_len(value->via.str.ptr, value->via.str.size);
            if (value_str == NULL) {
                flb_sds_destroy(key_str);
                return -1;
            }
            value_int = strtoll(value_str, NULL, 10);
            flb_sds_destroy(value_str);
        }
        else if (value->type == MSGPACK_OBJECT_POSITIVE_INTEGER ||
                 value->type == MSGPACK_OBJECT_NEGATIVE_INTEGER) {
            value_int = value->via.i64;
        }
        else {
            flb_sds_destroy(key_str);
            return -1;
        }

        ret = ctr_attributes_set_int64(attr, key_str, value_int);
        break;
    case MSGPACK_OBJECT_FLOAT32:
    case MSGPACK_OBJECT_FLOAT64:
        if (value->type == MSGPACK_OBJECT_STR) {
            value_str = flb_sds_create_len(value->via.str.ptr, value->via.str.size);
            if (value_str == NULL) {
                flb_sds_destroy(key_str);
                return -1;
            }
            value_double = strtod(value_str, NULL);
            flb_sds_destroy(value_str);
        }
        else if (value->type == MSGPACK_OBJECT_FLOAT32 ||
                 value->type == MSGPACK_OBJECT_FLOAT64) {
            value_double = value->via.f64;
        }
        else {
            flb_sds_destroy(key_str);
            return -1;
        }

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

    ret = flb_otel_utils_find_map_entry_by_key(&attr->via.map, "key", 0, FLB_TRUE);
    if (ret == -1) {
        return -1;
    }

    key = attr->via.map.ptr[ret].val;
    if (key.type != MSGPACK_OBJECT_STR) {
        return -1;
    }

    ret = flb_otel_utils_find_map_entry_by_key(&attr->via.map, "value", 0, FLB_TRUE);
    if (ret == -1) {
        return -1;
    }

    val = attr->via.map.ptr[ret].val;

    ret = flb_otel_utils_json_payload_get_wrapped_value(&val, &real_value, &type);
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
static struct ctrace_attributes *convert_attributes(msgpack_object *attributes,
                                                    const char *log_context)
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
            flb_warn("found invalid %s attribute, skipping", log_context);
            continue;
        }

        /* set attribute */
        ret = process_attribute(attr, &key, &value, value_type);
        if (ret == -1) {
            flb_warn("failed to set %s attribute, skipping", log_context);
            continue;
        }
    }

    return attr;
}

static int process_resource_attributes(struct ctrace *ctr,
                                       struct ctrace_resource_span *resource_span,
                                       msgpack_object *attributes,
                                       int *error_status)
{
    struct ctrace_resource *resource;
    struct ctrace_attributes *attr;

    attr = convert_attributes(attributes, "trace resource");
    if (!attr) {
        if (error_status) {
            *error_status = FLB_OTEL_TRACES_ERR_INVALID_ATTRIBUTES;
        }
        return -1;
    }

    resource = ctr_resource_span_get_resource(resource_span);
    ctr_resource_set_attributes(resource, attr);

    return 0;
}

static int process_scope_attributes(struct ctrace *ctr,
                                    struct ctrace_scope_span *scope_span,
                                    msgpack_object *name,
                                    msgpack_object *version,
                                    msgpack_object *attributes,
                                    msgpack_object *dropped_attributes_count,
                                    int *error_status)
{
    int dropped = 0;
    cfl_sds_t name_str = NULL;
    cfl_sds_t version_str = NULL;
    struct ctrace_attributes *attr = NULL;
    struct ctrace_instrumentation_scope *ins_scope;

    if (attributes) {
        attr = convert_attributes(attributes, "trace scope");
        if (!attr) {
            if (error_status) {
                *error_status = FLB_OTEL_TRACES_ERR_INVALID_ATTRIBUTES;
            }
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
        if (error_status) {
            *error_status = FLB_OTEL_TRACES_ERR_GENERIC_ERROR;
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

static int process_events(struct ctrace *ctr,
                          struct ctrace_span *span,
                          msgpack_object *events,
                          int *error_status)
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
            if (error_status) {
                *error_status = FLB_OTEL_TRACES_ERR_INVALID_EVENT_ENTRY;
            }
            return -1;
        }

        name_str = NULL;
        ts  = 0;

        /* name */
        ret = flb_otel_utils_find_map_entry_by_key(&event.via.map, "name", 0, FLB_TRUE);
        if (ret >= 0 && event.via.map.ptr[ret].val.type == MSGPACK_OBJECT_STR) {
            name = &event.via.map.ptr[ret].val;
            name_str = cfl_sds_create_len(name->via.str.ptr, name->via.str.size);
            if (name_str == NULL) {
                if (error_status) {
                    *error_status = FLB_OTEL_TRACES_ERR_INVALID_EVENT_ENTRY;
                }
                return -1;
            }
        }

        if (!name_str) {
            if (error_status) {
                *error_status = FLB_OTEL_TRACES_ERR_INVALID_EVENT_ENTRY;
            }
            return -1;
        }

        /* time_unix_nano */
        ret = flb_otel_utils_find_map_entry_by_key(&event.via.map, "timeUnixNano", 0, FLB_TRUE);
        if (ret >= 0 && event.via.map.ptr[ret].val.type == MSGPACK_OBJECT_STR) {
            /* convert to uint64_t */
            len = event.via.map.ptr[ret].val.via.str.size;
            if (len > sizeof(tmp) - 1) {
                len = sizeof(tmp) - 1;
                memcpy(tmp, event.via.map.ptr[ret].val.via.str.ptr, len);
                tmp[len] = '\0';

                if (name_str) {
                    cfl_sds_destroy(name_str);
                }
                if (error_status) {
                    *error_status = FLB_OTEL_TRACES_ERR_INVALID_EVENT_TIMESTAMP;
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
            if (error_status) {
                *error_status = FLB_OTEL_TRACES_ERR_INVALID_EVENT_ENTRY;
            }
            return -1;
        }

        /* attributes */
        ret = flb_otel_utils_find_map_entry_by_key(&event.via.map, "attributes", 0, FLB_TRUE);
        if (ret >= 0 && event.via.map.ptr[ret].val.type == MSGPACK_OBJECT_ARRAY) {
            attr = &event.via.map.ptr[ret].val;
            ctr_attr = convert_attributes(attr, "span event");
            if (ctr_attr) {
                ctr_span_event_set_attributes(ctr_event, ctr_attr);
            }
        }

        /* dropped_attributes_count */
        ret = flb_otel_utils_find_map_entry_by_key(&event.via.map, "droppedAttributesCount", 0, FLB_FALSE);
        if (ret >= 0 && event.via.map.ptr[ret].val.type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
            ctr_span_event_set_dropped_attributes_count(ctr_event, event.via.map.ptr[ret].val.via.u64);
        }
    }

    return 0;
}

static int process_links(struct ctrace *ctr,
                         struct ctrace_span *span,
                         msgpack_object *links,
                         int *error_status)
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
            if (error_status) {
                *error_status = FLB_OTEL_TRACES_ERR_INVALID_LINK_ENTRY;
            }
            return -1;
        }

        trace_id = NULL;
        span_id = NULL;
        trace_state = NULL;
        dropped_attr_count = NULL;
        flags = NULL;
        ctr_attr = NULL;

        /* traceId */
        ret = flb_otel_utils_find_map_entry_by_key(&link.via.map, "traceId", 0, FLB_TRUE);
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

                if (error_status) {
                    *error_status = FLB_OTEL_TRACES_ERR_INVALID_LINK_TRACE_ID;
                }
                return -1;
            }

            /* decode the hex string (16 bytes) */
            flb_otel_utils_hex_to_id((char *) trace_id->via.str.ptr, trace_id->via.str.size,
                                     (unsigned char *) trace_id_bin, 16);
        }

        if (!trace_id) {
            if (error_status) {
                *error_status = FLB_OTEL_TRACES_ERR_INVALID_LINK_TRACE_ID;
            }
            return -1;
        }

        /* spanId */
        ret = flb_otel_utils_find_map_entry_by_key(&link.via.map, "spanId", 0, FLB_TRUE);
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
                if (error_status) {
                    *error_status = FLB_OTEL_TRACES_ERR_INVALID_LINK_SPAN_ID;
                }
                return -1;
            }

            /* decode the hex string (8 bytes) */
            memset(tmp, '\0', sizeof(tmp));
            flb_otel_utils_hex_to_id((char *) span_id->via.str.ptr, span_id->via.str.size,
                                     (unsigned char *) span_id_bin, 8);
        }

        if (!span_id) {
            if (error_status) {
                *error_status = FLB_OTEL_TRACES_ERR_INVALID_LINK_SPAN_ID;
            }
            return -1;
        }

        /* traceState */
        ret = flb_otel_utils_find_map_entry_by_key(&link.via.map, "traceState", 0, FLB_FALSE);
        if (ret >= 0 && link.via.map.ptr[ret].val.type == MSGPACK_OBJECT_STR) {
            trace_state = &link.via.map.ptr[ret].val;
        }

        /* attributes */
        ret = flb_otel_utils_find_map_entry_by_key(&link.via.map, "attributes", 0, FLB_FALSE);
        if (ret >= 0 && link.via.map.ptr[ret].val.type == MSGPACK_OBJECT_ARRAY) {
            attr = &link.via.map.ptr[ret].val;
            ctr_attr = convert_attributes(attr, "event link");
        }

        /* droped_attributes_count */
        ret = flb_otel_utils_find_map_entry_by_key(&link.via.map, "droppedAttributesCount", 0, FLB_FALSE);
        if (ret >= 0 && link.via.map.ptr[ret].val.type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
            dropped_attr_count = &link.via.map.ptr[ret].val;
        }

        /* flags */
        ret = flb_otel_utils_find_map_entry_by_key(&link.via.map, "flags", 0, FLB_FALSE);
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
            if (error_status) {
                *error_status = FLB_OTEL_TRACES_ERR_INVALID_LINK_ENTRY;
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

static int process_span_status(struct ctrace *ctr,
                               struct ctrace_span *span,
                               msgpack_object *status,
                               int *error_status)
{
    int ret;
    int code = 0;
    cfl_sds_t tmp = NULL;
    char *message = NULL;

    if (status->type != MSGPACK_OBJECT_MAP) {
        flb_error("unexpected type for status");
        return -1;
    }

    /* code */
    ret = flb_otel_utils_find_map_entry_by_key(&status->via.map, "code", 0, FLB_TRUE);
    if (ret >= 0 && status->via.map.ptr[ret].val.type == MSGPACK_OBJECT_STR) {
        tmp = cfl_sds_create_len(status->via.map.ptr[ret].val.via.str.ptr,
                                 status->via.map.ptr[ret].val.via.str.size);
        if (!tmp) {
            return -1;
        }

        if (strcasecmp(tmp, "UNSET") == 0) {
            code = CTRACE_SPAN_STATUS_CODE_UNSET;
        }
        else if (strcasecmp(tmp, "OK") == 0) {
            code = CTRACE_SPAN_STATUS_CODE_OK;
        }
        else if (strcasecmp(tmp, "ERROR") == 0) {
            code = CTRACE_SPAN_STATUS_CODE_ERROR;
        }
        else {
            cfl_sds_destroy(tmp);
            if (error_status) {
                *error_status = FLB_OTEL_TRACES_ERR_STATUS_FAILURE;
            }
            return -1;
        }
        cfl_sds_destroy(tmp);
    }
    else {
        if (error_status) {
            *error_status = FLB_OTEL_TRACES_ERR_STATUS_FAILURE;
        }
        return -1;
    }

    /* message */
    ret = flb_otel_utils_find_map_entry_by_key(&status->via.map, "message", 0, FLB_FALSE);
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

static int process_spans(struct ctrace *ctr,
                         struct ctrace_scope_span *scope_span,
                         msgpack_object *spans,
                         int *error_status)
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
            if (error_status) {
                *error_status = FLB_OTEL_TRACES_ERR_UNEXPECTED_SPAN_ENTRY_TYPE;
            }
            return -1;
        }

        val_str = NULL;

        /* name */
        ret = flb_otel_utils_find_map_entry_by_key(&span.via.map, "name", 0, FLB_TRUE);
        if (ret >= 0 && span.via.map.ptr[ret].val.type == MSGPACK_OBJECT_STR) {
            name = &span.via.map.ptr[ret].val;
            val_str = cfl_sds_create_len(name->via.str.ptr, name->via.str.size);
        }

        if (!val_str) {
            if (error_status) {
                *error_status = FLB_OTEL_TRACES_ERR_SPAN_NAME_MISSING;
            }
            return -1;
        }

        /* create the span */
        ctr_span = ctr_span_create(ctr, scope_span, val_str, NULL);
        cfl_sds_destroy(val_str);

        if (ctr_span == NULL) {
            if (error_status) {
                *error_status = FLB_OTEL_TRACES_ERR_GENERIC_ERROR;
            }
            return -1;
        }

        /* traceId */
        ret = flb_otel_utils_find_map_entry_by_key(&span.via.map, "traceId", 0, FLB_TRUE);
        if (ret >= 0 && span.via.map.ptr[ret].val.type == MSGPACK_OBJECT_STR) {
            /* trace_id is an hex of 32 bytes */
            if (span.via.map.ptr[ret].val.via.str.size != 32) {
                len = span.via.map.ptr[ret].val.via.str.size;
                if (len > sizeof(tmp) - 1) {
                    len = sizeof(tmp) - 1;
                }
                memcpy(tmp, span.via.map.ptr[ret].val.via.str.ptr, len);
                tmp[len] = '\0';

                if (error_status) {
                    *error_status = FLB_OTEL_TRACES_ERR_INVALID_TRACE_ID;
                }
                return -1;
            }

            /* decode the hex string (16 bytes) */
            memset(tmp, '\0', sizeof(tmp));
            flb_otel_utils_hex_to_id((char *) span.via.map.ptr[ret].val.via.str.ptr,
                                     span.via.map.ptr[ret].val.via.str.size,
                                     (unsigned char *) tmp, 16);
            ctr_span_set_trace_id(ctr_span, tmp, 16);
        }

        /* spanId */
        ret = flb_otel_utils_find_map_entry_by_key(&span.via.map, "spanId", 0, FLB_TRUE);
        if (ret >= 0 && span.via.map.ptr[ret].val.type == MSGPACK_OBJECT_STR) {
            /* span_id is an hex of 16 bytes */
            if (span.via.map.ptr[ret].val.via.str.size != 16) {
                len = span.via.map.ptr[ret].val.via.str.size;
                if (len > sizeof(tmp) - 1) {
                    len = sizeof(tmp) - 1;
                }
                memcpy(tmp, span.via.map.ptr[ret].val.via.str.ptr, len);
                tmp[len] = '\0';
                if (error_status) {
                    *error_status = FLB_OTEL_TRACES_ERR_INVALID_SPAN_ID;
                }
                return -1;
            }

            /* decode the hex string (8 bytes) */
            memset(tmp, '\0', sizeof(tmp));
            flb_otel_utils_hex_to_id((char *) span.via.map.ptr[ret].val.via.str.ptr,
                                     span.via.map.ptr[ret].val.via.str.size,
                                     (unsigned char *) tmp, 8);
            ctr_span_set_span_id(ctr_span, tmp, 8);
        }

        /* traceState */
        ret = flb_otel_utils_find_map_entry_by_key(&span.via.map, "traceState", 0, FLB_TRUE);
        if (ret >= 0 && span.via.map.ptr[ret].val.type == MSGPACK_OBJECT_STR) {
            val_str = cfl_sds_create_len(span.via.map.ptr[ret].val.via.str.ptr,
                                         span.via.map.ptr[ret].val.via.str.size);
            ctr_span->trace_state = val_str;
            val_str = NULL;
        }

        /* flags */
        ret = flb_otel_utils_find_map_entry_by_key(&span.via.map, "flags", 0, FLB_TRUE);
        if (ret >= 0 && span.via.map.ptr[ret].val.type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
            /* unsupported in CTraces */
        }

        /* parentSpanId */
        ret = flb_otel_utils_find_map_entry_by_key(&span.via.map, "parentSpanId", 0, FLB_TRUE);
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
                if (error_status) {
                    *error_status = FLB_OTEL_TRACES_ERR_INVALID_PARENT_SPAN_ID;
                }
                return -1;
            }

            /* decode the hex string (8 bytes) */
            memset(tmp, '\0', sizeof(tmp));
            flb_otel_utils_hex_to_id((char *) span.via.map.ptr[ret].val.via.str.ptr,
                                     span.via.map.ptr[ret].val.via.str.size,
                                     (unsigned char *) tmp, 8);
            ctr_span_set_parent_span_id(ctr_span, tmp, 8);
        }

        /* flags */
        ret = flb_otel_utils_find_map_entry_by_key(&span.via.map, "flags", 0, FLB_TRUE);
        if (ret >= 0 && span.via.map.ptr[ret].val.type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
            ctr_span_set_flags(ctr_span, span.via.map.ptr[ret].val.via.u64);
        }

        /* start_time_unix_nano */
        ret = flb_otel_utils_find_map_entry_by_key(&span.via.map, "startTimeUnixNano", 0, FLB_TRUE);
        if (ret >= 0 && span.via.map.ptr[ret].val.type == MSGPACK_OBJECT_STR) {
            /* convert string number to integer */
            val = flb_otel_utils_convert_string_number_to_u64((char *) span.via.map.ptr[ret].val.via.str.ptr,
                                                              span.via.map.ptr[ret].val.via.str.size);
            ctr_span_start_ts(ctr, ctr_span, val);
        }

        /* end_time_unix_nano */
        ret = flb_otel_utils_find_map_entry_by_key(&span.via.map, "endTimeUnixNano", 0, FLB_TRUE);
        if (ret >= 0 && span.via.map.ptr[ret].val.type == MSGPACK_OBJECT_STR) {
            /* convert string number to integer */
            val = flb_otel_utils_convert_string_number_to_u64((char *) span.via.map.ptr[ret].val.via.str.ptr,
                                                              span.via.map.ptr[ret].val.via.str.size);
            ctr_span_end_ts(ctr, ctr_span, val);
        }

        /* kind */
        ret = flb_otel_utils_find_map_entry_by_key(&span.via.map, "kind", 0, FLB_TRUE);
        if (ret >= 0 && span.via.map.ptr[ret].val.type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
            ctr_span_kind_set(ctr_span, span.via.map.ptr[ret].val.via.u64);
        }

        /* attributes */
        ret = flb_otel_utils_find_map_entry_by_key(&span.via.map, "attributes", 0, FLB_TRUE);
        if (ret >= 0 && span.via.map.ptr[ret].val.type == MSGPACK_OBJECT_ARRAY) {
            attr = &span.via.map.ptr[ret].val;
            ctr_attr = convert_attributes(attr, "span");
            if (ctr_attr) {
                ctr_span_set_attributes(ctr_span, ctr_attr);
            }
        }

        /* dropped_attributes_count */
        ret = flb_otel_utils_find_map_entry_by_key(&span.via.map, "droppedAttributesCount", 0, FLB_TRUE);
        if (ret >= 0 && span.via.map.ptr[ret].val.type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
            ctr_span_set_dropped_attributes_count(ctr_span, span.via.map.ptr[ret].val.via.u64);
        }

        /* events */
        ret = flb_otel_utils_find_map_entry_by_key(&span.via.map, "events", 0, FLB_TRUE);
        if (ret >= 0 && span.via.map.ptr[ret].val.type == MSGPACK_OBJECT_ARRAY) {
            ret = process_events(ctr, ctr_span, &span.via.map.ptr[ret].val, error_status);
            if (ret == -1) {
                return -1;
            }
        }

        /* dropped_events_count */
        ret = flb_otel_utils_find_map_entry_by_key(&span.via.map, "droppedEventsCount", 0, FLB_TRUE);
        if (ret >= 0 && span.via.map.ptr[ret].val.type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
            ctr_span_set_dropped_events_count(ctr_span, span.via.map.ptr[ret].val.via.u64);
        }

        /* dropped_links_count */
        ret = flb_otel_utils_find_map_entry_by_key(&span.via.map, "droppedLinksCount", 0, FLB_TRUE);
        if (ret >= 0 && span.via.map.ptr[ret].val.type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
            ctr_span_set_dropped_links_count(ctr_span, span.via.map.ptr[ret].val.via.u64);
        }

        /* links */
        ret = flb_otel_utils_find_map_entry_by_key(&span.via.map, "links", 0, FLB_TRUE);
        if (ret >= 0 && span.via.map.ptr[ret].val.type == MSGPACK_OBJECT_ARRAY) {
            ret = process_links(ctr, ctr_span, &span.via.map.ptr[ret].val, error_status);
            if (ret == -1) {
                return -1;
            }
        }

        /* schema_url */
        ret = flb_otel_utils_find_map_entry_by_key(&span.via.map, "schemaUrl", 0, FLB_TRUE);
        if (ret >= 0 && span.via.map.ptr[ret].val.type == MSGPACK_OBJECT_STR) {
            val_str = cfl_sds_create_len(span.via.map.ptr[ret].val.via.str.ptr,
                                         span.via.map.ptr[ret].val.via.str.size);
            ctr_span_set_schema_url(ctr_span, val_str);
            cfl_sds_destroy(val_str);
            val_str = NULL;
        }

        /* status */
        ret = flb_otel_utils_find_map_entry_by_key(&span.via.map, "status", 0, FLB_TRUE);
        if (ret >= 0 && span.via.map.ptr[ret].val.type == MSGPACK_OBJECT_MAP) {
            ret = process_span_status(ctr, ctr_span, &span.via.map.ptr[ret].val, error_status);
            if (ret == -1) {
                return -1;
            }
        }
    }

    return 0;
}

static int process_scope_span(struct ctrace *ctr,
                              struct ctrace_resource_span *resource_span,
                              msgpack_object *scope_spans,
                              int *error_status)
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
    ret = flb_otel_utils_find_map_entry_by_key(&scope_spans->via.map, "scope", 0, FLB_TRUE);
    if (ret >= 0) {
        scope = scope_spans->via.map.ptr[ret].val;
        if (scope.type != MSGPACK_OBJECT_MAP) {
            flb_error("unexpected scope type in scope span");
            if (error_status) {
                *error_status = FLB_OTEL_TRACES_ERR_UNEXPECTED_SCOPE_SPANS_ENTRY_TYPE;
            }
            return -1;
        }

        /* create the scope_span */
        scope_span = ctr_scope_span_create(resource_span);
        if (scope_span == NULL) {
            if (error_status) {
                *error_status = FLB_OTEL_TRACES_ERR_GENERIC_ERROR;
            }
            return -1;
        }

        /* instrumentation scope: name */
        name = NULL;
        ret = flb_otel_utils_find_map_entry_by_key(&scope.via.map, "name", 0, FLB_TRUE);
        if (ret >= 0 && scope.via.map.ptr[ret].val.type == MSGPACK_OBJECT_STR) {
            name = &scope.via.map.ptr[ret].val;
        }

        /* instrumentation scope: version */
        version = NULL;
        ret = flb_otel_utils_find_map_entry_by_key(&scope.via.map, "version", 0, FLB_TRUE);
        if (ret >= 0 && scope.via.map.ptr[ret].val.type == MSGPACK_OBJECT_STR) {
            version = &scope.via.map.ptr[ret].val;
        }

        /* instrumentation scope: attributes */
        attr = NULL;
        ret = flb_otel_utils_find_map_entry_by_key(&scope.via.map, "attributes", 0, FLB_TRUE);
        if (ret >= 0 && scope.via.map.ptr[ret].val.type == MSGPACK_OBJECT_ARRAY) {
            attr = &scope.via.map.ptr[ret].val;
        }

        /* instrumentation scope: dropped_attributes_count */
        dropped_attr = NULL;
        ret = flb_otel_utils_find_map_entry_by_key(&scope.via.map, "droppedAttributesCount", 0, FLB_TRUE);
        if (ret >= 0 && scope.via.map.ptr[ret].val.type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
            dropped_attr = &scope.via.map.ptr[ret].val;
        }

        ret = process_scope_attributes(ctr,
                                       scope_span,
                                       name, version, attr, dropped_attr,
                                       error_status);
        if (ret == -1) {
            flb_warn("failed to process scope attributes");
            if (error_status && *error_status == 0) {
                *error_status = FLB_OTEL_TRACES_ERR_INVALID_ATTRIBUTES;
            }
            return -1;
        }
    }
    else {
        /* If scope is not defined we still need the scope span container */
        scope_span = ctr_scope_span_create(resource_span);
        if (scope_span == NULL) {
            if (error_status) {
                *error_status = FLB_OTEL_TRACES_ERR_GENERIC_ERROR;
            }
            return -1;
        }
    }

    /* schema_url */
    ret = flb_otel_utils_find_map_entry_by_key(&scope_spans->via.map, "schemaUrl", 0, FLB_TRUE);
    if (ret >= 0) {
        if (scope_spans->via.map.ptr[ret].val.type == MSGPACK_OBJECT_STR) {
            schema_url = &scope_spans->via.map.ptr[ret].val;
            url = cfl_sds_create_len(schema_url->via.str.ptr, schema_url->via.str.size);
            if (url) {
                ctr_scope_span_set_schema_url(scope_span, url);
                cfl_sds_destroy(url);
                url = NULL;
            }
        }
    }

    /* spans */
    spans = NULL;
    ret = flb_otel_utils_find_map_entry_by_key(&scope_spans->via.map, "spans", 0, FLB_TRUE);
    if (ret < 0) {
        if (error_status) {
            *error_status = FLB_OTEL_TRACES_ERR_SPANS_MISSING;
        }
        return -1;
    }

    if (scope_spans->via.map.ptr[ret].val.type == MSGPACK_OBJECT_ARRAY) {
        spans = &scope_spans->via.map.ptr[ret].val;
    }
    else {
        if (error_status) {
            *error_status = FLB_OTEL_TRACES_ERR_UNEXPECTED_SPANS_TYPE;
        }
        return -1;
    }

    ret = process_spans(ctr, scope_span, spans, error_status);
    if (ret == -1) {
        return -1;
    }

    return 0;
}

static int process_resource_span(struct ctrace *ctr,
                                 msgpack_object *resource_span,
                                 int *error_status)
{
    int ret;
    msgpack_object resource;
    msgpack_object *attr;
    msgpack_object *schema_url;
    msgpack_object *scope_spans;
    msgpack_object_array *scope_spans_array;
    cfl_sds_t url = NULL;
    struct ctrace_resource_span *ctr_resource_span;

    if (resource_span->type != MSGPACK_OBJECT_MAP) {
        if (error_status) {
            *error_status = FLB_OTEL_TRACES_ERR_UNEXPECTED_RESOURCE_SPANS_ENTRY_TYPE;
        }
        return -1;
    }

    /* create a resource span */
    ctr_resource_span = ctr_resource_span_create(ctr);
    if (ctr_resource_span == NULL) {
        if (error_status) {
            *error_status = FLB_OTEL_TRACES_ERR_GENERIC_ERROR;
        }
        return -1;
    }

    /* process resource data */
    ret = flb_otel_utils_find_map_entry_by_key(&resource_span->via.map, "resource", 0, FLB_TRUE);
    if (ret >= 0 && resource_span->via.map.ptr[ret].val.type == MSGPACK_OBJECT_MAP) {
        resource = resource_span->via.map.ptr[ret].val;

        /* attributes */
        attr = NULL;
        ret = flb_otel_utils_find_map_entry_by_key(&resource.via.map, "attributes", 0, FLB_TRUE);
        if (ret >= 0 && resource.via.map.ptr[ret].val.type == MSGPACK_OBJECT_ARRAY) {
            attr = &resource.via.map.ptr[ret].val;
            ret = process_resource_attributes(ctr, ctr_resource_span, attr, error_status);
            if (ret == -1) {
                if (error_status && *error_status == 0) {
                    *error_status = FLB_OTEL_TRACES_ERR_INVALID_ATTRIBUTES;
                }
                return -1;
            }
        }

        /* dropped_attributes_count */
        ret = flb_otel_utils_find_map_entry_by_key(&resource.via.map, "droppedAttributesCount", 0, FLB_TRUE);
        if (ret >= 0 && resource.via.map.ptr[ret].val.type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
            ctr_resource_set_dropped_attr_count(ctr_resource_span->resource,
                                                resource.via.map.ptr[ret].val.via.u64);
        }

        /* schema_url */
        ret = flb_otel_utils_find_map_entry_by_key(&resource.via.map, "schemaUrl", 0, FLB_TRUE);
        if (ret >= 0 && resource.via.map.ptr[ret].val.type == MSGPACK_OBJECT_STR) {
            schema_url = &resource.via.map.ptr[ret].val;
            url = cfl_sds_create_len(schema_url->via.str.ptr, schema_url->via.str.size);
            if (url) {
                ctr_resource_span_set_schema_url(ctr_resource_span, url);
                cfl_sds_destroy(url);
                url = NULL;
            }
        }
    }

    /* schema_url */
    ret = flb_otel_utils_find_map_entry_by_key(&resource_span->via.map, "schemaUrl", 0, FLB_TRUE);
    if (ret >= 0 && resource_span->via.map.ptr[ret].val.type == MSGPACK_OBJECT_STR) {
        schema_url = &resource_span->via.map.ptr[ret].val;
        url = cfl_sds_create_len(schema_url->via.str.ptr, schema_url->via.str.size);
        if (url) {
            ctr_resource_span_set_schema_url(ctr_resource_span, url);
            cfl_sds_destroy(url);
            url = NULL;
        }
    }

    /* scopeSpans */
    scope_spans = NULL;
    ret = flb_otel_utils_find_map_entry_by_key(&resource_span->via.map, "scopeSpans", 0, FLB_TRUE);
    if (ret < 0) {
        if (error_status) {
            *error_status = FLB_OTEL_TRACES_ERR_SCOPE_SPANS_MISSING;
        }
        return -1;
    }

    if (resource_span->via.map.ptr[ret].val.type == MSGPACK_OBJECT_ARRAY) {
        scope_spans = &resource_span->via.map.ptr[ret].val;
    }
    else {
        if (error_status) {
            *error_status = FLB_OTEL_TRACES_ERR_UNEXPECTED_SCOPE_SPANS_TYPE;
        }
        return -1;
    }

    scope_spans_array = &scope_spans->via.array;
    for (ret = 0; ret < scope_spans_array->size; ret++) {
        if (scope_spans_array->ptr[ret].type != MSGPACK_OBJECT_MAP) {
            if (error_status) {
                *error_status = FLB_OTEL_TRACES_ERR_UNEXPECTED_SCOPE_SPANS_ENTRY_TYPE;
            }
            return -1;
        }

        if (process_scope_span(ctr,
                               ctr_resource_span,
                               &scope_spans_array->ptr[ret],
                               error_status) == -1) {
            return -1;
        }
    }

    return 0;
}

static struct ctrace *process_root_msgpack(msgpack_object *obj,
                                           int *error_status)
{
    int ret;
    msgpack_object *resource_spans;
    struct ctrace *ctr;

    if (obj->type != MSGPACK_OBJECT_MAP) {
        if (error_status) {
            *error_status = FLB_OTEL_TRACES_ERR_UNEXPECTED_ROOT_OBJECT_TYPE;
        }
        return NULL;
    }

    ret = flb_otel_utils_find_map_entry_by_key(&obj->via.map, "resourceSpans", 0, FLB_TRUE);
    if (ret < 0) {
        if (error_status) {
            *error_status = FLB_OTEL_TRACES_ERR_RESOURCE_SPANS_MISSING;
        }
        return NULL;
    }

    if (obj->via.map.ptr[ret].val.type != MSGPACK_OBJECT_ARRAY) {
        if (error_status) {
            *error_status = FLB_OTEL_TRACES_ERR_UNEXPECTED_RESOURCE_SPANS_TYPE;
        }
        return NULL;
    }

    resource_spans = &obj->via.map.ptr[ret].val;
    ret = 0;

    ctr = ctr_create(NULL);
    if (!ctr) {
        if (error_status) {
            *error_status = FLB_OTEL_TRACES_ERR_GENERIC_ERROR;
        }
        return NULL;
    }

    for (ret = 0; ret < resource_spans->via.array.size; ret++) {
        if (process_resource_span(ctr,
                                  &resource_spans->via.array.ptr[ret],
                                  error_status) == -1) {
            ctr_destroy(ctr);
            return NULL;
        }
    }

    return ctr;
}

struct ctrace *flb_opentelemetry_json_traces_to_ctrace(const char *body, size_t len, int *error_status)

{
    int              result;
    int              root_type;
    char            *msgpack_body;
    size_t           msgpack_body_length;
    size_t           offset = 0;
    msgpack_unpacked unpacked_root;
    struct ctrace   *ctr;

    if (error_status) {
        *error_status = 0;
    }

    result = flb_pack_json(body, len, &msgpack_body, &msgpack_body_length,
                           &root_type, NULL);

    if (result != 0) {
        if (error_status) {
            *error_status = FLB_OTEL_TRACES_ERR_INVALID_JSON;
        }
        return NULL;
    }

    msgpack_unpacked_init(&unpacked_root);

    result = msgpack_unpack_next(&unpacked_root,
                                 msgpack_body,
                                 msgpack_body_length,
                                 &offset);

    if (result != MSGPACK_UNPACK_SUCCESS) {
        msgpack_unpacked_destroy(&unpacked_root);
        flb_free(msgpack_body);
        if (error_status) {
            *error_status = FLB_OTEL_TRACES_ERR_UNEXPECTED_ROOT_OBJECT_TYPE;
        }
        return NULL;
    }

    /* iterate msgpack and compose a CTraces context */
    ctr = process_root_msgpack(&unpacked_root.data, error_status);

    msgpack_unpacked_destroy(&unpacked_root);
    flb_free(msgpack_body);

    if (!ctr && error_status && *error_status == 0) {
        *error_status = FLB_OTEL_TRACES_ERR_GENERIC_ERROR;
    }

    return ctr;
}
