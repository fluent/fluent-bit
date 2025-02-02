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

static int process_resource_set_attribute(struct ctrace *ctr, struct ctrace_attributes *attr,
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

static int process_resource_unwrap_attribute(struct ctrace *ctr, msgpack_object *attr,
                                             msgpack_object *out_key,
                                             msgpack_object *out_value, int *out_value_type)
{
    int i;
    int ret;
    int type;
    msgpack_object obj;
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

static int process_resource_attributes(struct flb_opentelemetry *ctx,
                                       struct ctrace *ctr,
                                       struct ctrace_attributes *attr,
                                       msgpack_object *attributes)

{
    int i;
    int ret;
    int type;
    int value_type;
    msgpack_object key;
    msgpack_object value;

    for (i = 0; i < attributes->via.array.size; i++) {
        ret = process_resource_unwrap_attribute(ctr, &attributes->via.array.ptr[i],
                                                &key, &value, &value_type);
        if (ret == -1) {
            flb_plg_warn(ctx->ins, "found invalid trace resource attribute, skipping");
            continue;
        }

        /* set attribute */
        ret = process_resource_set_attribute(ctr, attr, &key, &value, value_type);
        if (ret == -1) {
            flb_plg_warn(ctx->ins, "failed to set trace resource attribute, skipping");
            continue;
        }
    }


    ctr_resource_set_attributes(ctr, attr);
    exit(0);
    return 0;
}

#include <ctraces/ctr_encode_text.h>

static int process_resource_span(struct flb_opentelemetry *ctx,
                                 msgpack_object *resource_spans)
{
    int i;
    int ret;
    int type;
    struct ctrace *ctr;
    msgpack_object obj;
    msgpack_object resource;
    msgpack_object attr;
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

    /* Get resource attributes */
    ret = find_map_entry_by_key(&resource.via.map, "attributes", 0, FLB_TRUE);
    if (ret >= 0) {
        attr = resource.via.map.ptr[ret].val;
        if (attr.type == MSGPACK_OBJECT_ARRAY) {
            /* initialize attributes context */
            ctr_attr = ctr_attributes_create();
            if (ctr_attr == NULL) {
                ctr_destroy(ctr);
                return -1;
            }

            /* iterate and register attributes */
            ret = process_resource_attributes(ctx, ctr, ctr_attr, &attr);
            // for (i = 0; i < attr.via.array.size; i++) {
            //     ret = process_resource_unwrap_attribute(ctr, &attr.via.array.ptr[i], &obj, &type);
            //     if (ret == -1) {
            //         flb_plg_warn(ctx->ins, "found invalid trace resource attribute, skipping");
            //         continue;
            //     }

            //     /* set attribute */
            //     ret = process_resource_set_attribute(ctr, ctr_attr, &obj, &obj, type);


            // }
        }
    }

    cfl_sds_t t = ctr_encode_text_create(ctr);
    printf("%s\n", t);
    ctr_destroy(ctr);

    printf("------\n\n");
    msgpack_object_print(stdout, resource);
    exit(0);
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


/* This code is definitely not complete and beyond fishy, it needs to be
 * refactored.
 */
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

    printf("json: %s\n", body);

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

    return process_json(ctx, data, size);

    return 0;
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
