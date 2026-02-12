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

#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_opentelemetry.h>

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
        if (result == -1) {
            ctr_destroy(decoded_context);
        }
    }

    return result;
}





static int process_json(struct flb_opentelemetry *ctx,
                        char *tag, size_t tag_len,
                        const char *body, size_t len)
{
    int result = -1;
    int error_status = 0;
    struct ctrace *ctr;

    /* Use the new centralized API for JSON to ctrace conversion */
    ctr = flb_opentelemetry_json_traces_to_ctrace(body, len, &error_status);
    if (ctr) {
        result = flb_input_trace_append(ctx->ins, tag, tag_len, ctr);
        if (result == -1) {
            ctr_destroy(ctr);
        }
    }
    else {
        flb_plg_error(ctx->ins, "invalid JSON trace: conversion error (status: %d)", error_status);
    }

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
        if (opentelemetry_is_json_content_type(content_type) == FLB_TRUE) {
            if (opentelemetry_payload_starts_with_json_object(buf, size) != FLB_TRUE) {
                flb_plg_error(ctx->ins, "Invalid JSON payload");
                return -1;
            }

            is_proto = FLB_FALSE;
        }
        else if (opentelemetry_is_protobuf_content_type(content_type) == FLB_TRUE) {
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
