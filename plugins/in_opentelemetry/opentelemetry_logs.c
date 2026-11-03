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
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_log_event_encoder.h>
#include <fluent-bit/flb_input_log.h>
#include <fluent-bit/flb_mp_chunk.h>
#include <fluent-bit/flb_opentelemetry.h>

#include "opentelemetry.h"
#include "opentelemetry_logs.h"
#include "opentelemetry_utils.h"

/*
 * Encode JSON logs through the single-pass CFL decoder. The generic JSON to
 * msgpack path parses the payload into msgpack first and then walks that
 * msgpack again to build the records, it is only used for the rare payloads
 * CFL cannot hold.
 */
static int opentelemetry_logs_json_encode_direct(struct flb_opentelemetry *ctx,
                                                 struct flb_log_event_encoder *encoder,
                                                 const char *payload, size_t size,
                                                 struct flb_opentelemetry_logs_decode_options *options,
                                                 size_t *record_count,
                                                 int *error_status)
{
    int ret;
    struct flb_mp_chunk_cobj *chunk;
    struct flb_opentelemetry_logs_json_cfl *result;

    result = NULL;
    ret = flb_opentelemetry_logs_json_to_cfl(payload, size, options, &result, error_status);
    if (ret == FLB_OTEL_LOGS_JSON_CFL_UNSUPPORTED) {
        return flb_opentelemetry_logs_json_to_msgpack(encoder, payload, size,
                                                      ctx->logs_body_key, error_status);
    }
    if (ret != 0) {
        flb_opentelemetry_logs_json_cfl_destroy(result);
        return -1;
    }

    chunk = flb_opentelemetry_logs_json_cfl_take_chunk(result);
    if (chunk == NULL) {
        flb_opentelemetry_logs_json_cfl_destroy(result);
        return -1;
    }

    /* the records borrow strings from the JSON document owned by 'result' */
    chunk->log_encoder = encoder;
    ret = flb_mp_chunk_cobj_encode_append(chunk);
    *record_count = flb_mp_chunk_cobj_count_log_records(chunk);
    chunk->log_encoder = NULL;

    flb_mp_chunk_cobj_destroy(chunk);
    flb_opentelemetry_logs_json_cfl_destroy(result);

    return ret;
}

/*
 * Main function used from opentelemetry_prot.c to process logs either in JSON or Protobuf format.
 * -----------------------------------------------------------------------------------------------
 */
int opentelemetry_process_logs(struct flb_opentelemetry *ctx,
                               flb_sds_t content_type,
                               flb_sds_t tag,
                               size_t tag_len,
                               void *data, size_t size)
{
    size_t remaining = ctx->logs_max_size;

    return opentelemetry_process_logs_with_budget(ctx, content_type, tag, tag_len,
                                                  data, size, &remaining);
}

int opentelemetry_process_logs_with_budget(struct flb_opentelemetry *ctx,
                                           flb_sds_t content_type,
                                           flb_sds_t tag, size_t tag_len,
                                           void *data, size_t size,
                                           size_t *remaining)
{
    int ret = -1;
    int is_proto = FLB_FALSE; /* default to JSON */
    int error_status = 0;
    char *buf;
    uint8_t *payload;
    uint64_t payload_size;
    size_t record_count;
    struct flb_log_event_encoder *encoder;
    struct flb_mp_chunk_cobj *chunk;
    struct flb_opentelemetry_logs_decode_options decode_options;
    struct flb_opentelemetry_logs_protobuf_cfl *cfl_result;
    struct flb_opentelemetry_logs_json_cfl *json_cfl_result;
    int worker_thread;

    buf = (char *) data;
    payload = data;
    payload_size = size;
    record_count = 0;
    cfl_result = NULL;
    json_cfl_result = NULL;
    worker_thread = opentelemetry_uses_worker_ingress_queue(ctx);
    decode_options.metadata_key = ctx->logs_metadata_key;
    decode_options.body_key = ctx->logs_body_key;
    decode_options.output_limit = *remaining;

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

    /*
     * JSON and protobuf records go straight to input processors as CFL records
     * when they can take them. Workers enqueue the serialized processor
     * output as already processed, so the engine does not run the chain twice.
     * A JSON payload CFL cannot hold takes the msgpack path below.
     */
    if (flb_input_log_chunk_supported(ctx->ins, worker_thread) == FLB_TRUE) {
        if (is_proto == FLB_TRUE) {
            ret = flb_opentelemetry_logs_protobuf_to_cfl(
                      payload, payload_size, &decode_options, &cfl_result);
            if (ret == 0) {
                *remaining -= flb_opentelemetry_logs_protobuf_cfl_get_encoded_size(cfl_result);
                chunk = flb_opentelemetry_logs_protobuf_cfl_take_chunk(cfl_result);
            }
        }
        else {
            ret = flb_opentelemetry_logs_json_to_cfl(
                      (const char *) payload, payload_size, &decode_options,
                      &json_cfl_result, &error_status);
            if (ret == FLB_OTEL_LOGS_JSON_CFL_UNSUPPORTED) {
                goto msgpack_path;
            }
            if (ret == 0) {
                *remaining -= flb_opentelemetry_logs_json_cfl_get_encoded_size(json_cfl_result);
                chunk = flb_opentelemetry_logs_json_cfl_take_chunk(json_cfl_result);
            }
        }
        if (ret != 0) {
            flb_plg_error(ctx->ins, "failed to process logs from %s payload (%i) %s",
                          is_proto == FLB_TRUE ? "protobuf" : "JSON", error_status,
                          flb_opentelemetry_error_to_string(error_status));
            flb_opentelemetry_logs_protobuf_cfl_destroy(cfl_result);
            flb_opentelemetry_logs_json_cfl_destroy(json_cfl_result);
            return -1;
        }

        /* like the Collector, a request without log records is accepted */
        if (cfl_list_is_empty(&chunk->records)) {
            flb_mp_chunk_cobj_destroy(chunk);
            ret = 0;
        }
        else {
            ret = flb_input_log_append_chunk(ctx->ins, tag, flb_sds_len(tag),
                                             chunk, worker_thread);
        }
        flb_opentelemetry_logs_protobuf_cfl_destroy(cfl_result);
        flb_opentelemetry_logs_json_cfl_destroy(json_cfl_result);
        if (ret == FLB_INPUT_INGRESS_BUSY) {
            /* the client retries once the ingress queue has room */
            return FLB_INPUT_INGRESS_BUSY;
        }
        else if (ret != 0) {
            flb_plg_error(ctx->ins, "failed to append logs to the input buffer");
            return -1;
        }

        return 0;
    }

msgpack_path:
    encoder = flb_log_event_encoder_create(FLB_LOG_EVENT_FORMAT_FLUENT_BIT_V2);
    if (encoder == NULL) {
        return -1;
    }
    encoder->output_limit = *remaining;

    if (is_proto == FLB_TRUE) {
        ret = flb_opentelemetry_logs_protobuf_to_msgpack(
                  encoder, payload, payload_size, &decode_options, &record_count);
        if (ret < 0) {
            flb_plg_error(ctx->ins, "failed to process logs from protobuf payload");
        }
    }
    else {
        ret = opentelemetry_logs_json_encode_direct(ctx, encoder,
                                                    (const char *) payload, payload_size,
                                                    &decode_options, &record_count,
                                                    &error_status);
        if (ret != 0) {
            flb_plg_error(ctx->ins, "failed to process logs from JSON payload (%i) %s",
                          error_status,
                          flb_opentelemetry_error_to_string(error_status));
        }
    }

    if (ret >= 0 && encoder->output_length == 0) {
        /* like the Collector, a request without log records is accepted */
        ret = 0;
    }
    else if (ret >= 0) {
        *remaining -= encoder->output_length;
        if (worker_thread == FLB_TRUE) {
            size_t allocation_size;
            void *resized_buffer;

            allocation_size = encoder->buffer.alloc;

            if (allocation_size > encoder->output_length) {
                resized_buffer = flb_realloc(encoder->output_buffer,
                                             encoder->output_length);
                if (resized_buffer != NULL) {
                    encoder->buffer.data = resized_buffer;
                    encoder->output_buffer = resized_buffer;
                    encoder->buffer.alloc = encoder->output_length;
                    allocation_size = encoder->output_length;
                }
            }

            ret = opentelemetry_ingest_logs_take(ctx,
                                                 record_count,
                                                 tag,
                                                 flb_sds_len(tag),
                                                 encoder->output_buffer,
                                                 encoder->output_length,
                                                 allocation_size);
            flb_log_event_encoder_claim_internal_buffer_ownership(encoder);
        }
        else {
            ret = opentelemetry_ingest_logs(ctx,
                                            tag,
                                            flb_sds_len(tag),
                                            encoder->output_buffer,
                                            encoder->output_length);
        }

        if (ret != 0) {
            flb_plg_error(ctx->ins, "failed to append logs to the input buffer");
        }
    }

    flb_log_event_encoder_destroy(encoder);
    return ret;
}
