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

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_log_event_encoder.h>
#include <fluent-bit/flb_mp_chunk.h>
#include <fluent-bit/flb_opentelemetry.h>

#include "flb_fuzz_header.h"

/*
 * Feed OTLP/HTTP log payloads to the decoders used by in_opentelemetry, the
 * way the input does: the CFL decoders followed by the record encoding, and
 * the msgpack decoders. The first byte selects the encoding, the body key and
 * the logs_max_size budget, the rest is the request body.
 */

/* Encode CFL records like the input does once processors are done */
static void encode_chunk(struct flb_mp_chunk_cobj *chunk)
{
    struct flb_log_event_encoder encoder;
    struct flb_mp_chunk_record *record;

    if (chunk == NULL) {
        return;
    }

    while (flb_mp_chunk_cobj_record_next(chunk, &record) == FLB_MP_CHUNK_RECORD_OK) {
    }

    if (flb_log_event_encoder_init(&encoder, FLB_LOG_EVENT_FORMAT_FLUENT_BIT_V2) == 0) {
        chunk->log_encoder = &encoder;
        flb_mp_chunk_cobj_encode_append(chunk);
        flb_mp_chunk_cobj_count_log_records(chunk);
        chunk->log_encoder = NULL;
        flb_log_event_encoder_destroy(&encoder);
    }

    flb_mp_chunk_cobj_destroy(chunk);
}

static void fuzz_protobuf(const char *payload, size_t size,
                          struct flb_opentelemetry_logs_decode_options *options)
{
    size_t record_count;
    struct flb_log_event_encoder encoder;
    struct flb_opentelemetry_logs_protobuf_cfl *result;

    result = NULL;
    if (flb_opentelemetry_logs_protobuf_to_cfl(payload, size, options, &result) == 0) {
        flb_opentelemetry_logs_protobuf_cfl_get_encoded_size(result);
        encode_chunk(flb_opentelemetry_logs_protobuf_cfl_take_chunk(result));
    }
    flb_opentelemetry_logs_protobuf_cfl_destroy(result);

    if (flb_log_event_encoder_init(&encoder, FLB_LOG_EVENT_FORMAT_FLUENT_BIT_V2) == 0) {
        encoder.output_limit = options->output_limit;
        flb_opentelemetry_logs_protobuf_to_msgpack(&encoder, payload, size, options,
                                                   &record_count);
        flb_log_event_encoder_destroy(&encoder);
    }
}

static void fuzz_json(const char *payload, size_t size,
                      struct flb_opentelemetry_logs_decode_options *options)
{
    int error_status;
    struct flb_log_event_encoder encoder;
    struct flb_opentelemetry_logs_json_cfl *result;

    result = NULL;
    error_status = 0;
    if (flb_opentelemetry_logs_json_to_cfl(payload, size, options, &result,
                                           &error_status) == 0) {
        flb_opentelemetry_logs_json_cfl_get_encoded_size(result);
        encode_chunk(flb_opentelemetry_logs_json_cfl_take_chunk(result));
    }
    flb_opentelemetry_logs_json_cfl_destroy(result);

    if (flb_log_event_encoder_init(&encoder, FLB_LOG_EVENT_FORMAT_FLUENT_BIT_V2) == 0) {
        encoder.output_limit = options->output_limit;
        error_status = 0;
        flb_opentelemetry_logs_json_to_msgpack(&encoder, payload, size,
                                               options->body_key, &error_status);
        flb_log_event_encoder_destroy(&encoder);
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    uint8_t selector;
    char *payload;
    struct flb_opentelemetry_logs_decode_options options;

    TIMEOUT_GUARD

    /* Set fuzzer-malloc chance of failure */
    flb_malloc_p = 0;
    flb_malloc_mod = 25000;

    if (size < 1) {
        return 0;
    }
    selector = data[0];
    MOVE_INPUT(1);

    /* exact-size copy, so reads past the payload are caught */
    payload = malloc(size > 0 ? size : 1);
    if (payload == NULL) {
        return 0;
    }
    if (size > 0) {
        memcpy(payload, data, size);
    }

    options.metadata_key = "otlp";
    options.body_key = (selector & 0x02) ? "log" : NULL;
    options.output_limit = (selector >> 2) == 0 ? SIZE_MAX : (size_t) (selector >> 2) * 256;

    if (selector & 0x01) {
        fuzz_protobuf(payload, size, &options);
    }
    else {
        fuzz_json(payload, size, &options);
    }

    free(payload);

    return 0;
}
