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
#include <stdlib.h>
#include <stdint.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_log_event_encoder.h>
#include <fluent-bit/flb_opentelemetry.h>
#include <cmetrics/cmt_decode_opentelemetry.h>
#include <ctraces/ctraces.h>

#include "flb_fuzz_header.h"

/*
 * Fuzzes the OTLP/JSON decoders in src/opentelemetry/, which the
 * opentelemetry input plugin runs on the body of an HTTP request posted to
 * /v1/logs, /v1/metrics or /v1/traces. The first byte selects the signal so
 * that a single target covers all three decoders.
 */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    struct flb_log_event_encoder *encoder;
    struct cfl_list context_list;
    struct ctrace *ctr;
    int error_status = 0;

    if (size < 2) {
        return 0;
    }

    TIMEOUT_GUARD

    /* Set fuzzer-malloc chance of failure */
    flb_malloc_p = 0;
    flb_malloc_mod = 25000;

    if (GET_MOD_EQ(3, 0)) {
        MOVE_INPUT(1)

        encoder = flb_log_event_encoder_create(FLB_LOG_EVENT_FORMAT_FLUENT_BIT_V2);
        if (encoder != NULL) {
            flb_opentelemetry_logs_json_to_msgpack(encoder,
                                                   (const char *) data, size,
                                                   NULL, &error_status);
            flb_log_event_encoder_destroy(encoder);
        }
    }
    else if (GET_MOD_EQ(3, 1)) {
        MOVE_INPUT(1)

        cfl_list_init(&context_list);
        if (flb_opentelemetry_metrics_json_to_cmt(&context_list,
                                                  (const char *) data,
                                                  size) ==
            CMT_DECODE_OPENTELEMETRY_SUCCESS) {
            cmt_decode_opentelemetry_destroy(&context_list);
        }
    }
    else {
        MOVE_INPUT(1)

        ctr = flb_opentelemetry_json_traces_to_ctrace((const char *) data, size,
                                                      &error_status);
        if (ctr != NULL) {
            ctr_destroy(ctr);
        }
    }

    return 0;
}
