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

#include <fluent-bit/flb_mem.h>
#include <ctraces/ctr_encode_opentelemetry.h>
#include <ctraces/ctr_decode_opentelemetry.h>
#include <ctraces/ctr_span.h>
#include "fts_telemetry.h"

const struct fts_signal_adapter fts_traces_adapter = {
    .event_type = FLB_PROCESSOR_TRACES,
    .register_helpers = fts_register_telemetry_helpers,
    .run_callback = fts_run_telemetry
};

/*
 * Trace processors commit in place: the framework retains the original
 * context pointer, so staged resource spans are moved into it.
 */
static void commit_trace(struct ctrace *input, struct ctrace *staged)
{
    struct cfl_list *head;
    struct cfl_list *tmp;
    struct ctrace_resource_span *resource;
    struct ctrace_span *span;

    cfl_list_foreach_safe(head, tmp, &input->resource_spans) {
        resource = cfl_list_entry(head, struct ctrace_resource_span, _head);
        ctr_resource_span_destroy(resource);
    }

    cfl_list_foreach_safe(head, tmp, &staged->resource_spans) {
        resource = cfl_list_entry(head, struct ctrace_resource_span, _head);
        cfl_list_del(head);
        cfl_list_add(head, &input->resource_spans);
        resource->ctx = input;
    }

    cfl_list_foreach_safe(head, tmp, &staged->span_list) {
        span = cfl_list_entry(head, struct ctrace_span, _head_global);
        cfl_list_del(head);
        cfl_list_add(head, &input->span_list);
        span->ctx = input;
    }

    input->last_span_id = staged->last_span_id;
    ctr_destroy(staged);
}

int fts_process_traces(struct flb_processor_instance *ins, struct ctrace *input,
                       struct ctrace **output, const char *tag, int tag_len)
{
    struct fts_runtime *ctx = ins->context;
    cfl_sds_t encoded;
    char *buffer = NULL;
    size_t size;
    size_t offset = 0;
    int ret;
    int handled_errors = 0;
    const char *phase = "encode native traces";

    *output = NULL;

    encoded = ctr_encode_opentelemetry_create(input);
    if (!encoded) {
        goto failure;
    }

    phase = "transform span policies";
    ret = fts_telemetry_transform(ins, encoded, cfl_sds_len(encoded), &buffer, &size,
                                  tag, tag_len);
    ctr_encode_opentelemetry_destroy(encoded);
    handled_errors = ret > 0;
    if (ret < 0) {
        goto failure;
    }

    if (size == 0) {
        flb_free(buffer);
        *output = ctr_create(NULL);
        if (!*output) {
            return FLB_PROCESSOR_FAILURE;
        }
        commit_trace(input, *output);
        *output = input;

        if (handled_errors) {
            fts_report_policy_error(ins);
        }
        return FLB_PROCESSOR_SUCCESS;
    }

    phase = "decode transformed traces";
    ret = ctr_decode_opentelemetry_create(output, buffer, size, &offset);
    flb_free(buffer);
    buffer = NULL;
    if (ret != 0 || offset != size || !*output) {
        ctr_destroy(*output);
        *output = NULL;
        goto failure;
    }

    commit_trace(input, *output);
    *output = input;

    if (handled_errors) {
        fts_report_policy_error(ins);
    }

    return FLB_PROCESSOR_SUCCESS;

failure:
    fts_report_policy_error(ins);
    flb_free(buffer);
    flb_plg_error(ins, "cannot construct FTS traces output (%s); edits discarded", phase);

    if (strcmp(ctx->error_mode, "drop") == 0) {
        *output = ctr_create(NULL);
        if (!*output) {
            return FLB_PROCESSOR_FAILURE;
        }
        commit_trace(input, *output);
    }

    *output = input;
    return FLB_PROCESSOR_SUCCESS;
}
