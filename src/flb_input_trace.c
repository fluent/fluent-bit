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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_input_chunk.h>
#include <fluent-bit/flb_input_trace.h>
#include <fluent-bit/flb_input_plugin.h>

#include <ctraces/ctraces.h>
#include <ctraces/ctr_decode_msgpack.h>

/*
 * Append a CTrace context into the pipeline. On success, this function returns 0 and -1
 * on error.
 *
 * Note that the memory pointed by the CTrace context will be handled automatically inside
 * this function if the return value is 0, otherwise if is -1, the caller is responsible
 * to destroy the context.
 */

static int input_trace_append(struct flb_input_instance *ins,
                              size_t processor_starting_stage,
                              const char *tag, size_t tag_len,
                              struct ctrace *ctr)
{
    int ret;
    char *out_buf = NULL;
    size_t out_size = 0;
    int processor_is_active;
    struct ctrace *out_context = NULL;

    processor_is_active = flb_processor_is_active(ins->processor);
    if (processor_is_active) {
        if (!tag) {
            if (ins->tag && ins->tag_len > 0) {
                tag = ins->tag;
                tag_len = ins->tag_len;
            }
            else {
                tag = ins->name;
                tag_len = strlen(ins->name);
            }
        }

        ret = flb_processor_run(ins->processor,
                                processor_starting_stage,
                                FLB_PROCESSOR_TRACES,
                                tag, tag_len,
                                (char *) ctr, 0,
                                (void **) &out_context, NULL);
        if (ret == -1) {
            return -1;
        }

        if (out_context == NULL) {
            /*
             * nothing to do: no output context was set (out_context) that means that likely
             * the original CTrace context is being handled by the processor itself. We don't
             * need to destroy it.
             */
            return 0;
        }
    }

    if (out_context) {
        ret = ctr_encode_msgpack_create(out_context, &out_buf, &out_size);
        if (out_context != ctr) {
            ctr_destroy(out_context);
        }
        if (ret != 0) {
            flb_plg_error(ins, "could not encode traces");
            return -1;
        }
    }
    else {
        ret = ctr_encode_msgpack_create(ctr, &out_buf, &out_size);
        if (ret != 0) {
            flb_plg_error(ins, "could not encode traces");
            return -1;
        }
    }

    /* Append packed metrics */
    ret = flb_input_chunk_append_raw(ins, FLB_INPUT_TRACES, 0,
                                     tag, tag_len, out_buf, out_size);

    ctr_encode_msgpack_destroy(out_buf);

    if (ret == 0) {
        /*
         * the CTrace context was processed properly, we need to destroy the contexts: the original
         * and the output one
         */
        if (out_context != NULL && out_context != ctr) {
            ctr_destroy(out_context);
        }

        /* destroy the original context */
        ctr_destroy(ctr);
    }

    return ret;
}

/* Take a CTrace context and enqueue it as a Trace chunk */
int flb_input_trace_append(struct flb_input_instance *ins,
                           const char *tag, size_t tag_len,
                           struct ctrace *ctr)
{
    return input_trace_append(ins,
                              0,
                              tag, tag_len,
                              ctr);
}

/* Take a CTrace context and enqueue it as a Trace chunk */
int flb_input_trace_append_skip_processor_stages(
        struct flb_input_instance *ins,
        size_t processor_starting_stage,
        const char *tag, size_t tag_len,
        struct ctrace *ctr)
{
    return input_trace_append(ins,
                              processor_starting_stage,
                              tag, tag_len,
                              ctr);
}
