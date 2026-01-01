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
#include <fluent-bit/flb_input_metric.h>
#include <fluent-bit/flb_input_plugin.h>
#include <cfl/cfl.h>

static int input_metrics_append(struct flb_input_instance *ins,
                                size_t processor_starting_stage,
                                const char *tag, size_t tag_len,
                                struct cmt *cmt)
{
    int ret;
    char *mt_buf;
    size_t mt_size;
    int processor_is_active;
    struct cmt *out_context = NULL;
    struct cmt *encode_context;

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
                                FLB_PROCESSOR_METRICS,
                                tag,
                                tag_len,
                                (char *) cmt, 0,
                                (void **)&out_context, NULL);

        if (ret == -1) {
            return -1;
        }
    }

    if (out_context) {
        encode_context = out_context;
    }
    else {
        encode_context = cmt;
    }

    /* Drop the context if it contains no metrics */
    if (encode_context == NULL || flb_metrics_is_empty(encode_context)) {
        if (out_context && out_context != cmt) {
            cmt_destroy(out_context);
        }
        return 0;
    }

    /* Convert metrics to msgpack */
    ret = cmt_encode_msgpack_create(encode_context, &mt_buf, &mt_size);

    if (out_context && out_context != cmt) {
        cmt_destroy(out_context);
    }

    if (ret != 0) {
        flb_plg_error(ins, "could not encode metrics");
        return -1;
    }

    /* Append packed metrics */
    ret = flb_input_chunk_append_raw(ins, FLB_INPUT_METRICS, 0,
                                     tag, tag_len, mt_buf, mt_size);

    cmt_encode_msgpack_destroy(mt_buf);

    return ret;
}

/* Take a metric context and enqueue it as a Metric's Chunk */
int flb_input_metrics_append(struct flb_input_instance *ins,
                             const char *tag, size_t tag_len,
                             struct cmt *cmt)
{
    return input_metrics_append(ins,
                                0,
                                tag, tag_len,
                                cmt);
}

/* Take a metric context and enqueue it as a Metric's Chunk */
int flb_input_metrics_append_skip_processor_stages(
        struct flb_input_instance *ins,
        size_t processor_starting_stage,
        const char *tag, size_t tag_len,
        struct cmt *cmt)
{
    return input_metrics_append(ins,
                                processor_starting_stage,
                                tag, tag_len,
                                cmt);
}
