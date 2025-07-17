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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_input_chunk.h>
#include <fluent-bit/flb_input_log.h>
#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_processor.h>


static int input_log_append(struct flb_input_instance *ins,
                            size_t processor_starting_stage,
                            size_t records,
                            const char *tag, size_t tag_len,
                            const void *buf, size_t buf_size)
{
    int ret;
    int processor_is_active;
    void *out_buf = (void *) buf;
    size_t out_size = buf_size;

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
                                FLB_PROCESSOR_LOGS,
                                tag, tag_len,
                                (char *) buf, buf_size,
                                &out_buf, &out_size);
        if (ret == -1) {
            return -1;
        }

        if (out_size == 0) {
            return 0;
        }

        if (buf != out_buf) {
            /* a new buffer was created, re-count the number of records */
            records = flb_mp_count(out_buf, out_size);
        }
    }


    ret = flb_input_chunk_append_raw(ins, FLB_INPUT_LOGS, records,
                                     tag, tag_len, out_buf, out_size);

    /* Only free if processor created a new buffer */
    if (processor_is_active && buf != out_buf) {
        flb_free(out_buf);
    }
    return ret;
}

/* Take a msgpack serialized record and enqueue it as a chunk */
int flb_input_log_append(struct flb_input_instance *ins,
                         const char *tag, size_t tag_len,
                         const void *buf, size_t buf_size)
{
    int ret;
    size_t records;

    records = flb_mp_count(buf, buf_size);
    ret = input_log_append(ins, 0, records, tag, tag_len, buf, buf_size);
    return ret;
}

/* Take a msgpack serialized record and enqueue it as a chunk */
int flb_input_log_append_skip_processor_stages(struct flb_input_instance *ins,
                                               size_t processor_starting_stage,
                                               const char *tag,
                                               size_t tag_len,
                                               const void *buf,
                                               size_t buf_size)
{
    return input_log_append(ins,
                            processor_starting_stage,
                            flb_mp_count(buf, buf_size),
                            tag,
                            tag_len,
                            buf,
                            buf_size);
}

/* Take a msgpack serialized record and enqueue it as a chunk */
int flb_input_log_append_records(struct flb_input_instance *ins,
                                 size_t records,
                                 const char *tag, size_t tag_len,
                                 const void *buf, size_t buf_size)
{
    int ret;

    ret = input_log_append(ins, 0, records, tag, tag_len, buf, buf_size);
    return ret;
}


