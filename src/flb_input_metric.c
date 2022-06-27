/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2022 The Fluent Bit Authors
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

/* Take a metric context and enqueue it as a Metric's Chunk */
int flb_input_metrics_append(struct flb_input_instance *ins,
                             const char *tag, size_t tag_len,
                             struct cmt *cmt)
{
    int ret;
    char *mt_buf;
    size_t mt_size;

    /* Convert metrics to msgpack */
    ret = cmt_encode_msgpack_create(cmt, &mt_buf, &mt_size);
    if (ret != 0) {
        flb_plg_error(ins, "could not encode metrics");
        return -1;

    }

    /* Append packed metrics */
    ret = flb_input_chunk_append_raw(ins, tag, tag_len, mt_buf, mt_size);
    cmt_encode_msgpack_destroy(mt_buf);

    return ret;
}
