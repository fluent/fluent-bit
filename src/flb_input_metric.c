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
#include <fluent-bit/flb_hash_table.h>
#include <fluent-bit/flb_mem.h>
#include <cfl/cfl.h>

struct input_metrics_encoded_context {
    char *buffer;
    size_t size;
};

static void input_metrics_resolve_tag(struct flb_input_instance *ins,
                                      const char **tag, size_t *tag_len)
{
    if (*tag != NULL) {
        return;
    }

    if (ins->tag && ins->tag_len > 0) {
        *tag = ins->tag;
        *tag_len = ins->tag_len;
    }
    else {
        *tag = ins->name;
        *tag_len = strlen(ins->name);
    }
}

static int input_metrics_encode(struct flb_input_instance *ins,
                                size_t processor_starting_stage,
                                const char *tag, size_t tag_len,
                                struct cmt *cmt, char **out_buf,
                                size_t *out_size)
{
    int ret;
    int processor_is_active;
    struct cmt *out_context = NULL;
    struct cmt *encode_context;

    *out_buf = NULL;
    *out_size = 0;

    processor_is_active = flb_processor_is_active(ins->processor);
    if (processor_is_active) {
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
    ret = cmt_encode_msgpack_create(encode_context, out_buf, out_size);

    if (out_context && out_context != cmt) {
        cmt_destroy(out_context);
    }

    if (ret != 0) {
        flb_plg_error(ins, "could not encode metrics");
        return -1;
    }

    return 0;
}

static int input_metrics_append_encoded(struct flb_input_instance *ins,
                                        const char *tag, size_t tag_len,
                                        const char *buf, size_t size,
                                        size_t records)
{
    int ret;

    /*
     * Metrics chunks still need a positive logical event count when they
     * enter the chunk/task pipeline. The record count is the number of encoded
     * contexts in the payload.
     */
    ret = flb_input_chunk_append_raw(ins, FLB_INPUT_METRICS, records,
                                     tag, tag_len, buf, size);

    if (ret == 0 && tag != NULL) {
        void *chunk_ref;

        /*
         * Keep metric chunks short-lived per append. Reusing the same tag-bound
         * metric chunk can delay task creation for rapidly updated series,
         * which makes runtime consumers miss freshly generated metrics.
         */
        pthread_mutex_lock(&ins->metrics_chunk_lock);
        chunk_ref = flb_hash_table_get_ptr(ins->ht_metric_chunks, tag, tag_len);
        if (chunk_ref != NULL) {
            flb_hash_table_del_ptr(ins->ht_metric_chunks,
                                   tag, tag_len, chunk_ref);
        }
        pthread_mutex_unlock(&ins->metrics_chunk_lock);
    }

    return ret;
}

static int input_metrics_append(struct flb_input_instance *ins,
                                size_t processor_starting_stage,
                                const char *tag, size_t tag_len,
                                struct cmt *cmt)
{
    int ret;
    char *mt_buf;
    size_t mt_size;

    input_metrics_resolve_tag(ins, &tag, &tag_len);

    ret = input_metrics_encode(ins, processor_starting_stage,
                               tag, tag_len, cmt, &mt_buf, &mt_size);
    if (ret != 0 || mt_buf == NULL) {
        return ret;
    }

    ret = input_metrics_append_encoded(ins, tag, tag_len, mt_buf, mt_size, 1);
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

int flb_input_metrics_append_list(struct flb_input_instance *ins,
                                  const char *tag, size_t tag_len,
                                  struct cfl_list *contexts)
{
    int ret;
    size_t index;
    size_t count;
    size_t encoded_count;
    size_t total_size;
    char *payload;
    char *write_offset;
    struct cmt *context;
    struct cfl_list *head;
    struct input_metrics_encoded_context *encoded;

    if (contexts == NULL || cfl_list_is_empty(contexts)) {
        return -1;
    }

    input_metrics_resolve_tag(ins, &tag, &tag_len);

    count = cfl_list_size(contexts);
    encoded = flb_calloc(count, sizeof(struct input_metrics_encoded_context));
    if (encoded == NULL) {
        flb_errno();
        return -1;
    }

    index = 0;
    encoded_count = 0;
    total_size = 0;
    cfl_list_foreach(head, contexts) {
        context = cfl_list_entry(head, struct cmt, _head);
        ret = input_metrics_encode(ins, 0, tag, tag_len, context,
                                   &encoded[index].buffer,
                                   &encoded[index].size);
        if (ret != 0) {
            goto cleanup;
        }

        if (encoded[index].buffer != NULL) {
            if (encoded[index].size > SIZE_MAX - total_size) {
                ret = -1;
                goto cleanup;
            }

            total_size += encoded[index].size;
            encoded_count++;
        }
        index++;
    }

    if (total_size == 0) {
        ret = 0;
        goto cleanup;
    }

    payload = flb_malloc(total_size);
    if (payload == NULL) {
        flb_errno();
        ret = -1;
        goto cleanup;
    }

    write_offset = payload;
    for (index = 0; index < count; index++) {
        if (encoded[index].buffer != NULL) {
            memcpy(write_offset, encoded[index].buffer, encoded[index].size);
            write_offset += encoded[index].size;
        }
    }

    ret = input_metrics_append_encoded(ins, tag, tag_len, payload,
                                       total_size, encoded_count);
    flb_free(payload);

cleanup:
    for (index = 0; index < count; index++) {
        if (encoded[index].buffer != NULL) {
            cmt_encode_msgpack_destroy(encoded[index].buffer);
        }
    }
    flb_free(encoded);

    return ret;
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
