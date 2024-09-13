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
#include <fluent-bit/flb_log_event_decoder.h>
#include <fluent-bit/flb_log_event_encoder.h>

#include <monkey/mk_core/mk_list.h>

struct buffer_entry {
    char *buf;
    size_t buf_size;
    struct mk_list _head;
};

static struct buffer_entry *new_buffer_entry(void *buf, size_t buf_size)
{
    struct buffer_entry *new_entry = flb_malloc(sizeof(struct buffer_entry));
    new_entry->buf_size = buf_size;
    new_entry->buf = buf;
    return new_entry;
}

static void buffer_entry_destroy(struct buffer_entry *entry) {
    if (!entry) {
        return;
    }
    if (entry->buf) {
        flb_free(entry->buf);
    }
    mk_list_del(&entry->_head);
    flb_free(entry);
}

static int split_buffer_entry(struct buffer_entry *entry,
                              struct mk_list *entries)
{
    int ret;
    int encoder_result;
    void *tmp_encoder_buf;
    size_t tmp_encoder_buf_size;
    struct flb_log_event_encoder log_encoder;
    struct flb_log_event_decoder log_decoder;
    struct flb_log_event log_event;
    int entries_processed;
    struct buffer_entry *new_buffer;

    ret = flb_log_event_decoder_init(&log_decoder, entry->buf, entry->buf_size);
    if (ret != FLB_EVENT_DECODER_SUCCESS) {
        flb_error("Log event decoder initialization error : %d", ret);

        return FLB_FALSE;
    }

    ret = flb_log_event_encoder_init(&log_encoder,
                                    FLB_LOG_EVENT_FORMAT_DEFAULT);
    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        flb_error("Log event encoder initialization error : %d", ret);

        flb_log_event_decoder_destroy(&log_decoder);

        return FLB_FALSE;
    }

    entries_processed = 0;
    while ((ret = flb_log_event_decoder_next(
                    &log_decoder,
                    &log_event)) == FLB_EVENT_DECODER_SUCCESS) {
        encoder_result = flb_log_event_encoder_begin_record(&log_encoder);
        if (encoder_result == FLB_EVENT_ENCODER_SUCCESS) {
            encoder_result = flb_log_event_encoder_set_timestamp(
                                     &log_encoder, &log_event.timestamp);
        }

        if (encoder_result == FLB_EVENT_ENCODER_SUCCESS) {
            encoder_result = \
                flb_log_event_encoder_set_metadata_from_msgpack_object(
                    &log_encoder, log_event.metadata);
        }

        if (encoder_result == FLB_EVENT_ENCODER_SUCCESS) {
            encoder_result = \
                flb_log_event_encoder_set_body_from_msgpack_object(
                    &log_encoder, log_event.body);
        }

        if (encoder_result == FLB_EVENT_ENCODER_SUCCESS) {
            encoder_result = flb_log_event_encoder_commit_record(&log_encoder);
        }

        if (encoder_result != FLB_EVENT_ENCODER_SUCCESS) {
            flb_error("log event encoder error : %d", encoder_result);
            continue;
        }

        if (log_encoder.output_length >= FLB_INPUT_CHUNK_FS_MAX_SIZE) {
            tmp_encoder_buf_size = log_encoder.output_length;
            tmp_encoder_buf = log_encoder.output_buffer;
            flb_log_event_encoder_claim_internal_buffer_ownership(&log_encoder);
            new_buffer = new_buffer_entry(tmp_encoder_buf, tmp_encoder_buf_size);
            mk_list_add(&new_buffer->_head, entries);
        }

        entries_processed++;
    }

    if (log_encoder.output_length >= 0) {
        tmp_encoder_buf_size = log_encoder.output_length;
        tmp_encoder_buf = flb_malloc(tmp_encoder_buf_size);
        memcpy(tmp_encoder_buf, log_encoder.output_buffer, tmp_encoder_buf_size);
        new_buffer = new_buffer_entry(tmp_encoder_buf, tmp_encoder_buf_size);
        mk_list_add(&new_buffer->_head, entries);
    }

    flb_log_event_encoder_destroy(&log_encoder);
    flb_log_event_decoder_destroy(&log_decoder);
    return FLB_TRUE;
}


static int input_log_append(struct flb_input_instance *ins,
                            size_t processor_starting_stage,
                            size_t records,
                            const char *tag, size_t tag_len,
                            void *buf, size_t buf_size)
{
    int ret;
    int processor_is_active;
    void *out_buf = (void *) buf;
    size_t out_size = buf_size;
    struct mk_list buffers;
    struct mk_list *head;
    struct mk_list *tmp;
    struct buffer_entry *start_buffer;
    struct buffer_entry *iter_buffer;

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

    if (buf_size > FLB_INPUT_CHUNK_FS_MAX_SIZE) {
        mk_list_init(&buffers);
        start_buffer = new_buffer_entry(buf, buf_size);
        split_buffer_entry(start_buffer, &buffers);
        flb_free(start_buffer);
        mk_list_foreach_safe(head, tmp, &buffers) {
            iter_buffer = mk_list_entry(head, struct buffer_entry, _head);
            records = flb_mp_count(iter_buffer->buf, iter_buffer->buf_size);
            ret = flb_input_chunk_append_raw(ins, FLB_INPUT_LOGS, records,
                                            tag, tag_len, iter_buffer->buf, iter_buffer->buf_size);
            buffer_entry_destroy(iter_buffer);
        }
    } else {
        ret = flb_input_chunk_append_raw(ins, FLB_INPUT_LOGS, records,
                                        tag, tag_len, buf, buf_size);
    }

    if (processor_is_active && buf != out_buf) {
        flb_free(out_buf);
    }
    return ret;
}

/* Take a msgpack serialized record and enqueue it as a chunk */
int flb_input_log_append(struct flb_input_instance *ins,
                         const char *tag, size_t tag_len,
                         void *buf, size_t buf_size)
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
                                               void *buf,
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
                                 void *buf, size_t buf_size)
{
    int ret;

    ret = input_log_append(ins, 0, records, tag, tag_len, buf, buf_size);
    return ret;
}


