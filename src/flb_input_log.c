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

static struct buffer_entry *new_buffer_entry(const void *buf, size_t buf_size)
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
                              struct buffer_entry ***entries)
{
    int ret;
    int encoder_result;
    struct buffer_entry **split_entries;
    void *tmp_encoder_buf;
    size_t tmp_encoder_buf_size;
    size_t split_size = entry->buf_size / 2;
    struct flb_log_event_encoder log_encoder;
    struct flb_log_event_decoder log_decoder;
    struct flb_log_event log_event;
    int entries_processed;

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

    split_entries = flb_calloc(2, sizeof(struct buffer_entry*));

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

        if (log_encoder.output_length >= split_size) {
            tmp_encoder_buf_size = log_encoder.output_length;
            tmp_encoder_buf = flb_malloc(tmp_encoder_buf_size);
            memcpy(tmp_encoder_buf, log_encoder.output_buffer, tmp_encoder_buf_size);
            split_entries[0] = new_buffer_entry(tmp_encoder_buf,
                                                tmp_encoder_buf_size);
            flb_log_event_encoder_claim_internal_buffer_ownership(&log_encoder);
            flb_log_event_encoder_reset(&log_encoder);
        }

        entries_processed++;
    }

    /**
     * Edge case: If only one entry was processed, that means this buffer of data
     * is one entry that exceeds the chunk max size.
     */
    if (entries_processed <= 1) {
        buffer_entry_destroy(split_entries[0]);
        buffer_entry_destroy(split_entries[1]);
        flb_free(split_entries);
        flb_log_event_encoder_destroy(&log_encoder);
        flb_log_event_decoder_destroy(&log_decoder);
        return FLB_FALSE;
    }

    if (log_encoder.output_length >= 0) {
        tmp_encoder_buf_size = log_encoder.output_length;
        tmp_encoder_buf = flb_malloc(tmp_encoder_buf_size);
        memcpy(tmp_encoder_buf, log_encoder.output_buffer, tmp_encoder_buf_size);
        split_entries[1] = new_buffer_entry(tmp_encoder_buf,
                                            tmp_encoder_buf_size);
        flb_log_event_encoder_claim_internal_buffer_ownership(&log_encoder);
    }

    flb_log_event_encoder_destroy(&log_encoder);
    flb_log_event_decoder_destroy(&log_decoder);
    *entries = split_entries;
    return FLB_TRUE;
}


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
    struct mk_list buffers;
    struct mk_list buffers_keep;
    struct mk_list buffers_discard;
    struct mk_list *head;
    struct mk_list *tmp;
    struct buffer_entry *curr_buffer;
    struct buffer_entry **split_entries = flb_calloc(2, sizeof(struct buffer_entry*));
    int all_buffers_sized;
    int something_resized;

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

    flb_info("start with buffer size %zu", buf_size);

    mk_list_init(&buffers);
    curr_buffer = new_buffer_entry(buf, buf_size);
    mk_list_add(&curr_buffer->_head, &buffers);

    all_buffers_sized = FLB_FALSE;
    while (all_buffers_sized != FLB_TRUE) {
        something_resized = FLB_FALSE;
        mk_list_init(&buffers_keep);
        mk_list_init(&buffers_discard);
        mk_list_foreach_safe(head, tmp, &buffers) {
            curr_buffer = mk_list_entry(head, struct buffer_entry, _head);

            if (curr_buffer->buf_size > FLB_INPUT_CHUNK_FS_MAX_SIZE) {
                ret = split_buffer_entry(curr_buffer, &split_entries);
                if (ret == FLB_TRUE) {
                    flb_info("split to size %zu and %zu", split_entries[0]->buf_size, split_entries[1]->buf_size);
                    mk_list_add(&(split_entries[0]->_head), &buffers_keep);
                    mk_list_add(&(split_entries[1]->_head), &buffers_keep);
                    mk_list_add(&curr_buffer->_head, &buffers_discard);
                    something_resized = FLB_TRUE;
                } else {
                    mk_list_add(&curr_buffer->_head, &buffers_keep);
                }
            }
        }

        if (something_resized == FLB_TRUE) {
            mk_list_foreach_safe(head, tmp, &buffers_discard) {
                curr_buffer = mk_list_entry(head, struct buffer_entry, _head);
                buffer_entry_destroy(curr_buffer);
            }
            mk_list_init(&buffers);
            mk_list_foreach_safe(head, tmp, &buffers_keep) {
                curr_buffer = mk_list_entry(head, struct buffer_entry, _head);
                mk_list_add(&curr_buffer->_head, &buffers);
            }
        } else {
            all_buffers_sized = FLB_TRUE;
        }
    }

    mk_list_foreach_safe(head, tmp, &buffers) {
        curr_buffer = mk_list_entry(head, struct buffer_entry, _head);
        flb_info("appending buf size %zu", curr_buffer->buf_size);
        ret = flb_input_chunk_append_raw(ins, FLB_INPUT_LOGS, records,
                                        tag, tag_len, curr_buffer->buf, curr_buffer->buf_size);
    }

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


