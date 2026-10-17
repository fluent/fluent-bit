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
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_mp.h>
#include <fluent-bit/flb_mp_chunk.h>

#include <fluent-bit/flb_slist.h>
#include <fluent-bit/flb_record_accessor.h>
#include <fluent-bit/flb_metrics.h>
#include <fluent-bit/flb_conditionals.h>

#include <fluent-bit/flb_log_event_encoder.h>
#include <fluent-bit/flb_log_event_decoder.h>

#include <cfl/cfl_arena.h>
#include <msgpack.h>
#include <mpack/mpack.h>
#include <ctraces/ctr_decode_msgpack.h>

/* don't do this at home */
#define pack_uint16(buf, d) _msgpack_store16(buf, (uint16_t) d)
#define pack_uint32(buf, d) _msgpack_store32(buf, (uint32_t) d)

/* Return the number of msgpack serialized events in the buffer */
int flb_mp_count(const void *data, size_t bytes)
{
    return flb_mp_count_remaining(data, bytes, NULL);
}

/*
 * Validate a MessagePack value with a read-only traversal: no msgpack object
 * tree or zone is constructed. Unusual or deeper inputs are rejected so the
 * counting API can fall back to the event decoder.
 */
static int scan_log_value(mpack_reader_t *reader, mpack_tag_t tag, int depth)
{
    int ret;
    uint32_t index;
    uint32_t count;
    mpack_tag_t key;

    if (depth >= 64 || mpack_reader_error(reader) != mpack_ok) {
        return -1;
    }

    switch (mpack_tag_type(&tag)) {
    case mpack_type_array:
        count = mpack_tag_array_count(&tag);
        for (index = 0; index < count; index++) {
            ret = scan_log_value(reader, mpack_read_tag(reader), depth + 1);
            if (ret != 0) {
                return -1;
            }
        }
        mpack_done_array(reader);
        break;
    case mpack_type_map:
        count = mpack_tag_map_count(&tag);
        for (index = 0; index < count; index++) {
            key = mpack_read_tag(reader);
            if (scan_log_value(reader, key, depth + 1) != 0) {
                return -1;
            }

            ret = scan_log_value(reader, mpack_read_tag(reader), depth + 1);
            if (ret != 0) {
                return -1;
            }
        }
        mpack_done_map(reader);
        break;
    case mpack_type_str:
        mpack_skip_bytes(reader, mpack_tag_str_length(&tag));
        mpack_done_str(reader);
        break;
    case mpack_type_bin:
        mpack_skip_bytes(reader, mpack_tag_bin_length(&tag));
        mpack_done_bin(reader);
        break;
    case mpack_type_ext:
        mpack_skip_bytes(reader, mpack_tag_ext_length(&tag));
        mpack_done_ext(reader);
        break;
    default:
        break;
    }

    if (mpack_reader_error(reader) != mpack_ok) {
        return -1;
    }

    return 0;
}

int flb_mp_scan_log_records(const void *data, size_t bytes, int *records)
{
    mpack_reader_t reader;
    mpack_tag_t tag;
    msgpack_object timestamp = {0};
    struct flb_time time;
    char extension[8];
    int header;
    int count = 0;
    int ret = -1;

    if (!data && bytes) {
        return -1;
    }

    mpack_reader_init_data(&reader, data, bytes);

    while (mpack_reader_remaining(&reader, NULL) > 0) {
        /* every event is a two entries array: [header|timestamp, body] */
        tag = mpack_read_tag(&reader);
        if (mpack_tag_type(&tag) != mpack_type_array || mpack_tag_array_count(&tag) != 2) {
            goto done;
        }

        /* the header form is [timestamp, metadata] */
        tag = mpack_read_tag(&reader);
        header = mpack_tag_type(&tag) == mpack_type_array;
        if (header) {
            if (mpack_tag_array_count(&tag) != 2) {
                goto done;
            }
            tag = mpack_read_tag(&reader);
        }

        if (mpack_tag_type(&tag) == mpack_type_uint) {
            timestamp.type = MSGPACK_OBJECT_POSITIVE_INTEGER;
            timestamp.via.u64 = mpack_tag_uint_value(&tag);
        }
        else if (mpack_tag_type(&tag) == mpack_type_ext &&
                 mpack_tag_ext_length(&tag) == 8 && mpack_tag_ext_exttype(&tag) == 0) {
            mpack_read_bytes(&reader, extension, sizeof(extension));
            mpack_done_ext(&reader);

            timestamp.type = MSGPACK_OBJECT_EXT;
            timestamp.via.ext.ptr = extension;
            timestamp.via.ext.size = sizeof(extension);
            timestamp.via.ext.type = 0;
        }
        else {
            /* the legacy decoder remains authoritative for float/int timestamps */
            goto done;
        }

        if (mpack_reader_error(&reader) != mpack_ok ||
            flb_log_event_decoder_decode_timestamp(&timestamp, &time) != 0) {
            goto done;
        }

        /* metadata */
        if (header) {
            tag = mpack_read_tag(&reader);
            if (mpack_tag_type(&tag) != mpack_type_map ||
                scan_log_value(&reader, tag, 0) != 0) {
                goto done;
            }
            mpack_done_array(&reader);
        }

        /* body */
        tag = mpack_read_tag(&reader);
        if (mpack_tag_type(&tag) != mpack_type_map ||
            scan_log_value(&reader, tag, 0) != 0) {
            goto done;
        }
        mpack_done_array(&reader);

        if (mpack_reader_error(&reader) != mpack_ok) {
            goto done;
        }

        /* group markers are not counted as records */
        if (time.tm.tv_sec == FLB_LOG_EVENT_GROUP_START ||
            time.tm.tv_sec == FLB_LOG_EVENT_GROUP_END) {
            continue;
        }
        else if (flb_time_is_valid_eventtime(&time) == FLB_TRUE && count < INT_MAX) {
            count++;
        }
        else {
            goto done;
        }
    }

    *records = count;
    ret = 0;

done:
    /*
     * Flag an error on early exits so the reader does not complain about
     * unfinished compound types when it is destroyed.
     */
    if (ret != 0) {
        mpack_reader_flag_error(&reader, mpack_error_invalid);
    }
    mpack_reader_destroy(&reader);

    return ret;
}

/* Return the number of log events excluding group markers */
int flb_mp_count_log_records(const void *data, size_t bytes)
{
    int count;
    int ret;
    struct flb_log_event log_event;
    struct flb_log_event_decoder decoder;

    if (flb_mp_scan_log_records(data, bytes, &count) == 0) {
        return count;
    }

    count = 0;

    ret = flb_log_event_decoder_init(&decoder, (char *) data, bytes);
    if (ret != FLB_EVENT_DECODER_SUCCESS) {
        return 0;
    }

    while ((ret = flb_log_event_decoder_next(&decoder,
                                             &log_event)) == FLB_EVENT_DECODER_SUCCESS) {
        count++;
    }

    flb_log_event_decoder_destroy(&decoder);

    return count;
}

/* TRUE when the event starting at 'data' is a group end marker */
static int log_event_is_group_end(const char *data, size_t bytes)
{
    mpack_reader_t reader;
    mpack_tag_t tag;
    msgpack_object timestamp = {0};
    struct flb_time time;
    char extension[8];
    int result = FLB_FALSE;

    mpack_reader_init_data(&reader, data, bytes);

    tag = mpack_read_tag(&reader);
    if (mpack_tag_type(&tag) == mpack_type_array && mpack_tag_array_count(&tag) == 2) {
        tag = mpack_read_tag(&reader);
        if (mpack_tag_type(&tag) == mpack_type_array && mpack_tag_array_count(&tag) == 2) {
            tag = mpack_read_tag(&reader);
        }

        /* group markers always use the EventTime extension */
        if (mpack_tag_type(&tag) == mpack_type_ext &&
            mpack_tag_ext_length(&tag) == 8 && mpack_tag_ext_exttype(&tag) == 0) {
            mpack_read_bytes(&reader, extension, sizeof(extension));
            if (mpack_reader_error(&reader) == mpack_ok) {
                timestamp.type = MSGPACK_OBJECT_EXT;
                timestamp.via.ext.ptr = extension;
                timestamp.via.ext.size = sizeof(extension);
                timestamp.via.ext.type = 0;
                result = flb_log_event_decoder_decode_timestamp(&timestamp, &time) == 0 &&
                         time.tm.tv_sec == FLB_LOG_EVENT_GROUP_END;
            }
        }
    }

    /* only the event header was read */
    mpack_reader_flag_error(&reader, mpack_error_invalid);
    mpack_reader_destroy(&reader);

    return result;
}

/*
 * Find the end of the log window starting at 'offset'. A window closes after
 * 'limit_bytes' of serialized events or 'limit_records' log records, but only
 * outside a group: every group stays whole within one window, which can exceed
 * the limits by up to one group.
 */
int flb_mp_log_window_next(const void *data, size_t bytes, size_t offset,
                           size_t limit_bytes, int limit_records,
                           size_t *window_end, int *window_records)
{
    mpack_reader_t reader;
    mpack_tag_t tag;
    msgpack_object timestamp = {0};
    struct flb_time time;
    char extension[8];
    size_t position = 0;
    int header;
    int records = 0;
    int in_group = FLB_FALSE;
    int ret = -1;

    if (!data || !window_end || !window_records || offset >= bytes) {
        return -1;
    }

    mpack_reader_init_data(&reader, (const char *) data + offset, bytes - offset);

    while (mpack_reader_remaining(&reader, NULL) > 0) {
        /* every event is a two entries array: [header|timestamp, body] */
        tag = mpack_read_tag(&reader);
        if (mpack_tag_type(&tag) != mpack_type_array || mpack_tag_array_count(&tag) != 2) {
            goto done;
        }

        /* the header form is [timestamp, metadata] */
        tag = mpack_read_tag(&reader);
        header = mpack_tag_type(&tag) == mpack_type_array;
        if (header) {
            if (mpack_tag_array_count(&tag) != 2) {
                goto done;
            }
            tag = mpack_read_tag(&reader);
        }

        if (mpack_tag_type(&tag) == mpack_type_uint) {
            timestamp.type = MSGPACK_OBJECT_POSITIVE_INTEGER;
            timestamp.via.u64 = mpack_tag_uint_value(&tag);
        }
        else if (mpack_tag_type(&tag) == mpack_type_double) {
            timestamp.type = MSGPACK_OBJECT_FLOAT;
            timestamp.via.f64 = mpack_tag_double_value(&tag);
        }
        else if (mpack_tag_type(&tag) == mpack_type_float) {
            timestamp.type = MSGPACK_OBJECT_FLOAT;
            timestamp.via.f64 = mpack_tag_float_value(&tag);
        }
        else if (mpack_tag_type(&tag) == mpack_type_ext &&
                 mpack_tag_ext_length(&tag) == 8 && mpack_tag_ext_exttype(&tag) == 0) {
            mpack_read_bytes(&reader, extension, sizeof(extension));
            mpack_done_ext(&reader);

            timestamp.type = MSGPACK_OBJECT_EXT;
            timestamp.via.ext.ptr = extension;
            timestamp.via.ext.size = sizeof(extension);
            timestamp.via.ext.type = 0;
        }
        else {
            goto done;
        }

        if (header) {
            mpack_discard(&reader);
            mpack_done_array(&reader);
        }

        /* body */
        mpack_discard(&reader);
        mpack_done_array(&reader);

        if (mpack_reader_error(&reader) != mpack_ok ||
            flb_log_event_decoder_decode_timestamp(&timestamp, &time) != 0) {
            goto done;
        }

        if (time.tm.tv_sec == FLB_LOG_EVENT_GROUP_START) {
            in_group = FLB_TRUE;
        }
        else if (time.tm.tv_sec == FLB_LOG_EVENT_GROUP_END) {
            in_group = FLB_FALSE;
        }
        else if (records < INT_MAX) {
            records++;
        }

        position = (bytes - offset) - mpack_reader_remaining(&reader, NULL);

        /*
         * Never start the next window with an end marker: per window it would
         * look like the end of a group opened by a previous append.
         */
        if (!in_group && (position >= limit_bytes || records >= limit_records) &&
            (offset + position >= bytes ||
             !log_event_is_group_end((const char *) data + offset + position,
                                     bytes - offset - position))) {
            break;
        }
    }

    if (position > 0) {
        *window_end = offset + position;
        *window_records = records;
        ret = 0;
    }

done:
    /* flag early exits so unfinished compound types are not reported */
    if (ret != 0) {
        mpack_reader_flag_error(&reader, mpack_error_invalid);
    }
    if (mpack_reader_destroy(&reader) != mpack_ok) {
        ret = -1;
    }

    return ret;
}

struct flb_mp_record_span {
    const char *base;
    size_t length;
    int type;
    int keep;
};

int flb_mp_normalize_log_buffer_groups_msgpack(const void *in_buf, size_t in_size,
                                               char **out_buf, size_t *out_size)
{
    int i;
    int ret;
    int entry_count;
    int stack_count;
    int *group_stack;
    int *group_has_content;
    struct flb_log_event log_event;
    struct flb_log_event_decoder decoder;
    struct flb_mp_record_span *entries;
    msgpack_sbuffer mp_sbuf;

    *out_buf = NULL;
    *out_size = 0;

    entry_count = flb_mp_count(in_buf, in_size);
    if (entry_count <= 0) {
        return 0;
    }

    entries = flb_calloc(entry_count, sizeof(struct flb_mp_record_span));
    if (entries == NULL) {
        flb_errno();
        return -1;
    }

    group_stack = flb_calloc(entry_count, sizeof(int));
    if (group_stack == NULL) {
        flb_errno();
        flb_free(entries);
        return -1;
    }

    group_has_content = flb_calloc(entry_count, sizeof(int));
    if (group_has_content == NULL) {
        flb_errno();
        flb_free(group_stack);
        flb_free(entries);
        return -1;
    }

    ret = flb_log_event_decoder_init(&decoder, (char *) in_buf, in_size);
    if (ret != FLB_EVENT_DECODER_SUCCESS) {
        flb_free(group_has_content);
        flb_free(group_stack);
        flb_free(entries);
        return -1;
    }

    ret = flb_log_event_decoder_read_groups(&decoder, FLB_TRUE);
    if (ret != FLB_EVENT_DECODER_SUCCESS) {
        flb_log_event_decoder_destroy(&decoder);
        flb_free(group_has_content);
        flb_free(group_stack);
        flb_free(entries);
        return -1;
    }

    i = 0;
    while (i < entry_count &&
           (ret = flb_log_event_decoder_next(&decoder, &log_event)) ==
           FLB_EVENT_DECODER_SUCCESS) {
        entries[i].base = decoder.record_base;
        entries[i].length = decoder.record_length;
        entries[i].keep = FLB_TRUE;

        ret = flb_log_event_decoder_get_record_type(&log_event,
                                                    &entries[i].type);
        if (ret != FLB_EVENT_DECODER_SUCCESS) {
            entries[i].type = FLB_LOG_EVENT_NORMAL;
        }

        i++;
    }

    flb_log_event_decoder_destroy(&decoder);

    entry_count = i;
    if (entry_count == 0) {
        flb_free(group_has_content);
        flb_free(group_stack);
        flb_free(entries);
        return 0;
    }

    stack_count = 0;

    for (i = 0; i < entry_count; i++) {
        if (entries[i].type == FLB_LOG_EVENT_GROUP_START) {
            group_stack[stack_count] = i;
            group_has_content[stack_count] = FLB_FALSE;
            stack_count++;
            continue;
        }

        if (entries[i].type == FLB_LOG_EVENT_GROUP_END) {
            if (stack_count == 0) {
                entries[i].keep = FLB_FALSE;
                continue;
            }

            stack_count--;

            if (group_has_content[stack_count] == FLB_FALSE) {
                entries[group_stack[stack_count]].keep = FLB_FALSE;
                entries[i].keep = FLB_FALSE;
            }
            else if (stack_count > 0) {
                group_has_content[stack_count - 1] = FLB_TRUE;
            }

            continue;
        }

        if (stack_count > 0) {
            group_has_content[stack_count - 1] = FLB_TRUE;
        }
    }

    while (stack_count > 0) {
        stack_count--;
        entries[group_stack[stack_count]].keep = FLB_FALSE;
    }

    msgpack_sbuffer_init(&mp_sbuf);

    for (i = 0; i < entry_count; i++) {
        if (entries[i].keep != FLB_TRUE) {
            continue;
        }

        msgpack_sbuffer_write(&mp_sbuf, entries[i].base, entries[i].length);
    }

    if (mp_sbuf.size > 0) {
        *out_buf = mp_sbuf.data;
        *out_size = mp_sbuf.size;
    }
    else {
        msgpack_sbuffer_destroy(&mp_sbuf);
    }

    flb_free(group_has_content);
    flb_free(group_stack);
    flb_free(entries);

    return 0;
}

int flb_mp_normalize_log_buffer_groups(const void *in_buf, size_t in_size,
                                       char **out_buf, size_t *out_size)
{
    int ret;
    char *encoded_buf;
    size_t encoded_size;
    struct flb_log_event_decoder *log_decoder;
    struct flb_log_event_encoder *log_encoder;
    struct flb_mp_chunk_cobj *chunk_cobj;
    struct flb_mp_chunk_record *record;

    *out_buf = NULL;
    *out_size = 0;

    log_decoder = flb_log_event_decoder_create((char *) in_buf, in_size);
    if (log_decoder == NULL) {
        return -1;
    }

    ret = flb_log_event_decoder_read_groups(log_decoder, FLB_TRUE);
    if (ret != FLB_EVENT_DECODER_SUCCESS) {
        flb_log_event_decoder_destroy(log_decoder);
        return -1;
    }

    log_encoder = flb_log_event_encoder_create(FLB_LOG_EVENT_FORMAT_DEFAULT);
    if (log_encoder == NULL) {
        flb_log_event_decoder_destroy(log_decoder);
        return -1;
    }

    chunk_cobj = flb_mp_chunk_cobj_create(log_encoder, log_decoder);
    if (chunk_cobj == NULL) {
        flb_log_event_encoder_destroy(log_encoder);
        flb_log_event_decoder_destroy(log_decoder);
        return -1;
    }

    while ((ret = flb_mp_chunk_cobj_record_next(chunk_cobj, &record)) ==
           FLB_MP_CHUNK_RECORD_OK) {
        (void) record;
    }

    if (ret != FLB_MP_CHUNK_RECORD_EOF) {
        flb_mp_chunk_cobj_destroy(chunk_cobj);
        flb_log_event_encoder_destroy(log_encoder);
        flb_log_event_decoder_destroy(log_decoder);
        return -1;
    }

    ret = flb_mp_chunk_cobj_normalize_groups(chunk_cobj);
    if (ret != 0) {
        flb_mp_chunk_cobj_destroy(chunk_cobj);
        flb_log_event_encoder_destroy(log_encoder);
        flb_log_event_decoder_destroy(log_decoder);
        return -1;
    }

    if (cfl_list_size(&chunk_cobj->records) == 0) {
        flb_mp_chunk_cobj_destroy(chunk_cobj);
        flb_log_event_encoder_destroy(log_encoder);
        flb_log_event_decoder_destroy(log_decoder);
        return 0;
    }

    ret = flb_mp_chunk_cobj_encode(chunk_cobj, &encoded_buf, &encoded_size);
    if (ret != 0) {
        flb_mp_chunk_cobj_destroy(chunk_cobj);
        flb_log_event_encoder_destroy(log_encoder);
        flb_log_event_decoder_destroy(log_decoder);
        return -1;
    }

    *out_buf = encoded_buf;
    *out_size = encoded_size;

    flb_mp_chunk_cobj_destroy(chunk_cobj);
    flb_log_event_encoder_destroy(log_encoder);
    flb_log_event_decoder_destroy(log_decoder);

    return 0;
}

int flb_mp_count_remaining(const void *data, size_t bytes, size_t *remaining_bytes)
{
    size_t remaining = 0;
    int count = 0;
    mpack_reader_t reader;

    if (data) {
        mpack_reader_init_data(&reader, (const char *) data, bytes);
        for (;;) {
            remaining = mpack_reader_remaining(&reader, NULL);
            if (!remaining) {
                break;
            }
            mpack_discard(&reader);
            if (mpack_reader_error(&reader)) {
                break;
            }
            count++;
        }
        mpack_reader_destroy(&reader);
    }

    if (remaining_bytes) {
        *remaining_bytes = remaining;
    }
    return count;
}

int flb_mp_validate_metric_chunk(const void *data, size_t bytes,
                                 int *out_series, size_t *processed_bytes)
{
    int ret;
    int ok = CMT_DECODE_MSGPACK_SUCCESS;
    int count = 0;
    size_t off = 0;
    size_t pre_off = 0;
    struct cmt *cmt;

    while ((ret = cmt_decode_msgpack_create(&cmt,
                                            (char *) data, bytes, &off)) == ok) {
        cmt_destroy(cmt);
        count++;
        pre_off = off;
    }

    switch (ret) {
        case CMT_DECODE_MSGPACK_INVALID_ARGUMENT_ERROR:
        case CMT_DECODE_MSGPACK_CORRUPT_INPUT_DATA_ERROR:
        case CMT_DECODE_MSGPACK_CONSUME_ERROR:
        case CMT_DECODE_MSGPACK_ENGINE_ERROR:
        case CMT_DECODE_MSGPACK_PENDING_MAP_ENTRIES:
        case CMT_DECODE_MSGPACK_PENDING_ARRAY_ENTRIES:
        case CMT_DECODE_MSGPACK_UNEXPECTED_KEY_ERROR:
        case CMT_DECODE_MSGPACK_UNEXPECTED_DATA_TYPE_ERROR:
        case CMT_DECODE_MSGPACK_DICTIONARY_LOOKUP_ERROR:
        case CMT_DECODE_MSGPACK_VERSION_ERROR:
            goto error;
    }

    if (ret == CMT_DECODE_MSGPACK_INSUFFICIENT_DATA && off == bytes) {
        *out_series = count;
        *processed_bytes = pre_off;
        return 0;
    }

error:
    *out_series = count;
    *processed_bytes = pre_off;

    return -1;
}

int flb_mp_validate_trace_chunk(const void *data, size_t bytes,
                                int *out_contexts, size_t *processed_bytes)
{
    int ret;
    int count;
    size_t offset;
    struct ctrace *trace;

    count = 0;
    offset = 0;
    *out_contexts = 0;
    *processed_bytes = 0;

    while (offset < bytes) {
        ret = ctr_decode_msgpack_create(&trace, (char *) data, bytes, &offset);
        if (ret != CTR_DECODE_MSGPACK_SUCCESS) {
            return -1;
        }
        ctr_destroy(trace);
        count++;
        *out_contexts = count;
        *processed_bytes = offset;
    }

    return 0;
}

int flb_mp_validate_log_chunk(const void *data, size_t bytes,
                              int *out_records, size_t *processed_bytes)
{
    int ret;
    int count = 0;
    size_t off = 0;
    size_t pre_off = 0;
    size_t ptr_size;
    unsigned char *ptr;
    msgpack_object array;
    msgpack_object ts;
    msgpack_object header;
    msgpack_object record;
    msgpack_object metadata;
    msgpack_unpacked result;

    msgpack_unpacked_init(&result);
    while (msgpack_unpack_next(&result, data, bytes, &off) == MSGPACK_UNPACK_SUCCESS) {
        array = result.data;

        if (array.type != MSGPACK_OBJECT_ARRAY) {
            /*
             * Sometimes there is a special case: Chunks might have extra zero
             * bytes at the end of a record, meaning: no more records. This is not
             * an error and actually it happens if a previous run of Fluent Bit
             * was stopped/killed before to adjust the file size.
             *
             * Just validate if all bytes are zero, if so, adjust counters
             * and return zero.
             */
            ptr = (unsigned char *) (data);
            ptr += pre_off;
            if (ptr[0] != 0) {
                goto error;
            }

            ptr_size = bytes - pre_off;
            ret = memcmp(ptr, ptr + 1, ptr_size - 1);
            if (ret == 0) {
                /*
                 * The chunk is valid, just let the caller know the last processed
                 * valid byte.
                 */
                msgpack_unpacked_destroy(&result);
                *out_records = count;
                *processed_bytes = pre_off;
                return 0;
            }
            goto error;
        }

        if (array.via.array.size != 2) {
            goto error;
        }

        header = array.via.array.ptr[0];
        record = array.via.array.ptr[1];

        if (header.type == MSGPACK_OBJECT_ARRAY) {
            if (header.via.array.size != 2) {
                goto error;
            }

            ts = header.via.array.ptr[0];
            metadata = header.via.array.ptr[1];

            if (metadata.type != MSGPACK_OBJECT_MAP) {
                goto error;
            }
        }
        else {
            ts = header;
        }

        if (ts.type != MSGPACK_OBJECT_POSITIVE_INTEGER &&
            ts.type != MSGPACK_OBJECT_FLOAT &&
            ts.type != MSGPACK_OBJECT_EXT &&
            ts.type != MSGPACK_OBJECT_NEGATIVE_INTEGER) {
            goto error;
        }

        if (ts.type == MSGPACK_OBJECT_NEGATIVE_INTEGER &&
            ts.via.i64 != FLB_LOG_EVENT_GROUP_START &&
            ts.via.i64 != FLB_LOG_EVENT_GROUP_END) {
            goto error;
        }

        if (record.type != MSGPACK_OBJECT_MAP) {
            goto error;
        }

        count++;
        pre_off = off;
    }

    msgpack_unpacked_destroy(&result);
    *out_records = count;
    *processed_bytes = pre_off;
    return 0;

 error:
    msgpack_unpacked_destroy(&result);
    *out_records = count;
    *processed_bytes = pre_off;

    return -1;
}

/* Adjust a mspack header buffer size */
void flb_mp_set_map_header_size(char *buf, int size)
{
    uint8_t h;
    char *tmp = buf;

    h = tmp[0];
    if (h >> 4 == 0x8) { /* 1000xxxx */
        *tmp = (uint8_t) 0x8 << 4 | ((uint8_t) size);
    }
    else if (h == 0xde) {
        tmp++;
        pack_uint16(tmp, size);
    }
    else if (h == 0xdf) {
        tmp++;
        pack_uint32(tmp, size);
    }
}

void flb_mp_set_array_header_size(char *buf, int size)
{
    uint8_t h;
    char *tmp = buf;

    h = tmp[0];
    if (h >> 4 == 0x9) { /* 1001xxxx */
        *tmp = (uint8_t) 0x9 << 4 | ((uint8_t) size);
    }
    else if (h == 0xdc) {
        tmp++;
        pack_uint16(tmp, size);
    }
    else if (h == 0xdd) {
        tmp++;
        pack_uint32(tmp, size);
    }
}

/*
 * msgpack-c requires to set the number of the entries in a map beforehand. For our
 * use case this adds some complexity, having developers to count all possible
 * entries that might be added.
 *
 * As a workaround and to avoid map's recomposition over and over, this simple API
 * allows to initialize the array header, 'register' new entries (as counters) and
 * finalize, upon finalization the proper array header size is adjusted.
 *
 * To make things easier, we make sure msgpack-c always register an array type of
 * 32 bits (identified by 0xdf, for number of entries >= 65536). Yes, for every
 * array using this API it will use 2 more bytes, not a big ideal. So whoever
 * uses this API, use it only if you don't know the exact number of entries to add.
 *
 * MANDATORY: make sure to always initialize, register every entry and finalize,
 * otherwise you will get a corrupted or incomplete msgpack buffer.
 *
 * Usage example
 * =============
 *
 *  struct flb_mp_map_header mh;
 *
 *  flb_mp_map_header_init(&mh, mp_pck);
 *
 *  -- First key/value entry --
 *  flb_mp_map_header_append(&mh);
 *  msgpack_pack_str(mp_pck, 4);
 *  msgpack_pack_str_body(mp_pck, "cool", 4);
 *  msgpack_pack_true(mp_pck);
 *
 *  -- Second key/value entry --
 *  flb_mp_map_header_append(&mh);
 *  msgpack_pack_str(mp_pck, 4);
 *  msgpack_pack_str_body(mp_pck, "slow", 4);
 *  msgpack_pack_false(mp_pck);
 *
 *  -- Finalize Map --
 *  flb_mp_map_header_end(&mh);
 */

static inline void mp_header_type_init(struct flb_mp_map_header *mh,
                                       msgpack_packer *mp_pck,
                                       int type)
{
    msgpack_sbuffer *mp_sbuf;

    mp_sbuf = (msgpack_sbuffer *) mp_pck->data;

    /* map sbuffer */
    mh->data = mp_pck->data;

    /* Reset entries */
    mh->entries = 0;

    /* Store the next byte available */
    mh->offset = mp_sbuf->size;
}

int flb_mp_map_header_init(struct flb_mp_map_header *mh, msgpack_packer *mp_pck)
{
    /* Initialize context for a map */
    mp_header_type_init(mh, mp_pck, FLB_MP_MAP);

    /*
     * Pack a map with size = 65536, so we force the underlaying msgpack-c
     * to use a 32 bit buffer size (0xdf), reference:
     *
     * - https://github.com/msgpack/msgpack/blob/master/spec.md#map-format-family
     */
    return msgpack_pack_map(mp_pck, 65536);
}

int flb_mp_array_header_init(struct flb_mp_map_header *mh, msgpack_packer *mp_pck)
{
    /* Initialize context for a map */
    mp_header_type_init(mh, mp_pck, FLB_MP_ARRAY);

    /*
     * Pack a map with size = 65536, so we force the underlaying msgpack-c
     * to use a 32 bit buffer size (0xdf), reference:
     *
     * - https://github.com/msgpack/msgpack/blob/master/spec.md#map-format-family
     */
    return msgpack_pack_array(mp_pck, 65536);
}


int flb_mp_map_header_append(struct flb_mp_map_header *mh)
{
    mh->entries++;
    return mh->entries;
}

int flb_mp_array_header_append(struct flb_mp_map_header *mh)
{
    mh->entries++;
    return mh->entries;
}

void flb_mp_map_header_end(struct flb_mp_map_header *mh)
{
    char *ptr;
    msgpack_sbuffer *mp_sbuf;

    mp_sbuf = mh->data;
    ptr = (char *) mp_sbuf->data + mh->offset;
    flb_mp_set_map_header_size(ptr, mh->entries);
}

void flb_mp_array_header_end(struct flb_mp_map_header *mh)
{
    char *ptr;
    msgpack_sbuffer *mp_sbuf;

    mp_sbuf = mh->data;
    ptr = (char *) mp_sbuf->data + mh->offset;
    flb_mp_set_array_header_size(ptr, mh->entries);
}

static int insert_by_subkey_count(struct flb_record_accessor *ra, struct flb_mp_accessor *mpa)
{
    int subkey_count;
    int count;
    struct mk_list *head;
    struct flb_mp_accessor_ra *val_ra;
    struct flb_mp_accessor_ra *mp_ra;

    mp_ra = flb_calloc(1, sizeof(struct flb_mp_accessor_ra));
    if (!mp_ra) {
        flb_errno();
        return -1;
    }
    mp_ra->is_active = FLB_TRUE;
    mp_ra->ra = ra;

    /*
     * sort flb_record_accessor by number of subkey
     *
     *  e.g.
     *    $kubernetes
     *    $kubernetes[2]['a']
     *    $kubernetes[2]['annotations']['fluentbit.io/tag']
     */
    subkey_count = flb_ra_subkey_count(ra);
    mk_list_foreach(head, &mpa->ra_list) {
        val_ra = mk_list_entry(head, struct flb_mp_accessor_ra, _head);
        count = flb_ra_subkey_count(val_ra->ra);
        if (count >=  subkey_count) {
            mk_list_add_before(&mp_ra->_head, &val_ra->_head, &mpa->ra_list);
            return 0;
        }
    }

    /* add to tail of list */
    mk_list_add(&mp_ra->_head, &mpa->ra_list);
    return 0;
}

/* Set the active status for all record accessor patterns */
void flb_mp_accessor_set_active(struct flb_mp_accessor *mpa, int status)
{
    struct mk_list *head;
    struct flb_mp_accessor_ra *mp_ra;

    mk_list_foreach(head, &mpa->ra_list) {
        mp_ra = mk_list_entry(head, struct flb_mp_accessor_ra, _head);
        mp_ra->is_active = status;
    }
}

/* Set the active status for a specific record accessor pattern */
int flb_mp_accessor_set_active_by_pattern(struct flb_mp_accessor *mpa,
                                          const char *pattern, int status)
{
    int len;
    struct mk_list *head;
    struct flb_mp_accessor_ra *mp_ra;

    len = strlen(pattern);

    mk_list_foreach(head, &mpa->ra_list) {
        mp_ra = mk_list_entry(head, struct flb_mp_accessor_ra, _head);

        if (len != flb_sds_len(mp_ra->ra->pattern)) {
            continue;
        }

        if (strcmp(mp_ra->ra->pattern, pattern) == 0) {
            mp_ra->is_active = status;
            return 0;
        }
    }

    return -1;
}

/*
 * Create an 'mp accessor' context: this context allows to create a list of
 * record accessor patterns based on a 'slist' context, where every slist string
 * buffer represents a key accessor.
 */
struct flb_mp_accessor *flb_mp_accessor_create(struct mk_list *slist_patterns)
{
    size_t size;
    struct mk_list *head;
    struct flb_slist_entry *entry;
    struct flb_record_accessor *ra;
    struct flb_mp_accessor *mpa;

    /* Allocate context */
    mpa = flb_calloc(1, sizeof(struct flb_mp_accessor));
    if (!mpa) {
        flb_errno();
        return NULL;
    }
    mk_list_init(&mpa->ra_list);

    mk_list_foreach(head, slist_patterns) {
        entry = mk_list_entry(head, struct flb_slist_entry, _head);

        /* Create the record accessor context */
        ra = flb_ra_create(entry->str, FLB_TRUE);
        if (!ra) {
            flb_error("[mp accessor] could not create entry for pattern '%s'",
                      entry->str);
            flb_mp_accessor_destroy(mpa);
            return NULL;
        }
        insert_by_subkey_count(ra, mpa);
    }

    if (mk_list_size(&mpa->ra_list) == 0) {
        return mpa;
    }

    size = sizeof(struct flb_mp_accessor_match) * mk_list_size(&mpa->ra_list);
    mpa->matches_size = size;
    mpa->matches = flb_calloc(1, size);
    if (!mpa->matches) {
        flb_errno();
        flb_mp_accessor_destroy(mpa);
        return NULL;
    }

    return mpa;
}

/**
 * Finds matches for a given key in the list of record accessor patterns.
 * Stores the indexes of the matches in the provided array.
 *
 * @return The number of matches found.
 */
static inline int accessor_key_find_matches(struct flb_mp_accessor *mpa,
                                            msgpack_object *key,
                                            int* matched_indexes)
{
    int i;
    int count;
    int match_count = 0;
    int out_index = 0;
    struct flb_mp_accessor_match *match;

    count = mk_list_size(&mpa->ra_list);
    for (i = 0; i < count; i++) {
        match = &mpa->matches[i];
        if (match->matched == FLB_FALSE) {
            continue;
        }

        if (match->start_key == key) {
            match_count++;
            matched_indexes[out_index++] = i;
        }
    }

    return match_count;
}

static inline int accessor_sub_pack(struct flb_mp_accessor *mpa,
                                    int* matched_indexes,
                                    int match_count,
                                    msgpack_packer *mp_pck,
                                    msgpack_object *key,
                                    msgpack_object *val)
{
    int i;
    int ret;
    msgpack_object *k;
    msgpack_object *v;
    struct flb_mp_map_header mh;
    struct flb_mp_accessor_match *match;

    for (i = 0; i < match_count; i++) {
        match = &mpa->matches[matched_indexes[i]];
        if (match->key == key || match->key == val) {
            return FLB_FALSE;
        }
    }

    if (key) {
        msgpack_pack_object(mp_pck, *key);
    }

    if (val->type == MSGPACK_OBJECT_MAP) {
        flb_mp_map_header_init(&mh, mp_pck);
        for (i = 0; i < val->via.map.size; i++) {
            k = &val->via.map.ptr[i].key;
            v = &val->via.map.ptr[i].val;

            ret = accessor_sub_pack(mpa, matched_indexes, match_count, mp_pck, k, v);
            if (ret == FLB_TRUE) {
                flb_mp_map_header_append(&mh);
            }
        }
        flb_mp_map_header_end(&mh);
    }
    else if (val->type == MSGPACK_OBJECT_ARRAY) {
        flb_mp_array_header_init(&mh, mp_pck);
        for (i = 0; i < val->via.array.size; i++) {
            v = &val->via.array.ptr[i];
            ret = accessor_sub_pack(mpa, matched_indexes, match_count, mp_pck, NULL, v);
            if (ret == FLB_TRUE) {
                flb_mp_array_header_append(&mh);
            }
        }
        flb_mp_array_header_end(&mh);
    }
    else {
        msgpack_pack_object(mp_pck, *val);
    }

    return FLB_TRUE;
}

/*
 * Remove keys or nested keys from a map. It compose the final result in a
 * new buffer. On error, it returns -1, if the map was modified it returns FLB_TRUE,
 * if no modification was required it returns FLB_FALSE.
 */
int flb_mp_accessor_keys_remove(struct flb_mp_accessor *mpa,
                                msgpack_object *map,
                                void **out_buf, size_t *out_size)
{
    int i;
    int ret;
    int rule_id = 0;
    int matches = 0;
    int* matched_indexes;
    msgpack_object *key;
    msgpack_object *val;
    msgpack_object *s_key;
    msgpack_object *o_key;
    msgpack_object *o_val;
    struct mk_list *head;
    struct flb_mp_accessor_match *match;
    struct flb_mp_accessor_ra *mp_ra;
    struct flb_mp_map_header mh;
    msgpack_sbuffer mp_sbuf;
    msgpack_packer mp_pck;

    if (map->via.map.size == 0) {
        return FLB_FALSE;
    }

    /* Reset matches cache */
    memset(mpa->matches, '\0', mpa->matches_size);

    mk_list_foreach(head, &mpa->ra_list) {
        mp_ra = mk_list_entry(head, struct flb_mp_accessor_ra, _head);

        if (mp_ra->is_active == FLB_FALSE) {
            rule_id++;
            continue;
        }

        /* Apply the record accessor rule against the map */
        ret = flb_ra_get_kv_pair(mp_ra->ra, *map, &s_key, &o_key, &o_val);
        if (ret == 0) {
            /* There is a match, register in the matches table */
            match = &mpa->matches[rule_id];
            match->matched = FLB_TRUE;
            match->start_key = s_key;        /* Initial key path that matched */
            match->key = o_key;              /* Final key that matched */
            match->val = o_val;              /* Final value */
            match->ra = mp_ra->ra;           /* Record accessor context */
            matches++;
        }
        rule_id++;
    }

    /* If no matches, no modifications were made */
    if (matches == 0) {
        return FLB_FALSE;
    }

    /* Some rules matched, compose a new outgoing buffer */
    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    /* Initialize map */
    flb_mp_map_header_init(&mh, &mp_pck);

    /* Initialize array of matching indexes to properly handle sibling keys */
    matched_indexes = flb_malloc(sizeof(int) * matches);
    if (!matched_indexes) {
        flb_errno();
        return -1;
    }

    for (i = 0; i < map->via.map.size; i++) {
        key = &map->via.map.ptr[i].key;
        val = &map->via.map.ptr[i].val;

        /*
         * For every entry on the path, check if we should do a step-by-step
         * repackaging or just pack the whole object.
         *
         * Find all matching rules that match this 'key'. Return the number of matches or 0
         * if no matches were found. Found matches are stored in the 'matched_indexes' array.
         */
        ret = accessor_key_find_matches(mpa, key, matched_indexes);
        if (ret == 0) {
            /* No matches, it's ok to pack the kv pair */
            flb_mp_map_header_append(&mh);
            msgpack_pack_object(&mp_pck, *key);
            msgpack_pack_object(&mp_pck, *val);
        }
        else {
            /* The key has a match. Now we do a step-by-step packaging */

            ret = accessor_sub_pack(mpa, matched_indexes, ret, &mp_pck, key, val);
            if (ret == FLB_TRUE) {
                flb_mp_map_header_append(&mh);
            }
        }
    }
    flb_mp_map_header_end(&mh);

    flb_free(matched_indexes);

    *out_buf = mp_sbuf.data;
    *out_size = mp_sbuf.size;

    return FLB_TRUE;
}

void flb_mp_accessor_destroy(struct flb_mp_accessor *mpa)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_mp_accessor_ra *mp_ra;

    if (!mpa) {
        return;
    }

    mk_list_foreach_safe(head, tmp, &mpa->ra_list) {
        mp_ra = mk_list_entry(head, struct flb_mp_accessor_ra, _head);
        mk_list_del(&mp_ra->_head);
        flb_ra_destroy(mp_ra->ra);
        flb_free(mp_ra);
    }

    if (mpa->matches) {
        flb_free(mpa->matches);
    }

    flb_free(mpa);
}


/*
 * Convert a msgpack object into a CFL variant. When 'arena' is set, the
 * variant and its children are allocated from it, otherwise from the heap.
 */
static struct cfl_variant *mp_variant_to_cfl(msgpack_object *object, struct cfl_arena *arena)
{
    struct cfl_variant *value;
    struct cfl_variant *child;
    struct cfl_array *array;
    struct cfl_kvlist *map;
    msgpack_object_kv *pair;
    size_t index;

    switch (object->type) {
    case MSGPACK_OBJECT_NIL:
        return cfl_variant_create_from_null_in(arena);
    case MSGPACK_OBJECT_BOOLEAN:
        return cfl_variant_create_from_bool_in(arena, object->via.boolean);
    case MSGPACK_OBJECT_POSITIVE_INTEGER:
        return cfl_variant_create_from_uint64_in(arena, object->via.u64);
    case MSGPACK_OBJECT_NEGATIVE_INTEGER:
        return cfl_variant_create_from_int64_in(arena, object->via.i64);
    case MSGPACK_OBJECT_FLOAT32:
    case MSGPACK_OBJECT_FLOAT64:
        return cfl_variant_create_from_double_in(arena, object->via.f64);
    case MSGPACK_OBJECT_STR:
        return cfl_variant_create_from_string_s_in(arena, (char *) object->via.str.ptr,
                                                   object->via.str.size, CFL_TRUE);
    case MSGPACK_OBJECT_BIN:
        return cfl_variant_create_from_bytes_in(arena, (char *) object->via.bin.ptr,
                                                object->via.bin.size, CFL_TRUE);
    case MSGPACK_OBJECT_ARRAY:
        array = cfl_array_create_in(arena, object->via.array.size);
        if (!array) {
            return NULL;
        }

        for (index = 0; index < object->via.array.size; index++) {
            child = mp_variant_to_cfl(&object->via.array.ptr[index], arena);
            if (!child || cfl_array_append(array, child) != 0) {
                cfl_variant_destroy(child);
                cfl_array_destroy(array);
                return NULL;
            }
        }

        value = cfl_variant_create_from_array_in(arena, array);
        if (!value) {
            cfl_array_destroy(array);
        }
        return value;
    case MSGPACK_OBJECT_MAP:
        map = cfl_kvlist_create_in(arena);
        if (!map) {
            return NULL;
        }

        for (index = 0; index < object->via.map.size; index++) {
            pair = &object->via.map.ptr[index];

            /* only string keys are supported */
            if (pair->key.type != MSGPACK_OBJECT_STR) {
                cfl_kvlist_destroy(map);
                return NULL;
            }

            child = mp_variant_to_cfl(&pair->val, arena);
            if (!child || cfl_kvlist_insert_s(map, (char *) pair->key.via.str.ptr,
                                              pair->key.via.str.size, child) != 0) {
                cfl_variant_destroy(child);
                cfl_kvlist_destroy(map);
                return NULL;
            }
        }

        value = cfl_variant_create_from_kvlist_in(arena, map);
        if (!value) {
            cfl_kvlist_destroy(map);
        }
        return value;
    default:
        /* extension types are not converted */
        return NULL;
    }
}

/* Only maps (kvlist) and arrays can be converted to a cfl_object */
static struct cfl_object *mp_object_to_cfl_in(msgpack_object *object, struct cfl_arena *arena)
{
    struct cfl_object *result;

    if (object->type != MSGPACK_OBJECT_MAP && object->type != MSGPACK_OBJECT_ARRAY) {
        return NULL;
    }

    result = cfl_object_create();
    if (!result) {
        return NULL;
    }

    result->variant = mp_variant_to_cfl(object, arena);
    if (!result->variant) {
        cfl_object_destroy(result);
        return NULL;
    }

    if (object->type == MSGPACK_OBJECT_MAP) {
        result->type = CFL_OBJECT_KVLIST;
    }
    else {
        result->type = CFL_OBJECT_ARRAY;
    }

    return result;
}

/* Convert a msgpack object to a cfl_object */
struct cfl_object *flb_mp_object_to_cfl(msgpack_object *o)
{
    return mp_object_to_cfl_in(o, NULL);
}

/*
 * Bytes a chunk value pool can hold before new record trees use the heap, and
 * its arena block size. Trees already in the pool can keep growing, so edits
 * on them never fail because the pool is full.
 */
#define FLB_MP_VALUE_POOL_LIMIT (1024 * 1024)
#define FLB_MP_VALUE_POOL_BLOCK 16384

/* Prefix of every pool allocation, it keeps the size for accounting */
union value_pool_header {
    size_t size;
    long double alignment;
    void *pointer;
};

static void *value_pool_malloc(void *context, size_t size)
{
    struct flb_mp_chunk_cobj *chunk = context;
    union value_pool_header *header;

    if (size > SIZE_MAX - sizeof(*header)) {
        return NULL;
    }

    header = flb_malloc(sizeof(*header) + size);
    if (!header) {
        flb_errno();
        return NULL;
    }

    header->size = sizeof(*header) + size;
    chunk->value_pool_bytes += header->size;

    return header + 1;
}

static void value_pool_free(void *context, void *pointer)
{
    struct flb_mp_chunk_cobj *chunk = context;
    union value_pool_header *header = (union value_pool_header *) pointer - 1;

    chunk->value_pool_bytes -= header->size;
    flb_free(header);
}

void flb_mp_chunk_cobj_value_pool_enable(struct flb_mp_chunk_cobj *chunk)
{
    struct cfl_arena_options options;

    if (chunk->value_pool) {
        return;
    }

    /* fixed size blocks, accounted against the chunk through the hooks */
    cfl_arena_options_init(&options);
    options.chunk_size = FLB_MP_VALUE_POOL_BLOCK;
    options.maximum_chunk_size = FLB_MP_VALUE_POOL_BLOCK;
    options.large_object_threshold = FLB_MP_VALUE_POOL_BLOCK;
    options.malloc_fn = value_pool_malloc;
    options.free_fn = value_pool_free;
    options.allocator_context = chunk;

    chunk->value_pool = cfl_arena_create_with_options(&options);
    if (chunk->value_pool) {
        cfl_arena_external_cache_limit_set(chunk->value_pool, 0);
    }
}

struct cfl_arena *flb_mp_chunk_cobj_value_pool_get(struct flb_mp_chunk_cobj *chunk,
                                                  size_t estimated_bytes)
{
    size_t available;

    if (!chunk || !chunk->value_pool ||
        chunk->value_pool_bytes >= FLB_MP_VALUE_POOL_LIMIT) {
        return NULL;
    }

    available = FLB_MP_VALUE_POOL_LIMIT - chunk->value_pool_bytes;

    /*
     * Leave room for a new arena block and its allocation headers. Oversized
     * roots use heap ownership as a whole, never mixed container ownership.
     */
    if (available < 2 * FLB_MP_VALUE_POOL_BLOCK ||
        estimated_bytes > available - 2 * FLB_MP_VALUE_POOL_BLOCK) {
        return NULL;
    }

    return chunk->value_pool;
}

/*
 * Upper estimate for arena nodes, aligned slots, kvpairs and copied map keys.
 * MessagePack string/byte payloads themselves remain borrowed from the decoder.
 */
static size_t mp_value_pool_cost(msgpack_object *object, int depth)
{
    size_t cost = 512;
    size_t child;
    size_t index;
    msgpack_object *value;

    if (depth >= 64) {
        return SIZE_MAX;
    }

    if (object->type != MSGPACK_OBJECT_MAP && object->type != MSGPACK_OBJECT_ARRAY) {
        return cost;
    }

    /* maps and arrays share the same 'size' layout in the msgpack union */
    for (index = 0; index < object->via.array.size; index++) {
        if (object->type == MSGPACK_OBJECT_MAP) {
            value = &object->via.map.ptr[index].val;

            child = 0;
            if (object->via.map.ptr[index].key.type == MSGPACK_OBJECT_STR) {
                child = object->via.map.ptr[index].key.via.str.size;
            }

            if (cost > SIZE_MAX - 512 || child > (SIZE_MAX - cost - 512) / 2) {
                return SIZE_MAX;
            }
            cost += 512 + 2 * child;
        }
        else {
            value = &object->via.array.ptr[index];
        }

        child = mp_value_pool_cost(value, depth + 1);
        if (child > SIZE_MAX - cost) {
            return SIZE_MAX;
        }
        cost += child;
    }

    return cost;
}

/*
 * Convert a decoded msgpack object for a chunk record. The chunk value pool is
 * used when enabled and large enough, falling back to heap allocations.
 */
static struct cfl_object *chunk_object_from_msgpack(struct flb_mp_chunk_cobj *chunk,
                                                    msgpack_object *object)
{
    struct cfl_arena *arena = NULL;
    struct cfl_object *result;

    if (chunk->value_pool) {
        arena = flb_mp_chunk_cobj_value_pool_get(chunk, mp_value_pool_cost(object, 0));
    }

    result = mp_object_to_cfl_in(object, arena);
    if (!result && arena) {
        result = mp_object_to_cfl_in(object, NULL);
    }

    return result;
}

static int mp_cfl_to_msgpack(struct cfl_variant *var,
                             msgpack_sbuffer *mp_sbuf, msgpack_packer *mp_pck)
{
    int i;
    int ret;
    struct cfl_list *head;
    struct cfl_kvpair *kv;
    struct cfl_kvlist *kvlist;
    struct cfl_variant *variant;
    struct flb_mp_map_header mh;

    switch (var->type) {
        case CFL_VARIANT_BOOL:
            if (var->data.as_bool) {
                msgpack_pack_true(mp_pck);
            }
            else {
                msgpack_pack_false(mp_pck);
            }
            break;
        case CFL_VARIANT_INT:
            msgpack_pack_int64(mp_pck, var->data.as_int64);
            break;
        case CFL_VARIANT_UINT:
            msgpack_pack_uint64(mp_pck, var->data.as_uint64);
            break;
        case CFL_VARIANT_DOUBLE:
            msgpack_pack_double(mp_pck, var->data.as_double);
            break;
        case CFL_VARIANT_NULL:
            msgpack_pack_nil(mp_pck);
            break;
        case CFL_VARIANT_REFERENCE:
            /* we don't save references */
            break;
        case CFL_VARIANT_STRING:
            msgpack_pack_str(mp_pck, cfl_variant_size_get(var));
            msgpack_pack_str_body(mp_pck,
                                  var->data.as_string, cfl_variant_size_get(var));
            break;
        case CFL_VARIANT_BYTES:
            msgpack_pack_bin(mp_pck, cfl_variant_size_get(var));
            msgpack_pack_bin_body(mp_pck,
                                  var->data.as_bytes, cfl_variant_size_get(var));
            break;
        case CFL_VARIANT_ARRAY:
        msgpack_pack_array(mp_pck, var->data.as_array->entry_count);
            for (i = 0; i < var->data.as_array->entry_count; i++) {
                variant = var->data.as_array->entries[i];
                ret = mp_cfl_to_msgpack(variant, mp_sbuf, mp_pck);
                if (ret == -1) {
                    return -1;
                }
            }
            break;
        case CFL_VARIANT_KVLIST:
            kvlist = var->data.as_kvlist;
            flb_mp_map_header_init(&mh, mp_pck);
            cfl_list_foreach(head, &kvlist->list) {
                kv = cfl_list_entry(head, struct cfl_kvpair, _head);

                flb_mp_map_header_append(&mh);

                /* key */
                msgpack_pack_str(mp_pck, cfl_sds_len(kv->key));
                msgpack_pack_str_body(mp_pck, kv->key, cfl_sds_len(kv->key));

                /* value */
                ret = mp_cfl_to_msgpack(kv->val, mp_sbuf,  mp_pck);
                if (ret == -1) {
                    return -1;
                }
            }
            flb_mp_map_header_end(&mh);
            break;
    }

    return 0;
}

/* Convert a CFL Object and serialize it content in a msgpack buffer */
int flb_mp_cfl_to_msgpack(struct cfl_object *obj, char **out_buf, size_t *out_size)
{
    int ret;
    msgpack_sbuffer mp_sbuf;
    msgpack_packer mp_pck;

    if (!obj) {
        return -1;
    }

    /* unitialized CFL object ? */
    if (obj->type == CFL_OBJECT_NONE) {
        return -1;
    }

    /* initialize msgpack buffer */
    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    ret = mp_cfl_to_msgpack(obj->variant, &mp_sbuf, &mp_pck);
    if (ret == -1) {
        return -1;
    }

    *out_buf = mp_sbuf.data;
    *out_size = mp_sbuf.size;

    return 0;
}

/* Records per pool block and maximum number of blocks per chunk */
#define FLB_MP_RECORD_BLOCK_ENTRIES 64
#define FLB_MP_RECORD_BLOCK_LIMIT 8

/*
 * A block has one owner reference plus one reference per live record. Moving
 * records between chunks does not change their storage lifetime.
 */
struct flb_mp_record_block {
    struct flb_mp_record_block *next;
    size_t references;
    size_t used;
    struct flb_mp_chunk_record records[FLB_MP_RECORD_BLOCK_ENTRIES];
};

static void record_block_release(struct flb_mp_record_block *block)
{
    block->references--;
    if (block->references == 0) {
        flb_free(block);
    }
}

static void record_storage_release(struct flb_mp_chunk_record *record)
{
    if (record->storage_block) {
        record_block_release(record->storage_block);
    }
    else {
        flb_free(record);
    }
}

struct flb_mp_chunk_record *flb_mp_chunk_record_create(struct flb_mp_chunk_cobj *chunk_cobj)
{
    struct flb_mp_chunk_record *record;
    struct flb_mp_record_block *block;

    if (chunk_cobj && chunk_cobj->record_pool_enabled) {
        block = chunk_cobj->record_pool;

        /* the current block is full (or missing), try to add a new one */
        if ((!block || block->used == FLB_MP_RECORD_BLOCK_ENTRIES) &&
            chunk_cobj->record_pool_blocks < FLB_MP_RECORD_BLOCK_LIMIT) {
            block = flb_calloc(1, sizeof(struct flb_mp_record_block));
            if (!block) {
                flb_errno();
            }
            else {
                block->references = 1;
                block->next = chunk_cobj->record_pool;
                chunk_cobj->record_pool = block;
                chunk_cobj->record_pool_blocks++;
            }
        }

        if (block && block->used < FLB_MP_RECORD_BLOCK_ENTRIES) {
            record = &block->records[block->used++];
            record->storage_block = block;
            block->references++;
            return record;
        }
    }

    /* pool disabled or exhausted: allocate the record individually */
    record = flb_calloc(1, sizeof(struct flb_mp_chunk_record));
    if (!record) {
        flb_errno();
        return NULL;
    }

    return record;
}

struct flb_mp_chunk_cobj *flb_mp_chunk_cobj_create(struct flb_log_event_encoder *log_encoder, struct flb_log_event_decoder *log_decoder)
{
    struct flb_mp_chunk_cobj *chunk_cobj;

    if (!log_encoder || !log_decoder) {
        return NULL;
    }

    chunk_cobj = flb_calloc(1, sizeof(struct flb_mp_chunk_cobj));
    if (!chunk_cobj) {
        flb_errno();
        return NULL;
    }
    cfl_list_init(&chunk_cobj->records);
    chunk_cobj->record_pos  = NULL;
    chunk_cobj->log_encoder = log_encoder;
    chunk_cobj->log_decoder = log_decoder;
    chunk_cobj->condition   = NULL;
    chunk_cobj->active_group_metadata = NULL;
    chunk_cobj->active_group_attributes = NULL;

    return chunk_cobj;
}

/*
 * Pack a record field into the scratch buffer, an empty map when the field is
 * not set. The buffer capacity is reused by every field of an encode call.
 */
static int encode_cfl_field(struct cfl_object *obj, msgpack_sbuffer *buffer,
                            msgpack_packer *packer)
{
    msgpack_sbuffer_clear(buffer);

    if (!obj) {
        return msgpack_pack_map(packer, 0);
    }

    if (obj->type == CFL_OBJECT_NONE || !obj->variant) {
        return -1;
    }

    return mp_cfl_to_msgpack(obj->variant, buffer, packer);
}

/*
 * Append the chunk records to its log encoder output. A failure resets the
 * encoder, including the output of previous appends.
 */
int flb_mp_chunk_cobj_encode_append(struct flb_mp_chunk_cobj *chunk_cobj)
{
    int ret;
    struct cfl_list *head;
    struct flb_mp_chunk_record *record;
    struct cfl_object *body;
    msgpack_sbuffer buffer;
    msgpack_packer packer;

    if (!chunk_cobj) {
        return -1;
    }

    msgpack_sbuffer_init(&buffer);
    msgpack_packer_init(&packer, &buffer, msgpack_sbuffer_write);

    /* Iterate all records */
    cfl_list_foreach(head, &chunk_cobj->records) {
        record = cfl_list_entry(head, struct flb_mp_chunk_record, _head);

        ret = flb_log_event_encoder_begin_record(chunk_cobj->log_encoder);
        if (ret != FLB_EVENT_ENCODER_SUCCESS) {
            goto failure;
        }

        ret = flb_log_event_encoder_set_timestamp(chunk_cobj->log_encoder,
                                                  &record->event.timestamp);
        if (ret != FLB_EVENT_ENCODER_SUCCESS) {
            goto failure;
        }

        /* metadata */
        if (encode_cfl_field(record->cobj_metadata, &buffer, &packer) != 0) {
            goto failure;
        }

        ret = flb_log_event_encoder_set_metadata_from_raw_msgpack(chunk_cobj->log_encoder,
                                                                 buffer.data, buffer.size);
        if (ret != FLB_EVENT_ENCODER_SUCCESS) {
            goto failure;
        }

        /* for group start records, use group attributes as body if available */
        body = record->cobj_record;
        if (record->event.timestamp.tm.tv_sec == FLB_LOG_EVENT_GROUP_START &&
            record->cobj_group_attributes) {
            body = record->cobj_group_attributes;
        }

        if (encode_cfl_field(body, &buffer, &packer) != 0) {
            goto failure;
        }

        ret = flb_log_event_encoder_set_body_from_raw_msgpack(chunk_cobj->log_encoder,
                                                             buffer.data, buffer.size);
        if (ret != FLB_EVENT_ENCODER_SUCCESS) {
            goto failure;
        }

        ret = flb_log_event_encoder_commit_record(chunk_cobj->log_encoder);
        if (ret != FLB_EVENT_ENCODER_SUCCESS) {
            goto failure;
        }
    }

    msgpack_sbuffer_destroy(&buffer);
    return 0;

failure:
    /* never leave partial records behind for the next chunk using this encoder */
    flb_log_event_encoder_reset(chunk_cobj->log_encoder);
    msgpack_sbuffer_destroy(&buffer);

    return -1;
}

int flb_mp_chunk_cobj_encode(struct flb_mp_chunk_cobj *chunk_cobj, char **out_buf, size_t *out_size)
{
    if (flb_mp_chunk_cobj_encode_append(chunk_cobj) != 0) {
        return -1;
    }

    /* set new output buffer */
    *out_buf = chunk_cobj->log_encoder->output_buffer;
    *out_size = chunk_cobj->log_encoder->output_length;

    flb_log_event_encoder_claim_internal_buffer_ownership(chunk_cobj->log_encoder);
    return 0;
}

int flb_mp_chunk_cobj_count_log_records(struct flb_mp_chunk_cobj *chunk_cobj)
{
    int count;
    int record_type;
    int ret;
    struct cfl_list *head;
    struct flb_mp_chunk_record *record;

    if (chunk_cobj == NULL) {
        return 0;
    }

    count = 0;

    cfl_list_foreach(head, &chunk_cobj->records) {
        record = cfl_list_entry(head, struct flb_mp_chunk_record, _head);

        ret = flb_log_event_decoder_get_record_type(&record->event, &record_type);
        if (ret != FLB_EVENT_DECODER_SUCCESS) {
            continue;
        }

        if (record_type == FLB_LOG_EVENT_NORMAL) {
            count++;
        }
    }

    return count;
}

static int cobj_remove_list_add(struct flb_mp_chunk_record **remove_list,
                                size_t remove_list_size,
                                size_t *remove_list_count,
                                struct flb_mp_chunk_record *record)
{
    size_t index;

    if (record == NULL) {
        return -1;
    }

    for (index = 0; index < *remove_list_count; index++) {
        if (remove_list[index] == record) {
            return 0;
        }
    }

    if (*remove_list_count >= remove_list_size) {
        return -1;
    }

    remove_list[*remove_list_count] = record;
    (*remove_list_count)++;

    return 0;
}

int flb_mp_chunk_cobj_normalize_groups(struct flb_mp_chunk_cobj *chunk_cobj)
{
    int ret;
    int record_type;
    size_t index;
    size_t stack_size;
    size_t stack_count;
    size_t remove_count;
    struct cfl_list *head;
    struct flb_mp_chunk_record *record;
    struct flb_mp_chunk_record **remove_list;
    struct flb_mp_chunk_record **group_start_stack;
    int *group_has_content;

    if (chunk_cobj == NULL) {
        return -1;
    }

    stack_size = cfl_list_size(&chunk_cobj->records);
    if (stack_size == 0) {
        return 0;
    }

    remove_list = flb_calloc(stack_size, sizeof(struct flb_mp_chunk_record *));
    if (remove_list == NULL) {
        flb_errno();
        return -1;
    }

    group_start_stack = flb_calloc(stack_size, sizeof(struct flb_mp_chunk_record *));
    if (group_start_stack == NULL) {
        flb_errno();
        flb_free(remove_list);
        return -1;
    }

    group_has_content = flb_calloc(stack_size, sizeof(int));
    if (group_has_content == NULL) {
        flb_errno();
        flb_free(group_start_stack);
        flb_free(remove_list);
        return -1;
    }

    stack_count = 0;
    remove_count = 0;

    cfl_list_foreach(head, &chunk_cobj->records) {
        record = cfl_list_entry(head, struct flb_mp_chunk_record, _head);

        ret = flb_log_event_decoder_get_record_type(&record->event, &record_type);
        if (ret != FLB_EVENT_DECODER_SUCCESS) {
            continue;
        }

        if (record_type == FLB_LOG_EVENT_GROUP_START) {
            if (stack_count < stack_size) {
                group_start_stack[stack_count] = record;
                group_has_content[stack_count] = FLB_FALSE;
                stack_count++;
            }
            continue;
        }

        if (record_type == FLB_LOG_EVENT_GROUP_END) {
            if (stack_count == 0) {
                cobj_remove_list_add(remove_list, stack_size, &remove_count, record);
                continue;
            }

            stack_count--;

            if (group_has_content[stack_count] == FLB_FALSE) {
                cobj_remove_list_add(remove_list, stack_size, &remove_count,
                                     group_start_stack[stack_count]);
                cobj_remove_list_add(remove_list, stack_size, &remove_count, record);
            }
            else if (stack_count > 0) {
                group_has_content[stack_count - 1] = FLB_TRUE;
            }

            continue;
        }

        for (index = 0; index < stack_count; index++) {
            group_has_content[index] = FLB_TRUE;
        }
    }

    while (stack_count > 0) {
        stack_count--;
        cobj_remove_list_add(remove_list, stack_size, &remove_count,
                             group_start_stack[stack_count]);
    }

    for (index = 0; index < remove_count; index++) {
        flb_mp_chunk_cobj_record_destroy(chunk_cobj, remove_list[index]);
    }

    flb_free(group_has_content);
    flb_free(group_start_stack);
    flb_free(remove_list);

    return 0;
}

int flb_mp_chunk_cobj_destroy(struct flb_mp_chunk_cobj *chunk_cobj)
{
    struct cfl_list *tmp;
    struct cfl_list *head;
    struct flb_mp_chunk_record *record;
    struct flb_mp_record_block *block;

    if (!chunk_cobj) {
        return -1;
    }

    cfl_list_foreach_safe(head, tmp, &chunk_cobj->records) {
        record = cfl_list_entry(head, struct flb_mp_chunk_record, _head);
        if (record->cobj_metadata) {
            cfl_object_destroy(record->cobj_metadata);
        }
        if (record->cobj_record) {
            cfl_object_destroy(record->cobj_record);
        }
        if (record->owns_group_metadata && record->cobj_group_metadata &&
            record->cobj_group_metadata != record->cobj_metadata) {
            cfl_object_destroy(record->cobj_group_metadata);
        }
        if (record->owns_group_attributes && record->cobj_group_attributes &&
            record->cobj_group_attributes != record->cobj_record) {
            cfl_object_destroy(record->cobj_group_attributes);
        }
        cfl_list_del(&record->_head);
        record_storage_release(record);
    }

    /* drop the owner reference, blocks still used by moved records survive */
    while (chunk_cobj->record_pool) {
        block = chunk_cobj->record_pool;
        chunk_cobj->record_pool = block->next;
        record_block_release(block);
    }

    cfl_arena_destroy(chunk_cobj->value_pool);
    flb_free(chunk_cobj);
    return 0;
}

int flb_mp_chunk_cobj_record_next(struct flb_mp_chunk_cobj *chunk_cobj,
                                  struct flb_mp_chunk_record **out_record)
{
    int ret = FLB_MP_CHUNK_RECORD_EOF;
    size_t bytes;
    int record_type = FLB_LOG_EVENT_NORMAL;
    struct flb_mp_chunk_record *record = NULL;
    struct flb_condition *condition = NULL;

    *out_record = NULL;

    /* Check if we have a condition */
    condition = chunk_cobj->condition;

    /*
     * Iterate until a record that matches the condition (if one is configured)
     * is found, or until the end of the chunk is reached.
     *
     * This was previously implemented with tail recursion: whenever a record
     * did not match the condition, the function called itself to advance to the
     * next record. With a large run of non-matching records (for example a
     * condition that filters out most of a chunk) the recursion depth grew
     * proportionally to the number of records and could exhaust the stack. An
     * explicit loop keeps the stack usage constant.
     */
    while (1) {
        /*
         * if there are remaining decoder bytes, keep iterating msgpack and
         * populate the cobj list. Otherwise it means all the content is ready
         * as a chunk_cobj_record.
         */
        bytes = chunk_cobj->log_decoder->length - chunk_cobj->log_decoder->offset;

        if (bytes > 0) {
            record = flb_mp_chunk_record_create(chunk_cobj);
            if (!record) {
                return FLB_MP_CHUNK_RECORD_ERROR;
            }

            ret = flb_log_event_decoder_next(chunk_cobj->log_decoder, &record->event);
            if (ret != FLB_EVENT_DECODER_SUCCESS) {
                record_storage_release(record);
                return -1;
            }

            record->cobj_metadata = chunk_object_from_msgpack(chunk_cobj,
                                                              record->event.metadata);
            if (!record->cobj_metadata) {
                record_storage_release(record);
                return FLB_MP_CHUNK_RECORD_ERROR;
            }

            record->cobj_record = chunk_object_from_msgpack(chunk_cobj, record->event.body);
            if (!record->cobj_record) {
                cfl_object_destroy(record->cobj_metadata);
                record_storage_release(record);
                return -1;
            }

            ret = flb_log_event_decoder_get_record_type(&record->event, &record_type);
            if (ret != FLB_EVENT_DECODER_SUCCESS) {
                cfl_object_destroy(record->cobj_record);
                cfl_object_destroy(record->cobj_metadata);
                record_storage_release(record);
                return FLB_MP_CHUNK_RECORD_ERROR;
            }

            record->owns_group_metadata = FLB_FALSE;
            record->owns_group_attributes = FLB_FALSE;

            if (record_type == FLB_LOG_EVENT_GROUP_START) {
                if (record->cobj_metadata) {
                    record->cobj_group_metadata = record->cobj_metadata;
                    record->owns_group_metadata = FLB_TRUE;
                }
                if (record->cobj_record) {
                    record->cobj_group_attributes = record->cobj_record;
                    record->owns_group_attributes = FLB_TRUE;
                }

                chunk_cobj->active_group_metadata = record->cobj_group_metadata;
                chunk_cobj->active_group_attributes = record->cobj_group_attributes;
            }
            else if (record_type == FLB_LOG_EVENT_GROUP_END) {
                record->cobj_group_metadata = chunk_cobj->active_group_metadata;
                record->cobj_group_attributes = chunk_cobj->active_group_attributes;

                chunk_cobj->active_group_metadata = NULL;
                chunk_cobj->active_group_attributes = NULL;
            }
            else {
                record->cobj_group_metadata = chunk_cobj->active_group_metadata;
                record->cobj_group_attributes = chunk_cobj->active_group_attributes;
            }

            if (!record->cobj_group_metadata &&
                record->event.group_metadata &&
                (record->event.group_metadata->type == MSGPACK_OBJECT_MAP ||
                 record->event.group_metadata->type == MSGPACK_OBJECT_ARRAY)) {
                record->cobj_group_metadata =
                    chunk_object_from_msgpack(chunk_cobj, record->event.group_metadata);
                if (!record->cobj_group_metadata) {
                    if (record->owns_group_attributes && record->cobj_group_attributes) {
                        cfl_object_destroy(record->cobj_group_attributes);
                    }
                    cfl_object_destroy(record->cobj_record);
                    cfl_object_destroy(record->cobj_metadata);
                    record_storage_release(record);
                    return FLB_MP_CHUNK_RECORD_ERROR;
                }
                record->owns_group_metadata = FLB_TRUE;
                if (!chunk_cobj->active_group_metadata) {
                    chunk_cobj->active_group_metadata = record->cobj_group_metadata;
                }
            }

            if (!record->cobj_group_attributes &&
                record->event.group_attributes &&
                (record->event.group_attributes->type == MSGPACK_OBJECT_MAP ||
                 record->event.group_attributes->type == MSGPACK_OBJECT_ARRAY)) {
                record->cobj_group_attributes =
                    chunk_object_from_msgpack(chunk_cobj, record->event.group_attributes);
                if (!record->cobj_group_attributes) {
                    if (record->owns_group_metadata && record->cobj_group_metadata) {
                        cfl_object_destroy(record->cobj_group_metadata);
                    }
                    cfl_object_destroy(record->cobj_record);
                    cfl_object_destroy(record->cobj_metadata);
                    record_storage_release(record);
                    return FLB_MP_CHUNK_RECORD_ERROR;
                }
                record->owns_group_attributes = FLB_TRUE;
                if (!chunk_cobj->active_group_attributes) {
                    chunk_cobj->active_group_attributes = record->cobj_group_attributes;
                }
            }

            cfl_list_add(&record->_head, &chunk_cobj->records);

            /* If there's a condition, check if the record matches */
            if (condition != NULL && record != NULL) {
                flb_trace("[mp] evaluating condition for record");
                ret = flb_condition_evaluate(condition, record);
                flb_trace("[mp] condition evaluation result: %s", ret ? "TRUE" : "FALSE");
                if (ret == FLB_FALSE) {
                    flb_trace("[mp] record didn't match condition, skipping");
                    /* Record doesn't match the condition, continue to next record */
                    continue;
                }
                flb_trace("[mp] record matched condition, processing");
            }

            ret = FLB_MP_CHUNK_RECORD_OK;
        }
        else if (chunk_cobj->record_pos != NULL) {
            /* is the actual record the last one ? */
            if (chunk_cobj->record_pos == cfl_list_entry_last(&chunk_cobj->records, struct flb_mp_chunk_record, _head)) {
                chunk_cobj->record_pos = NULL;
                return FLB_MP_CHUNK_RECORD_EOF;
            }

            record = cfl_list_entry_next(&chunk_cobj->record_pos->_head, struct flb_mp_chunk_record,
                                        _head, &chunk_cobj->records);

            /* If there's a condition, check if the record matches */
            if (condition != NULL && record != NULL) {
                flb_trace("[mp] evaluating condition for next record");
                ret = flb_condition_evaluate(condition, record);
                flb_trace("[mp] next record condition evaluation result: %s", ret ? "TRUE" : "FALSE");
                if (ret == FLB_FALSE) {
                    flb_trace("[mp] next record didn't match condition, skipping");
                    /* Record doesn't match the condition, set as current and try again */
                    chunk_cobj->record_pos = record;
                    continue;
                }
                flb_trace("[mp] next record matched condition, processing");
            }

            ret = FLB_MP_CHUNK_RECORD_OK;
        }
        else {
            if (cfl_list_size(&chunk_cobj->records) == 0) {
                return FLB_MP_CHUNK_RECORD_EOF;
            }

            /* check if we are the last in the list */
            record = cfl_list_entry_first(&chunk_cobj->records, struct flb_mp_chunk_record, _head);

            /* If there's a condition, check if the record matches */
            if (condition != NULL && record != NULL) {
                flb_trace("[mp] evaluating condition for first record");
                ret = flb_condition_evaluate(condition, record);
                flb_trace("[mp] first record condition evaluation result: %s", ret ? "TRUE" : "FALSE");
                if (ret == FLB_FALSE) {
                    flb_trace("[mp] first record didn't match condition, skipping");
                    /* Record doesn't match the condition, set as current and try again */
                    chunk_cobj->record_pos = record;
                    continue;
                }
                flb_trace("[mp] first record matched condition, processing");
            }

            ret = FLB_MP_CHUNK_RECORD_OK;
        }

        /* A matching record (or the next record) was found; stop iterating. */
        break;
    }

    chunk_cobj->record_pos = record;
    *out_record = chunk_cobj->record_pos;

    return ret;
}

int flb_mp_chunk_cobj_record_destroy(struct flb_mp_chunk_cobj *chunk_cobj,
                                     struct flb_mp_chunk_record *record)
{
    if (!record) {
        return -1;
    }

    /*
     * If the record being removed is the one under the iterator cursor, move
     * the cursor back to the previous entry so the next call to
     * flb_mp_chunk_cobj_record_next() continues with the record that follows
     * the removed one. If it was the first entry, reset the cursor so the
     * iteration restarts from the new head of the list.
     */
    if (chunk_cobj && chunk_cobj->record_pos == record) {
        if (record->_head.prev == &chunk_cobj->records) {
            chunk_cobj->record_pos = NULL;
        }
        else {
            chunk_cobj->record_pos = cfl_list_entry(record->_head.prev,
                                                    struct flb_mp_chunk_record, _head);
        }
    }

    if (chunk_cobj && record->owns_group_metadata &&
        chunk_cobj->active_group_metadata == record->cobj_group_metadata) {
        chunk_cobj->active_group_metadata = NULL;
    }
    if (chunk_cobj && record->owns_group_attributes &&
        chunk_cobj->active_group_attributes == record->cobj_group_attributes) {
        chunk_cobj->active_group_attributes = NULL;
    }

    if (record->cobj_metadata) {
        cfl_object_destroy(record->cobj_metadata);
    }
    if (record->cobj_record) {
        cfl_object_destroy(record->cobj_record);
    }
    if (record->owns_group_metadata && record->cobj_group_metadata &&
        record->cobj_group_metadata != record->cobj_metadata) {
        cfl_object_destroy(record->cobj_group_metadata);
    }
    if (record->owns_group_attributes && record->cobj_group_attributes &&
        record->cobj_group_attributes != record->cobj_record) {
        cfl_object_destroy(record->cobj_group_attributes);
    }

    cfl_list_del(&record->_head);
    record_storage_release(record);

    return 0;
}
