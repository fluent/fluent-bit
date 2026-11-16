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

#include <fluent-bit/flb_log_event_encoder.h>
#include <fluent-bit/flb_log_event_encoder_primitives.h>
#include <fluent-bit/flb_byteswap.h>
#include <stdarg.h>
#include <string.h>

/*
 * Encoder hot-path optimization notes (emit_record / commit_record / metadata):
 *
 * 1. emit_record: For FLUENT_BIT_V2 we use a direct-emit path that writes
 *    the record string [ [timestamp, metadata], body ] directly into the
 *    main buffer (no root buffer build/copy), matching the original format.
 *
 * 2. Possible future improvements:
 *    - Batch metadata: add append_metadata_kv_batch() or allow multiple
 *      key-value pairs in one call to cut va_list and call overhead.
 *    - Inline / fast path: move begin_record/commit_record hot branches
 *      into a header so the compiler can inline for the common case.
 *    - Buffer growth: reserve space for the next record (e.g. typical
 *      metadata + body size) to reduce reallocs in msgpack_sbuffer.
 *    - dynamic_field_flush: when there is only one scope per field, avoid
 *      the scope loop (single commit then set data/size).
 */

void static inline flb_log_event_encoder_update_internal_state(
    struct flb_log_event_encoder *context)
{
    context->output_buffer = context->buffer.data;
    context->output_length = context->buffer.size;
}

void flb_log_event_encoder_reset(struct flb_log_event_encoder *context)
{
    flb_log_event_encoder_dynamic_field_reset(&context->metadata);
    flb_log_event_encoder_dynamic_field_reset(&context->body);
    flb_log_event_encoder_dynamic_field_reset(&context->root);

    msgpack_sbuffer_clear(&context->buffer);
    context->raw_record_open = FLB_FALSE;
    context->raw_record_start = 0;

    flb_log_event_encoder_update_internal_state(context);
}

static int encoder_buffer_write(void *data, const char *buffer, size_t length)
{
    struct flb_log_event_encoder *context;

    context = (struct flb_log_event_encoder *)
              ((char *) data - offsetof(struct flb_log_event_encoder, buffer));

    if (context->buffer.size > context->output_limit ||
        length > context->output_limit - context->buffer.size) {
        return -1;
    }

    return msgpack_sbuffer_write(&context->buffer, buffer, length);
}

int flb_log_event_encoder_init(struct flb_log_event_encoder *context, int format)
{
    if (context == NULL) {
        return FLB_EVENT_ENCODER_ERROR_INVALID_CONTEXT;
    }

    if (format < FLB_LOG_EVENT_FORMAT_FORWARD ||
        format > FLB_LOG_EVENT_FORMAT_FLUENT_BIT_V2) {
        return FLB_EVENT_ENCODER_ERROR_INVALID_ARGUMENT;
    }

    memset(context, 0, sizeof(struct flb_log_event_encoder));

    context->dynamically_allocated = FLB_FALSE;
    context->initialized = FLB_TRUE;
    context->format = format;
    context->output_limit = SIZE_MAX;

    msgpack_sbuffer_init(&context->buffer);
    msgpack_packer_init(&context->packer,
                        &context->buffer,
                        encoder_buffer_write);

    flb_log_event_encoder_dynamic_field_init(&context->metadata,
                                             MSGPACK_OBJECT_MAP);

    flb_log_event_encoder_dynamic_field_init(&context->body,
                                             MSGPACK_OBJECT_MAP);

    flb_log_event_encoder_dynamic_field_init(&context->root,
                                             MSGPACK_OBJECT_ARRAY);

    return FLB_EVENT_ENCODER_SUCCESS;
}

struct flb_log_event_encoder *flb_log_event_encoder_create(int format)
{
    struct flb_log_event_encoder *context;
    int                           result;

    context = (struct flb_log_event_encoder *) \
        flb_calloc(1, sizeof(struct flb_log_event_encoder));

    result = flb_log_event_encoder_init(context, format);

    if (context != NULL) {
        context->dynamically_allocated = FLB_TRUE;

        if (result != FLB_EVENT_ENCODER_SUCCESS) {
            flb_log_event_encoder_destroy(context);

            context = NULL;
        }
    }

    return context;
}

void flb_log_event_encoder_destroy(struct flb_log_event_encoder *context)
{
    if (context != NULL) {
        if (context->initialized) {
            flb_log_event_encoder_dynamic_field_destroy(&context->metadata);
            flb_log_event_encoder_dynamic_field_destroy(&context->body);
            flb_log_event_encoder_dynamic_field_destroy(&context->root);

            msgpack_sbuffer_destroy(&context->buffer);

            context->initialized = FLB_FALSE;
        }

        if (context->dynamically_allocated) {
            flb_free(context);
        }
    }
}

void flb_log_event_encoder_claim_internal_buffer_ownership(
        struct flb_log_event_encoder *context)
{
    if (context != NULL) {
        msgpack_sbuffer_release(&context->buffer);
    }
}

/*
 * Raw records: see the description of the interface in the header.
 */

/* [[ TIMESTAMP (fixext 8, type 0), empty metadata map ], */
static int raw_record_header(struct flb_log_event_encoder *context,
                             struct flb_time *timestamp)
{
    uint32_t value;
    char header[17];

    header[0] = (char) 0x92;
    header[1] = (char) 0x92;
    header[2] = (char) 0xd7;
    header[3] = (char) 0x00;
    value = FLB_UINT32_TO_NETWORK_BYTE_ORDER((uint32_t) timestamp->tm.tv_sec);
    memcpy(&header[4], &value, 4);
    value = FLB_UINT32_TO_NETWORK_BYTE_ORDER((uint32_t) timestamp->tm.tv_nsec);
    memcpy(&header[8], &value, 4);

    /* same header generated for the (empty) metadata of a regular record */
    header[12] = (char) 0xdf;
    header[13] = 0;
    header[14] = 0;
    header[15] = 0;
    header[16] = 0;

    return msgpack_pack_str_body(&context->packer, header, sizeof(header));
}

/* map header as generated for the body of a regular record (map 32) */
static int raw_record_body_header(struct flb_log_event_encoder *context,
                                  uint32_t entries)
{
    uint32_t value;
    char header[5];

    header[0] = (char) 0xdf;
    value = FLB_UINT32_TO_NETWORK_BYTE_ORDER(entries);
    memcpy(&header[1], &value, 4);

    return msgpack_pack_str_body(&context->packer, header, sizeof(header));
}

/*
 * Read the header of a serialized map: returns the number of bytes used by
 * the header or zero if the content is not a map.
 */
static size_t raw_map_header(const unsigned char *data, size_t length,
                             uint32_t *entries)
{
    if (length < 1) {
        return 0;
    }

    if ((data[0] & 0xf0) == 0x80) {
        *entries = data[0] & 0x0f;
        return 1;
    }
    else if (data[0] == 0xde && length >= 3) {
        *entries = ((uint32_t) data[1] << 8) | data[2];
        return 3;
    }
    else if (data[0] == 0xdf && length >= 5) {
        *entries = ((uint32_t) data[1] << 24) | ((uint32_t) data[2] << 16) |
                   ((uint32_t) data[3] << 8) | data[4];
        return 5;
    }

    return 0;
}

/*
 * Skip 'count' serialized msgpack objects, returns the position after the
 * last one or NULL if the content is not complete or not valid.
 */
static const unsigned char *raw_skip_objects(const unsigned char *p,
                                             const unsigned char *end,
                                             uint64_t count)
{
    unsigned char c;
    uint64_t len;
    uint64_t children;

    while (count > 0) {
        if (p >= end) {
            return NULL;
        }

        c = *p++;
        count--;
        len = 0;
        children = 0;

        if (c <= 0x7f || c >= 0xe0 || c == 0xc0 || c == 0xc2 || c == 0xc3) {
            /* fixint, nil, booleans */
        }
        else if (c <= 0x8f) {
            children = (uint64_t) (c & 0x0f) * 2;
        }
        else if (c <= 0x9f) {
            children = c & 0x0f;
        }
        else if (c <= 0xbf) {
            len = c & 0x1f;
        }
        else {
            switch (c) {
            case 0xc4: /* bin 8 */
            case 0xd9: /* str 8 */
                if (end - p < 1) {
                    return NULL;
                }
                len = p[0];
                p += 1;
                break;
            case 0xc5: /* bin 16 */
            case 0xda: /* str 16 */
                if (end - p < 2) {
                    return NULL;
                }
                len = ((uint64_t) p[0] << 8) | p[1];
                p += 2;
                break;
            case 0xc6: /* bin 32 */
            case 0xdb: /* str 32 */
                if (end - p < 4) {
                    return NULL;
                }
                len = ((uint64_t) p[0] << 24) | ((uint64_t) p[1] << 16) |
                      ((uint64_t) p[2] << 8) | p[3];
                p += 4;
                break;
            case 0xc7: /* ext 8 */
                if (end - p < 1) {
                    return NULL;
                }
                len = (uint64_t) p[0] + 1;
                p += 1;
                break;
            case 0xc8: /* ext 16 */
                if (end - p < 2) {
                    return NULL;
                }
                len = (((uint64_t) p[0] << 8) | p[1]) + 1;
                p += 2;
                break;
            case 0xc9: /* ext 32 */
                if (end - p < 4) {
                    return NULL;
                }
                len = (((uint64_t) p[0] << 24) | ((uint64_t) p[1] << 16) |
                       ((uint64_t) p[2] << 8) | p[3]) + 1;
                p += 4;
                break;
            case 0xca: /* float 32 */
            case 0xce: /* uint 32 */
            case 0xd2: /* int 32 */
                len = 4;
                break;
            case 0xcb: /* float 64 */
            case 0xcf: /* uint 64 */
            case 0xd3: /* int 64 */
                len = 8;
                break;
            case 0xcc: /* uint 8 */
            case 0xd0: /* int 8 */
                len = 1;
                break;
            case 0xcd: /* uint 16 */
            case 0xd1: /* int 16 */
                len = 2;
                break;
            case 0xd4: /* fixext 1 */
                len = 2;
                break;
            case 0xd5: /* fixext 2 */
                len = 3;
                break;
            case 0xd6: /* fixext 4 */
                len = 5;
                break;
            case 0xd7: /* fixext 8 */
                len = 9;
                break;
            case 0xd8: /* fixext 16 */
                len = 17;
                break;
            case 0xdc: /* array 16 */
            case 0xde: /* map 16 */
                if (end - p < 2) {
                    return NULL;
                }
                children = ((uint64_t) p[0] << 8) | p[1];
                p += 2;
                if (c == 0xde) {
                    children *= 2;
                }
                break;
            case 0xdd: /* array 32 */
            case 0xdf: /* map 32 */
                if (end - p < 4) {
                    return NULL;
                }
                children = ((uint64_t) p[0] << 24) | ((uint64_t) p[1] << 16) |
                           ((uint64_t) p[2] << 8) | p[3];
                p += 4;
                if (c == 0xdf) {
                    children *= 2;
                }
                break;
            default:   /* 0xc1: never used */
                return NULL;
            }
        }

        if (len > (uint64_t) (end - p)) {
            return NULL;
        }
        p += len;
        count += children;
    }

    return p;
}

static int raw_record_open(struct flb_log_event_encoder *context)
{
    if (context == NULL) {
        return FLB_EVENT_ENCODER_ERROR_INVALID_CONTEXT;
    }

    if (context->format != FLB_LOG_EVENT_FORMAT_FLUENT_BIT_V2 ||
        context->raw_record_open == FLB_TRUE) {
        return FLB_EVENT_ENCODER_ERROR_INVALID_ARGUMENT;
    }

    context->raw_record_open = FLB_TRUE;
    context->raw_record_start = context->buffer.size;

    return FLB_EVENT_ENCODER_SUCCESS;
}

/* a failed 'begin' leaves nothing behind */
static int raw_record_begin_failed(struct flb_log_event_encoder *context,
                                   int result)
{
    flb_log_event_encoder_raw_record_rollback(context);

    return result;
}

static inline int raw_record_result(int result)
{
    if (result != 0) {
        return FLB_EVENT_ENCODER_ERROR_SERIALIZATION_FAILURE;
    }

    return FLB_EVENT_ENCODER_SUCCESS;
}

int flb_log_event_encoder_raw_record_begin(struct flb_log_event_encoder *context,
                                           struct flb_time *timestamp)
{
    int result;

    if (timestamp == NULL ||
        flb_time_is_valid_eventtime(timestamp) != FLB_TRUE) {
        return FLB_EVENT_ENCODER_ERROR_INVALID_ARGUMENT;
    }

    result = raw_record_open(context);
    if (result != FLB_EVENT_ENCODER_SUCCESS) {
        return result;
    }

    result = raw_record_result(raw_record_header(context, timestamp));
    if (result != FLB_EVENT_ENCODER_SUCCESS) {
        return raw_record_begin_failed(context, result);
    }

    return FLB_EVENT_ENCODER_SUCCESS;
}

int flb_log_event_encoder_raw_record_begin_map(
        struct flb_log_event_encoder *context,
        struct flb_time *timestamp,
        uint32_t entries)
{
    int result;

    result = flb_log_event_encoder_raw_record_begin(context, timestamp);
    if (result != FLB_EVENT_ENCODER_SUCCESS) {
        return result;
    }

    result = raw_record_result(raw_record_body_header(context, entries));
    if (result != FLB_EVENT_ENCODER_SUCCESS) {
        return raw_record_begin_failed(context, result);
    }

    return FLB_EVENT_ENCODER_SUCCESS;
}

int flb_log_event_encoder_raw_record_begin_from_map(
        struct flb_log_event_encoder *context,
        struct flb_time *timestamp,
        const char *map, size_t map_length,
        uint32_t extra_entries)
{
    int result;
    uint32_t entries = 0;
    size_t header = 0;

    /* no content is handled as an empty map */
    if (map != NULL && map_length > 0) {
        header = raw_map_header((const unsigned char *) map, map_length,
                                &entries);
        if (header == 0) {
            return FLB_EVENT_ENCODER_ERROR_INVALID_ARGUMENT;
        }
    }

    if (entries > UINT32_MAX - extra_entries) {
        return FLB_EVENT_ENCODER_ERROR_INVALID_ARGUMENT;
    }

    result = flb_log_event_encoder_raw_record_begin_map(context, timestamp,
                                                        entries + extra_entries);
    if (result != FLB_EVENT_ENCODER_SUCCESS) {
        return result;
    }

    if (map_length > header) {
        result = raw_record_result(msgpack_pack_str_body(&context->packer,
                                                         map + header,
                                                         map_length - header));
        if (result != FLB_EVENT_ENCODER_SUCCESS) {
            return raw_record_begin_failed(context, result);
        }
    }

    return FLB_EVENT_ENCODER_SUCCESS;
}

int flb_log_event_encoder_raw_record_begin_from_record(
        struct flb_log_event_encoder *context,
        const char *buffer, size_t length,
        uint32_t extra_entries,
        size_t *consumed)
{
    int result;
    uint32_t entries;
    size_t pos;
    size_t header;
    const unsigned char *rec = (const unsigned char *) buffer;
    const unsigned char *body;
    const unsigned char *next;

    if (buffer == NULL || consumed == NULL) {
        return FLB_EVENT_ENCODER_ERROR_INVALID_ARGUMENT;
    }

    /* [[ timestamp (fixext 8, type 0)... */
    if (length < 14 || rec[0] != 0x92 || rec[1] != 0x92 ||
        rec[2] != 0xd7 || rec[3] != 0x00) {
        return FLB_EVENT_ENCODER_ERROR_INVALID_ARGUMENT;
    }
    pos = 12;

    /* ...empty metadata map ], */
    if (rec[pos] == 0x80) {
        pos += 1;
    }
    else if (rec[pos] == 0xdf && length >= pos + 5 &&
             rec[pos + 1] == 0 && rec[pos + 2] == 0 &&
             rec[pos + 3] == 0 && rec[pos + 4] == 0) {
        pos += 5;
    }
    else {
        return FLB_EVENT_ENCODER_ERROR_INVALID_ARGUMENT;
    }

    /* body map: locate where its keys and values end */
    header = raw_map_header(rec + pos, length - pos, &entries);
    if (header == 0 || entries > UINT32_MAX - extra_entries) {
        return FLB_EVENT_ENCODER_ERROR_INVALID_ARGUMENT;
    }

    body = rec + pos + header;
    next = raw_skip_objects(body, rec + length, (uint64_t) entries * 2);
    if (next == NULL) {
        return FLB_EVENT_ENCODER_ERROR_INVALID_ARGUMENT;
    }

    result = raw_record_open(context);
    if (result != FLB_EVENT_ENCODER_SUCCESS) {
        return result;
    }

    /* record header and timestamp as they are, empty metadata */
    result = msgpack_pack_str_body(&context->packer, buffer, 12);
    if (result == 0) {
        result = msgpack_pack_str_body(&context->packer,
                                       "\xdf\x00\x00\x00\x00", 5);
    }
    if (result == 0) {
        result = raw_record_body_header(context, entries + extra_entries);
    }
    if (result == 0 && next > body) {
        result = msgpack_pack_str_body(&context->packer,
                                       (const char *) body, next - body);
    }

    if (result != 0) {
        return raw_record_begin_failed(
                    context, FLB_EVENT_ENCODER_ERROR_SERIALIZATION_FAILURE);
    }

    *consumed = next - rec;

    return FLB_EVENT_ENCODER_SUCCESS;
}

int flb_log_event_encoder_raw_record_append_map(
        struct flb_log_event_encoder *context,
        uint32_t entries)
{
    if (context->raw_record_open != FLB_TRUE) {
        return FLB_EVENT_ENCODER_ERROR_INVALID_CONTEXT;
    }

    return raw_record_result(msgpack_pack_map(&context->packer, entries));
}

int flb_log_event_encoder_raw_record_append_string(
        struct flb_log_event_encoder *context,
        const char *value, size_t length)
{
    int result;

    if (context->raw_record_open != FLB_TRUE) {
        return FLB_EVENT_ENCODER_ERROR_INVALID_CONTEXT;
    }

    result = msgpack_pack_str(&context->packer, length);
    if (result == 0) {
        result = msgpack_pack_str_body(&context->packer, value, length);
    }

    return raw_record_result(result);
}

int flb_log_event_encoder_raw_record_append_uint64(
        struct flb_log_event_encoder *context,
        uint64_t value)
{
    if (context->raw_record_open != FLB_TRUE) {
        return FLB_EVENT_ENCODER_ERROR_INVALID_CONTEXT;
    }

    return raw_record_result(msgpack_pack_uint64(&context->packer, value));
}

int flb_log_event_encoder_raw_record_append_msgpack(
        struct flb_log_event_encoder *context,
        const char *buffer, size_t length)
{
    if (context->raw_record_open != FLB_TRUE) {
        return FLB_EVENT_ENCODER_ERROR_INVALID_CONTEXT;
    }

    return raw_record_result(msgpack_pack_str_body(&context->packer,
                                                   buffer, length));
}

int flb_log_event_encoder_raw_record_commit(struct flb_log_event_encoder *context)
{
    if (context->raw_record_open != FLB_TRUE) {
        return FLB_EVENT_ENCODER_ERROR_INVALID_CONTEXT;
    }

    context->raw_record_open = FLB_FALSE;
    flb_log_event_encoder_update_internal_state(context);

    return FLB_EVENT_ENCODER_SUCCESS;
}

int flb_log_event_encoder_raw_record_rollback(struct flb_log_event_encoder *context)
{
    if (context->raw_record_open != FLB_TRUE) {
        return FLB_EVENT_ENCODER_ERROR_INVALID_CONTEXT;
    }

    context->buffer.size = context->raw_record_start;
    context->raw_record_open = FLB_FALSE;
    flb_log_event_encoder_update_internal_state(context);

    return FLB_EVENT_ENCODER_SUCCESS;
}

int flb_log_event_encoder_emit_raw_record(struct flb_log_event_encoder *context,
                                          const char *buffer,
                                          size_t length)
{
    int result;

    result = msgpack_pack_str_body(&context->packer, buffer, length);

    if (result != 0) {
        result = FLB_EVENT_ENCODER_ERROR_SERIALIZATION_FAILURE;
    }
    else {
        result = FLB_EVENT_ENCODER_SUCCESS;
    }

    flb_log_event_encoder_update_internal_state(context);
    flb_log_event_encoder_reset_record(context);

    return result;
}

/*
 * Optimized emit_record: for FLUENT_BIT_V2 appends the record as raw
 * msgpack array bytes [ [timestamp, metadata], body ] to the main buffer
 * (no root buffer build/copy), matching the slow path format.
 */
int flb_log_event_encoder_emit_record(struct flb_log_event_encoder *context)
{
    int      result;
    char     ts_buf[8];
    char     rec_header[5];
    size_t   original_size;
    uint32_t sec;
    uint32_t nsec;

    if (context == NULL) {
        return FLB_EVENT_ENCODER_ERROR_INVALID_CONTEXT;
    }

    original_size = context->buffer.size;
    result = FLB_EVENT_ENCODER_SUCCESS;

    if (context->root.size == 0) {
        if (context->format == FLB_LOG_EVENT_FORMAT_FLUENT_BIT_V2 &&
            context->metadata.data != NULL && context->body.data != NULL) {
            /*
             * Direct-emit: append raw array bytes [ [timestamp, metadata], body ]
             * (fixarray 2, fixarray 2, fixext 8 type 0, 8b ts, metadata, body).
             * Do not wrap in a msgpack string; match slow path which uses
             * msgpack_pack_str_body(root.data, root.size) with no str header.
             */
            rec_header[0] = (char) 0x92;
            rec_header[1] = (char) 0x92;
            rec_header[2] = (char) 0xd7;
            rec_header[3] = (char) 0x00;

            result = msgpack_pack_str_body(&context->packer,
                                           rec_header, (size_t) 4);
            if (result == 0) {
                sec = FLB_UINT32_TO_NETWORK_BYTE_ORDER((uint32_t) context->timestamp.tm.tv_sec);
                nsec = FLB_UINT32_TO_NETWORK_BYTE_ORDER((uint32_t) context->timestamp.tm.tv_nsec);
                memcpy(&ts_buf[0], &sec, 4);
                memcpy(&ts_buf[4], &nsec, 4);
                result = msgpack_pack_str_body(&context->packer, ts_buf, 8);
            }
            if (result == 0) {
                result = msgpack_pack_str_body(&context->packer,
                                               context->metadata.data,
                                               context->metadata.size);
            }
            if (result == 0) {
                result = msgpack_pack_str_body(&context->packer,
                                               context->body.data,
                                               context->body.size);
            }
            if (result != 0) {
                result = FLB_EVENT_ENCODER_ERROR_SERIALIZATION_FAILURE;
            }
            else {
                result = FLB_EVENT_ENCODER_SUCCESS;
            }
        }
        else {
            result = flb_log_event_encoder_root_begin_array(context);

            if (context->format == FLB_LOG_EVENT_FORMAT_FLUENT_BIT_V2) {
                if (result == FLB_EVENT_ENCODER_SUCCESS) {
                    result = flb_log_event_encoder_root_begin_array(context);
                }
            }

            if (result == FLB_EVENT_ENCODER_SUCCESS) {
                result = flb_log_event_encoder_append_root_timestamp(
                            context, &context->timestamp);
            }

            if (context->format == FLB_LOG_EVENT_FORMAT_FLUENT_BIT_V2) {
                if (result == FLB_EVENT_ENCODER_SUCCESS) {
                    result = flb_log_event_encoder_append_root_raw_msgpack(
                                context,
                                context->metadata.data,
                                context->metadata.size);
                }

                if (result == FLB_EVENT_ENCODER_SUCCESS) {
                    result = flb_log_event_encoder_root_commit_array(context);
                }
            }

            if (result == FLB_EVENT_ENCODER_SUCCESS) {
                result = flb_log_event_encoder_append_root_raw_msgpack(
                            context,
                            context->body.data,
                            context->body.size);
            }

            if (result == FLB_EVENT_ENCODER_SUCCESS) {
                result = flb_log_event_encoder_dynamic_field_flush(&context->root);
            }

            if (result == FLB_EVENT_ENCODER_SUCCESS &&
                context->root.data != NULL && context->root.size > 0) {
                result = msgpack_pack_str_body(&context->packer,
                                               context->root.data,
                                               context->root.size);

                if (result != 0) {
                    result = FLB_EVENT_ENCODER_ERROR_SERIALIZATION_FAILURE;
                }
                else {
                    result = FLB_EVENT_ENCODER_SUCCESS;
                }
            }
        }
    }
    else if (result == FLB_EVENT_ENCODER_SUCCESS &&
             context->root.data != NULL && context->root.size > 0) {
        result = msgpack_pack_str_body(&context->packer,
                                       context->root.data,
                                       context->root.size);

        if (result != 0) {
            result = FLB_EVENT_ENCODER_ERROR_SERIALIZATION_FAILURE;
        }
        else {
            result = FLB_EVENT_ENCODER_SUCCESS;
        }
    }

    if (result != FLB_EVENT_ENCODER_SUCCESS) {
        context->buffer.size = original_size;
    }

    flb_log_event_encoder_update_internal_state(context);
    flb_log_event_encoder_reset_record(context);

    return result;
}

int flb_log_event_encoder_reset_record(struct flb_log_event_encoder *context)
{
    flb_log_event_encoder_dynamic_field_reset(&context->metadata);
    flb_log_event_encoder_dynamic_field_reset(&context->body);
    flb_log_event_encoder_dynamic_field_reset(&context->root);

    flb_time_zero(&context->timestamp);

    return FLB_EVENT_ENCODER_SUCCESS;
}

int flb_log_event_encoder_rollback_record(struct flb_log_event_encoder *context)
{
    return flb_log_event_encoder_reset_record(context);
}

int flb_log_event_encoder_begin_record(struct flb_log_event_encoder *context)
{
    flb_log_event_encoder_reset_record(context);

    flb_log_event_encoder_metadata_begin_map(context);
    flb_log_event_encoder_body_begin_map(context);

    return FLB_EVENT_ENCODER_SUCCESS;
}

int flb_log_event_encoder_commit_record(struct flb_log_event_encoder *context)
{
    int result;

    result = flb_log_event_encoder_dynamic_field_flush(&context->metadata);

    if (result == FLB_EVENT_ENCODER_SUCCESS) {
        result = flb_log_event_encoder_dynamic_field_flush(&context->body);
    }

    if (result == FLB_EVENT_ENCODER_SUCCESS) {
        result = flb_log_event_encoder_emit_record(context);
    }
    else {
        flb_log_event_encoder_reset_record(context);
    }

    return result;
}

int flb_log_event_encoder_set_timestamp(struct flb_log_event_encoder *context,
                                        struct flb_time *timestamp)
{
    if (timestamp != NULL) {
        if (flb_time_is_valid_eventtime(timestamp) != FLB_TRUE &&
            !(timestamp->tm.tv_nsec == 0 &&
              (timestamp->tm.tv_sec == FLB_LOG_EVENT_GROUP_START ||
               timestamp->tm.tv_sec == FLB_LOG_EVENT_GROUP_END))) {
            return FLB_EVENT_ENCODER_ERROR_INVALID_ARGUMENT;
        }

        flb_time_copy(&context->timestamp, timestamp);
    }
    else {
        flb_time_get(&context->timestamp);
    }

    return FLB_EVENT_ENCODER_SUCCESS;
}

int flb_log_event_encoder_set_current_timestamp(struct flb_log_event_encoder *context)
{
    return flb_log_event_encoder_set_timestamp(context, NULL);
}

int flb_log_event_encoder_append_metadata_values_unsafe(struct flb_log_event_encoder *context, ...)
{
    va_list arguments;
    int     result;

    va_start(arguments, context);

    result = flb_log_event_encoder_append_values_unsafe(
            context,
            FLB_LOG_EVENT_METADATA,
            arguments);

    va_end(arguments);

    return result;
}

int flb_log_event_encoder_append_body_values_unsafe(
        struct flb_log_event_encoder *context,
        ...)
{
    va_list arguments;
    int     result;

    va_start(arguments, context);

    result = flb_log_event_encoder_append_values_unsafe(
            context,
            FLB_LOG_EVENT_BODY,
            arguments);

    va_end(arguments);

    return result;
}

int flb_log_event_encoder_append_root_values_unsafe(
        struct flb_log_event_encoder *context,
        ...)
{
    va_list arguments;
    int     result;

    va_start(arguments, context);

    result = flb_log_event_encoder_append_values_unsafe(
            context,
            FLB_LOG_EVENT_ROOT,
            arguments);

    va_end(arguments);

    return result;
}

const char *flb_log_event_encoder_get_error_description(int error_code)
{
    const char *ret;

    switch (error_code) {
    case FLB_EVENT_ENCODER_SUCCESS:
        ret = "Success";
        break;

    case FLB_EVENT_ENCODER_ERROR_UNSPECIFIED:
        ret = "Unspecified";
        break;

    case FLB_EVENT_ENCODER_ERROR_ALLOCATION_ERROR:
        ret = "Allocation error";
        break;

    case FLB_EVENT_ENCODER_ERROR_INVALID_CONTEXT:
        ret = "Invalid context";
        break;

    case FLB_EVENT_ENCODER_ERROR_INVALID_ARGUMENT:
        ret = "Invalid argument";
        break;

    case FLB_EVENT_ENCODER_ERROR_SERIALIZATION_FAILURE:
        ret = "Serialization failure";
        break;

    case FLB_EVENT_ENCODER_ERROR_INVALID_VALUE_TYPE:
        ret = "Invalid value type";
        break;

    default:
        ret = "Unknown error";
    }

    return ret;
}


int flb_log_event_encoder_group_init(struct flb_log_event_encoder *context)
{
    int ret;
    struct flb_time tm;

    ret = flb_log_event_encoder_begin_record(context);
    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        return -1;
    }

    flb_time_set(&tm, FLB_LOG_EVENT_GROUP_START, 0);
    ret = flb_log_event_encoder_set_timestamp(context, &tm);
    if (ret == -1) {
        return -1;
    }

    return 0;
}

int flb_log_event_encoder_group_header_end(struct flb_log_event_encoder *context)
{
    int ret;

    ret = flb_log_event_encoder_commit_record(context);
    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        return ret;
    }

    return 0;
}

int flb_log_event_encoder_group_end(struct flb_log_event_encoder *context)
{
    int ret;
    struct flb_time tm;

    ret = flb_log_event_encoder_begin_record(context);
    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        return -1;
    }

    flb_time_set(&tm, FLB_LOG_EVENT_GROUP_END, 0);
    ret = flb_log_event_encoder_set_timestamp(context, &tm);
    if (ret == -1) {
        return -1;
    }

    ret = flb_log_event_encoder_commit_record(context);
    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        return ret;
    }

    return 0;
}
