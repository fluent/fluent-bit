/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2023 The Fluent Bit Authors
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

#include <fluent-bit/flb_event_decoder.h>
#include <msgpack.h>

static int event_decoder_destroy_mpack(struct flb_event_decoder *dec)
{
    mpack_reader_destroy(&(dec->decoder.mpack.reader));
    return 0;
}
static int event_decoder_destroy_msgpack(struct flb_event_decoder *dec)
{
    msgpack_unpacked_destroy(&(dec->decoder.msgpack.upk));
    return 0;
}

int flb_event_decoder_clear(struct flb_event_decoder *dec)
{
    int ret = 0;

    if (dec == NULL) {
        flb_error("%s: dec is NULL", __FUNCTION__);
        return -1;
    }

    switch (dec->type) {
    case FLB_EVENT_LIB_TYPE_MSGPACK:
        ret = event_decoder_destroy_msgpack(dec);
        break;

    case FLB_EVENT_LIB_TYPE_MPACK:
        ret = event_decoder_destroy_mpack(dec);
        break;

    default:
        flb_error("%s: unknown type %d", __FUNCTION__, dec->type);
        return -1;
    }
    return ret;
}

int flb_event_decoder_destroy(struct flb_event_decoder *dec)
{
    int ret = 0;

    ret = flb_event_decoder_clear(dec);
    flb_free(dec);

    return ret;
}

static int event_decoder_create_mpack(struct flb_event_decoder *dec)
{
    mpack_reader_init_data(&(dec->decoder.mpack.reader), dec->raw_data, dec->raw_data_size);
    dec->offset = 0;
    return 0;
}

static int event_decoder_create_msgpack(struct flb_event_decoder *dec)
{
    msgpack_unpacked_init(&(dec->decoder.msgpack.upk));
    dec->offset = 0;
    return 0;
}

static int event_decoder_init(struct flb_event_decoder *dec, void *input_buf, size_t input_size)
{
    int ret;

    dec->raw_data = input_buf;
    dec->raw_data_size = input_size;

    switch (dec->type) {
    case FLB_EVENT_LIB_TYPE_MSGPACK:
        ret = event_decoder_create_msgpack(dec);
        break;

    case FLB_EVENT_LIB_TYPE_MPACK:
        ret = event_decoder_create_mpack(dec);
        break;

    default:
        flb_error("%s: unknown type %d", __FUNCTION__, dec->type);
        return -1;
    }

    return ret;
}

struct flb_event_decoder *flb_event_decoder_create(void *input_buf, size_t input_size, int decoder_opt)
{
    int ret;
    struct flb_event_decoder *dec = NULL;

    dec = flb_calloc(1, sizeof(struct flb_event_decoder));
    if (dec == NULL) {
        flb_errno();
        return NULL;
    }

    /* check decoder option */
    dec->type = FLB_EVENT_LIB_TYPE_MSGPACK;
    if (decoder_opt & FLB_EVENT_DECODER_OPT_USE_MPACK) {
        dec->type = FLB_EVENT_LIB_TYPE_MPACK;
    }

    ret = event_decoder_init(dec, input_buf, input_size);
    if (ret < 0) {
        flb_event_decoder_destroy(dec);
        return NULL;
    }

    return dec;
}

static int time_pop_from_mpack(struct flb_event *event, mpack_reader_t *reader)
{
    int ret = -1;

    switch(event->format) {
    case FLB_EVENT_FMT_TIME_RECORD:
        ret = flb_time_pop_from_mpack(&(event->timestamp), reader);
        break;
    default:
        flb_error("format=%d is not supported", event->format);
    }
    return ret;
}

static int time_pop_from_msgpack(struct flb_event *event, msgpack_unpacked *upk)
{
    int ret = -1;
    msgpack_object *obj;

    switch(event->format) {
    case FLB_EVENT_FMT_TIME_RECORD:
        ret = flb_time_pop_from_msgpack(&(event->timestamp), upk, &obj);
        event->record.reader.msgpack = obj;
        break;
    default:
        flb_error("format=%d is not supported", event->format);
    }
    return ret;
}

static int time_pop(struct flb_event_decoder *dec, struct flb_event *event)
{
    switch (dec->type) {
    case FLB_EVENT_LIB_TYPE_MSGPACK:
        return time_pop_from_msgpack(event, &(dec->decoder.msgpack.upk));
    case FLB_EVENT_LIB_TYPE_MPACK:
        return time_pop_from_mpack(event, &(dec->decoder.mpack.reader));
    default:
        flb_error("%s: unknown type %d", __FUNCTION__, dec->type);
    }
    return FLB_FALSE;
}

static int is_event_format_time_record_mpack(mpack_reader_t *reader)
{
    mpack_tag_t tag;
    const char *start_addr = reader->data;
    int ret = FLB_FALSE;

    tag = mpack_read_tag(reader);

    /* check if format is [TIMESTAMP, {RECORD}] */
    if (mpack_tag_type(&tag) != mpack_type_array) {
        flb_trace("%s: object is not array", __FUNCTION__);
        goto is_event_format_time_record_mpack_end;
    }
    if (mpack_tag_array_count(&tag) != 2) {
        flb_trace("%s: array size is not 2", __FUNCTION__);
        goto is_event_format_time_record_mpack_end;
    }

    /* TODO: is second element of array a map */

    ret = FLB_TRUE;
 is_event_format_time_record_mpack_end:
    /* reset pointer */
    reader->data = start_addr;
    return ret;
}

static int is_event_format_time_record_msgpack(msgpack_object *obj)
{
    /* check if format is [TIMESTAMP, {RECORD}] */
    if (obj->type != MSGPACK_OBJECT_ARRAY) {
        flb_trace("%s: object is not array", __FUNCTION__);
        return FLB_FALSE;
    }
    if (obj->via.array.size != 2) {
        flb_trace("%s: array size is not 2", __FUNCTION__);
        return FLB_FALSE;
    }
    if (obj->via.array.ptr[1].type != MSGPACK_OBJECT_MAP) {
        flb_trace("%s: object is not map", __FUNCTION__);
        return FLB_FALSE;
    }
    return FLB_TRUE;
}

static int is_event_format_time_record(struct flb_event_decoder *dec, struct flb_event *event)
{
    switch (dec->type) {
    case FLB_EVENT_LIB_TYPE_MSGPACK:
        return is_event_format_time_record_msgpack(&(dec->decoder.msgpack.upk.data));
    case FLB_EVENT_LIB_TYPE_MPACK:
        return is_event_format_time_record_mpack(&(dec->decoder.mpack.reader));
    default:
        flb_error("%s: unknown type %d", __FUNCTION__, dec->type);
    }
    return FLB_FALSE;
}

static int decode_event_format(struct flb_event_decoder *dec, struct flb_event *event)
{
    /* check if format is [TIMESTAMP, {RECORD}] */
    if (is_event_format_time_record(dec, event)) {
        event->format = FLB_EVENT_FMT_TIME_RECORD;
        return 0;
    }

    event->format = FLB_EVENT_FMT_UNKNOWN;
    return -1;
}

static int event_decode(struct flb_event_decoder *dec, struct flb_event *event)
{
    int ret;

    flb_event_set_default(event);

    ret = decode_event_format(dec, event);
    if (ret < 0) {
        flb_error("%s: Fluent event format is invalid", __FUNCTION__);
        return -1;
    }

    ret = time_pop(dec, event);
    if (ret < 0) {
        flb_error("%s: failed to get timestamp from event", __FUNCTION__);
    }
    event->record.type = FLB_EVENT_LIB_TYPE_MSGPACK;

    return 0;
}

static int event_decoder_next_mpack(struct flb_event_decoder *dec,
                                    struct flb_event *event)
{
    int i_ret;

    event->record.reader.mpack = NULL;
    if (((void*)dec->decoder.mpack.reader.data - dec->raw_data) >= dec->raw_data_size) {
        /* no data */
        printf("reader=%p raw_data=%p diff=%ld\n", dec->decoder.mpack.reader.data, dec->raw_data,
               (void*)dec->decoder.mpack.reader.data - dec->raw_data);
        return -1;
    }

    i_ret = event_decode(dec, event);
    event->record.reader.mpack = &(dec->decoder.mpack.reader);

    return i_ret;
}

static int event_decoder_next_msgpack(struct flb_event_decoder *dec,
                                      struct flb_event *event)
{
    msgpack_unpack_return m_ret;
    int i_ret;

    m_ret = msgpack_unpack_next(&(dec->decoder.msgpack.upk), dec->raw_data, dec->raw_data_size,
                              &(dec->offset));
    switch (m_ret) {
    case MSGPACK_UNPACK_SUCCESS:
        i_ret = event_decode(dec, event);
        break;
    case MSGPACK_UNPACK_EXTRA_BYTES:
        flb_trace("%s:MSGPACK_UNPACK_EXTRA_BYTES", __FUNCTION__);
        return 1;
    case MSGPACK_UNPACK_CONTINUE:
        flb_trace("%s:MSGPACK_UNPACK_CONTINUE", __FUNCTION__);
        return 1;
    case MSGPACK_UNPACK_PARSE_ERROR:
        flb_error("%s:MSGPACK_UNPACK_PARSE_ERROR", __FUNCTION__);
        return -1;
    case MSGPACK_UNPACK_NOMEM_ERROR:
        flb_error("%s:MSGPACK_UNPACK_NOMEM_ERROR", __FUNCTION__);
        return -1;
    }

    return i_ret;
}

int flb_event_decoder_next(struct flb_event_decoder *dec,
                           struct flb_event *event)
{
    int ret = -1;

    if (dec == NULL || event == NULL) {
        flb_error("%s: input and/or NULL. dec=%p event=%p", __FUNCTION__, dec, event);
        return -1;
    }

    switch (dec->type) {
    case FLB_EVENT_LIB_TYPE_MSGPACK:
        ret = event_decoder_next_msgpack(dec, event);
        break;

    case FLB_EVENT_LIB_TYPE_MPACK:
        ret = event_decoder_next_mpack(dec, event);
        break;

    default:
        flb_error("%s: unknown type %d",__FUNCTION__, dec->type);
        return -1;
    }

    return ret;
}

int flb_event_decoder_reuse(struct flb_event_decoder *dec, void *input_buf, size_t input_size)
{
    int ret;

    ret = flb_event_decoder_clear(dec);
    if (ret < 0) {
        return -1;
    }
    return event_decoder_init(dec, input_buf, input_size);
}
