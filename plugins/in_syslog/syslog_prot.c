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

#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_parser.h>
#include <fluent-bit/flb_time.h>

#include "syslog.h"
#include "syslog_conn.h"

#include <string.h>

static inline void consume_bytes(char *buf, int bytes, int length)
{
    memmove(buf, buf + bytes, length - bytes);
}

static int append_raw_message_to_record_data(char **result_buffer,
                                             size_t *result_size,
                                             flb_sds_t raw_message_key_name,
                                             char *base_object_buffer,
                                             size_t base_object_size,
                                             char *raw_message_buffer,
                                             size_t raw_message_size)
{
    int                i;
    int                result;
    size_t             unpacker_offset;
    msgpack_sbuffer    mp_sbuf;
    msgpack_packer     mp_pck;
    msgpack_unpacked   unpacked_buffer;
    *result_buffer = NULL;
    *result_size = 0;

    unpacker_offset = 0;
    msgpack_unpacked_init(&unpacked_buffer);
    result = msgpack_unpack_next(&unpacked_buffer,
                                 base_object_buffer,
                                 base_object_size,
                                 &unpacker_offset);

    if (result != MSGPACK_UNPACK_SUCCESS) {
        return -1;
    }

    if (unpacker_offset != base_object_size) {
        msgpack_unpacked_destroy(&unpacked_buffer);
        return -2;
    }

    if (unpacked_buffer.data.type != MSGPACK_OBJECT_MAP) {
        msgpack_unpacked_destroy(&unpacked_buffer);
        return -3;
    }

    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    msgpack_pack_map(&mp_pck, unpacked_buffer.data.via.map.size + 1);

    for (i = 0; i < unpacked_buffer.data.via.map.size; i++) {
        msgpack_pack_object(&mp_pck, unpacked_buffer.data.via.map.ptr[i].key);
        msgpack_pack_object(&mp_pck, unpacked_buffer.data.via.map.ptr[i].val);
    }

    msgpack_pack_str(&mp_pck, flb_sds_len(raw_message_key_name));
    msgpack_pack_str_body(&mp_pck, raw_message_key_name, flb_sds_len(raw_message_key_name));
    msgpack_pack_str(&mp_pck, raw_message_size);
    msgpack_pack_str_body(&mp_pck, raw_message_buffer, raw_message_size);

    *result_buffer = mp_sbuf.data;
    *result_size = mp_sbuf.size;

    msgpack_unpacked_destroy(&unpacked_buffer);
    return result;
}

static inline int pack_line(struct flb_syslog *ctx,
                            struct flb_time *time,
                            char *data, size_t data_size,
                            char *raw_data, size_t raw_data_size)
{
    char   *modified_data_buffer;
    size_t  modified_data_size;
    int     result;

    modified_data_buffer = NULL;

    if (ctx->raw_message_key != NULL) {
        result = append_raw_message_to_record_data(&modified_data_buffer,
                                                   &modified_data_size,
                                                   ctx->raw_message_key,
                                                   data,
                                                   data_size,
                                                   raw_data,
                                                   raw_data_size);

        if (result != 0) {
            flb_plg_debug(ctx->ins, "error appending raw message : %d", result);
        }
    }

    result = flb_log_event_encoder_begin_record(ctx->log_encoder);

    if (result == FLB_EVENT_ENCODER_SUCCESS) {
        result = flb_log_event_encoder_set_timestamp(ctx->log_encoder, time);
    }

    if (result == FLB_EVENT_ENCODER_SUCCESS) {
        if (modified_data_buffer != NULL) {
            result = flb_log_event_encoder_set_body_from_raw_msgpack(
                    ctx->log_encoder, modified_data_buffer, modified_data_size);
        }
        else {
            result = flb_log_event_encoder_set_body_from_raw_msgpack(
                        ctx->log_encoder, data, data_size);
        }
    }

    if (result == FLB_EVENT_ENCODER_SUCCESS) {
        result = flb_log_event_encoder_commit_record(ctx->log_encoder);
    }

    if (result == FLB_EVENT_ENCODER_SUCCESS) {
        flb_input_log_append(ctx->ins, NULL, 0,
                             ctx->log_encoder->output_buffer,
                             ctx->log_encoder->output_length);
        result = 0;
    }
    else {
        flb_plg_error(ctx->ins, "log event encoding error : %d", result);

        result = -1;
    }

    flb_log_event_encoder_reset(ctx->log_encoder);

    if (modified_data_buffer != NULL) {
        flb_free(modified_data_buffer);
    }

    return result;
}

int syslog_prot_process(struct syslog_conn *conn)
{
    int len;
    int ret;
    char *p;
    char *eof;
    char *end;
    void *out_buf;
    size_t out_size;
    struct flb_time out_time;
    struct flb_syslog *ctx = conn->ctx;

    eof = conn->buf_data;
    end = conn->buf_data + conn->buf_len;

    /* Always parse while some remaining bytes exists */
    while (eof < end) {
        /* Lookup the ending byte */
        eof = p = conn->buf_data + conn->buf_parsed;
        while (*eof != '\n' && *eof != '\0' && eof < end) {
            eof++;
        }

        /* Incomplete message */
        if (eof == end || (*eof != '\n' && *eof != '\0')) {
            break;
        }

        /* No data ? */
        len = (eof - p);
        if (len == 0) {
            consume_bytes(conn->buf_data, 1, conn->buf_len);
            conn->buf_len--;
            conn->buf_parsed = 0;
            conn->buf_data[conn->buf_len] = '\0';
            end = conn->buf_data + conn->buf_len;

            if (conn->buf_len == 0) {
                break;
            }

            continue;
        }

        /* Process the string */
        ret = flb_parser_do(ctx->parser, p, len,
                            &out_buf, &out_size, &out_time);
        if (ret >= 0) {
            if (flb_time_to_nanosec(&out_time) == 0L) {
                flb_time_get(&out_time);
            }
            pack_line(ctx, &out_time,
                      out_buf, out_size,
                      p, len);
            flb_free(out_buf);
        }
        else {
            flb_plg_warn(ctx->ins, "error parsing log message with parser '%s'",
                         ctx->parser->name);
            flb_plg_debug(ctx->ins, "unparsed log message: %.*s", len, p);
        }

        conn->buf_parsed += len + 1;
        end = conn->buf_data + conn->buf_len;
        eof = conn->buf_data + conn->buf_parsed;
    }

    if (conn->buf_parsed > 0) {
        consume_bytes(conn->buf_data, conn->buf_parsed, conn->buf_len);
        conn->buf_len -= conn->buf_parsed;
        conn->buf_parsed = 0;
        conn->buf_data[conn->buf_len] = '\0';
    }

    return 0;
}

int syslog_prot_process_udp(char *buf, size_t size, struct flb_syslog *ctx)
{
    int ret;
    void *out_buf;
    size_t out_size;
    struct flb_time out_time = {0};

    ret = flb_parser_do(ctx->parser, buf, size,
                        &out_buf, &out_size, &out_time);
    if (ret >= 0) {
        if (flb_time_to_double(&out_time) == 0) {
            flb_time_get(&out_time);
        }
        pack_line(ctx, &out_time,
                  out_buf, out_size,
                  buf, size);
        flb_free(out_buf);
    }
    else {
        flb_plg_warn(ctx->ins, "error parsing log message with parser '%s'",
                     ctx->parser->name);
        flb_plg_debug(ctx->ins, "unparsed log message: %.*s",
                      (int) size, buf);
        return -1;
    }

    return 0;
}
