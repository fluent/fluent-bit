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
                                             char *raw_message_key_name,
                                             char *base_object_buffer,
                                             size_t base_object_size,
                                             char *raw_message_buffer,
                                             size_t raw_message_size)
{
    size_t             new_entry_index;
    msgpack_unpacked   unpacked_buffer;
    size_t             unpacker_offset;
    size_t             new_object_size;
    msgpack_object    *resized_object;
    msgpack_sbuffer    packer_buffer;
    msgpack_object_kv *new_entry;
    msgpack_packer     packer;
    int                result;

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

    new_object_size = base_object_size + sizeof(msgpack_object);

    resized_object = flb_calloc(1, new_object_size);

    if (resized_object == NULL) {
        flb_errno();

        return -4;
    }

    memcpy(resized_object, &unpacked_buffer.data, base_object_size);

    new_entry_index = resized_object->via.map.size;
    resized_object->via.map.size++;

    new_entry = &resized_object->via.map.ptr[new_entry_index];

    new_entry->key.type = MSGPACK_OBJECT_STR;
    new_entry->key.via.str.size = strlen(raw_message_key_name);
    new_entry->key.via.str.ptr  = raw_message_key_name;

    new_entry->val.type = MSGPACK_OBJECT_BIN;
    new_entry->val.via.bin.size = raw_message_size;
    new_entry->val.via.bin.ptr  = raw_message_buffer;

    msgpack_sbuffer_init(&packer_buffer);

    msgpack_packer_init(&packer, &packer_buffer, msgpack_sbuffer_write);

    msgpack_pack_object(&packer, *resized_object);

    *result_buffer = flb_calloc(1, packer_buffer.size);

    if (*result_buffer == NULL) {
        flb_errno();

        result = -4;
    }
    else {
        memcpy(*result_buffer, packer_buffer.data, packer_buffer.size);

        *result_size = packer_buffer.size;

        result = 0;
    }

    msgpack_sbuffer_destroy(&packer_buffer);

    msgpack_unpacked_destroy(&unpacked_buffer);

    flb_free(resized_object);

    return result;
}

static inline int pack_line(struct flb_syslog *ctx,
                            struct flb_time *time,
                            char *data, size_t data_size,
                            char *raw_data, size_t raw_data_size)
{
    char           *modified_data_buffer;
    size_t          modified_data_size;
    msgpack_sbuffer mp_sbuf;
    msgpack_packer  mp_pck;
    int             result;

    modified_data_buffer = NULL;

    if (ctx->message_raw_key != NULL) {
        result = append_raw_message_to_record_data(&modified_data_buffer,
                                                   &modified_data_size,
                                                   ctx->message_raw_key,
                                                   data,
                                                   data_size,
                                                   raw_data,
                                                   raw_data_size);

        if (result != 0) {
            flb_plg_debug(ctx->ins, "error appending raw message : %d", result);
        }
    }

    /* Initialize local msgpack buffer */
    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    msgpack_pack_array(&mp_pck, 2);
    flb_time_append_to_msgpack(time, &mp_pck, 0);

    if (modified_data_buffer != NULL) {
        msgpack_sbuffer_write(&mp_sbuf, modified_data_buffer, modified_data_size);
    }
    else {
        msgpack_sbuffer_write(&mp_sbuf, data, data_size);
    }

    flb_input_log_append(ctx->ins, NULL, 0, mp_sbuf.data, mp_sbuf.size);
    msgpack_sbuffer_destroy(&mp_sbuf);

    if (modified_data_buffer != NULL) {
        flb_free(modified_data_buffer);
    }

    return 0;
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
