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

#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_parser.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_pack.h>

#include "syslog.h"
#include "syslog_conn.h"
#include "syslog_prot.h"

#include <string.h>

static inline void consume_bytes(char *buf, int bytes, int length)
{
    memmove(buf, buf + bytes, length - bytes);
}

static int append_message_to_record_data(char **result_buffer,
                                         size_t *result_size,
                                         flb_sds_t message_key_name,
                                         char *base_object_buffer,
                                         size_t base_object_size,
                                         char *message_buffer,
                                         size_t message_size,
                                         int message_type)
{
    int                result = FLB_MAP_NOT_MODIFIED;
    char              *modified_data_buffer;
    int                modified_data_size;
    msgpack_object_kv *new_map_entries[1];
    msgpack_object_kv  message_entry;
    *result_buffer = NULL;
    *result_size = 0;
    modified_data_buffer = NULL;

    if (message_key_name != NULL) {
        new_map_entries[0] = &message_entry;

        message_entry.key.type = MSGPACK_OBJECT_STR;
        message_entry.key.via.str.size = flb_sds_len(message_key_name);
        message_entry.key.via.str.ptr  = message_key_name;

        if (message_type == MSGPACK_OBJECT_BIN) {
            message_entry.val.type = MSGPACK_OBJECT_BIN;
            message_entry.val.via.bin.size = message_size;
            message_entry.val.via.bin.ptr  = message_buffer;
        }
        else if (message_type == MSGPACK_OBJECT_STR) {
            message_entry.val.type = MSGPACK_OBJECT_STR;
            message_entry.val.via.str.size = message_size;
            message_entry.val.via.str.ptr  = message_buffer;
        }
        else {
            result = FLB_MAP_EXPANSION_INVALID_VALUE_TYPE;
        }

        if (result == FLB_MAP_NOT_MODIFIED) {
            result = flb_msgpack_expand_map(base_object_buffer,
                                            base_object_size,
                                            new_map_entries, 1,
                                            &modified_data_buffer,
                                            &modified_data_size);
            if (result == 0) {
                result = FLB_MAP_EXPAND_SUCCESS;
            }
            else {
                result = FLB_MAP_EXPANSION_ERROR;
            }
        }
    }

    if (result == FLB_MAP_EXPAND_SUCCESS) {
        *result_buffer = modified_data_buffer;
        *result_size = modified_data_size;
    }

    return result;
}

static inline int pack_line(struct flb_syslog *ctx,
                            struct flb_time *time,
                            struct flb_connection *connection,
                            char *data, size_t data_size,
                            char *raw_data, size_t raw_data_size)
{
    char   *modified_data_buffer;
    size_t  modified_data_size;
    char   *appended_address_buffer;
    size_t  appended_address_size;
    int     result;
    char   *source_address;

    source_address = NULL;
    modified_data_buffer = NULL;
    appended_address_buffer = NULL;

    if (ctx->raw_message_key != NULL) {
        result = append_message_to_record_data(&modified_data_buffer,
                                               &modified_data_size,
                                               ctx->raw_message_key,
                                               data,
                                               data_size,
                                               raw_data,
                                               raw_data_size,
                                               MSGPACK_OBJECT_BIN);

        if (result == FLB_MAP_EXPANSION_ERROR) {
            flb_plg_debug(ctx->ins, "error expanding raw message : %d", result);
        }
    }

    if (ctx->source_address_key != NULL) {
        source_address = flb_connection_get_remote_address(connection);
        if (source_address != NULL) {
            if (modified_data_buffer != NULL) {
                result = append_message_to_record_data(&appended_address_buffer,
                                                       &appended_address_size,
                                                       ctx->source_address_key,
                                                       modified_data_buffer,
                                                       modified_data_size,
                                                       source_address,
                                                       strlen(source_address),
                                                       MSGPACK_OBJECT_STR);
            }
            else {
                result = append_message_to_record_data(&appended_address_buffer,
                                                       &appended_address_size,
                                                       ctx->source_address_key,
                                                       data,
                                                       data_size,
                                                       source_address,
                                                       strlen(source_address),
                                                       MSGPACK_OBJECT_STR);
            }

            if (result == FLB_MAP_EXPANSION_ERROR) {
                flb_plg_debug(ctx->ins, "error expanding source_address : %d", result);
            }
        }
    }

    result = flb_log_event_encoder_begin_record(ctx->log_encoder);

    if (result == FLB_EVENT_ENCODER_SUCCESS) {
        result = flb_log_event_encoder_set_timestamp(ctx->log_encoder, time);
    }

    if (result == FLB_EVENT_ENCODER_SUCCESS) {
        if (appended_address_buffer != NULL) {
            result = flb_log_event_encoder_set_body_from_raw_msgpack(
                    ctx->log_encoder, appended_address_buffer, appended_address_size);
        }
        else if (modified_data_buffer != NULL) {
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
    if (appended_address_buffer != NULL) {
        flb_free(appended_address_buffer);
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
        while (*eof != '\n' && eof < end) {
            /* Skip null bytes - they should not be treated as message delimiters */
            if (*eof == '\0') {
                eof++;
                continue;
            }
            eof++;
        }

        /* Incomplete message */
        if (eof == end || *eof != '\n') {
            break;
        }

        /* No data ? */
        len = (eof - p);
        if (len == 0) {
            conn->buf_parsed += 1;
            eof = conn->buf_data + conn->buf_parsed;
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
                      conn->connection,
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

int syslog_prot_process_udp(struct syslog_conn *conn)
{
    int ret;
    void *out_buf;
    size_t out_size;
    struct flb_time out_time = {0};
    char *buf;
    size_t size;
    struct flb_syslog *ctx;
    struct flb_connection *connection;

    buf = conn->buf_data;
    size = conn->buf_len;
    ctx = conn->ctx;
    connection = conn->connection;

    ret = flb_parser_do(ctx->parser, buf, size,
                        &out_buf, &out_size, &out_time);
    if (ret >= 0) {
        if (flb_time_to_double(&out_time) == 0) {
            flb_time_get(&out_time);
        }
        pack_line(ctx, &out_time,
                  connection,
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
