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

#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_engine.h>
#include <fluent-bit/flb_network.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_error.h>
#include <fluent-bit/flb_msgpack_append_message.h>

#include "tcp.h"
#include "tcp_conn.h"

static inline void consume_bytes(char *buf, int bytes, int length)
{
    memmove(buf, buf + bytes, length - bytes);
}

static inline int process_pack(struct tcp_conn *conn,
                               char *pack, size_t size)
{
    int ret;
    size_t off = 0;
    size_t prev_off = 0;
    msgpack_unpacked result;
    msgpack_object entry;
    struct flb_in_tcp_config *ctx;
    char   *appended_address_buffer;
    size_t  appended_address_size;
    char   *source_address;

    ctx = conn->ctx;

    flb_log_event_encoder_reset(ctx->log_encoder);

    /* First pack the results, iterate concatenated messages */
    msgpack_unpacked_init(&result);
    while (msgpack_unpack_next(&result, pack, size, &off) == MSGPACK_UNPACK_SUCCESS) {
        entry = result.data;

        appended_address_buffer = NULL;
        source_address = NULL;

        ret = flb_log_event_encoder_begin_record(ctx->log_encoder);

        if (ret == FLB_EVENT_ENCODER_SUCCESS) {
            ret = flb_log_event_encoder_set_current_timestamp(ctx->log_encoder);
        }

        if (ctx->source_address_key != NULL) {
            source_address = flb_connection_get_remote_address(conn->connection);
        }

        if (ret == FLB_EVENT_ENCODER_SUCCESS) {
            if (entry.type == MSGPACK_OBJECT_MAP) {
                if (ctx->source_address_key != NULL && source_address != NULL) {
                    ret = flb_msgpack_append_message_to_record(&appended_address_buffer,
                                                               &appended_address_size,
                                                               ctx->source_address_key,
                                                               pack + prev_off,
                                                               size,
                                                               source_address,
                                                               strlen(source_address),
                                                               MSGPACK_OBJECT_STR);
                }

                if (ret == FLB_MAP_EXPANSION_ERROR) {
                    flb_plg_debug(ctx->ins, "error expanding source_address : %d", ret);
                }

                if (appended_address_buffer != NULL) {
                    ret = flb_log_event_encoder_set_body_from_raw_msgpack(
                            ctx->log_encoder, appended_address_buffer, appended_address_size);
                }
                else {
                    ret = flb_log_event_encoder_set_body_from_msgpack_object(
                            ctx->log_encoder, &entry);
                }
            }
            else if (entry.type == MSGPACK_OBJECT_ARRAY) {
                if (ctx->source_address_key != NULL && source_address != NULL) {
                    ret = flb_log_event_encoder_append_body_values(
                        ctx->log_encoder,
                        FLB_LOG_EVENT_CSTRING_VALUE("msg"),
                        FLB_LOG_EVENT_MSGPACK_OBJECT_VALUE(&entry),
                        FLB_LOG_EVENT_CSTRING_VALUE(ctx->source_address_key),
                        FLB_LOG_EVENT_CSTRING_VALUE(source_address));
                }
                else {
                    ret = flb_log_event_encoder_append_body_values(
                        ctx->log_encoder,
                        FLB_LOG_EVENT_CSTRING_VALUE("msg"),
                        FLB_LOG_EVENT_MSGPACK_OBJECT_VALUE(&entry));
                }
            }
            else {
                ret = FLB_EVENT_ENCODER_ERROR_INVALID_VALUE_TYPE;
            }

            if (ret == FLB_EVENT_ENCODER_SUCCESS) {
                ret = flb_log_event_encoder_commit_record(ctx->log_encoder);
            }

            if (appended_address_buffer != NULL) {
                flb_free(appended_address_buffer);
            }

            if (ret != FLB_EVENT_ENCODER_SUCCESS) {
                break;
            }
        }
        prev_off = off;
    }

    msgpack_unpacked_destroy(&result);

    if (ret == FLB_EVENT_ENCODER_SUCCESS) {
        flb_input_log_append(conn->ins, NULL, 0,
                             ctx->log_encoder->output_buffer,
                             ctx->log_encoder->output_length);
        ret = 0;
    }
    else {
        flb_plg_error(ctx->ins, "log event encoding error : %d", ret);

        ret = -1;
    }

    return ret;
}

/* Process a JSON payload, return the number of processed bytes */
static ssize_t parse_payload_json(struct tcp_conn *conn)
{
    int ret;
    int out_size;
    char *pack;

    ret = flb_pack_json_state(conn->buf_data, conn->buf_len,
                              &pack, &out_size, &conn->pack_state);
    if (ret == FLB_ERR_JSON_PART) {
        flb_plg_debug(conn->ins, "JSON incomplete, waiting for more data...");
        return 0;
    }
    else if (ret == FLB_ERR_JSON_INVAL) {
        flb_plg_warn(conn->ins, "invalid JSON message, skipping");
        conn->buf_len = 0;
        conn->pack_state.multiple = FLB_TRUE;
        return -1;
    }
    else if (ret == -1) {
        return -1;
    }

    /* Process the packaged JSON and return the last byte used */
    process_pack(conn, pack, out_size);
    flb_free(pack);

    return conn->pack_state.last_byte;
}

/*
 * Process a raw text payload, uses the delimited character to split records,
 * return the number of processed bytes
 */
static ssize_t parse_payload_none(struct tcp_conn *conn)
{
    int ret;
    int len;
    int sep_len;
    size_t consumed = 0;
    char *buf;
    char *s;
    char *separator;
    char *source_address;
    struct flb_in_tcp_config *ctx;

    ctx = conn->ctx;

    separator = conn->ctx->separator;
    sep_len = flb_sds_len(conn->ctx->separator);

    buf = conn->buf_data;
    ret = FLB_EVENT_ENCODER_SUCCESS;

    flb_log_event_encoder_reset(ctx->log_encoder);

    while ((s = strstr(buf, separator))) {
        len = (s - buf);
        if (len == 0) {
            break;
        }
        else if (len > 0) {
            ret = flb_log_event_encoder_begin_record(ctx->log_encoder);

            if (ret == FLB_EVENT_ENCODER_SUCCESS) {
                ret = flb_log_event_encoder_set_current_timestamp(ctx->log_encoder);
            }

            if (ret == FLB_EVENT_ENCODER_SUCCESS) {
                source_address = NULL;
                if (ctx->source_address_key != NULL) {
                    source_address = flb_connection_get_remote_address(conn->connection);
                }

                if (ctx->source_address_key != NULL && source_address != NULL) {
                    ret = flb_log_event_encoder_append_body_values(
                        ctx->log_encoder,
                        FLB_LOG_EVENT_CSTRING_VALUE("log"),
                        FLB_LOG_EVENT_STRING_VALUE(buf, len),
                        FLB_LOG_EVENT_CSTRING_VALUE(ctx->source_address_key),
                        FLB_LOG_EVENT_CSTRING_VALUE(source_address));
                } 
                else {
                    ret = flb_log_event_encoder_append_body_values(
                        ctx->log_encoder,
                        FLB_LOG_EVENT_CSTRING_VALUE("log"),
                        FLB_LOG_EVENT_STRING_VALUE(buf, len));
                }
            }

            if (ret == FLB_EVENT_ENCODER_SUCCESS) {
                ret = flb_log_event_encoder_commit_record(ctx->log_encoder);
            }

            if (ret != FLB_EVENT_ENCODER_SUCCESS) {
                break;
            }

            consumed += len + sep_len;
            buf += len + sep_len;
        }
        else {
            break;
        }
    }

    if (ret == FLB_EVENT_ENCODER_SUCCESS) {
        flb_input_log_append(conn->ins, NULL, 0,
                             ctx->log_encoder->output_buffer,
                             ctx->log_encoder->output_length);
    }
    else {
        flb_plg_error(ctx->ins, "log event encoding error : %d", ret);
    }

    return consumed;
}

/* Callback invoked every time an event is triggered for a connection */
int tcp_conn_event(void *data)
{
    int bytes;
    int available;
    int size;
    ssize_t ret_payload = -1;
    char *tmp;
    struct mk_event *event;
    struct tcp_conn *conn;
    struct flb_connection *connection;
    struct flb_in_tcp_config *ctx;
    int ret = 0;

    connection = (struct flb_connection *) data;

    conn = connection->user_data;

    ctx = conn->ctx;

    event = &connection->event;

    conn->busy = FLB_TRUE;

    if (event->mask & MK_EVENT_READ) {
        available = (conn->buf_size - conn->buf_len) - 1;
        if (available < 1) {
            if (conn->buf_size + ctx->chunk_size > ctx->buffer_size) {
                flb_plg_warn(ctx->ins,
                             "fd=%i incoming data exceeds 'Buffer_Size' (%zu KB)",
                             event->fd, (ctx->buffer_size / 1024));
                conn->busy = FLB_FALSE;
                tcp_conn_del(conn);
                return -1;
            }

            size = conn->buf_size + ctx->chunk_size;
            tmp = flb_realloc(conn->buf_data, size);
            if (!tmp) {
                conn->busy = FLB_FALSE;
                flb_errno();
                return -1;
            }
            flb_plg_trace(ctx->ins, "fd=%i buffer realloc %i -> %i",
                          event->fd, conn->buf_size, size);

            conn->buf_data = tmp;
            conn->buf_size = size;
            available = (conn->buf_size - conn->buf_len) - 1;
        }

        /* Read data */
        bytes = flb_io_net_read(connection,
                                (void *) &conn->buf_data[conn->buf_len],
                                available);

        if (bytes <= 0) {
            flb_plg_trace(ctx->ins, "fd=%i closed connection", event->fd);
            conn->busy = FLB_FALSE;
            tcp_conn_del(conn);
            return -1;
        }

        flb_plg_trace(ctx->ins, "read()=%i pre_len=%i now_len=%i",
                      bytes, conn->buf_len, conn->buf_len + bytes);
        conn->buf_len += bytes;
        conn->buf_data[conn->buf_len] = '\0';

        /* Strip CR or LF if found at first byte */
        if (conn->buf_data[0] == '\r' || conn->buf_data[0] == '\n') {
            /* Skip message with one byte with CR or LF */
            flb_plg_trace(ctx->ins, "skip one byte message with ASCII code=%i",
                      conn->buf_data[0]);
            consume_bytes(conn->buf_data, 1, conn->buf_len);
            conn->buf_len--;
            conn->buf_data[conn->buf_len] = '\0';
        }

        /* JSON Format handler */
        if (ctx->format == FLB_TCP_FMT_JSON) {
            ret_payload = parse_payload_json(conn);
            if (ret_payload == 0) {
                /* Incomplete JSON message, we need more data */
                ret = -1;
                goto cleanup;
            }
            else if (ret_payload == -1) {
                flb_pack_state_reset(&conn->pack_state);
                flb_pack_state_init(&conn->pack_state);
                conn->pack_state.multiple = FLB_TRUE;
                ret = -1;
                goto cleanup;
            }
        }
        else if (ctx->format == FLB_TCP_FMT_NONE) {
            ret_payload = parse_payload_none(conn);
            if (ret_payload == 0) {
                ret = -1;
                goto cleanup;
            }
            else if (ret_payload == -1) {
                conn->buf_len = 0;
                ret = -1;
                goto cleanup;
            }
        }


        consume_bytes(conn->buf_data, ret_payload, conn->buf_len);
        conn->buf_len -= ret_payload;
        conn->buf_data[conn->buf_len] = '\0';

        if (ctx->format == FLB_TCP_FMT_JSON) {
            jsmn_init(&conn->pack_state.parser);
            conn->pack_state.tokens_count = 0;
            conn->pack_state.last_byte = 0;
            conn->pack_state.buf_len = 0;
        }

        ret = bytes;
        goto cleanup;
    }

    if (event->mask & MK_EVENT_CLOSE) {
        flb_plg_trace(ctx->ins, "fd=%i hangup", event->fd);
        conn->busy = FLB_FALSE;
        tcp_conn_del(conn);
        return -1;
    }

    ret = 0;

cleanup:
    conn->busy = FLB_FALSE;
    if (conn->pending_close) {
        tcp_conn_del(conn);
        return -1;
    }

    return ret;
}

/* Create a new mqtt request instance */
struct tcp_conn *tcp_conn_add(struct flb_connection *connection,
                              struct flb_in_tcp_config *ctx)
{
    struct tcp_conn *conn;
    int              ret;

    conn = flb_malloc(sizeof(struct tcp_conn));
    if (!conn) {
        flb_errno();
        return NULL;
    }

    conn->connection = connection;

    /* Set data for the event-loop */
    MK_EVENT_NEW(&connection->event);

    connection->user_data     = conn;
    connection->event.type    = FLB_ENGINE_EV_CUSTOM;
    connection->event.handler = tcp_conn_event;

    /* Connection info */
    conn->ctx     = ctx;
    conn->buf_len = 0;
    conn->rest    = 0;
    conn->status  = TCP_NEW;

    conn->buf_data = flb_malloc(ctx->chunk_size);
    if (!conn->buf_data) {
        flb_errno();

        flb_plg_error(ctx->ins, "could not allocate new connection");
        flb_free(conn);

        return NULL;
    }
    conn->buf_size = ctx->chunk_size;
    conn->ins      = ctx->ins;

    /* Initialize JSON parser */
    if (ctx->format == FLB_TCP_FMT_JSON) {
        flb_pack_state_init(&conn->pack_state);
        conn->pack_state.multiple = FLB_TRUE;
    }

    /* Register instance into the event loop */
    ret = mk_event_add(flb_engine_evl_get(),
                       connection->fd,
                       FLB_ENGINE_EV_CUSTOM,
                       MK_EVENT_READ,
                       &connection->event);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "could not register new connection");

        flb_free(conn->buf_data);
        flb_free(conn);

        return NULL;
    }

    mk_list_add(&conn->_head, &ctx->connections);

    conn->busy = FLB_FALSE;
    conn->pending_close = FLB_FALSE;

    return conn;
}

int tcp_conn_del(struct tcp_conn *conn)
{
    struct flb_in_tcp_config *ctx;

    ctx = conn->ctx;

    if (ctx->format == FLB_TCP_FMT_JSON) {
        flb_pack_state_reset(&conn->pack_state);
    }

    /* The downstream unregisters the file descriptor from the event-loop
     * so there's nothing to be done by the plugin
     */
    flb_downstream_conn_release(conn->connection);

    /* Release resources */
    mk_list_del(&conn->_head);

    flb_free(conn->buf_data);
    flb_free(conn);

    return 0;
}
