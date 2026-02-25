/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2024 The Fluent Bit Authors
 *  Copyright (C) 2026 Matwey V. Kornilov <matwey.kornilov@gmail.com>
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


#include <time.h>

#include <rabbitmq-c/ssl_socket.h>
#include <rabbitmq-c/tcp_socket.h>

#include <msgpack.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_config_map.h>
#include <fluent-bit/flb_error.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_log_event.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_parser.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_utils.h>


#include "in_amqp.h"
#include "fluent-bit/flb_log_event_encoder.h"

static void in_amqp_log_reply_error(struct flb_input_instance *in, amqp_rpc_reply_t x, char const *context) {
    switch (x.reply_type) {
        case AMQP_RESPONSE_NORMAL: return;

        case AMQP_RESPONSE_NONE: {
            flb_plg_error(in, "%s: missing RPC reply type", context);
            break;
        }
        case AMQP_RESPONSE_LIBRARY_EXCEPTION: {
            flb_plg_error(in, "%s: %s", context, amqp_error_string2(x.library_error));
            break;
        }
        case AMQP_RESPONSE_SERVER_EXCEPTION: {
            switch (x.reply.id) {
                case AMQP_CONNECTION_CLOSE_METHOD: {
                    amqp_connection_close_t *m = (amqp_connection_close_t *)x.reply.decoded;

                    flb_plg_error(in, "%s: server connection error %hu, message: %.*s", context, m->reply_code, (int)m->reply_text.len, (char *)m->reply_text.bytes);
                    break;
                }
                case AMQP_CHANNEL_CLOSE_METHOD: {
                    amqp_channel_close_t *m = (amqp_channel_close_t *)x.reply.decoded;

                    flb_plg_error(in, "%s: server channel error %hu, message: %.*s", context, m->reply_code, (int)m->reply_text.len, (char *)m->reply_text.bytes);
                    break;
                }
                default:
                    flb_plg_error(in, "%s: unknown server error, method id 0x%08X", context, x.reply.id);
                    break;
            }
            break;
        }
    }
}

static int in_amqp_append_metadata_bytes(struct flb_log_event_encoder* encoder, const char* key, amqp_bytes_t bytes) {
    return flb_log_event_encoder_append_metadata_values(encoder,
        FLB_LOG_EVENT_CSTRING_VALUE(key),
        FLB_LOG_EVENT_STRING_VALUE(bytes.bytes, bytes.len));
}

static int in_amqp_append_metadata_entry(struct flb_log_event_encoder* encoder, struct amqp_table_entry_t_* entry) {
    struct flb_time out_time;

    amqp_bytes_t* key = &entry->key;
    amqp_field_value_t* value = &entry->value;

    switch (value->kind) {
        case AMQP_FIELD_KIND_BOOLEAN:
            return flb_log_event_encoder_append_metadata_values(encoder,
                FLB_LOG_EVENT_STRING_VALUE(key->bytes, key->len),
                FLB_LOG_EVENT_BOOLEAN_VALUE(value->value.boolean));
        case AMQP_FIELD_KIND_I8:
            return flb_log_event_encoder_append_metadata_values(encoder,
                FLB_LOG_EVENT_STRING_VALUE(key->bytes, key->len),
                FLB_LOG_EVENT_INT8_VALUE(value->value.i8));
        case AMQP_FIELD_KIND_U8:
            return flb_log_event_encoder_append_metadata_values(encoder,
                FLB_LOG_EVENT_STRING_VALUE(key->bytes, key->len),
                FLB_LOG_EVENT_UINT8_VALUE(value->value.u8));
        case AMQP_FIELD_KIND_I16:
            return flb_log_event_encoder_append_metadata_values(encoder,
                FLB_LOG_EVENT_STRING_VALUE(key->bytes, key->len),
                FLB_LOG_EVENT_INT16_VALUE(value->value.i16));
        case AMQP_FIELD_KIND_U16:
            return flb_log_event_encoder_append_metadata_values(encoder,
                FLB_LOG_EVENT_STRING_VALUE(key->bytes, key->len),
                FLB_LOG_EVENT_UINT16_VALUE(value->value.u16));
        case AMQP_FIELD_KIND_I32:
            return flb_log_event_encoder_append_metadata_values(encoder,
                FLB_LOG_EVENT_STRING_VALUE(key->bytes, key->len),
                FLB_LOG_EVENT_INT32_VALUE(value->value.i32));
        case AMQP_FIELD_KIND_U32:
            return flb_log_event_encoder_append_metadata_values(encoder,
                FLB_LOG_EVENT_STRING_VALUE(key->bytes, key->len),
                FLB_LOG_EVENT_UINT32_VALUE(value->value.u32));
        case AMQP_FIELD_KIND_I64:
            return flb_log_event_encoder_append_metadata_values(encoder,
                FLB_LOG_EVENT_STRING_VALUE(key->bytes, key->len),
                FLB_LOG_EVENT_INT64_VALUE(value->value.i64));
        case AMQP_FIELD_KIND_U64:
            return flb_log_event_encoder_append_metadata_values(encoder,
                FLB_LOG_EVENT_STRING_VALUE(key->bytes, key->len),
                FLB_LOG_EVENT_UINT64_VALUE(value->value.u64));
        case AMQP_FIELD_KIND_F32:
            return flb_log_event_encoder_append_metadata_values(encoder,
                FLB_LOG_EVENT_STRING_VALUE(key->bytes, key->len),
                FLB_LOG_EVENT_DOUBLE_VALUE(value->value.f32));
        case AMQP_FIELD_KIND_F64:
            return flb_log_event_encoder_append_metadata_values(encoder,
                FLB_LOG_EVENT_STRING_VALUE(key->bytes, key->len),
                FLB_LOG_EVENT_DOUBLE_VALUE(value->value.f64));
        case AMQP_FIELD_KIND_UTF8:
            /* fallthrough */
        case AMQP_FIELD_KIND_BYTES:
            return flb_log_event_encoder_append_metadata_values(encoder,
                FLB_LOG_EVENT_STRING_VALUE(key->bytes, key->len),
                FLB_LOG_EVENT_STRING_VALUE(value->value.bytes.bytes, value->value.bytes.len));
        case AMQP_FIELD_KIND_TIMESTAMP:
            flb_time_set(&out_time, value->value.u64, 0);
            return flb_log_event_encoder_append_metadata_values(encoder,
                FLB_LOG_EVENT_STRING_VALUE(key->bytes, key->len),
                FLB_LOG_EVENT_TIMESTAMP_VALUE(&out_time));
        default: /* Unsupported */
        break;
    };

    return FLB_EVENT_ENCODER_SUCCESS;
}

static int in_amqp_handle_envelope(struct flb_amqp *ctx, amqp_envelope_t *envelope) {
    amqp_message_t* message = &envelope->message;
    amqp_bytes_t* body = &message->body;
    amqp_basic_properties_t* properties = &message->properties;
    amqp_table_t* headers = &properties->headers;

    int ret, i;
    void *out_buf = NULL;
    size_t out_size = 0;
    struct flb_time out_time;

    flb_time_zero(&out_time);

    if (ctx->parser) {
        ret = flb_parser_do(ctx->parser, body->bytes, body->len, &out_buf, &out_size, &out_time);

        if (ret < 0) {
            flb_plg_trace(ctx->ins, "tried to parse '%.*s'", (int)body->len, (char*)body->bytes);
            flb_plg_trace(ctx->ins, "buf_size %zu", body->len);
            flb_plg_error(ctx->ins, "parser returned an error");

            return ret;
        }
    }

    if (flb_time_to_nanosec(&out_time) == 0L && (properties->_flags & AMQP_BASIC_TIMESTAMP_FLAG)) {
        flb_time_set(&out_time, properties->timestamp, 0);
    }

    if (flb_time_to_nanosec(&out_time) == 0L) {
        flb_time_get(&out_time);
    }

    ret = flb_log_event_encoder_begin_record(&ctx->encoder);

    if (ret == FLB_EVENT_ENCODER_SUCCESS) {
        ret = flb_log_event_encoder_set_timestamp(&ctx->encoder, &out_time);
    }

    if (ret == FLB_EVENT_ENCODER_SUCCESS) {
        ret = in_amqp_append_metadata_bytes(&ctx->encoder, "routing_key", envelope->routing_key);
    }

    if (ret == FLB_EVENT_ENCODER_SUCCESS && (properties->_flags & AMQP_BASIC_CONTENT_TYPE_FLAG)) {
        ret = in_amqp_append_metadata_bytes(&ctx->encoder, "content_type", properties->content_type);
    }

    if (ret == FLB_EVENT_ENCODER_SUCCESS && (properties->_flags & AMQP_BASIC_CONTENT_ENCODING_FLAG)) {
        ret = in_amqp_append_metadata_bytes(&ctx->encoder, "content_encoding", properties->content_encoding);
    }

    if (ret == FLB_EVENT_ENCODER_SUCCESS && (properties->_flags & AMQP_BASIC_CORRELATION_ID_FLAG)) {
        ret = in_amqp_append_metadata_bytes(&ctx->encoder, "correlation_id", properties->correlation_id);
    }

    if (ret == FLB_EVENT_ENCODER_SUCCESS && (properties->_flags & AMQP_BASIC_REPLY_TO_FLAG)) {
        ret = in_amqp_append_metadata_bytes(&ctx->encoder, "reply_to", properties->reply_to);
    }

    if (ret == FLB_EVENT_ENCODER_SUCCESS && (properties->_flags & AMQP_BASIC_HEADERS_FLAG)) {
        ret = flb_log_event_encoder_append_metadata_cstring(&ctx->encoder, "headers");

        if (ret == FLB_EVENT_ENCODER_SUCCESS) {
            ret = flb_log_event_encoder_metadata_begin_map((&ctx->encoder));
        }

        for (i = 0; i < headers->num_entries && ret == FLB_EVENT_ENCODER_SUCCESS; ++i) {
            ret = in_amqp_append_metadata_entry(&ctx->encoder, &headers->entries[i]);
        }

        if (ret == FLB_EVENT_ENCODER_SUCCESS) {
            ret = flb_log_event_encoder_metadata_commit_map((&ctx->encoder));
        }
    }

    if (ctx->parser) {
        if (ret == FLB_EVENT_ENCODER_SUCCESS) {
            ret = flb_log_event_encoder_set_body_from_raw_msgpack(
                    &ctx->encoder,
                    out_buf,
                    out_size);
        }
    } else {
        if (ret == FLB_EVENT_ENCODER_SUCCESS) {
            ret = flb_log_event_encoder_append_body_cstring(
                    &ctx->encoder, "amqp");
        }

        if (ret == FLB_EVENT_ENCODER_SUCCESS) {
            ret = flb_log_event_encoder_append_body_string(
                    &ctx->encoder,
                    body->bytes,
                    body->len);
        }
    }

    if (ret == FLB_EVENT_ENCODER_SUCCESS) {
        ret = flb_log_event_encoder_commit_record(&ctx->encoder);
    }

    if (ret == FLB_EVENT_ENCODER_SUCCESS) {
        flb_input_log_append(ctx->ins, NULL, 0,
                             ctx->encoder.output_buffer,
                             ctx->encoder.output_length);

    } else {
        flb_plg_error(ctx->ins, "Error encoding record : %d", ret);
    }

    flb_log_event_encoder_reset(&ctx->encoder);

    flb_free(out_buf);

    return ret;
}

static int in_amqp_consumer_start(struct flb_amqp *ctx, struct flb_config *config);

static void in_amqp_connection_destroy(struct flb_amqp *ctx);

static int in_amqp_collect(struct flb_input_instance *in,
                            struct flb_config *config,
                            void *in_context)
{
    const struct timeval tv = {.tv_sec = 0, .tv_usec = 0};

    struct flb_amqp* ctx = in_context;
    struct flb_amqp_connection* c = &ctx->conn;

    amqp_frame_t frame;
    amqp_rpc_reply_t reply;
    amqp_envelope_t envelope;
    int ret;

    for (;;) {
        amqp_maybe_release_buffers(c->conn);
        reply = amqp_consume_message(c->conn, &envelope, &tv, 0);

        if (reply.reply_type == AMQP_RESPONSE_NORMAL) {
            in_amqp_handle_envelope(ctx, &envelope);

            amqp_destroy_envelope(&envelope);

            /* Proceed to the next message */
            continue;
        } else if (reply.reply_type == AMQP_RESPONSE_LIBRARY_EXCEPTION &&
                   reply.library_error == AMQP_STATUS_TIMEOUT) {
            /* All messages have been processed */
            return 0;
        } else if (reply.reply_type == AMQP_RESPONSE_LIBRARY_EXCEPTION &&
                   reply.library_error == AMQP_STATUS_UNEXPECTED_STATE) {
            /*
             * If ret.reply_type == AMQP_RESPONSE_LIBRARY_EXCEPTION, and
             * ret.library_error == AMQP_STATUS_UNEXPECTED_STATE, a frame
             * other than AMQP_BASIC_DELIVER_METHOD was received, the caller
             * should call amqp_simple_wait_frame() to read this frame and
             * take appropriate action.
             */
            ret = amqp_simple_wait_frame(c->conn, &frame);
            if (ret != AMQP_STATUS_OK) {
                flb_plg_error(in, "An error occurred during waiting frame: %s", amqp_error_string2(ret));
            } else if (frame.frame_type == AMQP_FRAME_METHOD) {
                switch (frame.payload.method.id) {
                    case AMQP_CHANNEL_CLOSE_METHOD: {
                        amqp_channel_close_t *m = (amqp_channel_close_t *)frame.payload.method.decoded;
                        flb_plg_warn(in, "AMQP server channel error %hu, message: %.*s", m->reply_code, (int)m->reply_text.len, (char *)m->reply_text.bytes);
                        break;
                    }
                    case AMQP_CONNECTION_CLOSE_METHOD: {
                        amqp_connection_close_t *m = (amqp_connection_close_t *)frame.payload.method.decoded;
                        flb_plg_warn(in, "AMQP server connection error %hu, message: %.*s", m->reply_code, (int)m->reply_text.len, (char *)m->reply_text.bytes);
                        break;
                    }
                    default:
                        flb_plg_warn(in, "An unexpected AMQP method id 0x%08X", frame.payload.method.id);
                }

                /* Out of bound frame is not an error */
                continue;
            }
        }

        in_amqp_log_reply_error(in, reply, "An error occurred during consuming message");

        in_amqp_connection_destroy(ctx);

        if (in_amqp_consumer_start(ctx, config) < 0) {
            return -1;
        } else if (c->conn == NULL) {
            return 0;
        }
    }

    return 0;
}

static void in_amqp_connection_destroy(struct flb_amqp *ctx)
{
    struct flb_amqp_connection* c = &ctx->conn;

    if (c->conn) {
        /* Attached socket FD will be invalidated */
        if (c->coll_id >= 0) {
            flb_input_collector_delete(c->coll_id, ctx->ins);
            c->coll_id = -1;
        }

        amqp_destroy_connection(c->conn);
        c->conn = NULL;
    }
}

static int in_amqp_connection_init(struct flb_amqp *ctx, struct flb_config *config)
{
    struct flb_amqp_connection* c = &ctx->conn;
    int ret;
    amqp_rpc_reply_t reply;
    amqp_bytes_t queue_bytes;

    c->conn = amqp_new_connection();
    if (c->conn == NULL) {
        flb_plg_error(ctx->ins, "Cannot create AMQP connection");

        return -1;
    }

    c->sock = ctx->conn_info.ssl ? amqp_ssl_socket_new(c->conn) : amqp_tcp_socket_new(c->conn);
    if (c->sock == NULL) {
        flb_plg_error(ctx->ins, "Cannot create AMQP socket");
        goto error;
    }

    ret = amqp_socket_open(c->sock, ctx->conn_info.host, ctx->conn_info.port);
    if (ret != AMQP_STATUS_OK) {
        flb_plg_error(ctx->ins, "Cannot open AMQP socket: %s", amqp_error_string2(ret));
        goto error;
    }

    reply = amqp_login(c->conn, ctx->conn_info.vhost, 0, AMQP_DEFAULT_FRAME_SIZE, 0, AMQP_SASL_METHOD_PLAIN, ctx->conn_info.user, ctx->conn_info.password);
    if (reply.reply_type != AMQP_RESPONSE_NORMAL) {
        in_amqp_log_reply_error(ctx->ins, reply, "Cannot login to the broker");
        goto error;
    }

    c->chan = 1;
    if (amqp_channel_open(c->conn, c->chan) == NULL) {
        in_amqp_log_reply_error(ctx->ins, amqp_get_rpc_reply(c->conn), "Cannot open AMQP channel");
        goto error;
    }

    queue_bytes.len = flb_sds_len(ctx->queue_name);
    queue_bytes.bytes = ctx->queue_name;
    if (amqp_basic_consume(c->conn, c->chan, queue_bytes, amqp_empty_bytes, 0, 1, 1, amqp_empty_table) == NULL) {
        in_amqp_log_reply_error(ctx->ins, amqp_get_rpc_reply(c->conn), "Cannot consume");
        goto error;
    }

    c->coll_id = flb_input_set_collector_socket(ctx->ins, in_amqp_collect, amqp_socket_get_sockfd(c->sock), config);
    if (c->coll_id < 0) {
        flb_plg_error(ctx->ins, "Could not set collector for AMQP input plugin");
        goto error;
    }

    ret = flb_input_collector_start(c->coll_id, ctx->ins);
    if (ret < 0) {
        flb_plg_error(ctx->ins, "Could not start collector for AMQP input plugin");
        goto collector_start_error;
    }

    flb_plg_info(ctx->ins, "Consuming from %.*s queue", (int)queue_bytes.len, (char*)queue_bytes.bytes);

    return 0;

collector_start_error:
    flb_input_collector_delete(c->coll_id, ctx->ins);
    c->coll_id = -1;
error:
    in_amqp_connection_destroy(ctx);

    return -1;
}

static int in_amqp_consumer_start(struct flb_amqp *ctx, struct flb_config *config)
{
    struct flb_amqp_connection* c = &ctx->conn;
    int ret;

    if (c->conn) {
        return 0; // Already connected
    }

    ret = in_amqp_connection_init(ctx, config);
    if (ret < 0) {
        if (++ctx->retry >= ctx->reconnect_retry_limits) {
            flb_plg_error(ctx->ins, "Failed to reconnect after %d attempts", ctx->retry);

            flb_input_collector_pause(ctx->retry_coll_id, ctx->ins);

            ctx->retry = 0;

            return -1;
        }

        if (!flb_input_collector_running(ctx->retry_coll_id, ctx->ins)) {
            flb_input_collector_resume(ctx->retry_coll_id, ctx->ins);
        }

        return 0;
    }

    ctx->retry = 0;

    flb_input_collector_pause(ctx->retry_coll_id, ctx->ins);

    return 0;
}

static int in_amqp_config_destroy(struct flb_amqp *ctx)
{
    flb_log_event_encoder_destroy(&ctx->encoder);
    if (ctx->retry_coll_id >= 0) {
        flb_input_collector_delete(ctx->retry_coll_id, ctx->ins);
    }
    in_amqp_connection_destroy(ctx);
    flb_free(ctx);

    return 0;
}

static int in_amqp_reconnect(struct flb_input_instance *in, struct flb_config *config, void *in_context)
{
    struct flb_amqp* ctx = in_context;

    if (in_amqp_consumer_start(ctx, config) < 0) {
        return -1;
    }

    /* Read pending messages which were buffered by rabbitmq-c during
     * the connection negotiation. */
    if (ctx->conn.conn) {
        in_amqp_collect(in, config, ctx);
    }

    return 0;
}

/* Set plugin configuration */
static int in_amqp_configure(struct flb_amqp *ctx,
                     struct flb_input_instance *in,
                     struct timespec *tm)
{
    int ret = -1;

    ret = flb_input_config_map_set(in, (void *) ctx);
    if (ret == -1) {
        return -1;
    }

    if (ctx->uri) {
        ret = amqp_parse_url(ctx->uri, &ctx->conn_info);
        if (ret != AMQP_STATUS_OK) {
            flb_plg_error(in, "Error while parsing AMQP URI: %s", amqp_error_string2(ret));

            return -1;
        }
    } else {
        amqp_default_connection_info(&ctx->conn_info);
    }

    if (!ctx->queue_name) {
        flb_plg_error(in, "AMQP queue name is not provided");

        return -1;
    }

    if (ctx->reconnect_retry_interval < 1) {
        flb_plg_error(in, "reconnect.retry_interval must be >= 1");

        return -1;
    }

    return 0;
}

/* Initialize plugin */
static int in_amqp_init(struct flb_input_instance *in,
                         struct flb_config *config, void *data)
{
    int ret = -1;
    struct flb_amqp *ctx = NULL;
    struct timespec tm;

    /* Allocate space for the configuration */
    ctx = flb_calloc(1, sizeof(struct flb_amqp));
    if (ctx == NULL) {
        return -1;
    }

    ctx->parser = NULL;
    ctx->ins = in;
    ctx->retry_coll_id = -1;
    ctx->retry = 0;
    ctx->conn.conn = NULL;
    ctx->conn.sock = NULL;
    ctx->conn.chan = 0;
    ctx->conn.coll_id = -1;

    /* Initialize head config */
    ret = in_amqp_configure(ctx, in, &tm);
    if (ret < 0) {
        in_amqp_config_destroy(ctx);
        return -1;
    }

    ret = flb_log_event_encoder_init(&ctx->encoder, FLB_LOG_EVENT_FORMAT_DEFAULT);
    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        flb_plg_error(in, "could not initialize event encoder");
        in_amqp_config_destroy(ctx);

        return -1;
    }

    if (ctx->parser_name) {
        ctx->parser = flb_parser_get(ctx->parser_name, config);
        if (ctx->parser == NULL) {
            flb_plg_error(in, "Requested parser '%s' not found", ctx->parser_name);
            in_amqp_config_destroy(ctx);

            return -1;
        }
    }

    flb_input_set_context(in, ctx);

    ctx->retry_coll_id = flb_input_set_collector_time(in, &in_amqp_reconnect, ctx->reconnect_retry_interval, 0, config);
    if (ctx->retry_coll_id < 0) {
        flb_plg_error(in, "Cannot create reconnection collector");
        in_amqp_config_destroy(ctx);

        return -1;
    }

    flb_input_collector_pause(ctx->retry_coll_id, in);

    ret = in_amqp_consumer_start(ctx, config);
    if (ret < 0) {
        flb_plg_error(in, "Cannot start AMQP consumer");
        in_amqp_config_destroy(ctx);

        return -1;
    }

    /* Read pending messages which were buffered by rabbitmq-c during
     * the connection negotiation. */
    if (ctx->conn.conn) {
        in_amqp_collect(in, config, ctx);
    }

    return 0;
}

static void in_amqp_pause(void *data, struct flb_config *config)
{
    struct flb_amqp *ctx = data;

    if (ctx->conn.conn) {
        flb_input_collector_pause(ctx->conn.coll_id, ctx->ins);
    } else {
        flb_input_collector_pause(ctx->retry_coll_id, ctx->ins);
    }
}

static void in_amqp_resume(void *data, struct flb_config *config)
{
    struct flb_amqp *ctx = data;

    if (ctx->conn.conn) {
        flb_input_collector_resume(ctx->conn.coll_id, ctx->ins);
    } else {
        flb_input_collector_resume(ctx->retry_coll_id, ctx->ins);
    }
}

static int in_amqp_exit(void *data, struct flb_config *config)
{
    (void)config;
    struct flb_amqp *ctx = data;

    if (ctx) {
        in_amqp_config_destroy(ctx);
    }

    return 0;
}

/* Configuration properties map */
static struct flb_config_map config_map[] = {
    {
     FLB_CONFIG_MAP_STR, "uri", "amqp://",
     0, FLB_TRUE, offsetof(struct flb_amqp, uri),
     "Specify an AMQP URI to connect the broker"
    },
    {
     FLB_CONFIG_MAP_STR, "queue", NULL,
     0, FLB_TRUE, offsetof(struct flb_amqp, queue_name),
     "Specify an AMQP queue name to consume from"
    },
    {
     FLB_CONFIG_MAP_STR, "parser", NULL,
     0, FLB_TRUE, offsetof(struct flb_amqp, parser_name),
     "Set a parser"
    },
    {
     FLB_CONFIG_MAP_INT, "reconnect.retry_limits", "5",
     0, FLB_TRUE, offsetof(struct flb_amqp, reconnect_retry_limits),
     "Maximum number to retry to connect the broker"
    },
    {
     FLB_CONFIG_MAP_INT, "reconnect.retry_interval", "60",
     0, FLB_TRUE, offsetof(struct flb_amqp, reconnect_retry_interval),
     "Retry interval to connect the broker"
    },
    {0},
};


struct flb_input_plugin in_amqp_plugin = {
    .name         = "amqp",
    .description  = "AMQP input plugin",
    .cb_init      = in_amqp_init,
    .cb_pre_run   = NULL,
    .cb_collect   = in_amqp_collect,
    .cb_flush_buf = NULL,
    .config_map   = config_map,
    .cb_pause     = in_amqp_pause,
    .cb_resume    = in_amqp_resume,
    .cb_exit      = in_amqp_exit
};
