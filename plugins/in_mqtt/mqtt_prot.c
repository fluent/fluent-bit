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
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_utils.h>
#include <msgpack.h>

#include "mqtt.h"
#include "mqtt_prot.h"

#define BUFC()          conn->buf[conn->buf_pos]
#define BUF_AVAIL()     conn->buf_len - conn->buf_pos
#define BIT_SET(a, b)   ((a) |= (1 << (b)))
#define BIT_CHECK(a, b) ((a) & (1 << (b)))

/*
static inline void print_hex(struct mqtt_conn *conn)
{
    int x;

    printf("\n--------HEX--------> ");
    printf("buf_pos=%i buf_len=%i\n", conn->buf_pos, conn->buf_len);
    for (x = conn->buf_pos; x < conn->buf_len; x++) {
        printf("%x ", conn->buf[x]);
    }
    printf("\n--------------------\n\n");
}

static inline void print_str(struct mqtt_conn *conn)
{
    int x;

    printf("\n--------HEX--------> ");
    printf("buf_pos=%i buf_len=%i\n", conn->buf_pos, conn->buf_len);
    for (x = conn->buf_pos; x < conn->buf_len; x++) {
        printf("%c", conn->buf[x]);
    }
    printf("\n--------------------\n\n");
}
*/

/*
 * It drop the current packet from the buffer, it move the remaining bytes
 * from right-to-left and adjust the new length.
 */
static inline int mqtt_packet_drop(struct mqtt_conn *conn)
{
    int move_bytes;

    if (conn->buf_pos == conn->buf_len) {
        conn->buf_frame_end = 0;
        conn->buf_len = 0;
        conn->buf_pos = 0;
        return 0;
    }

    /* Check boundaries */
    if (conn->buf_pos + 1 > conn->buf_len) {
        conn->buf_frame_end = 0;
        conn->buf_len = 0;
        conn->buf_pos = 0;
        return 0;
    }

    move_bytes = conn->buf_pos + 1;
    memmove(conn->buf,
            conn->buf + move_bytes,
            conn->buf_len - move_bytes);

    conn->buf_frame_end = 0;
    conn->buf_len -= move_bytes;
    conn->buf_pos  = 0;

    return 0;
}

/*
 * It writes the packet control header which includes the packet type
 * and the remaining length of the packet. The incoming buffer must have
 * at least 6 bytes of space.
 *
 * The function returns the number of bytes used.
 */
static inline int mqtt_packet_header(int type, int length, char *buf)
{
    int i = 0;
    uint8_t byte;

    buf[i] = (type << 4) | 0;
    i++;

    do {
        byte = length % 128;
        length = (length / 128);
        if (length > 0) {
            byte = (byte | 128);
        }
        buf[i] = byte;
        i++;
    } while (length > 0);

    return i;
}

/* Collect a buffer of JSON data and convert it to Fluent Bit format */
static int mqtt_data_append(char *topic, size_t topic_len,
                            char *msg, int msg_len,
                            void *in_context)
{
    int i;
    int ret;
    int root_type;
    size_t out;
    size_t off = 0;
    char *pack;
    msgpack_object root;
    msgpack_unpacked result;
    struct flb_in_mqtt_config *ctx = in_context;

    /* Convert our incoming JSON to MsgPack */
    ret = flb_pack_json(msg, msg_len, &pack, &out, &root_type, NULL);
    if (ret != 0) {
        flb_plg_warn(ctx->ins, "MQTT Packet incomplete or is not JSON");
        return -1;
    }

    off = 0;
    msgpack_unpacked_init(&result);
    if (msgpack_unpack_next(&result, pack, out, &off) != MSGPACK_UNPACK_SUCCESS) {
        msgpack_unpacked_destroy(&result);
        flb_free(pack);
        return -1;
    }

    if (result.data.type != MSGPACK_OBJECT_MAP){
        msgpack_unpacked_destroy(&result);
        flb_free(pack);
        return -1;
    }
    root = result.data;


    ret = flb_log_event_encoder_begin_record(ctx->log_encoder);

    if (ret == FLB_EVENT_ENCODER_SUCCESS) {
        ret = flb_log_event_encoder_set_current_timestamp(ctx->log_encoder);
    }

    if (ret == FLB_EVENT_ENCODER_SUCCESS) {
        ret = flb_log_event_encoder_append_body_values(
                ctx->log_encoder,
                FLB_LOG_EVENT_CSTRING_VALUE("topic"),
                FLB_LOG_EVENT_STRING_VALUE(topic, topic_len));
    }

    if (ctx->payload_key) {
        flb_log_event_encoder_append_body_string_length(ctx->log_encoder, flb_sds_len(ctx->payload_key));
        flb_log_event_encoder_append_body_string_body(ctx->log_encoder, ctx->payload_key,
                                                      flb_sds_len(ctx->payload_key));
        flb_log_event_encoder_body_begin_map(ctx->log_encoder);
    }

    /* Re-pack original KVs */
    for (i = 0;
         i < root.via.map.size &&
         ret == FLB_EVENT_ENCODER_SUCCESS;
         i++) {
        ret = flb_log_event_encoder_append_body_values(
                ctx->log_encoder,
                FLB_LOG_EVENT_MSGPACK_OBJECT_VALUE(&root.via.map.ptr[i].key),
                FLB_LOG_EVENT_MSGPACK_OBJECT_VALUE(&root.via.map.ptr[i].val));
    }

    if (ctx->payload_key) {
        flb_log_event_encoder_body_commit_map(ctx->log_encoder);
    }

    if (ret == FLB_EVENT_ENCODER_SUCCESS) {
        ret = flb_log_event_encoder_commit_record(ctx->log_encoder);
    }

    if (ret == FLB_EVENT_ENCODER_SUCCESS) {
        flb_input_log_append(ctx->ins, NULL, 0,
                             ctx->log_encoder->output_buffer,
                             ctx->log_encoder->output_length);
        ret = 0;
    }
    else {
        flb_plg_error(ctx->ins, "log event encoding error : %d", ret);

        ret = -1;
    }

    flb_log_event_encoder_reset(ctx->log_encoder);

    msgpack_unpacked_destroy(&result);
    flb_free(pack);

    return ret;
}


/*
 * Handle a CONNECT request control packet:
 *
 * basically we need to acknoledge the sender so it can start
 * publishing messages to our service.
 */
static int mqtt_handle_connect(struct mqtt_conn *conn)
{
    int i;
    int ret;
    size_t sent;
    char buf[4] = {0, 0, 0, 0};
    struct flb_in_mqtt_config *ctx = conn->ctx;

    i = mqtt_packet_header(MQTT_CONNACK, 2 , (char *) &buf);
    BIT_SET(buf[i], 0);
    i++;
    buf[i] = MQTT_CONN_ACCEPTED;

    /* write CONNACK message */
    ret = flb_io_net_write(conn->connection,
                           (void *) buf,
                           4,
                           &sent);

    flb_plg_trace(ctx->ins, "[fd=%i] CMD CONNECT (connack=%i bytes)",
                  conn->connection->fd, ret);

    return ret;
}

/*
 * Handle a PUBLISH control packet
 */
static int mqtt_handle_publish(struct mqtt_conn *conn)
{
    int topic;
    int topic_len;
    uint8_t qos;
    size_t sent;
    uint16_t hlen;
    uint16_t packet_id;
    char buf[4];
    struct flb_in_mqtt_config *ctx = conn->ctx;

    /*
     * DUP: we skip duplicated messages.
     * QOS: We process this.
     * Retain: skipped
     */

    qos = ((conn->buf[0] >> 1) & 0x03);
    conn->buf_pos++;

    /* Topic */
    hlen = BUFC() << 8;
    conn->buf_pos++;
    hlen |= BUFC();

    /* Validate topic length against current buffer capacity (overflow) */
    if (hlen > (conn->buf_len - conn->buf_pos)) {
        flb_plg_debug(ctx->ins, "invalid topic length");
        return -1;
    }

    conn->buf_pos++;
    topic     = conn->buf_pos;
    topic_len = hlen;
    conn->buf_pos += hlen;

    /* Check QOS flag and respond if required */
    if (qos > MQTT_QOS_LEV0) {
        /* Packet Identifier */
        packet_id = BUFC() << 8;
        conn->buf_pos++;
        packet_id |= BUFC();
        conn->buf_pos++;

        if (qos == MQTT_QOS_LEV1) {
            mqtt_packet_header(MQTT_PUBACK, 2 , (char *) &buf);
        }
        else if (qos == MQTT_QOS_LEV2) {
            mqtt_packet_header(MQTT_PUBREC, 2 , (char *) &buf);
        }
        /* Set the identifier that we are replying to */
        buf[2] = (packet_id >> 8) & 0xff;
        buf[3] = (packet_id & 0xff);

        /* This operation should be checked */
        flb_io_net_write(conn->connection,
                         (void *) buf,
                         4,
                         &sent);
    }

    /* Message */
    mqtt_data_append((char *) (conn->buf + topic), topic_len,
                     (char *) (conn->buf + conn->buf_pos),
                     conn->buf_frame_end - conn->buf_pos + 1,
                     conn->ctx);

    flb_plg_trace(ctx->ins, "[fd=%i] CMD PUBLISH",
                  conn->connection->fd);
    return 0;
}

/* Handle a PINGREQ control packet */
static int mqtt_handle_ping(struct mqtt_conn *conn)
{
    int ret;
    size_t sent;
    char buf[2] = {0, 0};
    struct flb_in_mqtt_config *ctx = conn->ctx;

    mqtt_packet_header(MQTT_PINGRESP, 0 , (char *) &buf);

    /* write PINGRESP message */

    ret = flb_io_net_write(conn->connection,
                           (void *) buf,
                           2,
                           &sent);

    flb_plg_trace(ctx->ins, "[fd=%i] CMD PING (pong=%i bytes)",
                  conn->connection->fd, ret);
    return ret;
}

int mqtt_prot_parser(struct mqtt_conn *conn)
{
    int ret;
    int length = 0;
    int pos = conn->buf_pos;
    int mult;
    struct flb_in_mqtt_config *ctx = conn->ctx;

    for (; conn->buf_pos < conn->buf_len; conn->buf_pos++) {
        if (conn->status & (MQTT_NEW | MQTT_NEXT)) {
            /*
             * Do we have at least the Control Packet fixed header
             * and the remaining length byte field ?
             */
            if (BUF_AVAIL() < 2) {
                conn->buf_pos = pos;
                flb_plg_trace(ctx->ins, "[fd=%i] Need more data",
                              conn->connection->fd);
                return MQTT_MORE;
            }

            /* As the connection is new we expect a MQTT_CONNECT request */
            conn->packet_type = BUFC() >> 4;
            if (conn->status == MQTT_NEW && conn->packet_type != MQTT_CONNECT) {
                flb_plg_trace(ctx->ins, "[fd=%i] error, expecting MQTT_CONNECT",
                              conn->connection->fd);
                return MQTT_ERROR;
            }
            conn->packet_length = conn->buf_pos;
            conn->buf_pos++;

            /* Get the remaining length */
            mult   = 1;
            length = 0;

            do {
                if (conn->buf_pos + 1 > conn->buf_len) {
                    conn->buf_pos = pos;
                    flb_plg_trace(ctx->ins, "[fd=%i] Need more data",
                                  conn->connection->fd);
                    return MQTT_MORE;
                }

                length += (BUFC() & 127) * mult;
                mult *= 128;
                if (mult > 128*128*128) {
                    return MQTT_ERROR;
                }

                if (length + 2 > (conn->buf_len - pos)) {
                    conn->buf_pos = pos;
                    flb_plg_trace(ctx->ins, "[fd=%i] Need more data",
                                  conn->connection->fd);
                    return MQTT_MORE;
                }

                if ((BUFC() & 128) == 0) {
                    if (conn->buf_len - 2 < length) {
                        conn->buf_pos = pos;
                        flb_plg_trace(ctx->ins, "[fd=%i] Need more data",
                                      conn->connection->fd);
                        return MQTT_MORE;
                    }
                    else {
                        conn->buf_frame_end = conn->buf_pos + length;
                        break;
                    }
                }

                if (conn->buf_pos + 1 < conn->buf_len) {
                    conn->buf_pos++;
                }
                else {
                    conn->buf_pos = pos;
                    flb_plg_trace(ctx->ins, "[fd=%i] Need more data",
                                  conn->connection->fd);
                    return MQTT_MORE;
                }
            } while (1);

            conn->packet_length = length;

            /* At this point we have a full control packet in place */
            if (conn->packet_type == MQTT_CONNECT) {
                mqtt_handle_connect(conn);
            }
            else if (conn->packet_type == MQTT_PUBLISH) {
                ret = mqtt_handle_publish(conn);
                if (ret == -1) {
                    return MQTT_ERROR;
                }
            }
            else if (conn->packet_type == MQTT_PINGREQ) {
                mqtt_handle_ping(conn);
            }
            else if (conn->packet_type == MQTT_DISCONNECT) {
                flb_plg_trace(ctx->ins, "[fd=%i] CMD DISCONNECT",
                          conn->connection->fd);
                return MQTT_HANGUP;
            }
            else {
            }

            /* Prepare for next round */
            conn->status = MQTT_NEXT;
            conn->buf_pos = conn->buf_frame_end;

            mqtt_packet_drop(conn);

            if (conn->buf_len > 0) {
                conn->buf_pos = -1;
            }
        }
    }
    conn->buf_pos--;
    return 0;
}
