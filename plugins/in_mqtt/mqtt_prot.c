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
#include <fluent-bit/flb_downstream.h>
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

struct mqtt_data_append_args {
    char *topic;
    size_t topic_len;
    char *msg;
    int msg_len;
    struct flb_in_mqtt_config *ctx;
};

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

static int mqtt_data_append_dispatch(void *data)
{
    struct mqtt_data_append_args *args;

    args = data;

    return mqtt_data_append(args->topic, args->topic_len,
                            args->msg, args->msg_len, args->ctx);
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

    /*
     * This plugin does not keep any session state, so the Session Present
     * flag in the CONNACK must always be zero (MQTT-3.2.2-1, MQTT-3.2.2-2).
     */
    i = mqtt_packet_header(MQTT_CONNACK, 2 , (char *) &buf);
    buf[i] = 0;
    i++;
    buf[i] = MQTT_CONN_ACCEPTED;

    /* write CONNACK message */
    ret = flb_io_net_write(conn->connection,
                           (void *) buf,
                           4,
                           &sent);

    flb_plg_trace(ctx->ins, "[fd=%i] CMD CONNECT (connack=%i bytes)",
                  conn->connection->fd, ret);

    if (ret == -1) {
        return -1;
    }

    return 0;
}

/*
 * QoS 2 publications that were acknowledged with a PUBREC and are waiting for
 * their PUBREL are tracked in a bitmap with one bit per Packet Identifier, so
 * a retransmitted PUBLISH is acknowledged again without ingesting it twice.
 */
static int mqtt_qos2_is_pending(struct mqtt_conn *conn, uint16_t packet_id)
{
    if (conn->qos2_pending == NULL) {
        return FLB_FALSE;
    }

    return (conn->qos2_pending[packet_id >> 3] >> (packet_id & 7)) & 1;
}

static int mqtt_qos2_set_pending(struct mqtt_conn *conn, uint16_t packet_id)
{
    if (conn->qos2_pending == NULL) {
        conn->qos2_pending = flb_calloc(MQTT_QOS2_BITMAP_SIZE, 1);
        if (conn->qos2_pending == NULL) {
            flb_errno();
            return -1;
        }
    }

    conn->qos2_pending[packet_id >> 3] |= (1 << (packet_id & 7));
    return 0;
}

static void mqtt_qos2_clear_pending(struct mqtt_conn *conn, uint16_t packet_id)
{
    if (conn->qos2_pending != NULL) {
        conn->qos2_pending[packet_id >> 3] &= ~(1 << (packet_id & 7));
    }
}

/*
 * Handle a PUBLISH control packet
 */
static int mqtt_handle_publish(struct mqtt_conn *conn)
{
    int ret;
    int duplicate = FLB_FALSE;
    int frame_avail;
    int topic;
    int topic_len;
    uint8_t qos;
    size_t sent;
    uint16_t hlen;
    uint16_t packet_id;
    char buf[4] = {0, 0, 0, 0};
    struct mqtt_data_append_args args;
    struct flb_in_mqtt_config *ctx = conn->ctx;

    /*
     * DUP: we skip duplicated messages.
     * QOS: We process this.
     * Retain: skipped
     */

    qos = ((conn->buf[0] >> 1) & 0x03);
    if (qos > MQTT_QOS_LEV2) {
        /* MQTT-3.3.1-4: a PUBLISH packet must not have both QoS bits set */
        flb_plg_debug(ctx->ins, "invalid publish QoS");
        return -1;
    }
    conn->buf_pos++;

    /* Topic */
    frame_avail = conn->buf_frame_end - conn->buf_pos + 1;
    if (frame_avail < 2) {
        flb_plg_debug(ctx->ins, "truncated publish topic length");
        return -1;
    }

    hlen = BUFC() << 8;
    conn->buf_pos++;
    hlen |= BUFC();

    /* Validate topic length against current buffer capacity (overflow) */
    frame_avail = conn->buf_frame_end - conn->buf_pos + 1;
    if (hlen > frame_avail) {
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
        frame_avail = conn->buf_frame_end - conn->buf_pos + 1;
        if (frame_avail < 2) {
            flb_plg_debug(ctx->ins, "truncated publish packet id");
            return -1;
        }

        packet_id = BUFC() << 8;
        conn->buf_pos++;
        packet_id |= BUFC();
        conn->buf_pos++;

        if (qos == MQTT_QOS_LEV1) {
            mqtt_packet_header(MQTT_PUBACK, 2 , (char *) &buf);
        }
        else if (qos == MQTT_QOS_LEV2) {
            mqtt_packet_header(MQTT_PUBREC, 2 , (char *) &buf);

            /* a retransmission of a message that was already ingested */
            duplicate = mqtt_qos2_is_pending(conn, packet_id);
            if (duplicate == FLB_FALSE &&
                mqtt_qos2_set_pending(conn, packet_id) == -1) {
                return -1;
            }
        }
        /* Set the identifier that we are replying to */
        buf[2] = (packet_id >> 8) & 0xff;
        buf[3] = (packet_id & 0xff);

        ret = flb_io_net_write(conn->connection,
                               (void *) buf,
                               4,
                               &sent);
        if (ret == -1) {
            flb_plg_debug(ctx->ins, "[fd=%i] could not acknowledge publish",
                          conn->connection->fd);
            return -1;
        }

        if (duplicate == FLB_TRUE) {
            flb_plg_trace(ctx->ins, "[fd=%i] CMD PUBLISH (duplicate QoS 2 id=%i)",
                          conn->connection->fd, packet_id);
            return 0;
        }
    }

    /* Message */
    if (conn->buf_pos > conn->buf_frame_end + 1) {
        flb_plg_debug(ctx->ins, "truncated publish payload");
        return -1;
    }

    args.topic = (char *) (conn->buf + topic);
    args.topic_len = topic_len;
    args.msg = (char *) (conn->buf + conn->buf_pos);
    args.msg_len = conn->buf_frame_end - conn->buf_pos + 1;
    args.ctx = conn->ctx;

    /*
     * Filters and processors run while records are appended, keep them on
     * the parent stack instead of the connection coroutine stack.
     */
    flb_downstream_conn_event_call_parent(conn->connection,
                                          mqtt_data_append_dispatch,
                                          &args);

    flb_plg_trace(ctx->ins, "[fd=%i] CMD PUBLISH",
                  conn->connection->fd);
    return 0;
}

/*
 * Handle a PUBREL control packet: complete the QoS 2 exchange started by a
 * PUBLISH by replying with a PUBCOMP that carries the same Packet Identifier.
 */
static int mqtt_handle_pubrel(struct mqtt_conn *conn)
{
    int ret;
    size_t sent;
    char *body;
    char buf[4] = {0, 0, 0, 0};
    struct flb_in_mqtt_config *ctx = conn->ctx;

    /* MQTT-3.6.1-1: fixed header flags must be 0010, remaining length is 2 */
    if ((conn->buf[0] & 0x0f) != 0x02 || conn->packet_length != 2) {
        flb_plg_debug(ctx->ins, "[fd=%i] invalid PUBREL packet",
                      conn->connection->fd);
        return -1;
    }

    body = (char *) conn->buf + conn->buf_frame_end - conn->packet_length + 1;

    /* the exchange is complete: the identifier can be used again */
    mqtt_qos2_clear_pending(conn,
                            ((uint8_t) body[0] << 8) | (uint8_t) body[1]);

    mqtt_packet_header(MQTT_PUBCOMP, 2, (char *) &buf);
    buf[2] = body[0];
    buf[3] = body[1];

    ret = flb_io_net_write(conn->connection, (void *) buf, 4, &sent);
    flb_plg_trace(ctx->ins, "[fd=%i] CMD PUBREL (pubcomp=%i)",
                  conn->connection->fd, ret);

    if (ret == -1) {
        return -1;
    }

    return 0;
}

/*
 * Handle SUBSCRIBE and UNSUBSCRIBE control packets. This is an input plugin
 * that only ingests published messages, so every topic filter of a SUBSCRIBE
 * is answered with the failure code 0x80 in the SUBACK, and an UNSUBSCRIBE is
 * acknowledged with an UNSUBACK, so clients do not wait forever.
 */
static int mqtt_handle_subscription(struct mqtt_conn *conn)
{
    int ret;
    int len;
    int filters = 0;
    int offset;
    int filter_len;
    size_t sent;
    size_t out_len;
    uint8_t *body;
    uint8_t *reply = NULL;
    uint8_t small_reply[4];
    struct flb_in_mqtt_config *ctx = conn->ctx;

    /* MQTT-3.8.1-1 / MQTT-3.10.1-1: fixed header flags must be 0010 */
    if ((conn->buf[0] & 0x0f) != 0x02 || conn->packet_length < 2) {
        flb_plg_debug(ctx->ins, "[fd=%i] invalid SUBSCRIBE/UNSUBSCRIBE packet",
                      conn->connection->fd);
        return -1;
    }

    body = conn->buf + conn->buf_frame_end - conn->packet_length + 1;
    len = conn->packet_length;
    offset = 2;

    if (conn->packet_type == MQTT_SUBSCRIBE) {
        /* Payload: one or more { filter length (2), filter, requested QoS } */
        while (offset < len) {
            if (len - offset < 3) {
                return -1;
            }
            offset += 2 + ((body[offset] << 8) | body[offset + 1]) + 1;
            if (offset > len) {
                return -1;
            }
            filters++;
        }
        if (filters == 0) {
            return -1;
        }

        /* one return code per topic filter, after the packet identifier */
        out_len = 2 + 2 + filters;
        reply = flb_malloc(out_len);
        if (reply == NULL) {
            flb_errno();
            return -1;
        }

        mqtt_packet_header(MQTT_SUBACK, 2 + filters, (char *) reply);
        memset(&reply[4], MQTT_SUBACK_FAILURE, filters);
    }
    else {
        /* Payload: one or more { filter length (2), filter } */
        while (offset < len) {
            if (len - offset < 2) {
                return -1;
            }
            filter_len = (body[offset] << 8) | body[offset + 1];
            if (filter_len == 0 || filter_len > len - offset - 2) {
                return -1;
            }
            offset += 2 + filter_len;
            filters++;
        }
        if (filters == 0) {
            return -1;
        }

        reply = small_reply;
        mqtt_packet_header(MQTT_UNSUBACK, 2, (char *) reply);
        out_len = 4;
    }

    /* Set the identifier that we are replying to */
    reply[2] = body[0];
    reply[3] = body[1];

    ret = flb_io_net_write(conn->connection, (void *) reply, out_len, &sent);
    flb_plg_trace(ctx->ins, "[fd=%i] CMD SUBSCRIPTION (reply=%i)",
                  conn->connection->fd, ret);

    if (reply != small_reply) {
        flb_free(reply);
    }

    if (ret == -1) {
        return -1;
    }

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

    if (ret == -1) {
        return -1;
    }

    return 0;
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

                if (length + (conn->buf_pos - pos + 1) > (conn->buf_len - pos)) {
                    conn->buf_pos = pos;
                    flb_plg_trace(ctx->ins, "[fd=%i] Need more data",
                                  conn->connection->fd);
                    return MQTT_MORE;
                }

                if ((BUFC() & 128) == 0) {
                    if (conn->buf_len - (conn->buf_pos - pos + 1) < length) {
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
                if (conn->status == MQTT_NEXT) {
                    /* MQTT-3.1.0-2: a second CONNECT is a protocol violation */
                    flb_plg_debug(ctx->ins,
                                  "[fd=%i] error, duplicated MQTT_CONNECT",
                                  conn->connection->fd);
                    return MQTT_ERROR;
                }
                ret = mqtt_handle_connect(conn);
                if (ret == -1) {
                    return MQTT_ERROR;
                }
            }
            else if (conn->packet_type == MQTT_PUBLISH) {
                ret = mqtt_handle_publish(conn);
                if (ret == -1) {
                    return MQTT_ERROR;
                }
            }
            else if (conn->packet_type == MQTT_PUBREL) {
                ret = mqtt_handle_pubrel(conn);
                if (ret == -1) {
                    return MQTT_ERROR;
                }
            }
            else if (conn->packet_type == MQTT_SUBSCRIBE ||
                     conn->packet_type == MQTT_UNSUBSCRIBE) {
                ret = mqtt_handle_subscription(conn);
                if (ret == -1) {
                    return MQTT_ERROR;
                }
            }
            else if (conn->packet_type == MQTT_PINGREQ) {
                ret = mqtt_handle_ping(conn);
                if (ret == -1) {
                    return MQTT_ERROR;
                }
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
