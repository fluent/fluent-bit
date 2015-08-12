/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015 Treasure Data Inc.
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

#include <unistd.h>
#include <msgpack.h>

#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_pack.h>

#include "mqtt.h"
#include "mqtt_prot.h"

#define BUFC()          conn->buf[conn->buf_pos]
#define BUF_AVAIL()     conn->buf_len - conn->buf_pos
#define BIT_SET(a, b)   ((a) |= (1 << (b)))
#define BIT_CHECK(a, b) ((a) & (1 << (b)))

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

/*
 * It drop the current packet from the buffer, it move the remaining bytes
 * from right-to-left and adjust the new length.
 */
static inline int mqtt_packet_drop(struct mqtt_conn *conn, int content_len)
{
    int drop;

    if (conn->buf_len - content_len == 0) {
        conn->buf_pos = 0;
        conn->buf_len = 0;
        return 0;
    }

    drop = conn->buf_len - content_len;
    memmove(conn->buf,
            conn->buf + conn->buf_pos,
            drop);

    conn->buf_pos  = 0;
    conn->buf_len -= drop;
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

/*
 * Handle a CONNECT request control packet:
 *
 * basically we need to acknoledge the sender so it can start
 * publishing messages to our service.
 */
static int mqtt_handle_connect(struct mqtt_conn *conn)
{
    int i;
    char buf[4] = {0, 0, 0, 0};

    i = mqtt_packet_header(MQTT_CONNACK, 2 , (char *) &buf);
    BIT_SET(buf[i], 0);
    i++;
    buf[i] = MQTT_CONN_ACCEPTED;

    /* write CONNACK message */
    return write(conn->event.fd, buf, 4);
}

/* Collect a buffer of JSON data and convert it to MsgPack */
static int mqtt_data_append(char *buf, int len, void *in_context)
{
    int out;
    char *pack;
    struct flb_in_mqtt_config *ctx = in_context;

    pack = flb_pack_json(buf, len, &out);
    if (!pack) {
        //flb_debug("MQTT Packet incomplete or is not JSON");
        return -1;
    }

    memcpy(ctx->msgp + ctx->msgp_len, pack, out);
    ctx->msgp_len += out;
    free(pack);

    return 0;
}

/*
 * Handle a PUBLISH control packet
 */
static int mqtt_handle_publish(struct mqtt_conn *conn)
{
    uint8_t qos;
    uint16_t hlen;
    uint16_t packet_id;
    char buf[4];

    /*
     * DUP: we skip dplicated messages.
     * QOS: We process this.
     * Retain: skipped
     */

    qos = ((conn->buf[0] >> 1) & 0x03);
    conn->buf_pos++;

    /* Topic */
    hlen = BUFC() << 8;
    conn->buf_pos++;
    hlen |= BUFC();
    conn->buf_pos++;
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
        buf[2] = (packet_id & 0xf0) >> 4;
        buf[3] = (packet_id & 0xf);
        write(conn->event.fd, buf, 4);
    }

    /* Message */
    mqtt_data_append(conn->buf + conn->buf_pos,
                     conn->buf_len - conn->buf_pos,
                     conn->ctx);
    return 0;
}

int mqtt_prot_parser(struct mqtt_conn *conn)
{
    int bytes;
    int length;
    int mult;

    for (; conn->buf_pos < conn->buf_len; conn->buf_pos++) {
        if (conn->status & (MQTT_NEW | MQTT_NEXT)) {
            /*
             * Do we have at least the Control Packet fixed header
             * and the remaining length byte field ? */
            if (BUF_AVAIL() < 2) {
                return MQTT_MORE;
            }

            /* As the connection is new we expect a MQTT_CONNECT request */
            conn->packet_type = BUFC() >> 4;
            if (conn->status == MQTT_NEW && conn->packet_type != MQTT_CONNECT) {
                return MQTT_ERROR;
            }
            conn->packet_length = conn->buf_pos;
            conn->buf_pos++;

            /* Get the remaining length */
            mult   = 1;
            length = 0;
            bytes  = 0;
            do {
                bytes++;
                length += (BUFC() & 127) * mult;
                mult *= 128;
                if (mult > 128*128*128) {
                    return MQTT_ERROR;
                }

                if ((BUFC() & 128) == 0) {
                    if (length < conn->buf_len - 2) {
                        return MQTT_MORE;
                    }
                    else {
                        break;
                    }
                }

                if (conn->buf_pos + 1 < conn->buf_len) {
                    conn->buf_pos++;
                }
                else {
                    return MQTT_MORE;
                }
            } while (1);

            conn->buf_pos += bytes - 1;
            conn->packet_length = length;

            /* At this point we have a full control packet in place */
            if (conn->packet_type == MQTT_CONNECT) {
                mqtt_handle_connect(conn);
            }
            else if (conn->packet_type == MQTT_PUBLISH) {
                mqtt_handle_publish(conn);
            }
            else if (conn->packet_type == MQTT_DISCONNECT) {
                return MQTT_HANGUP;
            }

            /* Prepare for next round */
            conn->status = MQTT_NEXT;
            mqtt_packet_drop(conn, 1 + bytes + length);
        }
    }
    conn->buf_pos--;
    return 0;
}
