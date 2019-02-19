/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019      The Fluent Bit Authors
 *  Copyright (C) 2015-2018 Treasure Data Inc.
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
    int n_size;
    int root_type;
    size_t out;
    size_t off = 0;
    char *pack;
    msgpack_object root;
    msgpack_unpacked result;
    msgpack_packer mp_pck;
    msgpack_sbuffer mp_sbuf;
    struct flb_in_mqtt_config *ctx = in_context;

    /* Convert our incoming JSON to MsgPack */
    ret = flb_pack_json(msg, msg_len, &pack, &out, &root_type);
    if (ret != 0) {
        flb_warn("MQTT Packet incomplete or is not JSON");
        return -1;
    }

    off = 0;
    msgpack_unpacked_init(&result);
    if (msgpack_unpack_next(&result, pack, out, &off) != MSGPACK_UNPACK_SUCCESS) {
        msgpack_unpacked_destroy(&result);
        return -1;
    }

    if (result.data.type != MSGPACK_OBJECT_MAP){
        msgpack_unpacked_destroy(&result);
        return -1;
    }
    root = result.data;

    /* Initialize local msgpack buffer */
    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    /* Pack data */
    msgpack_pack_array(&mp_pck, 2);
    flb_pack_time_now(&mp_pck);

    n_size = root.via.map.size;
    msgpack_pack_map(&mp_pck, n_size + 1);
    msgpack_pack_str(&mp_pck, 5);
    msgpack_pack_str_body(&mp_pck, "topic", 5);
    msgpack_pack_str(&mp_pck, topic_len);
    msgpack_pack_str_body(&mp_pck, topic, topic_len);

    /* Re-pack original KVs */
    for (i = 0; i < n_size; i++) {
        msgpack_pack_object(&mp_pck, root.via.map.ptr[i].key);
        msgpack_pack_object(&mp_pck, root.via.map.ptr[i].val);
    }


    flb_input_chunk_append_raw(ctx->i_ins, NULL, 0, mp_sbuf.data, mp_sbuf.size);
    msgpack_sbuffer_destroy(&mp_sbuf);

    msgpack_unpacked_destroy(&result);
    flb_free(pack);
    return 0;
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
    char buf[4] = {0, 0, 0, 0};

    i = mqtt_packet_header(MQTT_CONNACK, 2 , (char *) &buf);
    BIT_SET(buf[i], 0);
    i++;
    buf[i] = MQTT_CONN_ACCEPTED;

    /* write CONNACK message */
    ret = write(conn->event.fd, buf, 4);
    flb_trace("[in_mqtt] [fd=%i] CMD CONNECT (connack=%i bytes)",
              conn->event.fd, ret);
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
    uint16_t hlen;
    uint16_t packet_id;
    char buf[4];

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
        buf[2] = (packet_id & 0xf0) >> 4;
        buf[3] = (packet_id & 0xf);
        write(conn->event.fd, buf, 4);
    }

    /* Message */
    mqtt_data_append((char *) (conn->buf + topic), topic_len,
                     (char *) (conn->buf + conn->buf_pos),
                     conn->buf_frame_end - conn->buf_pos + 1,
                     conn->ctx);

    flb_trace("[in_mqtt] [fd=%i] CMD PUBLISH",
              conn->event.fd);
    return 0;
}

/* Handle a PINGREQ control packet */
static int mqtt_handle_ping(struct mqtt_conn *conn)
{
    int ret;
    char buf[2] = {0, 0};

    mqtt_packet_header(MQTT_PINGRESP, 2 , (char *) &buf);

    /* write PINGRESP message */
    ret = write(conn->event.fd, buf, 2);

    flb_trace("[in_mqtt] [fd=%i] CMD PING (pong=%i bytes)",
              conn->event.fd, ret);
    return ret;
}

int mqtt_prot_parser(struct mqtt_conn *conn)
{
    int bytes = 0;
    int length = 0;
    int pos = conn->buf_pos;
    int mult;

    for (; conn->buf_pos < conn->buf_len; conn->buf_pos++) {
        if (conn->status & (MQTT_NEW | MQTT_NEXT)) {
            /*
             * Do we have at least the Control Packet fixed header
             * and the remaining length byte field ?
             */
            if (BUF_AVAIL() < 2) {
                conn->buf_pos = pos;
                flb_trace("[in_mqtt] [fd=%i] Need more data at %s:%i",
                          conn->event.fd, __FILENAME__, __LINE__);
                return MQTT_MORE;
            }

            /* As the connection is new we expect a MQTT_CONNECT request */
            conn->packet_type = BUFC() >> 4;
            if (conn->status == MQTT_NEW && conn->packet_type != MQTT_CONNECT) {
                flb_trace("[in_mqtt] [fd=%i] error, expecting MQTT_CONNECT",
                          conn->event.fd);
                return MQTT_ERROR;
            }
            conn->packet_length = conn->buf_pos;
            conn->buf_pos++;

            /* Get the remaining length */
            mult   = 1;
            length = 0;
            bytes  = 0;
            do {
                if (conn->buf_pos + 1 > conn->buf_len) {
                    conn->buf_pos = pos;
                    flb_trace("[in_mqtt] [fd=%i] Need more data at %s:%i",
                              conn->event.fd, __FILENAME__, __LINE__);
                    return MQTT_MORE;
                }

                bytes++;
                length += (BUFC() & 127) * mult;
                mult *= 128;
                if (mult > 128*128*128) {
                    return MQTT_ERROR;
                }

                if (length + 2 > (conn->buf_len - pos)) {
                    conn->buf_pos = pos;
                    flb_trace("[in_mqtt] [fd=%i] Need more data at %s:%i",
                              conn->event.fd, __FILENAME__, __LINE__);
                    return MQTT_MORE;
                }

                if ((BUFC() & 128) == 0) {
                    if (conn->buf_len - 2 < length) {
                        conn->buf_pos = pos;
                        flb_trace("[in_mqtt] [fd=%i] Need more data at %s:%i",
                                  conn->event.fd, __FILENAME__, __LINE__);
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
                    flb_trace("[in_mqtt] [fd=%i] Need more data at %s:%i",
                              conn->event.fd, __FILENAME__, __LINE__);
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
            else if (conn->packet_type == MQTT_PINGREQ) {
                mqtt_handle_ping(conn);
            }
            else if (conn->packet_type == MQTT_DISCONNECT) {
                flb_trace("[in_mqtt] [fd=%i] CMD DISCONNECT",
                          conn->event.fd);
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
