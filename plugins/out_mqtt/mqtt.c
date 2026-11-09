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

#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_compat.h>
#include <fluent-bit/flb_io.h>
#include <fluent-bit/flb_log_event_decoder.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_record_accessor.h>
#include <fluent-bit/flb_router.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_socket.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_upstream.h>
#include <fluent-bit/flb_upstream_conn.h>

#include <msgpack.h>

#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "mqtt.h"
#include "mqtt_conf.h"
#include "mqtt_prot.h"

#ifndef MSG_DONTWAIT
#define MSG_DONTWAIT 0
#endif

/* Results of the per record helpers */
#define MQTT_RECORD_OK       0
#define MQTT_RECORD_SKIP     1
#define MQTT_RECORD_FAIL    -1

/* Message composition errors: retried with the chunk, or permanent */
#define MQTT_PACK_NOMEM     -1
#define MQTT_PACK_INVALID   -2

/* State of one flush: a single chunk published through one broker session */
struct mqtt_flush {
    struct flb_out_mqtt *ctx;
    struct flb_config *config;

    /* Broker session, opened when the first packets are written */
    struct flb_connection *conn;
    int conn_error;
    int session_ready;              /* CONNACK received or session reused */

    /* Keep alive: time of the last packet written, PINGREQ packets */
    time_t last_send;
    int pings_sent;
    int pings_answered;

    /*
     * Time limit of the broker reply being waited for (0: not waiting). The
     * network I/O timeout is renewed by any received byte, this limit is
     * only renewed when an awaited reply arrives.
     */
    time_t reply_deadline;
    int reply_timeout;

    /* Formatter test: the packets are collected instead of being sent */
    int test_mode;
    flb_sds_t capture;

    /* PUBLISH packets not written yet (the current window) */
    flb_sds_t wbuf;
    int window_count;
    uint16_t window_first_id;
    uint16_t next_packet_id;

    /* QoS 1: acknowledged flags for the packets of the window */
    unsigned char *acked;

    /* Bytes received from the broker and not consumed yet */
    unsigned char rbuf[FLB_MQTT_READ_BUFFER_SIZE];
    size_t rbuf_len;

    /* Message composition buffer */
    msgpack_sbuffer mp_sbuf;
    msgpack_packer mp_pck;

    /* Topic used by every record of the chunk without a topic_key value */
    flb_sds_t topic_buf;
    const char *topic;
    size_t topic_len;

    /* Accounting */
    int published;
    size_t published_bytes;
    int skipped;
    size_t skipped_bytes;
    int skipped_no_topic;
    int skipped_no_payload;
    int skipped_too_large;
    int skipped_encoding;
    int topic_key_invalid;

    /* The chunk could not be decoded after 'decoded_bytes' */
    int decode_error;
    size_t decoded_bytes;
    size_t chunk_bytes;
};

static void flush_destroy(struct mqtt_flush *mf)
{
    if (!mf) {
        return;
    }

    if (mf->capture) {
        flb_sds_destroy(mf->capture);
    }
    if (mf->wbuf) {
        flb_sds_destroy(mf->wbuf);
    }
    if (mf->topic_buf) {
        flb_sds_destroy(mf->topic_buf);
    }
    if (mf->acked) {
        flb_free(mf->acked);
    }
    msgpack_sbuffer_destroy(&mf->mp_sbuf);
    flb_free(mf);
}

static struct mqtt_flush *flush_create(struct flb_out_mqtt *ctx,
                                       struct flb_config *config, int test_mode)
{
    struct mqtt_flush *mf;

    mf = flb_calloc(1, sizeof(struct mqtt_flush));
    if (!mf) {
        flb_errno();
        return NULL;
    }
    mf->ctx = ctx;
    mf->config = config;
    mf->test_mode = test_mode;
    mf->next_packet_id = 1;

    msgpack_sbuffer_init(&mf->mp_sbuf);
    msgpack_packer_init(&mf->mp_pck, &mf->mp_sbuf, msgpack_sbuffer_write);

    mf->wbuf = flb_sds_create_size(4096);
    if (!mf->wbuf) {
        flush_destroy(mf);
        return NULL;
    }

    if (test_mode) {
        mf->capture = flb_sds_create_size(4096);
        if (!mf->capture) {
            flush_destroy(mf);
            return NULL;
        }
    }

    if (ctx->qos > 0) {
        mf->acked = flb_calloc(ctx->max_inflight, sizeof(unsigned char));
        if (!mf->acked) {
            flb_errno();
            flush_destroy(mf);
            return NULL;
        }
    }

    return mf;
}

/*
 * Check a keepalive connection taken from the pool before using it. The
 * broker can close an idle connection at any time and MQTT 3.1.1 brokers send
 * nothing on their own to a client without subscriptions, so an end of file,
 * a socket error or unexpected pending data (plain TCP only, TLS records like
 * session tickets can be pending) mean the connection must not be used.
 */
static int connection_is_alive(struct flb_connection *conn)
{
    int ret;
    char c;

    if (conn->fd == FLB_INVALID_SOCKET) {
        return FLB_FALSE;
    }

    /* Blocking sockets cannot be checked without waiting */
    if ((flb_connection_get_flags(conn) & FLB_IO_ASYNC) == 0) {
        return FLB_TRUE;
    }

    ret = recv(conn->fd, &c, 1, MSG_PEEK | MSG_DONTWAIT);
    if (ret == 0) {
        return FLB_FALSE;
    }
    else if (ret > 0) {
        if (conn->tls_session != NULL) {
            return FLB_TRUE;
        }
        return FLB_FALSE;
    }

    if (FLB_WOULDBLOCK()) {
        return FLB_TRUE;
    }

    return FLB_FALSE;
}

/* Tell if the connection goes back to the keepalive pool on release */
static int connection_will_recycle(struct flb_connection *conn)
{
    if (conn->net->keepalive != FLB_TRUE || conn->recycle != FLB_TRUE) {
        return FLB_FALSE;
    }

    if (conn->net->keepalive_max_recycle > 0 &&
        conn->ka_count + 1 > conn->net->keepalive_max_recycle) {
        return FLB_FALSE;
    }

    return FLB_TRUE;
}

static void rbuf_consume(struct mqtt_flush *mf, size_t bytes)
{
    if (bytes >= mf->rbuf_len) {
        mf->rbuf_len = 0;
        return;
    }

    memmove(mf->rbuf, mf->rbuf + bytes, mf->rbuf_len - bytes);
    mf->rbuf_len -= bytes;
}

/* Write packets to the broker, the time is kept for the keep alive */
static int session_write(struct mqtt_flush *mf, const void *data, size_t len)
{
    int ret;
    size_t sent;

    ret = flb_io_net_write(mf->conn, data, len, &sent);
    if (ret == -1 || sent != len) {
        return -1;
    }
    mf->last_send = time(NULL);

    return 0;
}

/* Send a PINGREQ packet, the broker answers PINGREQ packets in order */
static int ping_send(struct mqtt_flush *mf)
{
    int ret;
    flb_sds_t buf;

    buf = flb_sds_create_size(2);
    if (!buf) {
        flb_errno();
        return -1;
    }

    ret = out_mqtt_prot_pingreq(&buf);
    if (ret == 0) {
        ret = session_write(mf, buf, flb_sds_len(buf));
    }
    flb_sds_destroy(buf);

    if (ret != 0) {
        return -1;
    }
    mf->pings_sent++;

    return 0;
}

/* A PINGRESP the broker sent without a PINGREQ is ignored */
static void pingresp_received(struct mqtt_flush *mf)
{
    if (mf->pings_answered < mf->pings_sent) {
        mf->pings_answered++;
    }
}

/*
 * A client must send a packet at least every keep_alive seconds
 * (MQTT-3.1.2-23), the broker closes a silent session after one and a half
 * times the interval. While broker replies are awaited, a PINGREQ is sent
 * when half of the interval passed since the last packet written.
 */
static int keep_alive_ping(struct mqtt_flush *mf)
{
    int interval;
    struct flb_out_mqtt *ctx = mf->ctx;

    if (!mf->session_ready || ctx->keep_alive <= 0) {
        return 0;
    }

    interval = ctx->keep_alive / 2;
    if (interval < 1) {
        interval = 1;
    }

    if (time(NULL) - mf->last_send < interval) {
        return 0;
    }

    flb_plg_debug(ctx->ins, "sending PINGREQ to keep the session alive while "
                  "waiting for the broker");

    return ping_send(mf);
}

/* Allow net.io_timeout seconds for the next awaited broker reply */
static void reply_deadline_set(struct mqtt_flush *mf)
{
    mf->reply_deadline = time(NULL) + mf->ctx->u->base.net.io_timeout;
}

/*
 * Read from the broker while a reply is awaited. Every byte received renews
 * net.io_timeout, so packets the broker sends on its own could extend the
 * wait forever: the reply deadline ends it. The read itself waits until
 * data arrives or net.io_timeout expires, a keep alive PINGREQ is sent
 * before it when one is due.
 */
static ssize_t net_read(struct mqtt_flush *mf, void *buf, size_t len)
{
    /* Whole seconds: at least net.io_timeout seconds are allowed */
    if (mf->reply_deadline > 0 && time(NULL) > mf->reply_deadline) {
        mf->reply_timeout = FLB_TRUE;
        return -1;
    }

    if (keep_alive_ping(mf) != 0) {
        return -1;
    }

    return flb_io_net_read(mf->conn, buf, len);
}

/* Make the next 'n' bytes of the stream available in the receive buffer */
static int rbuf_fill(struct mqtt_flush *mf, size_t n)
{
    ssize_t bytes;

    while (mf->rbuf_len < n) {
        bytes = net_read(mf, mf->rbuf + mf->rbuf_len,
                         sizeof(mf->rbuf) - mf->rbuf_len);
        if (bytes <= 0) {
            return -1;
        }
        mf->rbuf_len += bytes;
    }

    return 0;
}

/* Discard the next 'n' bytes of the stream */
static int stream_skip(struct mqtt_flush *mf, size_t n)
{
    size_t want;
    ssize_t bytes;

    if (n <= mf->rbuf_len) {
        rbuf_consume(mf, n);
        return 0;
    }

    n -= mf->rbuf_len;
    mf->rbuf_len = 0;

    while (n > 0) {
        want = n < sizeof(mf->rbuf) ? n : sizeof(mf->rbuf);
        bytes = net_read(mf, mf->rbuf, want);
        if (bytes <= 0) {
            return -1;
        }
        n -= bytes;
    }

    return 0;
}

/* Send a PUBACK, PUBREC or PUBCOMP packet to the broker */
static int ack_send(struct mqtt_flush *mf, int type, uint16_t id)
{
    unsigned char packet[4];

    out_mqtt_prot_ack(packet, type, id);

    return session_write(mf, packet, sizeof(packet));
}

/*
 * A PUBLISH packet sent by the broker, for example because of a server side
 * subscription. The message is not used, but QoS 1 and 2 messages are
 * acknowledged as the protocol requires (QoS 2 continues with PUBREL and
 * PUBCOMP in packet_read()), so the broker does not deliver them again. The
 * packet can be larger than the receive buffer, it is read as a stream.
 */
static int broker_publish_discard(struct mqtt_flush *mf, int flags,
                                  size_t header_size, size_t length)
{
    int qos;
    size_t topic_len;
    uint16_t id;
    struct flb_out_mqtt *ctx = mf->ctx;

    qos = (flags >> 1) & 0x03;
    if (qos == 3) {
        flb_plg_error(ctx->ins, "malformed PUBLISH packet received from the "
                      "broker (QoS 3)");
        return -1;
    }

    flb_plg_debug(ctx->ins, "discarding PUBLISH packet (QoS %i, %zu bytes) sent "
                  "by the broker", qos, length);

    rbuf_consume(mf, header_size);

    if (qos == 0) {
        return stream_skip(mf, length);
    }

    /* Topic name, then the packet identifier */
    if (length < 4 || rbuf_fill(mf, 2) != 0) {
        return -1;
    }
    topic_len = ((size_t) mf->rbuf[0] << 8) | mf->rbuf[1];
    rbuf_consume(mf, 2);

    if (topic_len > length - 4) {
        flb_plg_error(ctx->ins, "malformed PUBLISH packet received from the broker");
        return -1;
    }

    if (stream_skip(mf, topic_len) != 0 || rbuf_fill(mf, 2) != 0) {
        return -1;
    }
    id = (uint16_t) ((mf->rbuf[0] << 8) | mf->rbuf[1]);
    rbuf_consume(mf, 2);

    if (id == 0) {
        flb_plg_error(ctx->ins, "malformed PUBLISH packet received from the broker "
                      "(packet identifier 0)");
        return -1;
    }

    /* Payload */
    if (stream_skip(mf, length - 4 - topic_len) != 0) {
        return -1;
    }

    return ack_send(mf, qos == 1 ? FLB_MQTT_PUBACK : FLB_MQTT_PUBREC, id);
}

/*
 * At the end of a flush, handle the complete packets the broker sent on its
 * own (PUBLISH, PUBREL) and the answers to keep alive PINGREQ packets that
 * are already in the receive buffer, so the session can be reused. Nothing
 * is read from the network: a partial or unexpected packet leaves data in
 * the buffer and the session is closed.
 */
static void rbuf_drain(struct mqtt_flush *mf)
{
    int ret;
    int p_type;
    int p_flags;
    size_t length;
    size_t header_size;
    uint16_t id;

    while (mf->rbuf_len > 0) {
        ret = out_mqtt_prot_decode_fixed_header(mf->rbuf, mf->rbuf_len,
                                                &p_type, &p_flags,
                                                &length, &header_size);
        if (ret != FLB_MQTT_DECODE_OK || mf->rbuf_len - header_size < length) {
            return;
        }

        if (p_type == FLB_MQTT_PUBLISH) {
            if (broker_publish_discard(mf, p_flags, header_size, length) != 0) {
                mf->conn_error = FLB_TRUE;
                return;
            }
        }
        else if (p_type == FLB_MQTT_PUBREL && p_flags == 0x02 && length == 2) {
            id = (uint16_t) ((mf->rbuf[header_size] << 8) |
                             mf->rbuf[header_size + 1]);
            rbuf_consume(mf, header_size + length);
            if (ack_send(mf, FLB_MQTT_PUBCOMP, id) != 0) {
                mf->conn_error = FLB_TRUE;
                return;
            }
        }
        else if (p_type == FLB_MQTT_PINGRESP && p_flags == 0 && length == 0 &&
                 mf->pings_answered < mf->pings_sent) {
            rbuf_consume(mf, header_size);
            pingresp_received(mf);
        }
        else {
            return;
        }
    }
}

/*
 * Read the next control packet sent by the broker into 'body'. The client
 * only waits for CONNACK, PUBACK and PINGRESP packets, their body is two
 * bytes at most. PUBLISH packets and the PUBREL of a QoS 2 PUBLISH, sent by
 * the broker on its own, are handled here and never returned.
 */
static int packet_read(struct mqtt_flush *mf, int *type, int *flags,
                       unsigned char *body, size_t body_size, size_t *body_len)
{
    int ret;
    int p_type;
    int p_flags;
    size_t length;
    size_t header_size;
    ssize_t bytes;
    uint16_t id;
    struct flb_out_mqtt *ctx = mf->ctx;

    while (1) {
        ret = out_mqtt_prot_decode_fixed_header(mf->rbuf, mf->rbuf_len,
                                                &p_type, &p_flags,
                                                &length, &header_size);
        if (ret == FLB_MQTT_DECODE_ERROR) {
            flb_plg_error(ctx->ins, "malformed packet received from the broker");
            return -1;
        }

        if (ret == FLB_MQTT_DECODE_OK) {
            if (p_type == FLB_MQTT_PUBLISH) {
                if (broker_publish_discard(mf, p_flags, header_size, length) != 0) {
                    return -1;
                }
                continue;
            }

            if (length > body_size) {
                flb_plg_error(ctx->ins, "unexpected packet type %i (%zu bytes) "
                              "received from the broker", p_type, length);
                return -1;
            }

            if (mf->rbuf_len - header_size >= length) {
                memcpy(body, mf->rbuf + header_size, length);
                rbuf_consume(mf, header_size + length);

                /* Second step of a QoS 2 PUBLISH sent by the broker */
                if (p_type == FLB_MQTT_PUBREL) {
                    if (p_flags != 0x02 || length != 2) {
                        flb_plg_error(ctx->ins, "malformed PUBREL packet received "
                                      "from the broker");
                        return -1;
                    }
                    id = (uint16_t) ((body[0] << 8) | body[1]);
                    if (ack_send(mf, FLB_MQTT_PUBCOMP, id) != 0) {
                        return -1;
                    }
                    continue;
                }

                *type = p_type;
                *flags = p_flags;
                *body_len = length;
                return 0;
            }
        }

        /* A fixed header and a two bytes body always fit in the buffer */
        if (mf->rbuf_len >= sizeof(mf->rbuf)) {
            return -1;
        }

        bytes = net_read(mf, mf->rbuf + mf->rbuf_len,
                         sizeof(mf->rbuf) - mf->rbuf_len);
        if (bytes <= 0) {
            return -1;
        }
        mf->rbuf_len += bytes;
    }
}

/* Send CONNECT on a new connection and wait for the broker CONNACK */
static int session_connect(struct mqtt_flush *mf)
{
    int ret;
    int type;
    int flags;
    unsigned int seq;
    size_t len;
    size_t id_len;
    size_t user_len;
    size_t pass_len;
    const char *id;
    char id_buf[FLB_MQTT_CLIENT_ID_SIZE];
    unsigned char body[2];
    flb_sds_t buf;
    struct flb_out_mqtt *ctx = mf->ctx;

    if (ctx->fixed_client_id) {
        id = ctx->client_id;
        id_len = flb_sds_len(ctx->client_id);
    }
    else {
        pthread_mutex_lock(&ctx->lock);
        seq = ctx->client_id_seq++;
        pthread_mutex_unlock(&ctx->lock);

        snprintf(id_buf, sizeof(id_buf), "%s%08x", ctx->client_id_prefix, seq);
        id = id_buf;
        id_len = strlen(id_buf);
    }

    user_len = ctx->username ? flb_sds_len(ctx->username) : 0;
    pass_len = ctx->password ? flb_sds_len(ctx->password) : 0;

    buf = flb_sds_create_size(64 + id_len + user_len + pass_len);
    if (!buf) {
        flb_errno();
        mf->conn_error = FLB_TRUE;
        return FLB_RETRY;
    }

    ret = out_mqtt_prot_connect(&buf, id, id_len,
                                ctx->username, user_len,
                                ctx->password, pass_len,
                                ctx->keep_alive);
    if (ret != 0) {
        flb_plg_error(ctx->ins, "cannot compose CONNECT packet");
        flb_sds_destroy(buf);
        mf->conn_error = FLB_TRUE;
        return FLB_RETRY;
    }

    ret = session_write(mf, buf, flb_sds_len(buf));
    flb_sds_destroy(buf);
    if (ret != 0) {
        flb_plg_error(ctx->ins, "could not send CONNECT to %s:%i",
                      ctx->u->tcp_host, ctx->u->tcp_port);
        mf->conn_error = FLB_TRUE;
        return FLB_RETRY;
    }

    reply_deadline_set(mf);
    ret = packet_read(mf, &type, &flags, body, sizeof(body), &len);
    if (ret != 0) {
        flb_plg_error(ctx->ins, "no CONNACK received from %s:%i",
                      ctx->u->tcp_host, ctx->u->tcp_port);
        mf->conn_error = FLB_TRUE;
        return FLB_RETRY;
    }

    /* The Session Present bit is ignored: a clean session is requested */
    if (type != FLB_MQTT_CONNACK || flags != 0 || len != 2 ||
        (body[0] & 0xfe) != 0) {
        flb_plg_error(ctx->ins, "invalid CONNACK received from %s:%i "
                      "(packet type %i)", ctx->u->tcp_host, ctx->u->tcp_port, type);
        mf->conn_error = FLB_TRUE;
        return FLB_RETRY;
    }

    if (body[1] != FLB_MQTT_CONNACK_ACCEPTED) {
        flb_plg_error(ctx->ins, "connection refused by %s:%i: %s (return code %i)",
                      ctx->u->tcp_host, ctx->u->tcp_port,
                      out_mqtt_prot_connack_str(body[1]), body[1]);
        mf->conn_error = FLB_TRUE;
        return FLB_RETRY;
    }

    flb_plg_debug(ctx->ins, "connected to %s:%i with client identifier '%.*s'",
                  ctx->u->tcp_host, ctx->u->tcp_port, (int) id_len, id);

    mf->reply_deadline = 0;
    mf->session_ready = FLB_TRUE;

    return FLB_OK;
}

/* Get a broker session: a live keepalive connection or a new one */
static int session_open(struct mqtt_flush *mf)
{
    int i;
    struct flb_connection *conn;
    struct flb_out_mqtt *ctx = mf->ctx;

    for (i = 0; i <= FLB_MQTT_MAX_STALE_CONNECTIONS; i++) {
        conn = flb_upstream_conn_get(ctx->u);
        if (!conn) {
            flb_plg_error(ctx->ins, "no upstream connections available to %s:%i",
                          ctx->u->tcp_host, ctx->u->tcp_port);
            return FLB_RETRY;
        }

        /* A connection used before already went through CONNECT */
        if (conn->ka_count == 0) {
            mf->conn = conn;
            return session_connect(mf);
        }

        if (connection_is_alive(conn)) {
            mf->conn = conn;
            mf->session_ready = FLB_TRUE;
            mf->last_send = time(NULL);
            return FLB_OK;
        }

        flb_plg_debug(ctx->ins, "keepalive connection #%i was closed by the "
                      "broker, discarding it", conn->fd);
        flb_upstream_conn_recycle(conn, FLB_FALSE);
        flb_upstream_conn_release(conn);
    }

    flb_plg_error(ctx->ins, "could not get a usable connection to %s:%i",
                  ctx->u->tcp_host, ctx->u->tcp_port);

    return FLB_RETRY;
}

/*
 * Tell if a healthy session can wait in the keepalive pool for the next
 * flush. A PINGREQ not answered yet is not allowed: the next flush would
 * read its PINGRESP. The pool closes an idle connection after
 * net.keepalive_idle_timeout counted from its release, checked every 1.5
 * seconds with a one second resolution, while the broker counts the silence
 * from the last packet written and drops the session after one and a half
 * times keep_alive. A session already silent for a while at the end of the
 * flush (slow acknowledgements) is not kept: whole seconds round the silence
 * down by less than one second.
 */
static int session_poolable(struct mqtt_flush *mf, struct flb_connection *conn)
{
    time_t silence;
    time_t budget;
    struct flb_out_mqtt *ctx = mf->ctx;

    if (mf->pings_answered != mf->pings_sent) {
        flb_plg_debug(ctx->ins, "PINGREQ not answered yet, the session is ended "
                      "instead of being kept for the next flush");
        return FLB_FALSE;
    }

    if (ctx->keep_alive <= 0) {
        return FLB_TRUE;
    }

    /* (silence + 1) + (idle timeout + 2.5) <= 1.5 x keep_alive, doubled */
    silence = time(NULL) - mf->last_send;
    budget = 3 * (time_t) ctx->keep_alive - 2 * (time_t) conn->net->keepalive_idle_timeout - 7;
    if (2 * silence > budget) {
        flb_plg_debug(ctx->ins, "session silent for %li seconds, it is ended "
                      "instead of being kept for the next flush", (long) silence);
        return FLB_FALSE;
    }

    return FLB_TRUE;
}

/*
 * Release the connection. A failed session is closed, and so is a session
 * with unread data: its stream position is unknown. A healthy session goes
 * back to the keepalive pool for the next flush, the pool closes it later
 * without DISCONNECT (idle timeout or shutdown), the broker sees a network
 * close and no Will message exists. A healthy session that is not kept is
 * ended with DISCONNECT.
 */
static void session_close(struct mqtt_flush *mf, int result)
{
    int keep;
    int disconnect;
    flb_sds_t buf;
    struct flb_connection *conn;

    conn = mf->conn;
    if (!conn) {
        return;
    }

    keep = FLB_FALSE;
    disconnect = FLB_FALSE;

    if (result == FLB_OK && !mf->conn_error) {
        rbuf_drain(mf);

        if (!mf->conn_error && mf->rbuf_len == 0) {
            if (connection_will_recycle(conn) && session_poolable(mf, conn)) {
                keep = FLB_TRUE;
            }
            else {
                disconnect = FLB_TRUE;
            }
        }
    }

    if (!keep) {
        flb_upstream_conn_recycle(conn, FLB_FALSE);
    }

    if (disconnect) {
        buf = flb_sds_create_size(2);
        if (buf) {
            if (out_mqtt_prot_disconnect(&buf) == 0) {
                session_write(mf, buf, flb_sds_len(buf));
            }
            flb_sds_destroy(buf);
        }
    }

    flb_upstream_conn_release(conn);
    mf->conn = NULL;
}

/* Position of a packet identifier in the window, identifiers wrap to 1 */
static int packet_id_offset(uint16_t first, uint16_t id)
{
    return (int) (((uint32_t) id + FLB_MQTT_MAX_PACKET_ID - first) %
                  FLB_MQTT_MAX_PACKET_ID);
}

static uint16_t packet_id_next(struct mqtt_flush *mf)
{
    uint16_t id;

    id = mf->next_packet_id;
    if (mf->next_packet_id == FLB_MQTT_MAX_PACKET_ID) {
        mf->next_packet_id = 1;
    }
    else {
        mf->next_packet_id++;
    }

    return id;
}

/*
 * QoS 1: wait for one PUBACK per PUBLISH packet of the window. The window
 * was just written, each PUBACK allows net.io_timeout seconds for the next
 * one: the wait is bounded whatever else the broker sends.
 */
static int puback_wait(struct mqtt_flush *mf)
{
    int ret;
    int type;
    int flags;
    int index;
    int count;
    size_t len;
    uint16_t id;
    unsigned char body[2];
    struct flb_out_mqtt *ctx = mf->ctx;

    reply_deadline_set(mf);

    count = 0;
    while (count < mf->window_count) {
        ret = packet_read(mf, &type, &flags, body, sizeof(body), &len);
        if (ret != 0) {
            if (mf->reply_timeout) {
                flb_plg_error(ctx->ins, "no PUBACK received from %s:%i within %i "
                              "seconds, %i messages are not acknowledged",
                              ctx->u->tcp_host, ctx->u->tcp_port,
                              ctx->u->base.net.io_timeout, mf->window_count - count);
            }
            else {
                flb_plg_error(ctx->ins, "connection to %s:%i lost while waiting for "
                              "%i PUBACK packets", ctx->u->tcp_host,
                              ctx->u->tcp_port, mf->window_count - count);
            }
            return -1;
        }

        /* Answer to a keep alive PINGREQ, or harmless */
        if (type == FLB_MQTT_PINGRESP && flags == 0 && len == 0) {
            pingresp_received(mf);
            continue;
        }

        if (type != FLB_MQTT_PUBACK || flags != 0 || len != 2) {
            flb_plg_error(ctx->ins, "unexpected packet type %i received while "
                          "waiting for PUBACK", type);
            return -1;
        }

        id = (uint16_t) ((body[0] << 8) | body[1]);
        index = packet_id_offset(mf->window_first_id, id);

        if (id == 0 || index >= mf->window_count || mf->acked[index]) {
            flb_plg_error(ctx->ins, "unexpected PUBACK for packet identifier %u",
                          (unsigned int) id);
            return -1;
        }

        mf->acked[index] = 1;
        count++;
        reply_deadline_set(mf);
    }

    mf->reply_deadline = 0;

    return 0;
}

/*
 * QoS 0 has no acknowledgements: a PINGREQ round trip after the last PUBLISH
 * confirms the broker read every packet of the flush, packets are processed
 * in order. A session the broker closed or lost is detected here instead of
 * dropping the messages silently.
 */
static int session_confirm(struct mqtt_flush *mf)
{
    int ret;
    int type;
    int flags;
    int confirm;
    size_t len;
    unsigned char body[2];
    struct flb_out_mqtt *ctx = mf->ctx;

    if (ping_send(mf) != 0) {
        flb_plg_error(ctx->ins, "could not send PINGREQ to %s:%i",
                      ctx->u->tcp_host, ctx->u->tcp_port);
        mf->conn_error = FLB_TRUE;
        return FLB_RETRY;
    }
    confirm = mf->pings_sent;

    reply_deadline_set(mf);

    /*
     * PINGREQ packets are answered in order, the ones sent while waiting to
     * keep the session alive are not waited for.
     */
    while (mf->pings_answered < confirm) {
        ret = packet_read(mf, &type, &flags, body, sizeof(body), &len);
        if (ret != 0 || type != FLB_MQTT_PINGRESP || flags != 0 || len != 0) {
            flb_plg_error(ctx->ins, "no PINGRESP received from %s:%i, the delivery "
                          "of %i messages is not confirmed",
                          ctx->u->tcp_host, ctx->u->tcp_port, mf->published);
            mf->conn_error = FLB_TRUE;
            return FLB_RETRY;
        }
        pingresp_received(mf);
    }

    mf->reply_deadline = 0;

    return FLB_OK;
}

static void window_reset(struct mqtt_flush *mf)
{
    flb_sds_len_set(mf->wbuf, 0);

    if (mf->acked && mf->window_count > 0) {
        memset(mf->acked, 0, mf->window_count);
    }
    mf->window_count = 0;
}

/* Write the pending PUBLISH packets and, with QoS 1, wait for the PUBACKs */
static int window_flush(struct mqtt_flush *mf)
{
    int ret;
    struct flb_out_mqtt *ctx = mf->ctx;

    if (mf->window_count == 0) {
        return FLB_OK;
    }

    if (mf->test_mode) {
        ret = flb_sds_cat_safe(&mf->capture, mf->wbuf, flb_sds_len(mf->wbuf));
        if (ret != 0) {
            return FLB_RETRY;
        }
        window_reset(mf);
        return FLB_OK;
    }

    if (!mf->conn) {
        ret = session_open(mf);
        if (ret != FLB_OK) {
            return ret;
        }
    }

    ret = session_write(mf, mf->wbuf, flb_sds_len(mf->wbuf));
    if (ret != 0) {
        flb_plg_error(ctx->ins, "could not write %i PUBLISH packets to %s:%i",
                      mf->window_count, ctx->u->tcp_host, ctx->u->tcp_port);
        mf->conn_error = FLB_TRUE;
        return FLB_RETRY;
    }

    if (ctx->qos > 0) {
        ret = puback_wait(mf);
        if (ret != 0) {
            mf->conn_error = FLB_TRUE;
            return FLB_RETRY;
        }
    }

    window_reset(mf);

    return FLB_OK;
}

/*
 * Topic for the records of a chunk that do not provide their own topic. A
 * template is expanded with the chunk tag, $TAG[n] is the n-th part of the
 * tag split on '.' (empty when the tag has fewer parts).
 */
static int chunk_topic_set(struct mqtt_flush *mf, const char *tag, int tag_len)
{
    int ret;
    int index;
    const char *p;
    const char *end;
    const char *dot;
    struct mk_list *head;
    struct flb_out_mqtt_topic_part *part;
    struct flb_out_mqtt *ctx = mf->ctx;

    if (!ctx->topic_has_tag) {
        mf->topic = ctx->topic;
        mf->topic_len = flb_sds_len(ctx->topic);
        return 0;
    }

    mf->topic_buf = flb_sds_create_size(flb_sds_len(ctx->topic) + tag_len);
    if (!mf->topic_buf) {
        flb_errno();
        return -1;
    }

    ret = 0;
    mk_list_foreach(head, &ctx->topic_parts) {
        part = mk_list_entry(head, struct flb_out_mqtt_topic_part, _head);

        if (part->type == FLB_MQTT_TOPIC_LITERAL) {
            ret = flb_sds_cat_safe(&mf->topic_buf, part->literal,
                                   flb_sds_len(part->literal));
        }
        else if (part->type == FLB_MQTT_TOPIC_TAG) {
            ret = flb_sds_cat_safe(&mf->topic_buf, tag, tag_len);
        }
        else {
            p = tag;
            end = tag + tag_len;
            index = 0;

            while (p != NULL && index < part->index) {
                dot = memchr(p, '.', end - p);
                p = dot ? dot + 1 : NULL;
                index++;
            }

            if (p != NULL) {
                dot = memchr(p, '.', end - p);
                ret = flb_sds_cat_safe(&mf->topic_buf, p,
                                       dot ? dot - p : end - p);
            }
        }

        if (ret != 0) {
            return -1;
        }
    }

    if (!out_mqtt_prot_topic_valid(mf->topic_buf, flb_sds_len(mf->topic_buf))) {
        flb_plg_warn(ctx->ins, "topic '%s' composed for tag '%.*s' is not a valid "
                     "MQTT topic name", mf->topic_buf, tag_len, tag);
        mf->topic = NULL;
        mf->topic_len = 0;
        return 0;
    }

    mf->topic = mf->topic_buf;
    mf->topic_len = flb_sds_len(mf->topic_buf);

    return 0;
}

static int record_topic(struct mqtt_flush *mf, msgpack_object *body,
                        const char **topic, size_t *topic_len)
{
    int ret;
    msgpack_object *start_key;
    msgpack_object *key;
    msgpack_object *val;
    struct flb_out_mqtt *ctx = mf->ctx;

    if (ctx->ra_topic_key) {
        ret = flb_ra_get_kv_pair(ctx->ra_topic_key, *body, &start_key, &key, &val);
        if (ret == 0) {
            if (val->type == MSGPACK_OBJECT_STR &&
                out_mqtt_prot_topic_valid(val->via.str.ptr, val->via.str.size)) {
                *topic = val->via.str.ptr;
                *topic_len = val->via.str.size;
                return MQTT_RECORD_OK;
            }

            /* Reported only when the default topic is used instead */
            if (mf->topic) {
                mf->topic_key_invalid++;
            }
        }
    }

    if (!mf->topic) {
        return MQTT_RECORD_SKIP;
    }

    *topic = mf->topic;
    *topic_len = mf->topic_len;

    return MQTT_RECORD_OK;
}

/*
 * Pack the record timestamp. Returns 0, MQTT_PACK_NOMEM when the message
 * buffer cannot grow or MQTT_PACK_INVALID when the timestamp cannot be
 * formatted.
 */
static int date_pack(struct mqtt_flush *mf, struct flb_time *tm)
{
    int ret;
    int len;
    size_t size;
    struct tm gmt;
    char buf[64];
    const char *date_fmt;
    const char *frac_fmt;
    msgpack_packer *pck = &mf->mp_pck;

    switch (mf->ctx->json_date_format) {
    case FLB_PACK_JSON_DATE_EPOCH:
        ret = msgpack_pack_uint64(pck, (uint64_t) tm->tm.tv_sec);
        return ret == 0 ? 0 : MQTT_PACK_NOMEM;
    case FLB_PACK_JSON_DATE_EPOCH_MS:
        ret = msgpack_pack_uint64(pck, flb_time_to_millisec(tm));
        return ret == 0 ? 0 : MQTT_PACK_NOMEM;
    case FLB_PACK_JSON_DATE_ISO8601:
        date_fmt = FLB_PACK_JSON_DATE_ISO8601_FMT;
        frac_fmt = ".%06" PRIu64 "Z";
        break;
    case FLB_PACK_JSON_DATE_JAVA_SQL_TIMESTAMP:
        date_fmt = FLB_PACK_JSON_DATE_JAVA_SQL_TIMESTAMP_FMT;
        frac_fmt = ".%06" PRIu64;
        break;
    default:
        ret = msgpack_pack_double(pck, flb_time_to_double(tm));
        return ret == 0 ? 0 : MQTT_PACK_NOMEM;
    }

    /* A timestamp out of the calendar range fails the same way every time */
    if (gmtime_r(&tm->tm.tv_sec, &gmt) == NULL) {
        return MQTT_PACK_INVALID;
    }

    size = strftime(buf, sizeof(buf), date_fmt, &gmt);
    if (size == 0) {
        return MQTT_PACK_INVALID;
    }

    /* Microseconds precision, like the other JSON outputs */
    len = snprintf(buf + size, sizeof(buf) - size, frac_fmt,
                   (uint64_t) tm->tm.tv_nsec / 1000);
    if (len < 0 || (size_t) len >= sizeof(buf) - size) {
        return MQTT_PACK_INVALID;
    }
    size += len;

    ret = msgpack_pack_str(pck, size);
    if (ret == 0) {
        ret = msgpack_pack_str_body(pck, buf, size);
    }

    return ret == 0 ? 0 : MQTT_PACK_NOMEM;
}

/*
 * Compose the message object: the date key, when enabled, and the record
 * body. A body that is not a map is nested under a 'log' key. Returns 0,
 * MQTT_PACK_NOMEM or MQTT_PACK_INVALID.
 */
static int message_pack(struct mqtt_flush *mf, struct flb_log_event *event)
{
    int ret;
    uint32_t i;
    uint32_t size;
    msgpack_object *body;
    msgpack_packer *pck = &mf->mp_pck;
    struct flb_out_mqtt *ctx = mf->ctx;

    body = event->body;

    if (body->type == MSGPACK_OBJECT_MAP) {
        size = body->via.map.size;
    }
    else {
        size = 1;
    }

    if (ctx->date_key) {
        size++;
    }

    /* msgpack-c packing only fails when the buffer cannot grow */
    ret = msgpack_pack_map(pck, size);

    if (ret == 0 && ctx->date_key) {
        ret = msgpack_pack_str(pck, flb_sds_len(ctx->date_key));
        if (ret == 0) {
            ret = msgpack_pack_str_body(pck, ctx->date_key,
                                        flb_sds_len(ctx->date_key));
        }
        if (ret == 0) {
            ret = date_pack(mf, &event->timestamp);
            if (ret != 0) {
                return ret;
            }
        }
    }

    if (ret == 0 && body->type == MSGPACK_OBJECT_MAP) {
        for (i = 0; ret == 0 && i < body->via.map.size; i++) {
            ret = msgpack_pack_object(pck, body->via.map.ptr[i].key);
            if (ret == 0) {
                ret = msgpack_pack_object(pck, body->via.map.ptr[i].val);
            }
        }
    }
    else if (ret == 0) {
        ret = msgpack_pack_str(pck, 3);
        if (ret == 0) {
            ret = msgpack_pack_str_body(pck, "log", 3);
        }
        if (ret == 0) {
            ret = msgpack_pack_object(pck, *body);
        }
    }

    return ret == 0 ? 0 : MQTT_PACK_NOMEM;
}

/*
 * Compose the message payload. With payload_key, a string or binary value is
 * sent as is and other values are encoded with the configured format.
 * Otherwise the record, with its date key, is encoded as JSON or MessagePack.
 * A memory allocation failure fails the flush, so the chunk is retried
 * instead of losing the record. A timestamp that cannot be formatted or a
 * record JSON cannot represent skips the record: a retry would fail the
 * same way.
 */
static int record_payload(struct mqtt_flush *mf, struct flb_log_event *event,
                          const char **payload, size_t *payload_len,
                          flb_sds_t *json)
{
    int ret;
    msgpack_object *start_key;
    msgpack_object *key;
    msgpack_object *val;
    struct flb_out_mqtt *ctx = mf->ctx;

    *json = NULL;
    msgpack_sbuffer_clear(&mf->mp_sbuf);

    if (ctx->ra_payload_key) {
        ret = flb_ra_get_kv_pair(ctx->ra_payload_key, *event->body,
                                 &start_key, &key, &val);
        if (ret != 0) {
            mf->skipped_no_payload++;
            return MQTT_RECORD_SKIP;
        }

        if (val->type == MSGPACK_OBJECT_STR) {
            *payload = val->via.str.ptr;
            *payload_len = val->via.str.size;
            return MQTT_RECORD_OK;
        }
        else if (val->type == MSGPACK_OBJECT_BIN) {
            *payload = val->via.bin.ptr;
            *payload_len = val->via.bin.size;
            return MQTT_RECORD_OK;
        }

        ret = msgpack_pack_object(&mf->mp_pck, *val);
        if (ret != 0) {
            ret = MQTT_PACK_NOMEM;
        }
    }
    else {
        ret = message_pack(mf, event);
    }

    if (ret == MQTT_PACK_INVALID) {
        mf->skipped_encoding++;
        return MQTT_RECORD_SKIP;
    }
    else if (ret != 0) {
        flb_plg_error(ctx->ins, "cannot compose a message, memory allocation failed");
        return MQTT_RECORD_FAIL;
    }

    if (ctx->out_format == FLB_MQTT_FORMAT_MSGPACK) {
        *payload = mf->mp_sbuf.data;
        *payload_len = mf->mp_sbuf.size;
        return MQTT_RECORD_OK;
    }

    /*
     * The conversion fails for good with EINVAL, set just before returning,
     * on a value JSON cannot represent, like a map key that is an array or a
     * map. Any other failure is a memory allocation failure: errno is not
     * always ENOMEM then, the core logs the error and the logging can change
     * errno (isatty() sets ENOTTY when stderr is not a terminal).
     */
    errno = 0;
    *json = flb_msgpack_raw_to_json_sds(mf->mp_sbuf.data, mf->mp_sbuf.size,
                                        mf->config->json_escape_unicode);
    if (!*json) {
        if (errno == EINVAL) {
            mf->skipped_encoding++;
            return MQTT_RECORD_SKIP;
        }
        flb_plg_error(ctx->ins, "cannot convert a message to JSON, memory "
                      "allocation failed");
        return MQTT_RECORD_FAIL;
    }

    *payload = *json;
    *payload_len = flb_sds_len(*json);

    return MQTT_RECORD_OK;
}

/* Append the PUBLISH packet of one record to the window */
static int record_add(struct mqtt_flush *mf, struct flb_log_event *event,
                      size_t record_size)
{
    int ret;
    size_t length;
    size_t topic_len;
    size_t payload_len;
    uint16_t packet_id;
    const char *topic;
    const char *payload;
    flb_sds_t json;
    struct flb_out_mqtt *ctx = mf->ctx;

    if (event->body == NULL) {
        mf->skipped_encoding++;
        return MQTT_RECORD_SKIP;
    }

    ret = record_topic(mf, event->body, &topic, &topic_len);
    if (ret != MQTT_RECORD_OK) {
        mf->skipped_no_topic++;
        return ret;
    }

    ret = record_payload(mf, event, &payload, &payload_len, &json);
    if (ret != MQTT_RECORD_OK) {
        return ret;
    }

    /* Topic length field, topic, packet identifier and payload */
    length = 2 + topic_len + (ctx->qos > 0 ? 2 : 0);
    if (payload_len > FLB_MQTT_MAX_REMAINING_LENGTH - length) {
        mf->skipped_too_large++;
        if (json) {
            flb_sds_destroy(json);
        }
        return MQTT_RECORD_SKIP;
    }

    packet_id = 0;
    if (ctx->qos > 0) {
        packet_id = packet_id_next(mf);
    }

    ret = out_mqtt_prot_publish(&mf->wbuf, topic, topic_len, payload, payload_len,
                                ctx->qos, ctx->retain, packet_id);
    if (json) {
        flb_sds_destroy(json);
    }

    if (ret != 0) {
        flb_plg_error(ctx->ins, "cannot compose PUBLISH packet");
        return MQTT_RECORD_FAIL;
    }

    if (mf->window_count == 0) {
        mf->window_first_id = packet_id;
    }
    mf->window_count++;

    mf->published++;
    mf->published_bytes += record_size;

    return MQTT_RECORD_OK;
}

/* Publish every record of a chunk, returns FLB_OK, FLB_RETRY or FLB_ERROR */
static int flush_records(struct mqtt_flush *mf, const char *tag, int tag_len,
                         const void *data, size_t bytes)
{
    int ret;
    size_t decoded_end;
    struct flb_log_event event;
    struct flb_log_event_decoder decoder;
    struct flb_out_mqtt *ctx = mf->ctx;

    ret = chunk_topic_set(mf, tag, tag_len);
    if (ret != 0) {
        return FLB_RETRY;
    }

    /* The initialization only fails when memory runs out */
    ret = flb_log_event_decoder_init(&decoder, (char *) data, bytes);
    if (ret != FLB_EVENT_DECODER_SUCCESS) {
        flb_plg_error(ctx->ins, "log event decoder initialization error: %i", ret);
        return FLB_RETRY;
    }

    /* End of the last record decoded */
    decoded_end = 0;

    while ((ret = flb_log_event_decoder_next(&decoder, &event)) ==
           FLB_EVENT_DECODER_SUCCESS) {
        decoded_end = decoder.offset;

        ret = record_add(mf, &event, decoder.record_length);
        if (ret == MQTT_RECORD_FAIL) {
            flb_log_event_decoder_destroy(&decoder);
            return FLB_RETRY;
        }
        else if (ret == MQTT_RECORD_SKIP) {
            mf->skipped++;
            mf->skipped_bytes += decoder.record_length;
            continue;
        }

        if ((ctx->qos > 0 && mf->window_count >= ctx->max_inflight) ||
            flb_sds_len(mf->wbuf) >= FLB_MQTT_WRITE_BUFFER_SIZE) {
            ret = window_flush(mf);
            if (ret != FLB_OK) {
                flb_log_event_decoder_destroy(&decoder);
                return ret;
            }
        }
    }

    /* A chunk decoded to its end reports success */
    ret = flb_log_event_decoder_get_last_result(&decoder);
    if (ret != FLB_EVENT_DECODER_SUCCESS) {
        mf->decode_error = FLB_TRUE;
        mf->chunk_bytes = bytes;
        mf->decoded_bytes = decoded_end;
        flb_plg_error(ctx->ins, "invalid chunk data after %zu of %zu bytes (%s), "
                      "the remaining records are dropped", mf->decoded_bytes, bytes,
                      flb_log_event_decoder_get_error_description(ret));
    }

    flb_log_event_decoder_destroy(&decoder);

    ret = window_flush(mf);
    if (ret == FLB_OK && ctx->qos == 0 && mf->conn != NULL) {
        ret = session_confirm(mf);
    }

    return ret;
}

/*
 * Report the records of a successful flush that were not published: records
 * skipped one by one and, after a decoding error, the rest of the chunk.
 */
static void drop_report(struct mqtt_flush *mf, struct flb_event_chunk *event_chunk,
                        struct flb_output_flush *out_flush)
{
    size_t handled;
    size_t dropped;
    size_t dropped_bytes;
    struct flb_out_mqtt *ctx = mf->ctx;

    if (mf->topic_key_invalid > 0) {
        flb_plg_warn(ctx->ins, "%i records have a '%s' value that is not a valid "
                     "MQTT topic name, the default topic was used",
                     mf->topic_key_invalid, ctx->topic_key);
    }

    dropped = mf->skipped;
    dropped_bytes = mf->skipped_bytes;

    if (mf->decode_error) {
        handled = (size_t) mf->published + (size_t) mf->skipped;
        if (event_chunk->total_events > handled) {
            dropped += event_chunk->total_events - handled;
        }
        if (mf->chunk_bytes > mf->decoded_bytes) {
            dropped_bytes += mf->chunk_bytes - mf->decoded_bytes;
        }
    }

    if (mf->skipped > 0) {
        flb_plg_warn(ctx->ins, "%i records were not published: %i without a valid "
                     "topic, %i without the payload key, %i over the MQTT size "
                     "limit, %i could not be encoded",
                     mf->skipped, mf->skipped_no_topic, mf->skipped_no_payload,
                     mf->skipped_too_large, mf->skipped_encoding);
    }

    if (dropped == 0 && !mf->decode_error) {
        return;
    }

#ifdef FLB_HAVE_METRICS
    if (dropped > 0) {
        cmt_counter_add(ctx->ins->cmt_dropped_records, cfl_time_now(), dropped,
                        1, (char *[]) { (char *) flb_output_name(ctx->ins) });

        if (mf->config->router != NULL && event_chunk->type == FLB_EVENT_TYPE_LOGS) {
            cmt_counter_add(mf->config->router->logs_drop_records_total,
                            cfl_time_now(), dropped,
                            2, (char *[]) {
                                (char *) flb_input_name(out_flush->task->i_ins),
                                (char *) flb_output_name(ctx->ins)
                            });
            cmt_counter_add(mf->config->router->logs_drop_bytes_total,
                            cfl_time_now(), dropped_bytes,
                            2, (char *[]) {
                                (char *) flb_input_name(out_flush->task->i_ins),
                                (char *) flb_output_name(ctx->ins)
                            });
        }
    }
#else
    (void) dropped_bytes;
#endif

    /* Only the published records count as processed by this route */
    flb_output_set_successful_route_data(out_flush, mf->published,
                                         mf->published_bytes);
}

static int cb_mqtt_init(struct flb_output_instance *ins,
                        struct flb_config *config, void *data)
{
    struct flb_out_mqtt *ctx;

    (void) data;

    ctx = flb_out_mqtt_conf_create(ins, config);
    if (!ctx) {
        return -1;
    }

    flb_output_set_context(ins, ctx);

    flb_plg_debug(ins, "broker %s:%i, topic '%s', qos %i, retain %s, client "
                  "identifier %s", ins->host.name, ins->host.port, ctx->topic,
                  ctx->qos, ctx->retain ? "on" : "off",
                  ctx->fixed_client_id ? ctx->client_id : "generated");

    return 0;
}

static void cb_mqtt_flush(struct flb_event_chunk *event_chunk,
                          struct flb_output_flush *out_flush,
                          struct flb_input_instance *i_ins,
                          void *out_context,
                          struct flb_config *config)
{
    int ret;
    struct mqtt_flush *mf;
    struct flb_out_mqtt *ctx = out_context;

    (void) i_ins;

    mf = flush_create(ctx, config, FLB_FALSE);
    if (!mf) {
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }

    ret = flush_records(mf, event_chunk->tag, flb_sds_len(event_chunk->tag),
                        event_chunk->data, event_chunk->size);

    session_close(mf, ret);

    if (ret == FLB_OK) {
        drop_report(mf, event_chunk, out_flush);
    }

    flush_destroy(mf);

    FLB_OUTPUT_RETURN(ret);
}

static int cb_mqtt_exit(void *data, struct flb_config *config)
{
    struct flb_out_mqtt *ctx = data;

    (void) config;

    flb_out_mqtt_conf_destroy(ctx);

    return 0;
}

/*
 * Formatter test: return the PUBLISH packets a flush would write for the
 * chunk, no connection is made.
 */
static int cb_mqtt_format_test(struct flb_config *config,
                               struct flb_input_instance *ins,
                               void *plugin_context,
                               void *flush_ctx,
                               int event_type,
                               const char *tag, int tag_len,
                               const void *data, size_t bytes,
                               void **out_data, size_t *out_size)
{
    int ret;
    char *buf;
    struct mqtt_flush *mf;
    struct flb_out_mqtt *ctx = plugin_context;

    (void) ins;
    (void) flush_ctx;
    (void) event_type;

    *out_data = NULL;
    *out_size = 0;

    mf = flush_create(ctx, config, FLB_TRUE);
    if (!mf) {
        return FLB_ERROR;
    }

    ret = flush_records(mf, tag, tag_len, data, bytes);
    if (ret == FLB_OK && flb_sds_len(mf->capture) > 0) {
        buf = flb_malloc(flb_sds_len(mf->capture));
        if (!buf) {
            flb_errno();
            flush_destroy(mf);
            return FLB_ERROR;
        }
        memcpy(buf, mf->capture, flb_sds_len(mf->capture));
        *out_data = buf;
        *out_size = flb_sds_len(mf->capture);
    }

    flush_destroy(mf);

    return ret;
}

/* Configuration properties map */
static struct flb_config_map config_map[] = {
    {
     FLB_CONFIG_MAP_STR, "topic", "fluent-bit",
     0, FLB_TRUE, offsetof(struct flb_out_mqtt, topic),
     "Topic name of the published messages. $TAG and $TAG[n] are replaced "
     "with the record tag, or the n-th part of the tag split on '.'"
    },

    {
     FLB_CONFIG_MAP_STR, "topic_key", NULL,
     0, FLB_TRUE, offsetof(struct flb_out_mqtt, topic_key),
     "Record key (record accessor syntax supported) whose string value is "
     "used as topic name. Records without a valid value use 'topic'"
    },

    {
     FLB_CONFIG_MAP_INT, "qos", "1",
     0, FLB_TRUE, offsetof(struct flb_out_mqtt, qos),
     "Quality of service: 0 or 1. QoS 0 messages are not acknowledged one by "
     "one, a flush ends with a PINGREQ round trip and a failed flush is "
     "retried, so a message can be published more than once (set "
     "'retry_limit' to 'no_retries' for at most once delivery). With QoS 1 "
     "every message is acknowledged by the broker before the chunk succeeds "
     "(at least once)"
    },

    {
     FLB_CONFIG_MAP_BOOL, "retain", "false",
     0, FLB_TRUE, offsetof(struct flb_out_mqtt, retain),
     "Set the retain flag on published messages. As defined by MQTT, a "
     "retained message with an empty payload (an empty 'payload_key' value) "
     "removes the message retained by the broker for that topic. A chunk "
     "published again after a failure can replace the retained message with "
     "an older record"
    },

    {
     FLB_CONFIG_MAP_STR, "client_id", NULL,
     0, FLB_TRUE, offsetof(struct flb_out_mqtt, client_id),
     "Client identifier. When not set every connection uses a unique "
     "generated identifier. A fixed identifier, often required by broker "
     "access policies, needs 'workers' set to 1 or 0"
    },

    {
     FLB_CONFIG_MAP_STR, "username", NULL,
     0, FLB_TRUE, offsetof(struct flb_out_mqtt, username),
     "User name for broker authentication"
    },

    {
     FLB_CONFIG_MAP_STR, "password", NULL,
     0, FLB_TRUE, offsetof(struct flb_out_mqtt, password),
     "Password for broker authentication, it requires 'username'"
    },

    {
     FLB_CONFIG_MAP_TIME, "keep_alive", "60s",
     0, FLB_TRUE, offsetof(struct flb_out_mqtt, keep_alive),
     "MQTT keep alive interval sent to the broker, 0 disables it. PINGREQ "
     "packets keep a session alive while broker replies are slow, idle "
     "keepalive connections are closed before the broker drops them (after "
     "one and a half times this interval of silence)"
    },

    {
     FLB_CONFIG_MAP_STR, "format", "json",
     0, FLB_FALSE, 0,
     "Message payload format: json or msgpack"
    },

    {
     FLB_CONFIG_MAP_STR, "payload_key", NULL,
     0, FLB_TRUE, offsetof(struct flb_out_mqtt, payload_key),
     "Publish only the value of this record key (record accessor syntax "
     "supported). String and binary values are sent as is, other values are "
     "encoded with 'format'. Records without the key are dropped"
    },

    {
     FLB_CONFIG_MAP_STR, "json_date_key", "date",
     0, FLB_TRUE, offsetof(struct flb_out_mqtt, json_date_key),
     "Name of the key holding the record timestamp, set it to false to omit "
     "the timestamp"
    },

    {
     FLB_CONFIG_MAP_STR, "json_date_format", "double",
     0, FLB_FALSE, 0,
     FBL_PACK_JSON_DATE_FORMAT_DESCRIPTION
    },

    {
     FLB_CONFIG_MAP_INT, "max_inflight", "64",
     0, FLB_TRUE, offsetof(struct flb_out_mqtt, max_inflight),
     "QoS 1: maximum number of messages sent before waiting for their "
     "acknowledgements"
    },

    /* EOF */
    {0}
};

/* Plugin reference */
struct flb_output_plugin out_mqtt_plugin = {
    .name           = "mqtt",
    .description    = "Publish records to an MQTT broker (MQTT 3.1.1)",
    .cb_init        = cb_mqtt_init,
    .cb_flush       = cb_mqtt_flush,
    .cb_exit        = cb_mqtt_exit,
    .config_map     = config_map,

    /* for testing */
    .test_formatter.callback = cb_mqtt_format_test,

    .workers        = 1,
    .event_type     = FLB_OUTPUT_LOGS,

    /*
     * Chunks are published one at a time, like a regular MQTT client with a
     * single session: messages keep their order across chunks (retries
     * aside) and a fixed client_id never has two sessions at once. Pending
     * chunks wait in the engine queue, not in the plugin.
     */
    .flags          = FLB_OUTPUT_NET | FLB_IO_OPT_TLS | FLB_OUTPUT_SYNCHRONOUS,
};
