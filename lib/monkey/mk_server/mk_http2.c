/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Monkey HTTP Server
 *  ==================
 *  Copyright 2001-2017 Eduardo Silva <eduardo@monkey.io>
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

#define _GNU_SOURCE

#include <inttypes.h>

#include <monkey/mk_http2.h>
#include <monkey/mk_http2_settings.h>
#include <monkey/mk_header.h>
#include <monkey/mk_scheduler.h>

/* HTTP/2 Connection Preface */
#define MK_HTTP2_PREFACE "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
static mk_ptr_t http2_preface = {
    .data = MK_HTTP2_PREFACE,
    .len  = sizeof(MK_HTTP2_PREFACE) - 1
};

static inline void buffer_consume(struct mk_http2_session *h2s, int bytes)
{
    memmove(h2s->buffer,
            h2s->buffer + bytes,
            h2s->buffer_length - bytes);

    MK_TRACE("[h2] consume buffer length from %i to %i",
             h2s->buffer_length, h2s->buffer_length - bytes);
    h2s->buffer_length -= bytes;
}

static struct mk_http2_session *mk_http2_session_create()
{
    struct mk_http2_session *h2s;

    h2s = mk_mem_alloc(sizeof(struct mk_http2_session));
    if (!h2s) {
        return NULL;
    }
    h2s->buffer = NULL;
    h2s->buffer_length = 0;
    h2s->buffer_size = sizeof(h2s->buffer_fixed);
    h2s->buffer = h2s->buffer_fixed;
    h2s->settings = MK_HTTP2_SETTINGS_DEFAULT;

    return h2s;
}

/* FIXME
static int mk_http2_session_destroy(struct mk_http2_session *h2s)
{
    if (h2s->buffer != h2s->buffer_fixed) {
        mk_mem_free(h2s->buffer);
    }
    mk_mem_free(h2s);
    return 0;
}

static int mk_http2_frame_header(char *buf, uint32_t length, uint8_t type,
                                 uint32_t flags, void *data)
{
    struct mk_http2_frame *f = (struct mk_http2_frame *) buf;

    f->len_type = (length << 8 | type);
    f->flags    = flags;
    f->payload  = data;

    return sizeof(struct mk_http2_frame);
}

*/

/* Handle an upgraded session */
static int mk_http2_upgrade(void *cs, void *sr, struct mk_server *server)
{
    struct mk_http_session *s = cs;
    struct mk_http_request *r = sr;
    struct mk_http2_session *h2s;

    mk_header_set_http_status(r, MK_INFO_SWITCH_PROTOCOL);
    r->headers.connection = MK_HEADER_CONN_UPGRADED;
    r->headers.upgrade = MK_HEADER_UPGRADED_H2C;
    mk_header_prepare(s, r, server);

    h2s = mk_http2_session_create();
    if (!h2s) {
        return -1;
    }

    h2s->status = MK_HTTP2_UPGRADED;
    s->conn->data = h2s;

    return MK_HTTP_OK;
}

/* FIXME Decode a frame header, no more... no less
static inline void mk_http2_frame_decode_header(uint8_t *buf,
                                                struct mk_http2_frame *frame)
{
    struct mk_http2_session *h2s;
    (void) h2s;

    frame->len_type  = mk_http2_bitdec_32u(buf);
    frame->flags     = buf[4];
    frame->stream_id = mk_http2_bitdec_stream_id(buf + 5);
    frame->payload   = buf + 9;

#ifdef MK_HAVE_TRACE
    MK_TRACE("Frame Header");
    printf(" length=%i, type=%i, stream_id=%i\n",
           mk_http2_frame_len(frame),
           mk_http2_frame_type(frame),
           frame->stream_id);
#endif
}
*/

static inline int mk_http2_handle_settings(struct mk_sched_conn *conn,
                                           struct mk_http2_frame *frame)
{
    int i;
    int frame_len;
    int settings;
    int setting_size = 6; /* 16 bits identifier + 32 bits value = 6 bytes */
    uint16_t setting_id;
    uint32_t setting_value;
    uint8_t *p;
    struct mk_http2_session *h2s;

    h2s = conn->data;
    frame_len = mk_http2_frame_len(frame);
    if (frame->flags == MK_HTTP2_SETTINGS_ACK) {
        /*
         * Nothing to do, the peer just received our SETTINGS and it's
         * sending an acknowledge.
         *
         * note: validate that frame length is zero.
         */
        if (frame_len > 0) {
            /*
             * This must he handled as a connection error, we must reply
             * with a FRAME_SIZE_ERROR. ref:
             *
             *  https://httpwg.github.io/specs/rfc7540.html#SETTINGS
             */

            /* FIXME: send a GOAWAY error frame */
            MK_TRACE("FRAME SIZE ERR: %i\n", frame_len);
            return -1;

        }
        return 0;
    }

    /*
     * Iterate our SETTINGS payload, it may contain many entries in the
     * following format:
     *
     * +-------------------------------+
     * |       Identifier (16)         |
     * +-------------------------------+-------------------------------+
     * |                        Value (32)                             |
     * +---------------------------------------------------------------+
     *
     * 48 bits = 6 bytes
     */
    settings = (frame_len / setting_size);
    for (i = 0; i < settings; i++ ) {
        /* Seek payload per SETTINGS entry */
        p = frame->payload + (setting_size * i);

        setting_id = p[0] << 8 | p[1];
        setting_value = p[2] << 24 | p[3] << 16 | p[4] << 8  | p[5];
        MK_H2_TRACE(conn, "[Setting] ID=%" PRIu16 " VAL=%" PRIu32,
                    setting_id, setting_value);

        switch (setting_id) {
        case MK_HTTP2_SETTINGS_HEADER_TABLE_SIZE:
            /* unhandled */
            break;
        case MK_HTTP2_SETTINGS_ENABLE_PUSH:
            if (setting_value != 0 && setting_value != 1) {
                /* FIXME: PROTOCOL_ERROR */
                MK_H2_TRACE(conn, "Invalid SETTINGS_ENABLE_PUSH");
                return -1;
            }
            h2s->settings.enable_push = setting_value;
            break;
        case MK_HTTP2_SETTINGS_MAX_CONCURRENT_STREAMS:
            if (setting_value < 64) {
                h2s->settings.max_concurrent_streams = setting_value;
            }
            else {
                h2s->settings.max_concurrent_streams = 64;
            }
            MK_H2_TRACE(conn, "SETTINGS MAX_CONCURRENT_STREAMS=%i",
                        setting_value);
            break;
        case MK_HTTP2_SETTINGS_INITIAL_WINDOW_SIZE:
            if (setting_value < 65535 || setting_value > 2147483647) {
                /* FIXME: send FLOW_CONTROL_ERROR */
                MK_H2_TRACE(conn, "Invalid INITIAL_WINDOW_SIZE");
                return -1;
            }
            h2s->settings.initial_window_size = setting_value;
            break;
        case MK_HTTP2_SETTINGS_MAX_FRAME_SIZE:
            if (setting_value < 16384 || setting_value > 2147483647) {
                /* FIXME: send PROTOCOL_ERROR */
                return -1;
            }
            h2s->settings.max_frame_size = setting_value;
            break;
        case MK_HTTP2_SETTINGS_MAX_HEADER_LIST_SIZE:
            /* Unhandled */
            break;
        default:
            /*
             * 5.5 Extending HTTP/2: ...Implementations MUST ignore unknown
             * or unsupported values in all extensible protocol elements...
             */
            break;
        }
    }

    /* FIXME // No errors, send the ACK
    mk_http2_send_raw(conn, MK_HTTP2_SETTINGS_ACK_FRAME,
                      sizeof(MK_HTTP2_SETTINGS_ACK_FRAME) - 1);
    */
    return 0;
}


static inline int mk_http2_frame_run(struct mk_sched_conn *conn,
                                     struct mk_sched_worker *worker)
{
    int ret;
    struct mk_http2_frame frame;
    struct mk_http2_session *h2s;
    (void) worker;

    h2s = conn->data;

    /* Decode the frame header */
    //FIXME mk_http2_frame_decode_header(h2s->buffer, &frame);

    /* Do some validations */
    if (h2s->buffer_length < (MK_HTTP2_HEADER_SIZE + (frame.len_type >> 8))) {
        /* FIXME: need more data */
        return 0;
    }

    /* Do some work based on the frame type */
    if (mk_http2_frame_type(&frame) == MK_HTTP2_SETTINGS) {
        ret = mk_http2_handle_settings(conn, &frame);
        /* FIXME: send our MK_HTTP2_SETTINGS_ACK_FRAME */
        return ret;
    }

    return 0;
}

static int mk_http2_sched_read(struct mk_sched_conn *conn,
                               struct mk_sched_worker *worker,
                               struct mk_server *server)
{
    int bytes;
    int new_size;
    int available;
    char *tmp;
    struct mk_http2_session *h2s;
    (void) worker;
    (void) server;

    h2s = conn->data;
    available = h2s->buffer_size - h2s->buffer_length;
    if (available == 0) {
        new_size = h2s->buffer_size + MK_HTTP2_CHUNK;
        if (h2s->buffer == h2s->buffer_fixed) {
            h2s->buffer = mk_mem_alloc(new_size);
            if (!h2s->buffer) {
                /* FIXME: send internal server error ? */
                return -1;
            }
            memcpy(h2s->buffer, h2s->buffer_fixed, h2s->buffer_length);
            MK_TRACE("[FD %i] Buffer new size: %i, length: %i",
                     conn->event.fd, new_size, h2s->buffer_length);
        }
        else {
            MK_TRACE("[FD %i] Buffer realloc from %i to %i",
                     conn->event.fd, h2s->buffer_size, new_size);
            tmp = mk_mem_realloc(h2s->buffer, new_size);
            if (tmp) {
                h2s->buffer = tmp;
                h2s->buffer_size = new_size;
            }
            else {
                /* FIXME: send internal server error ? */
                return -1;
            }

        }
    }

    /* Read the incoming data */
    bytes = mk_sched_conn_read(conn,
                               h2s->buffer,
                               h2s->buffer_size - h2s->buffer_length);
    if (bytes == 0) {
        errno = 0;
        return -1;
    }
    else if (bytes == -1) {
        return -1;
    }

    h2s->buffer_length += bytes;

    /* Upgraded connections from HTTP/1.x requires the preface */
    if (h2s->status == MK_HTTP2_UPGRADED) {
        if (h2s->buffer_length >= http2_preface.len) {
            if (memcmp(h2s->buffer,
                       http2_preface.data, http2_preface.len) != 0) {
                MK_H2_TRACE(conn, "Invalid HTTP/2 preface");
                return 0;
            }

            MK_H2_TRACE(conn, "HTTP/2 preface OK");

            buffer_consume(h2s, http2_preface.len);
            h2s->status = MK_HTTP2_OK;

            /* Send out our default settings
            mk_stream_set(&h2s->stream_settings,
                          MK_STREAM_RAW,
                          &conn->channel,
                          MK_HTTP2_SETTINGS_DEFAULT_FRAME,
                          sizeof(MK_HTTP2_SETTINGS_DEFAULT_FRAME) - 1,
                          NULL,
                          NULL, NULL, NULL);
            */
        }
        else {
            /* We need more data */
            return 0;
        }
    }

    /* Check that we have a minimum header size */
    if (h2s->buffer_length < MK_HTTP2_HEADER_SIZE) {
        MK_TRACE("HEADER FRAME incomplete %i/%i bytes",
                 h2s->buffer_length, MK_HTTP2_HEADER_SIZE);
        return 0;
    }

    /* We have at least one frame */
    return mk_http2_frame_run(conn, worker);
}


struct mk_sched_handler mk_http2_handler = {
    .name             = "http2",
    .cb_read          = mk_http2_sched_read,
    .cb_close         = NULL,
    .cb_done          = NULL,
    .cb_upgrade       = mk_http2_upgrade,
    .sched_extra_size = sizeof(struct mk_http2_session),
    .capabilities     = MK_CAP_HTTP2
};
