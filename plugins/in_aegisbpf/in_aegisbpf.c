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

/* AegisBPF input plugin
 * ---------------------
 * Streams runtime-security events from a co-located AegisBPF agent into the
 * Fluent Bit pipeline. AegisBPF (https://github.com/ErenAri/Aegis-BPF) is a
 * BPF-LSM enforcement agent that exposes an opt-in, root-only Unix control
 * socket; a "GET /events" request turns the connection into a newline-delimited
 * stream of JSON (OCSF) security events. This plugin connects out to that
 * socket, forwards each event as a record, and reconnects if the agent restarts.
 *
 * The agent drops slow readers (its broadcast uses non-blocking sends), so the
 * plugin drains the socket in an event-driven collector rather than polling.
 */

#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_config_map.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_log_event_encoder.h>

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "in_aegisbpf.h"

static void aegisbpf_disconnect(struct flb_in_aegisbpf *ctx)
{
    if (ctx->coll_fd_read >= 0) {
        flb_input_collector_delete(ctx->coll_fd_read, ctx->ins);
        ctx->coll_fd_read = -1;
    }
    if (ctx->fd >= 0) {
        close(ctx->fd);
        ctx->fd = -1;
    }
    ctx->connected = 0;
    ctx->handshake_done = 0;
    ctx->skipping_line = 0;
    ctx->buf_len = 0;
}

static int write_all(int fd, const char *buf, size_t len)
{
    size_t off = 0;
    ssize_t w;

    while (off < len) {
        w = write(fd, buf + off, len - off);
        if (w < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        off += (size_t) w;
    }
    return 0;
}

/* Encode every complete newline-terminated JSON line held in ctx->buf into the
 * event encoder, then compact the leftover partial line to the front. */
static void aegisbpf_process_lines(struct flb_in_aegisbpf *ctx)
{
    size_t start = 0;
    size_t i;
    char *nl;
    char *line;
    size_t line_len;
    char *mp;
    size_t mp_size;
    int root_type;
    size_t consumed;
    int ret;
    int r;
    struct flb_time tm;

    /* If a previous read dropped an oversized line, discard bytes up to and
     * including the next newline so the tail of that line is never parsed as a
     * (truncated) event. */
    if (ctx->skipping_line) {
        nl = memchr(ctx->buf, '\n', ctx->buf_len);
        if (nl == NULL) {
            ctx->buf_len = 0;
            return;
        }
        ctx->skipping_line = 0;
        start = (size_t) (nl - ctx->buf) + 1;
    }

    for (i = start; i < ctx->buf_len; i++) {
        if (ctx->buf[i] != '\n') {
            continue;
        }

        line = ctx->buf + start;
        line_len = i - start;

        /* strip a trailing CR if present */
        if (line_len > 0 && line[line_len - 1] == '\r') {
            line_len--;
        }

        start = i + 1;

        /* The agent's first line is the streaming ack, not an event. */
        if (!ctx->handshake_done) {
            ctx->handshake_done = 1;
            continue;
        }
        if (line_len == 0) {
            continue;
        }

        mp = NULL;
        mp_size = 0;
        root_type = 0;
        consumed = 0;
        ret = flb_pack_json(line, line_len, &mp, &mp_size, &root_type, &consumed);
        /* Accept only a single, whole JSON object per line: reject parse errors,
         * arrays/scalars, and any trailing bytes after the object (which
         * flb_pack_json would otherwise pack as extra roots). */
        if (ret != 0 || mp == NULL ||
            root_type != FLB_PACK_JSON_OBJECT || consumed != line_len) {
            flb_plg_debug(ctx->ins,
                          "skipping line: not a single JSON object (%zu bytes)",
                          line_len);
            if (mp != NULL) {
                flb_free(mp);
            }
            continue;
        }

        if (flb_log_event_encoder_begin_record(ctx->encoder) ==
                FLB_EVENT_ENCODER_SUCCESS) {
            flb_time_get(&tm);
            flb_log_event_encoder_set_timestamp(ctx->encoder, &tm);
            r = flb_log_event_encoder_set_body_from_raw_msgpack(ctx->encoder,
                                                                mp, mp_size);
            if (r == FLB_EVENT_ENCODER_SUCCESS) {
                flb_log_event_encoder_commit_record(ctx->encoder);
            }
            else {
                flb_log_event_encoder_rollback_record(ctx->encoder);
            }
        }
        flb_free(mp);
    }

    if (start > 0) {
        if (start < ctx->buf_len) {
            memmove(ctx->buf, ctx->buf + start, ctx->buf_len - start);
        }
        ctx->buf_len -= start;
    }
}

/* Socket collector: drain all currently-available bytes, then flush records. */
static int in_aegisbpf_read(struct flb_input_instance *ins,
                            struct flb_config *config, void *data)
{
    struct flb_in_aegisbpf *ctx = data;
    int disconnected = 0;
    size_t drained = 0;
    ssize_t n;
    size_t new_size;
    char *tmp;

    (void) config;

    flb_log_event_encoder_reset(ctx->encoder);

    while (1) {
        if (ctx->buf_len == ctx->buf_size) {
            if (ctx->buf_size >= FLB_IN_AEGISBPF_BUF_MAX) {
                /* A single line exceeded the cap; drop the buffered head and mark
                 * the line for skipping so its remaining tail (still in the
                 * socket) is discarded up to the next newline rather than parsed
                 * as a truncated event. */
                flb_plg_warn(ins, "line exceeded %d bytes, dropping",
                             FLB_IN_AEGISBPF_BUF_MAX);
                ctx->buf_len = 0;
                ctx->skipping_line = 1;
            }
            else {
                new_size = ctx->buf_size * 2;
                if (new_size > FLB_IN_AEGISBPF_BUF_MAX) {
                    new_size = FLB_IN_AEGISBPF_BUF_MAX;
                }
                tmp = flb_realloc(ctx->buf, new_size);
                if (tmp == NULL) {
                    flb_errno();
                    break;
                }
                ctx->buf = tmp;
                ctx->buf_size = new_size;
            }
        }

        n = recv(ctx->fd, ctx->buf + ctx->buf_len,
                 ctx->buf_size - ctx->buf_len, 0);
        if (n > 0) {
            ctx->buf_len += (size_t) n;
            aegisbpf_process_lines(ctx);
            /* Bound work per wake so a continuously-writing agent can't hold the
             * engine thread or grow the append arbitrarily large. The socket
             * collector re-arms and continues on the next wake. */
            drained += (size_t) n;
            if (drained >= FLB_IN_AEGISBPF_DRAIN_MAX) {
                break;
            }
            continue;
        }
        else if (n == 0) {
            flb_plg_info(ins, "agent closed the connection");
            disconnected = 1;
            break;
        }
        else {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                break; /* drained */
            }
            if (errno == EINTR) {
                continue;
            }
            flb_plg_warn(ins, "read error: %s", strerror(errno));
            disconnected = 1;
            break;
        }
    }

    if (ctx->encoder->output_length > 0) {
        flb_input_log_append(ins, NULL, 0,
                             ctx->encoder->output_buffer,
                             ctx->encoder->output_length);
    }

    if (disconnected) {
        aegisbpf_disconnect(ctx);
    }

    return 0;
}

static int aegisbpf_connect(struct flb_in_aegisbpf *ctx,
                            struct flb_config *config)
{
    struct sockaddr_un addr;
    int fd;
    int flags;
    static const char req[] = "GET /events\n";

    if (flb_sds_len(ctx->socket_path) >= sizeof(addr.sun_path)) {
        flb_plg_error(ctx->ins, "socket_path too long: %s", ctx->socket_path);
        return -1;
    }

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        flb_errno();
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, ctx->socket_path, sizeof(addr.sun_path) - 1);

    if (connect(fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
        flb_plg_debug(ctx->ins, "connect(%s) failed: %s",
                      ctx->socket_path, strerror(errno));
        close(fd);
        return -1;
    }

    /* Request the event stream (blocking write; the request is tiny). */
    if (write_all(fd, req, sizeof(req) - 1) < 0) {
        flb_plg_warn(ctx->ins, "failed to send stream request: %s",
                     strerror(errno));
        close(fd);
        return -1;
    }

    /* Non-blocking reads so the collector never stalls the engine. */
    flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        flb_errno();
        close(fd);
        return -1;
    }

    ctx->fd = fd;
    ctx->connected = 1;
    ctx->handshake_done = 0;
    ctx->buf_len = 0;

    ctx->coll_fd_read = flb_input_set_collector_socket(ctx->ins,
                                                       in_aegisbpf_read,
                                                       fd, config);
    if (ctx->coll_fd_read < 0) {
        flb_plg_error(ctx->ins, "could not register read collector");
        aegisbpf_disconnect(ctx);
        return -1;
    }
    if (flb_input_collector_start(ctx->coll_fd_read, ctx->ins) < 0) {
        flb_plg_error(ctx->ins, "could not start read collector");
        aegisbpf_disconnect(ctx);
        return -1;
    }

    flb_plg_info(ctx->ins, "connected to AegisBPF at %s", ctx->socket_path);
    return 0;
}

/* Time collector: (re)establish the connection while disconnected. */
static int in_aegisbpf_reconnect(struct flb_input_instance *ins,
                                 struct flb_config *config, void *data)
{
    struct flb_in_aegisbpf *ctx = data;

    (void) ins;

    if (ctx->connected) {
        return 0;
    }
    aegisbpf_connect(ctx, config);
    return 0;
}

static int in_aegisbpf_init(struct flb_input_instance *in,
                            struct flb_config *config, void *data)
{
    struct flb_in_aegisbpf *ctx;
    int ret;

    (void) data;

    ctx = flb_calloc(1, sizeof(struct flb_in_aegisbpf));
    if (ctx == NULL) {
        flb_errno();
        return -1;
    }
    ctx->ins = in;
    ctx->fd = -1;
    ctx->coll_fd_read = -1;
    ctx->coll_fd_reconnect = -1;

    flb_input_set_context(in, ctx);

    if (flb_input_config_map_set(in, (void *) ctx) < 0) {
        flb_plg_error(in, "unable to load configuration");
        flb_free(ctx);
        return -1;
    }

    if (ctx->reconnect_sec <= 0) {
        ctx->reconnect_sec = FLB_IN_AEGISBPF_DEFAULT_RECONN;
    }

    ctx->buf_size = FLB_IN_AEGISBPF_BUF_INIT;
    ctx->buf = flb_malloc(ctx->buf_size);
    if (ctx->buf == NULL) {
        flb_errno();
        flb_free(ctx);
        return -1;
    }

    ctx->encoder = flb_log_event_encoder_create(FLB_LOG_EVENT_FORMAT_DEFAULT);
    if (ctx->encoder == NULL) {
        flb_plg_error(in, "could not initialize event encoder");
        flb_free(ctx->buf);
        flb_free(ctx);
        return -1;
    }

    /* Drive (re)connection from a timer; the read collector is registered once
     * a connection is established. */
    ret = flb_input_set_collector_time(in, in_aegisbpf_reconnect,
                                       ctx->reconnect_sec, 0, config);
    if (ret < 0) {
        flb_plg_error(in, "could not register reconnect collector");
        flb_log_event_encoder_destroy(ctx->encoder);
        flb_free(ctx->buf);
        flb_free(ctx);
        return -1;
    }
    ctx->coll_fd_reconnect = ret;

    return 0;
}

static int in_aegisbpf_exit(void *data, struct flb_config *config)
{
    struct flb_in_aegisbpf *ctx = data;

    (void) config;

    if (ctx == NULL) {
        return 0;
    }
    aegisbpf_disconnect(ctx);
    if (ctx->encoder != NULL) {
        flb_log_event_encoder_destroy(ctx->encoder);
    }
    if (ctx->buf != NULL) {
        flb_free(ctx->buf);
    }
    flb_free(ctx);
    return 0;
}

static void in_aegisbpf_pause(void *data, struct flb_config *config)
{
    struct flb_in_aegisbpf *ctx = data;

    (void) config;

    if (ctx->coll_fd_reconnect >= 0) {
        flb_input_collector_pause(ctx->coll_fd_reconnect, ctx->ins);
    }
    if (ctx->coll_fd_read >= 0) {
        flb_input_collector_pause(ctx->coll_fd_read, ctx->ins);
    }
}

static void in_aegisbpf_resume(void *data, struct flb_config *config)
{
    struct flb_in_aegisbpf *ctx = data;

    (void) config;

    if (ctx->coll_fd_reconnect >= 0) {
        flb_input_collector_resume(ctx->coll_fd_reconnect, ctx->ins);
    }
    if (ctx->coll_fd_read >= 0) {
        flb_input_collector_resume(ctx->coll_fd_read, ctx->ins);
    }
}

static struct flb_config_map config_map[] = {
    {
        FLB_CONFIG_MAP_STR, "socket_path", FLB_IN_AEGISBPF_DEFAULT_SOCKET,
        0, FLB_TRUE, offsetof(struct flb_in_aegisbpf, socket_path),
        "Path to the AegisBPF control socket (root-only Unix stream socket)."
    },
    {
        FLB_CONFIG_MAP_INT, "reconnect_sec", "2",
        0, FLB_TRUE, offsetof(struct flb_in_aegisbpf, reconnect_sec),
        "Interval in seconds between reconnection attempts."
    },
    /* EOF */
    {0}
};

struct flb_input_plugin in_aegisbpf_plugin = {
    .name         = "aegisbpf",
    .description  = "AegisBPF runtime-security events",
    .cb_init      = in_aegisbpf_init,
    .cb_pre_run   = NULL,
    .cb_collect   = in_aegisbpf_reconnect,
    .cb_flush_buf = NULL,
    .config_map   = config_map,
    .cb_pause     = in_aegisbpf_pause,
    .cb_resume    = in_aegisbpf_resume,
    .cb_exit      = in_aegisbpf_exit
};
