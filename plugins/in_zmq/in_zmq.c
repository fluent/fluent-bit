/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  ZMQ input plugin for Fluent Bit
 *  ===============================
 *  Copyright (C) 2019      The Fluent Bit Authors
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
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_engine.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_error.h>
#include <msgpack.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <errno.h>
#include <inttypes.h>
#include <czmq.h>

#include "in_zmq.h"

#ifdef __GNUC__
#define likely(x)       __builtin_expect(!!(x), 1)
#define unlikely(x)     __builtin_expect(!!(x), 0)
#else
#define likely(x)       (x)
#define unlikely(x)     (x)
#endif

static int zmq_config_read(struct flb_in_zmq_ctx *ctx,
                           struct flb_input_instance *i_ins)
{
    const char *hwm_str;

    /* Get input properties */
    ctx->zmq_endpoint = flb_input_get_property("endpoint", i_ins);

    if (ctx->zmq_endpoint == NULL) {
        flb_error("[in_zmq] error reading 'endpoint' from configuration");
        return -1;
    }

    hwm_str = flb_input_get_property("hwm", i_ins);
    if (hwm_str == NULL)
        ctx->zmq_hwm = 0;    /* default of unlimited */
    else {
        ctx->zmq_hwm = atoi(hwm_str);
        if (ctx->zmq_hwm < 0) {
            flb_error("[in_zmq] invalid config value for 'hwm' (%s)", hwm_str);
            return -1;
        }
    }

    ctx->zmq_pull_socket = NULL;
    ctx->ul_fd = -1;

    flb_debug("[in_zmq] endpoint='%s', hwm=%d", ctx->zmq_endpoint,
              ctx->zmq_hwm);

    return 0;
}

/* Callback triggered when some zmq msgs are available */
static int in_zmq_collect(struct flb_input_instance *in,
                          struct flb_config *config, void *in_context)
{
    int ret;
    struct flb_in_zmq_ctx *ctx = in_context;
    msgpack_packer mp_pck;
    msgpack_sbuffer mp_sbuf;
    int zevents = zsock_events(ctx->zmq_pull_socket);
    zmsg_t *zmsg;
    size_t num_frames;
    zframe_t *frame;

    if ((zevents & ZMQ_POLLIN) == 0)    /* nothing to read */
        return 0;

    /* Note that all messages need read, as ZMQ events are edge-triggered */
    while (zevents & ZMQ_POLLIN) {
        zmsg = zmsg_recv(ctx->zmq_pull_socket);
        if (zmsg == NULL)
            continue;

        /* There should be 3 frames - topic, key, and payload */
        num_frames = zmsg_size(zmsg);
        if (num_frames != 3) {
            flb_warn("[in_zmq] dropping message with wrong number of frames "
                     "(%d)", num_frames);
            zmsg_destroy(&zmsg);
            continue;
        }

        /* Initialize local msgpack buffer */
        msgpack_sbuffer_init(&mp_sbuf);
        msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

        /*
         * Msgpack format is an array of two items: the first item is the
         * time, and the second is a MAP of keys with their values.
         */
        msgpack_pack_array(&mp_pck, 2);
        flb_pack_time_now(&mp_pck);

        /* We then store the 3 parts - "topic", "key", and "payload". */
        msgpack_pack_map(&mp_pck, 3);

        frame = zmsg_pop(zmsg);
        if (unlikely(frame == NULL)) {
            flb_warn("[in_zmq] dropping message with missing frame 1 "
                     "(%d)", num_frames);
            msgpack_sbuffer_destroy(&mp_sbuf);
            zmsg_destroy(&zmsg);
            continue;
        }
        msgpack_pack_str(&mp_pck, 5);
        msgpack_pack_str_body(&mp_pck, "topic", 5);
        msgpack_pack_str(&mp_pck, zframe_size(frame));
        msgpack_pack_str_body(&mp_pck, zframe_data(frame), zframe_size(frame));
        zframe_destroy(&frame);

        frame = zmsg_pop(zmsg);
        if (unlikely(frame == NULL)) {
            flb_warn("[in_zmq] dropping message with missing frame 2 "
                     "(%d)", num_frames);
            msgpack_sbuffer_destroy(&mp_sbuf);
            zmsg_destroy(&zmsg);
            continue;
        }
        msgpack_pack_str(&mp_pck, 3);
        msgpack_pack_str_body(&mp_pck, "key", 3);
        msgpack_pack_str(&mp_pck, zframe_size(frame));
        msgpack_pack_str_body(&mp_pck, zframe_data(frame), zframe_size(frame));
        zframe_destroy(&frame);

        frame = zmsg_pop(zmsg);
        if (unlikely(frame == NULL)) {
            flb_warn("[in_zmq] dropping message with missing frame 3 "
                     "(%d)", num_frames);
            msgpack_sbuffer_destroy(&mp_sbuf);
            zmsg_destroy(&zmsg);
            continue;
        }
        msgpack_pack_str(&mp_pck, 7);
        msgpack_pack_str_body(&mp_pck, "payload", 7);
        msgpack_pack_bin(&mp_pck, zframe_size(frame));
        msgpack_pack_bin_body(&mp_pck, zframe_data(frame), zframe_size(frame));
        zframe_destroy(&frame);

        ret = flb_input_chunk_append_raw(in, NULL, 0, mp_sbuf.data,
                                         mp_sbuf.size);
        if (unlikely(ret < 0))
            flb_warn("[in_zmq] flb_input_chunk_append_raw failed of size %u",
                     mp_sbuf.size);
        msgpack_sbuffer_destroy(&mp_sbuf);

        zevents = zsock_events(ctx->zmq_pull_socket);
    }

    return 0;
}

static void in_zmq_pause(void *data, struct flb_config *config)
{
    struct flb_in_zmq_ctx *ctx = data;
    flb_debug("[in_zmq] pausing endpoint %s on fd %d", ctx->zmq_endpoint,
              ctx->ul_fd);
    flb_input_collector_pause(ctx->ul_fd, ctx->i_ins);
}

static void in_zmq_resume(void *data, struct flb_config *config)
{
    struct flb_in_zmq_ctx *ctx = data;
    flb_debug("[in_zmq] resuming endpoint %s on fd %d", ctx->zmq_endpoint,
              ctx->ul_fd);
    flb_input_collector_resume(ctx->ul_fd, ctx->i_ins);
}

/* Cleanup zmq input */
int in_zmq_exit(void *in_context, struct flb_config *config)
{
    struct flb_in_zmq_ctx *ctx = in_context;

    flb_debug("[in_zmq] exiting '%s'", ctx->zmq_endpoint);

    if (ctx->zmq_pull_socket)
        zsock_destroy(&(ctx->zmq_pull_socket));

    flb_free(ctx);

    return 0;
}

/* Init zmq input */
int in_zmq_init(struct flb_input_instance *in,
                struct flb_config *config, void *data)
{
    int ret;
    struct flb_in_zmq_ctx *ctx = NULL;
    (void) data;

    /*
     * Disable czmq from overriding fluent-bits SIGINT/SIGTERM signal
     * handling, as prevents application from existing.
     */
    setenv("ZSYS_SIGHANDLER", "false", 1);

    ctx = flb_calloc(1, sizeof(struct flb_in_zmq_ctx));
    if (!ctx) {
        flb_error("[in_zmq] flb_calloc failed: %s", strerror(errno));
        goto error;
    }

    if (zmq_config_read(ctx, in) < 0) {
        flb_error("[in_zmq] zmq_config_read failed");
        goto error;
    }

    ctx->zmq_pull_socket = zsock_new(ZMQ_PULL);
    if (ctx->zmq_pull_socket == NULL) {
        flb_error("[in_zmq] zsock_new failed: %s", strerror(errno));
        goto error;
    }

    /* NB: HWMs need set before zsock_connect() */
    zsock_set_sndhwm(ctx->zmq_pull_socket, ctx->zmq_hwm);
    zsock_set_rcvhwm(ctx->zmq_pull_socket, ctx->zmq_hwm);

    ret = zsock_connect(ctx->zmq_pull_socket, "%s", ctx->zmq_endpoint);
    if (ret < 0) {
        flb_error("[in_zmq] zsock_connect(%s) failed: %s", ctx->zmq_endpoint,
                  strerror(errno));
        goto error;
    }

    ctx->ul_fd = zsock_fd(ctx->zmq_pull_socket);

    if (ctx->ul_fd < 0) {
        flb_error("[in_zmq] zsock_fd failed: %s", strerror(errno));
        goto error;
    }

    /* Set our collector based on an fd event using underlying fd */
    ret = flb_input_set_collector_event(in, in_zmq_collect, ctx->ul_fd, config);

    if (ret < 0) {
        flb_error("[in_zmq] flb_input_set_collector_event failed: %s",
                  strerror(errno));
        goto error;
    }

    ctx->i_ins = in;

    flb_input_set_context(in, ctx);

    return 0;

error:
    if (ctx) {
        if (ctx->zmq_pull_socket)
            zsock_destroy(&(ctx->zmq_pull_socket));

        flb_free(ctx);
    }

    return -1;
}

/* Plugin reference */
struct flb_input_plugin in_zmq_plugin = {
    .name         = "zmq",
    .description  = "Process logs in zmq msgs",
    .cb_init      = in_zmq_init,
    .cb_pre_run   = NULL,
    .cb_collect   = in_zmq_collect,
    .cb_flush_buf = NULL,
    .cb_pause     = in_zmq_pause,
    .cb_resume    = in_zmq_resume,
    .cb_exit      = in_zmq_exit
};
