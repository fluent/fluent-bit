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

#ifndef FLB_STREAM_H
#define FLB_STREAM_H

#include <fluent-bit/flb_io.h>
#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_socket.h>
#include <fluent-bit/flb_config.h>

#define FLB_DOWNSTREAM            1
#define FLB_UPSTREAM              2

#define FLB_TRANSPORT_UNSET       0
#define FLB_TRANSPORT_TCP         1
#define FLB_TRANSPORT_UDP         2
#define FLB_TRANSPORT_UNIX_STREAM 3
#define FLB_TRANSPORT_UNIX_DGRAM  4

/* Base stream from which both downstream and upstream inherit */
struct flb_stream {
    int                  dynamically_allocated;
    int                  thread_safety_flag;
    int                  transport;
    int                  flags;
    int                  type;

    pthread_mutex_t      list_mutex;
    struct flb_tls      *tls_context;
    struct flb_config   *config;
    struct flb_net_setup net;

    struct mk_list       _head;
};

static inline int flb_stream_is_shutting_down(struct flb_stream *stream)
{
    return stream->config->is_shutting_down;
}

static inline void flb_stream_setup(struct flb_stream *stream,
                                    int type,
                                    int transport,
                                    int flags,
                                    struct flb_tls *tls_context,
                                    struct flb_config *config,
                                    struct flb_net_setup *net_setup)
{
    stream->thread_safety_flag = FLB_FALSE;
    stream->tls_context        = tls_context;
    stream->transport          = transport;
    stream->config             = config;
    stream->flags              = flags;
    stream->type               = type;

    /* Set default networking setup values */
    if (net_setup == NULL) {
        flb_net_setup_init(&stream->net);
    }
    else {
        memcpy(&stream->net, net_setup, sizeof(struct flb_net_setup));
    }
}

static inline int flb_stream_get_flags(struct flb_stream *stream)
{
    return stream->flags;
}

static inline void flb_stream_set_flags(struct flb_stream *stream, int flags)
{
    stream->flags = flags;
}

static inline int flb_stream_get_flag_status(struct flb_stream *stream, int flag)
{
    return ((flb_stream_get_flags(stream) & flag) != 0);
}

static inline void flb_stream_enable_flags(struct flb_stream *stream, int flag)
{
    flb_stream_set_flags(stream, flb_stream_get_flags(stream) | flag);
}

static inline void flb_stream_disable_flags(struct flb_stream *stream, int flag)
{
    flb_stream_set_flags(stream, flb_stream_get_flags(stream) & ~flag);
}

static inline void flb_stream_enable_async_mode(struct flb_stream *stream)
{
    flb_stream_enable_flags(stream, FLB_IO_ASYNC);
}

static inline void flb_stream_disable_async_mode(struct flb_stream *stream)
{
    flb_stream_disable_flags(stream, FLB_IO_ASYNC);
}

static inline int flb_stream_is_async(struct flb_stream *stream)
{
    return flb_stream_get_flag_status(stream, FLB_IO_ASYNC);
}

static inline void flb_stream_enable_keepalive(struct flb_stream *stream)
{
    flb_stream_enable_flags(stream, FLB_IO_TCP_KA);
}

static inline void flb_stream_disable_keepalive(struct flb_stream *stream)
{
    flb_stream_disable_flags(stream, FLB_IO_TCP_KA);
}

static inline int flb_stream_is_keepalive(struct flb_stream *stream)
{
    return flb_stream_get_flag_status(stream, FLB_IO_TCP_KA);
}

static inline int flb_stream_is_secure(struct flb_stream *stream)
{
    return flb_stream_get_flag_status(stream, FLB_IO_TLS);
}

static inline int flb_stream_is_thread_safe(struct flb_stream *stream)
{
    return stream->thread_safety_flag;
}

static inline void flb_stream_enable_thread_safety(struct flb_stream *stream)
{
    stream->thread_safety_flag = FLB_TRUE;

    pthread_mutex_init(&stream->list_mutex, NULL);

    /* We have to avoid any access to ensure that this stream context
     * is only this context outside of the worker
     * thread.
     */
    if (mk_list_entry_orphan(&stream->_head) == 0) {
        mk_list_del(&stream->_head);
    }
}

static inline int flb_stream_acquire_lock(struct flb_stream *stream,
                                          int wait_flag)
{
    int result;

    result = 0;

    if (stream->thread_safety_flag) {
        if (wait_flag) {
            result = pthread_mutex_lock(&stream->list_mutex);
        }
        else {
            result = pthread_mutex_trylock(&stream->list_mutex);
        }
    }

    if (result == 0) {
        result = FLB_TRUE;
    }
    else {
        result = FLB_FALSE;
    }

    return result;
}

static inline int flb_stream_release_lock(struct flb_stream *stream)
{
    int result;

    result = 0;

    if (stream->thread_safety_flag) {
        result = pthread_mutex_unlock(&stream->list_mutex);
    }

    if (result == 0) {
        result = FLB_TRUE;
    }
    else {
        result = FLB_FALSE;
    }

    return result;
}

#endif