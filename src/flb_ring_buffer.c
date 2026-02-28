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

/*
 * This interface is a wrapper of the 'lwrb' ring buffer implementation:
 *
 *  - https://github.com/MaJerle/lwrb
 */

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_pipe.h>
#include <fluent-bit/flb_ring_buffer.h>
#include <fluent-bit/flb_engine_macros.h>

#include <monkey/mk_core.h>

#include <math.h>

/* lwrb header */
#include <lwrb/lwrb.h>

static void flb_ring_buffer_remove_event_loop(struct flb_ring_buffer *rb);

struct flb_ring_buffer *flb_ring_buffer_create(uint64_t size)
{
    lwrb_t *lwrb;
    void *  data_buf;
    size_t  data_size;
    struct flb_ring_buffer *rb;

    rb = flb_calloc(1, sizeof(struct flb_ring_buffer));
    if (!rb) {
        flb_errno();
        return NULL;
    }
    rb->data_size = size;

    /* lwrb context */
    lwrb = flb_malloc(sizeof(lwrb_t));
    if (!lwrb) {
        flb_errno();
        flb_free(rb);
        return NULL;
    }
    rb->ctx = lwrb;

    /* data buffer for backend library */
    data_size = 1 + (sizeof(uint8_t) * size);
    data_buf = flb_calloc(1, data_size);
    if (!data_buf) {
        flb_errno();
        flb_free(rb);
        flb_free(lwrb);
        return NULL;
    }
    rb->data_buf = data_buf;

    /* initialize lwrb */
    lwrb_init(rb->ctx, data_buf, data_size);

    return rb;
}

void flb_ring_buffer_destroy(struct flb_ring_buffer *rb)
{
    flb_ring_buffer_remove_event_loop(rb);

    if (rb->data_buf) {
        flb_free(rb->data_buf);
    }

    if (rb->ctx) {
        flb_free(rb->ctx);
    }

    flb_free(rb);
}

int flb_ring_buffer_add_event_loop(struct flb_ring_buffer *rb, void *evl, uint8_t window_size)
{
    int result;

    if (window_size == 0) {
        return -1;
    }
    else if (window_size > 100) {
        window_size = 100;
    }

    rb->data_window = (uint64_t) floor((rb->data_size * window_size) / 100);

    result = flb_pipe_create(rb->signal_channels);

    if (result) {
        return -2;
    }

    flb_pipe_set_nonblocking(rb->signal_channels[0]);
    flb_pipe_set_nonblocking(rb->signal_channels[1]);

    rb->signal_event = (void *) flb_calloc(1, sizeof(struct mk_event));

    if (rb->signal_event == NULL) {
        flb_pipe_destroy(rb->signal_channels);

        return -2;
    }

    MK_EVENT_ZERO(rb->signal_event);

    result = mk_event_add(evl,
                          rb->signal_channels[0],
                          FLB_ENGINE_EV_THREAD_INPUT,
                          MK_EVENT_READ,
                          rb->signal_event);

    if (result) {
        flb_pipe_destroy(rb->signal_channels);
        flb_free(rb->signal_event);

        rb->signal_event = NULL;

        return -3;
    }

    rb->event_loop = evl;

    return 0;
}

static void flb_ring_buffer_remove_event_loop(struct flb_ring_buffer *rb)
{
    if (rb->event_loop != NULL) {
        mk_event_del(rb->event_loop, rb->signal_event);
        flb_pipe_destroy(rb->signal_channels);
        flb_free(rb->signal_event);

        rb->signal_event = NULL;
        rb->data_window = 0;
        rb->event_loop = NULL;
    }
}

int flb_ring_buffer_write(struct flb_ring_buffer *rb, void *ptr, size_t size)
{
    size_t used_size;
    size_t ret;
    size_t av;

    /* make sure there is enough space available */
    av = lwrb_get_free(rb->ctx);
    if (av < size) {
        return -1;
    }

    /* write the content */
    ret = lwrb_write(rb->ctx, ptr, size);
    if (ret == 0) {
        return -1;
    }

    if (!rb->flush_pending) {
        used_size = rb->data_size - (av - size);

        if (used_size >= rb->data_window) {
            rb->flush_pending = FLB_TRUE;

            flb_pipe_write_all(rb->signal_channels[1], ".", 1);
        }
    }

    return 0;
}

int flb_ring_buffer_read(struct flb_ring_buffer *rb, void *ptr, size_t size)
{
    size_t ret;

    ret = lwrb_read(rb->ctx, ptr, size);
    if (ret == 0) {
        return -1;
    }

    return 0;
}

int flb_ring_buffer_peek(struct flb_ring_buffer *rb, int skip_count, void *ptr, size_t size)
{
    size_t ret;

    ret = lwrb_peek(rb->ctx, skip_count, ptr, size);
    if (ret == 0) {
        return -1;
    }

    return 0;
}

int flb_ring_buffer_skip(struct flb_ring_buffer *rb, size_t size)
{
    size_t ret;

    ret = lwrb_skip(rb->ctx, size);
    if (ret == 0) {
        return -1;
    }

    return 0;
}
