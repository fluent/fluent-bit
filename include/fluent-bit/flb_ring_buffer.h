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

#ifndef FLB_RING_BUFFER_H
#define FLB_RING_BUFFER_H

#include <fluent-bit/flb_pipe.h>

struct flb_ring_buffer {
    void *ctx;                        /* pointer to backend context */
    void *event_loop;                 /* event loop where this ring buffer emits flush request signals */
    int flush_pending;                /* flag meant to prevent flush request signal flood */
    void *signal_event;               /* event loop entry for the flush request signal */
    flb_pipefd_t signal_channels[2];  /* flush request signaling channel */
    uint64_t data_window;             /* 0% - 100% occupancy window flush request */
    uint64_t data_size;               /* ring buffer size */
    void *data_buf;                   /* ring buffer */
};

struct flb_ring_buffer *flb_ring_buffer_create(uint64_t size);
void flb_ring_buffer_destroy(struct flb_ring_buffer *rb);

int flb_ring_buffer_add_event_loop(struct flb_ring_buffer *rb, void *evl, uint8_t window_size);

int flb_ring_buffer_write(struct flb_ring_buffer *rb, void *ptr, size_t size);
int flb_ring_buffer_read(struct flb_ring_buffer *rb, void *ptr, size_t size);
size_t flb_ring_buffer_get_used(struct flb_ring_buffer *rb);

#endif
