/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2022 The Fluent Bit Authors
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
#include <fluent-bit/flb_ring_buffer.h>

/* lwrb header */
#include <lwrb/lwrb.h>

struct flb_ring_buffer *flb_ring_buffer_create(uint64_t size)
{
    lwrb_t *lwrb;
    size_t data_size;
    void *  data_buf;
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
    if (rb->data_buf) {
        flb_free(rb->data_buf);
    }
    if (rb->ctx) {
        flb_free(rb->ctx);
    }

    flb_free(rb);
}

int flb_ring_buffer_write(struct flb_ring_buffer *rb, void *ptr, size_t size)
{
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


