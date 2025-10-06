/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2024 The Fluent Bit Authors
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
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_sds.h>

#include "vivo.h"
#include "vivo_stream.h"

static inline void stream_lock(struct vivo_stream *vs)
{
    pthread_mutex_lock(&vs->stream_mutex);
}

static inline void stream_unlock(struct vivo_stream *vs)
{
    pthread_mutex_unlock(&vs->stream_mutex);
}

struct vivo_stream *vivo_stream_create(struct vivo_exporter *ctx)
{
    struct vivo_stream *vs;

    vs = flb_calloc(1, sizeof(struct vivo_stream));
    if (!vs) {
        flb_errno();
        return NULL;
    }
    vs->parent = ctx;
    vs->entries_added = 0;
    pthread_mutex_init(&vs->stream_mutex, NULL);
    mk_list_init(&vs->entries);
    mk_list_init(&vs->purge);

    return vs;
}

static uint64_t vivo_stream_get_new_id(struct vivo_stream *vs)
{
    uint64_t id = 0;

    stream_lock(vs);

    /* to get the next id, we simply use the value of the counter 'entries' added */
    id = vs->entries_added;

    stream_unlock(vs);

    return id;
}


struct vivo_stream_entry *vivo_stream_entry_create(struct vivo_stream *vs,
                                                   void *data, size_t size)
{
    struct vivo_stream_entry *e;

    if (size == 0) {
        return NULL;
    }

    e = flb_calloc(1, sizeof(struct vivo_stream_entry));
    if (!e) {
        flb_errno();
        return NULL;
    }
    e->id = vivo_stream_get_new_id(vs);

    e->data = flb_sds_create_len(data, size);
    if (!e->data) {
        flb_free(e);
        return NULL;
    }

    return e;
}

/*
 * NOTE: this function must always invoked under the stream_mutex in a locked state, we don't do the lock
 * inside the function since the caller might be itering the parent list
 */
static void vivo_stream_entry_destroy(struct vivo_stream *vs, struct vivo_stream_entry *e)
{
    mk_list_del(&e->_head);
    vs->current_bytes_size -= flb_sds_len(e->data);
    flb_sds_destroy(e->data);
    flb_free(e);
}

/* NOTE: this function must run inside a stream_lock()/stream_unlock() protection */
static void vivo_stream_cleanup(struct vivo_stream *vs)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct vivo_stream_entry *e;

    mk_list_foreach_safe(head, tmp, &vs->entries) {
        e = mk_list_entry(head, struct vivo_stream_entry, _head);
        vivo_stream_entry_destroy(vs, e);
    }
}

void vivo_stream_destroy(struct vivo_stream *vs)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct vivo_stream_entry *e;

    stream_lock(vs);
    mk_list_foreach_safe(head, tmp, &vs->entries) {
        e = mk_list_entry(head, struct vivo_stream_entry, _head);
        vivo_stream_entry_destroy(vs, e);
    }
    stream_unlock(vs);

    flb_free(vs);
}

flb_sds_t vivo_stream_get_content(struct vivo_stream *vs, int64_t from, int64_t to,
                                  int64_t limit,
                                  int64_t *stream_start_id, int64_t *stream_end_id,
                                  int64_t *stream_next_id)
{
    int64_t count = 0;
    flb_sds_t buf;
    struct mk_list *head;
    struct vivo_stream_entry *e;
    struct vivo_exporter *ctx = vs->parent;

    buf = flb_sds_create_size(vs->current_bytes_size);
    if (!buf) {
        return NULL;
    }

    stream_lock(vs);

    if (stream_start_id) {
        *stream_start_id = -1;
    }

    if (stream_end_id) {
        *stream_end_id = -1;
    }

    if (stream_next_id) {
        *stream_next_id = vs->entries_added;
    }

    mk_list_foreach(head, &vs->entries) {
        e = mk_list_entry(head, struct vivo_stream_entry, _head);

        if (e->id < from && from != -1) {
            continue;
        }

        if (e->id > to && to != -1 && to != 0) {
            break;
        }

        if (count == 0 && stream_start_id) {
            *stream_start_id = e->id;
        }

        flb_sds_cat_safe(&buf, e->data, flb_sds_len(e->data));

        if (stream_end_id) {
            *stream_end_id = e->id;
        }
        count++;

        if (limit > 0 && count >= limit) {
            break;
        }
    }

    if (ctx->empty_stream_on_read) {
        vivo_stream_cleanup(vs);
    }

    stream_unlock(vs);

    return buf;
}

/* Remove entries from the stream until cleanup 'size' bytes. This function is inside a stream_lock()/stream_unlock() */
static void vivo_stream_make_room(struct vivo_stream *vs, size_t size)
{
    size_t deleted = 0;
    struct mk_list *tmp;
    struct mk_list *head;
    struct vivo_stream_entry *e;

    mk_list_foreach_safe(head, tmp, &vs->entries) {
        e = mk_list_entry(head, struct vivo_stream_entry, _head);
        deleted += flb_sds_len(e->data);
        vivo_stream_entry_destroy(vs, e);
        if (deleted >= size) {
            break;
        }
    }
}

struct vivo_stream_entry *vivo_stream_append(struct vivo_stream *vs, void *data, size_t size)
{
    struct vivo_stream_entry *e;
    struct vivo_exporter *ctx = vs->parent;

    e = vivo_stream_entry_create(vs, data, size);
    if (!e) {
        return NULL;
    }

    stream_lock(vs);

    /* check queue space */
    if (vs->current_bytes_size + size > ctx->stream_queue_size) {
        /* free up some space */
        if (mk_list_size(&vs->entries) == 0) {
            /* do nothing, the user size setup is smaller that the incoming size, let it pass */
        }
        else {
            /* release at least 'size' bytes */
            vivo_stream_make_room(vs, size);
        }
    }

    /* add entry to the end of the list */
    mk_list_add(&e->_head, &vs->entries);

    vs->entries_added++;
    vs->current_bytes_size += size;

    stream_unlock(vs);

    return e;
}
