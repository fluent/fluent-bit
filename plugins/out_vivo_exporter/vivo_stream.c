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
    if (pthread_mutex_init(&vs->stream_mutex, NULL) != 0) {
        flb_free(vs);
        return NULL;
    }
    mk_list_init(&vs->entries);
    mk_list_init(&vs->purge);

    return vs;
}

struct vivo_stream_entry *vivo_stream_entry_create(struct vivo_stream *vs,
                                                   void *data, size_t size, flb_sds_t otlp)
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

    e->data = flb_sds_create_len(data, size);
    if (!e->data) {
        flb_free(e);
        return NULL;
    }

    e->otlp = flb_sds_create_len(otlp, flb_sds_len(otlp));
    if (!e->otlp) {
        flb_sds_destroy(e->data);
        flb_free(e);
        return NULL;
    }
    e->size = size + flb_sds_len(otlp);
    return e;
}

/*
 * NOTE: this function must always invoked under the stream_mutex in a locked state, we don't do the lock
 * inside the function since the caller might be itering the parent list
 */
static void vivo_stream_entry_destroy(struct vivo_stream *vs, struct vivo_stream_entry *e)
{
    mk_list_del(&e->_head);
    vs->current_bytes_size -= e->size;
    vs->snapshot.retained_entries--;
    flb_sds_destroy(e->data);
    flb_sds_destroy(e->otlp);
    flb_free(e);
}

void vivo_stream_destroy(struct vivo_stream *vs)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct vivo_stream_entry *e;

    if (!vs) {
        return;
    }

    stream_lock(vs);
    mk_list_foreach_safe(head, tmp, &vs->entries) {
        e = mk_list_entry(head, struct vivo_stream_entry, _head);
        vivo_stream_entry_destroy(vs, e);
    }
    stream_unlock(vs);

    pthread_mutex_destroy(&vs->stream_mutex);
    flb_free(vs);
}

flb_sds_t vivo_stream_get_content(struct vivo_stream *vs, int version, int64_t from, int64_t to,
                                  int64_t limit,
                                  int64_t *stream_start_id, int64_t *stream_end_id,
                                  int64_t *stream_next_id, struct vivo_stream_snapshot *snapshot)
{
    int64_t count = 0;
    size_t length;
    size_t budget;
    int prefix_length;
    char prefix[40];
    flb_sds_t buf;
    struct mk_list *head;
    struct vivo_stream_entry *e;
    struct vivo_exporter *ctx = vs->parent;

    buf = flb_sds_create_size(1024);
    if (!buf) {
        return NULL;
    }

    stream_lock(vs);

    *snapshot = vs->snapshot;
    snapshot->retained_bytes = vs->current_bytes_size;
    snapshot->next = vs->entries_added;
    snapshot->oldest = vs->entries_added;
    if (mk_list_is_empty(&vs->entries) != 0) {
        e = mk_list_entry(vs->entries.next, struct vivo_stream_entry, _head);
        snapshot->oldest = e->id;
    }

    if (stream_start_id) {
        *stream_start_id = -1;
    }

    if (stream_end_id) {
        *stream_end_id = -1;
    }

    if (stream_next_id) {
        *stream_next_id = vs->entries_added;
    }

    budget = version == 2 ? ctx->stream_page_size - 512 : ctx->stream_page_size;

    mk_list_foreach(head, &vs->entries) {
        e = mk_list_entry(head, struct vivo_stream_entry, _head);

        if (e->id < from && from != -1) {
            continue;
        }

        if (e->id > to && to != -1) {
            break;
        }

        prefix_length = 0;
        length = flb_sds_len(e->data);
        if (version == 2) {
            prefix_length = snprintf(prefix, sizeof(prefix), "%s{\"id\":\"%" PRId64 "\",",
                                     count ? "," : "", e->id);
            length = prefix_length + flb_sds_len(e->otlp) - 1;
        }
        if (length > budget - flb_sds_len(buf)) {
            break;
        }

        if (count == 0 && stream_start_id) {
            *stream_start_id = e->id;
        }

        if ((version == 1 && flb_sds_cat_safe(&buf, e->data, length) < 0) ||
            (version == 2 && (flb_sds_cat_safe(&buf, prefix, prefix_length) < 0 ||
                             flb_sds_cat_safe(&buf, e->otlp + 1, flb_sds_len(e->otlp) - 1) < 0))) {
            stream_unlock(vs);
            flb_sds_destroy(buf);
            return NULL;
        }
        if (stream_next_id) {
            *stream_next_id = e->id + 1;
        }

        if (stream_end_id) {
            *stream_end_id = e->id;
        }
        count++;

        if (limit > 0 && count >= limit) {
            break;
        }
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
        deleted += e->size;
        vs->snapshot.evicted_entries++;
        vs->snapshot.evicted_bytes += e->size;
        vivo_stream_entry_destroy(vs, e);
        if (deleted >= size) {
            break;
        }
    }
}

int vivo_stream_append(struct vivo_stream *vs, void *data, size_t size, flb_sds_t otlp)
{
    struct vivo_stream_entry *e;
    size_t retained_size;
    struct vivo_exporter *ctx = vs->parent;

    if (flb_sds_len(otlp) > ctx->stream_queue_size ||
        size > ctx->stream_queue_size - flb_sds_len(otlp) || size > ctx->stream_page_size ||
        flb_sds_len(otlp) > ctx->stream_page_size - 552) {
        stream_lock(vs);
        vs->snapshot.rejected_entries++;
        stream_unlock(vs);
        flb_plg_error(ctx->ins, "entry sizes v1=%zu v2=%zu exceed queue/page limits %zu/%zu",
                      size, flb_sds_len(otlp), ctx->stream_queue_size, ctx->stream_page_size);
        return -2;
    }

    e = vivo_stream_entry_create(vs, data, size, otlp);
    if (!e) {
        return -1;
    }

    retained_size = e->size;
    stream_lock(vs);

    /* Subtraction avoids overflow and evicts only the actual excess. */
    if (vs->current_bytes_size > ctx->stream_queue_size - retained_size) {
        vivo_stream_make_room(vs, vs->current_bytes_size - (ctx->stream_queue_size - retained_size));
    }
    e->id = vs->entries_added;

    /* add entry to the end of the list */
    mk_list_add(&e->_head, &vs->entries);

    vs->entries_added++;
    vs->snapshot.retained_entries++;
    vs->current_bytes_size += retained_size;

    stream_unlock(vs);

    return 0;
}
