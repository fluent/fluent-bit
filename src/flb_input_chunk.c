/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2018 Treasure Data Inc.
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
#include <fluent-bit/flb_input_chunk.h>
#include <fluent-bit/flb_storage.h>
#include <fluent-bit/flb_time.h>

static void generate_chunk_name(struct flb_input_instance *in,
                                char *out_buf, int buf_size)
{
    struct flb_time tm;
    (void) in;

    flb_time_get(&tm);
    snprintf(out_buf, buf_size - 1,
             "%i-%lu.%4lu.flb",
             getpid(),
             tm.tm.tv_sec, tm.tm.tv_nsec);
}

ssize_t flb_input_chunk_get_size(struct flb_input_chunk *ic)
{
    return cio_chunk_get_content_size(ic->chunk);
}

int flb_input_chunk_write(void *data, const char *buf, size_t len)
{
    struct flb_input_chunk *ic;

    ic = (struct flb_input_chunk *) data;

    return cio_chunk_write(ic->chunk, buf, len);
}

int flb_input_chunk_write_at(void *data, off_t offset,
                             const char *buf, size_t len)
{
    struct flb_input_chunk *ic;

    ic = (struct flb_input_chunk *) data;

    return cio_chunk_write_at(ic->chunk, offset, buf, len);
}

struct flb_input_chunk *flb_input_chunk_create(struct flb_input_instance *in,
                                               char *tag, int tag_len)
{
    int ret;
    char name[256];
    struct cio_chunk *chunk;
    struct flb_storage_input *storage;
    struct flb_input_chunk *ic;

    storage = in->storage;

    /* chunk name */
    generate_chunk_name(in, name, sizeof(name) - 1);

    /* open/create target chunk file */
    chunk = cio_chunk_open(storage->cio, storage->stream, name,
                           CIO_OPEN, FLB_INPUT_CHUNK_SIZE);
    if (!chunk) {
        flb_error("[input chunk] could not create chunk file");
        return NULL;
    }

    /* write metadata (tag) */
    if (tag_len > 65535) {
        /* truncate length */
        tag_len = 65535;
    }

    /* Write tag into metadata section */
    ret = cio_meta_write(chunk, tag, tag_len);
    if (ret == -1) {
        flb_error("[input chunk] could not write metadata");
        cio_chunk_close(chunk, CIO_TRUE);
        return NULL;
    }

    /* Create context for the input instance */
    ic = flb_malloc(sizeof(struct flb_input_chunk));
    if (!ic) {
        flb_errno();
        return NULL;
    }
    ic->busy = FLB_FALSE;
    ic->chunk = chunk;
    ic->in = in;
    msgpack_packer_init(&ic->mp_pck, ic, flb_input_chunk_write);
    mk_list_add(&ic->_head, &in->chunks);

    return ic;
}

int flb_input_chunk_destroy(struct flb_input_chunk *ic)
{
    cio_chunk_close(ic->chunk, CIO_TRUE);
    mk_list_del(&ic->_head);
    flb_free(ic);

    return 0;
}

/* analog for flb_input_dyntag_exit() */
void flb_input_chunk_destroy_all(struct flb_input_instance *in)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_input_chunk *ic;

    mk_list_foreach_safe(head, tmp, &in->chunks) {
        ic = mk_list_entry(head, struct flb_input_chunk, _head);
        flb_input_chunk_destroy(ic);
    }
}

/* Return or create an available chunk to write data */
static struct flb_input_chunk *input_chunk_get(char *tag, int tag_len,
                                               struct flb_input_instance *in)
{
    struct mk_list *head;
    struct flb_input_chunk *ic = NULL;

    /* Try to find a current chunk context to append the data */
    mk_list_foreach(head, &in->chunks) {
        ic = mk_list_entry(head, struct flb_input_chunk, _head);
        if (ic->busy == FLB_TRUE || cio_chunk_is_locked(ic->chunk)) {
            ic = NULL;
            continue;
        }

        if (cio_meta_cmp(ic->chunk, tag, tag_len) != 0) {
            ic = NULL;
            continue;
        }
        break;
    }

    /* No chunk was found, we need to create a new one */
    if (!ic) {
        ic = flb_input_chunk_create(in, tag, tag_len);
        if (!ic) {
            return NULL;
        }
    }

    return ic;
}

static inline int flb_input_chunk_is_overlimit(struct flb_input_instance *i)
{
    if (i->mem_buf_limit <= 0) {
        return FLB_FALSE;
    }

    if (i->mem_chunks_size >= i->mem_buf_limit) {
        return FLB_TRUE;
    }

    return FLB_FALSE;
}

/*
 * Count and update the number of bytes being used by the instance. Also
 * check if the instance is paused, if so, check if it can be resumed if
 * is not longer over the limits.
 */
int flb_input_chunk_set_limits(struct flb_input_instance *in)
{
    size_t total;
    ssize_t bytes;
    struct mk_list *head;
    struct flb_input_chunk *ic;

    /*
     * Check all chunks associated to the input instance and summarize
     * the number of bytes in use.
     */
    total = 0;
    mk_list_foreach(head, &in->chunks) {
        ic = mk_list_entry(head, struct flb_input_chunk, _head);
        bytes = flb_input_chunk_get_size(ic);
        if (bytes < 0) {
            flb_error("[input chunk] %s cannot retrieve chunk size",
                      in->name);
            continue;
        }
        total += bytes;
    }

    /* Register the total into the context variable */
    in->mem_chunks_size = total;

    /*
     * After the adjustments, validate if the plugin is overlimit or paused
     * and perform further adjustments.
     */
    if (flb_input_chunk_is_overlimit(in) == FLB_FALSE &&
        flb_input_buf_paused(in) && in->config->is_running == FLB_TRUE) {
        in->mem_buf_status = FLB_INPUT_RUNNING;
        if (in->p->cb_resume) {
            in->p->cb_resume(in->context, in->config);
            flb_debug("[input] %s resume (mem buf overlimit)",
                      in->name);
        }
    }

    return 0;
}

/*
 * If the number of bytes in use by the chunks are over the imposed limit
 * by configuration, pause the instance.
 */
static inline int flb_input_chunk_protect(struct flb_input_instance *i)
{
    if (flb_input_chunk_is_overlimit(i) == FLB_TRUE) {
        flb_debug("[input] %s paused (mem buf overlimit)",
                 i->name);
        if (!flb_input_buf_paused(i)) {
            if (i->p->cb_pause) {
                i->p->cb_pause(i->context, i->config);
            }
        }
        i->mem_buf_status = FLB_INPUT_PAUSED;
        return FLB_TRUE;
    }

    return FLB_FALSE;
}

/* Append a RAW MessagPack buffer to the input instance */
int flb_input_chunk_append_raw(struct flb_input_instance *in,
                               char *tag, size_t tag_len,
                               void *buf, size_t buf_size)
{
    int ret;
    size_t size;
    struct flb_input_chunk *ic;
#ifdef FLB_HAVE_METRICS
    int records;
#endif

    /* Check if the input plugin has been paused */
    if (flb_input_buf_paused(in) == FLB_TRUE) {
        flb_debug("[input chunk] %s is paused, cannot append records",
                  in->name);
        return -1;
    }

    /*
     * Some callers might not set a custom tag, on that case just inherit
     * the instance name.
     */
    if (!tag) {
        tag = in->name;
        tag_len = strlen(in->name);
    }

    /*
     * Get a target input chunk, can be one with remaining space available
     * or a new one.
     */
    ic = input_chunk_get(tag, tag_len, in);
    if (!ic) {
        flb_error("[input chunk] no available chunk");
        return -1;
    }

    /* Write the new data */
    ret = flb_input_chunk_write(ic, buf, buf_size);
    if (ret == -1) {
        flb_error("[input chunk] error writing data from %s instance",
                  in->name);
        cio_chunk_tx_rollback(ic->chunk);
        return -1;
    }

    /* Update 'input' metrics */
#ifdef FLB_HAVE_METRICS
    records = flb_mp_count(buf, buf_size);
    if (records > 0) {
        flb_metrics_sum(FLB_METRIC_N_RECORDS, records, in->metrics);
        flb_metrics_sum(FLB_METRIC_N_BYTES, buf_size, in->metrics);
    }
#endif

    /* Apply filters */
    flb_filter_do(ic,
                  buf, buf_size,
                  tag, tag_len, in->config);

    /* Get chunk size */
    size = cio_chunk_get_content_size(ic->chunk);

    /* Lock buffers where size > 2MB */
    if (size > 2048000) {
        cio_chunk_lock(ic->chunk);
    }

    /* Make sure the data was not filtered out and the buffer size is zero */
    if (size == 0) {
        flb_input_chunk_destroy(ic);
    }

    /* Update memory counters and adjust limits if any */
    flb_input_chunk_set_limits(in);
    flb_input_chunk_protect(in);

    return 0;
}

/* Retrieve a raw buffer from a dyntag node */
void *flb_input_chunk_flush(struct flb_input_chunk *ic, size_t *size)
{
    void *buf;

    /*
     * msgpack-c internal use a raw buffer for it operations, since we
     * already appended data we just can take out the references to avoid
     * a new memory allocation and skip a copy operation.
     */

    buf = cio_chunk_get_content(ic->chunk, size);
    if (!buf) {
        *size = 0;
        return NULL;
    }

    /* Set it busy as it likely it's a reference for an outgoing task */
    ic->busy = FLB_TRUE;

    return buf;
}

int flb_input_chunk_release_lock(struct flb_input_chunk *ic)
{
    if (ic->busy == FLB_FALSE) {
        return -1;
    }

    ic->busy = FLB_FALSE;
    return 0;
}

int flb_input_chunk_get_tag(struct flb_input_chunk *ic,
                            char **tag_buf, int *tag_len)
{
    return cio_meta_read(ic->chunk, tag_buf, tag_len);

}
