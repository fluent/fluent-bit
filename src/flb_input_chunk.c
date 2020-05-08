/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2020 The Fluent Bit Authors
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
#include <fluent-bit/stream_processor/flb_sp.h>

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
    int ret;
    struct flb_input_chunk *ic;

    ic = (struct flb_input_chunk *) data;

    ret = cio_chunk_write(ic->chunk, buf, len);
#ifdef FLB_HAVE_METRICS
    if (ret == CIO_OK) {
        ic->added_records = flb_mp_count(buf, len);
        ic->total_records += ic->added_records;
    }
#endif

    return ret;
}

int flb_input_chunk_write_at(void *data, off_t offset,
                             const char *buf, size_t len)
{
    int ret;
    struct flb_input_chunk *ic;

    ic = (struct flb_input_chunk *) data;

    ret = cio_chunk_write_at(ic->chunk, offset, buf, len);
    return ret;
}

/* Create an input chunk using a Chunk I/O */
struct flb_input_chunk *flb_input_chunk_map(struct flb_input_instance *in,
                                            void *chunk)
{
#ifdef FLB_HAVE_METRICS
    int ret;
    int records;
    char *buf_data;
    size_t buf_size;
#endif
    struct flb_input_chunk *ic;

    /* Create context for the input instance */
    ic = flb_malloc(sizeof(struct flb_input_chunk));
    if (!ic) {
        flb_errno();
        return NULL;
    }

    ic->busy = FLB_FALSE;
    ic->fs_backlog = FLB_TRUE;
    ic->chunk = chunk;
    ic->in = in;
    msgpack_packer_init(&ic->mp_pck, ic, flb_input_chunk_write);
    mk_list_add(&ic->_head, &in->chunks);

#ifdef FLB_HAVE_METRICS
    ret = cio_chunk_get_content(ic->chunk, &buf_data, &buf_size);
    if (ret != CIO_OK) {
        flb_error("[input chunk] error retrieving content for metrics");
        return ic;
    }

    ic->total_records = flb_mp_count(buf_data, buf_size);
    if (ic->total_records > 0) {
        flb_metrics_sum(FLB_METRIC_N_RECORDS, ic->total_records, in->metrics);
        flb_metrics_sum(FLB_METRIC_N_BYTES, buf_size, in->metrics);
    }
#endif

    return ic;
}

struct flb_input_chunk *flb_input_chunk_create(struct flb_input_instance *in,
                                               const char *tag, int tag_len)
{
    int ret;
    int err;
    int set_down = FLB_FALSE;
    char name[64];
    struct cio_chunk *chunk;
    struct flb_storage_input *storage;
    struct flb_input_chunk *ic;

    storage = in->storage;

    /* chunk name */
    generate_chunk_name(in, name, sizeof(name) - 1);

    /* open/create target chunk file */
    chunk = cio_chunk_open(storage->cio, storage->stream, name,
                           CIO_OPEN, FLB_INPUT_CHUNK_SIZE, &err);
    if (!chunk) {
        flb_error("[input chunk] could not create chunk file: %s:%s",
                  storage->stream, name);
        flb_sds_destroy(name);
        return NULL;
    }

    /*
     * If the returned chunk at open is 'down', just put it up, write the
     * content and set it down again.
     */
    ret = cio_chunk_is_up(chunk);
    if (ret == CIO_FALSE) {
        ret = cio_chunk_up_force(chunk);
        if (ret == -1) {
            cio_chunk_close(chunk, CIO_TRUE);
            return NULL;
        }
        set_down = FLB_TRUE;
    }

    /* write metadata (tag) */
    if (tag_len > 65535) {
        /* truncate length */
        tag_len = 65535;
    }

    /* Write tag into metadata section */
    ret = cio_meta_write(chunk, (char *) tag, tag_len);
    if (ret == -1) {
        flb_error("[input chunk] could not write metadata");
        flb_sds_destroy(name);
        cio_chunk_close(chunk, CIO_TRUE);
        return NULL;
    }

    /* Create context for the input instance */
    ic = flb_malloc(sizeof(struct flb_input_chunk));
    if (!ic) {
        flb_errno();
        cio_chunk_close(chunk, CIO_TRUE);
        return NULL;
    }
    ic->busy = FLB_FALSE;
    ic->chunk = chunk;
    ic->fs_backlog = FLB_FALSE;
    ic->in = in;
    ic->stream_off = 0;
#ifdef FLB_HAVE_METRICS
    ic->total_records = 0;
#endif
    msgpack_packer_init(&ic->mp_pck, ic, flb_input_chunk_write);
    mk_list_add(&ic->_head, &in->chunks);

    if (set_down == FLB_TRUE) {
        cio_chunk_down(chunk);
    }

    return ic;
}

int flb_input_chunk_destroy(struct flb_input_chunk *ic, int del)
{
    cio_chunk_close(ic->chunk, del);
    mk_list_del(&ic->_head);
    flb_free(ic);

    return 0;
}

/* Return or create an available chunk to write data */
static struct flb_input_chunk *input_chunk_get(const char *tag, int tag_len,
                                               struct flb_input_instance *in)
{
    struct mk_list *head;
    struct flb_input_chunk *ic = NULL;

    /* Try to find a current chunk context to append the data */
    mk_list_foreach_r(head, &in->chunks) {
        ic = mk_list_entry(head, struct flb_input_chunk, _head);
        if (ic->busy == FLB_TRUE || cio_chunk_is_locked(ic->chunk)) {
            ic = NULL;
            continue;
        }

        if (cio_chunk_is_up(ic->chunk) == CIO_FALSE) {
            ic = NULL;
            continue;
        }

        if (cio_meta_cmp(ic->chunk, (char *) tag, tag_len) != 0) {
            ic = NULL;
            continue;
        }
        break;
    }

    /* No chunk was found, we need to create a new one */
    if (!ic) {
        ic = flb_input_chunk_create(in, (char *) tag, tag_len);
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
 * Check all chunks associated to the input instance and summarize
 * the number of bytes in use.
 */
size_t flb_input_chunk_total_size(struct flb_input_instance *in)
{
    ssize_t bytes;
    size_t total = 0;
    struct mk_list *head;
    struct flb_input_chunk *ic;

    mk_list_foreach(head, &in->chunks) {
        ic = mk_list_entry(head, struct flb_input_chunk, _head);

        /* Skip files who are 'down' */
        if (cio_chunk_is_up(ic->chunk) == CIO_FALSE) {
            continue;
        }

        bytes = flb_input_chunk_get_size(ic);
        if (bytes <= 0) {
            continue;
        }
        total += bytes;
    }

    return total;
}

/*
 * Count and update the number of bytes being used by the instance. Also
 * check if the instance is paused, if so, check if it can be resumed if
 * is not longer over the limits.
 *
 * It always returns the number of bytes in use.
 */
size_t flb_input_chunk_set_limits(struct flb_input_instance *in)
{
    size_t total;

    /* Gather total number of enqueued bytes */
    total = flb_input_chunk_total_size(in);

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

    return total;
}

/*
 * If the number of bytes in use by the chunks are over the imposed limit
 * by configuration, pause the instance.
 */
static inline int flb_input_chunk_protect(struct flb_input_instance *i)
{
    if (flb_input_chunk_is_overlimit(i) == FLB_TRUE) {
        flb_warn("[input] %s paused (mem buf overlimit)",
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

/*
 * Validate if the chunk coming from the input plugin basd on config and
 * resources usage must be 'up' or 'down' (applicable for filesystem storage
 * type).
 *
 * FIXME: can we find a better name for this function ?
 */
int flb_input_chunk_set_up_down(struct flb_input_chunk *ic)
{
    size_t total;
    struct flb_input_instance *in;

    in = ic->in;

    /* Gather total number of enqueued bytes */
    total = flb_input_chunk_total_size(in);

    /* Register the total into the context variable */
    in->mem_chunks_size = total;

    if (flb_input_chunk_is_overlimit(in) == FLB_TRUE) {
        if (cio_chunk_is_up(ic->chunk) == CIO_TRUE) {
            cio_chunk_down(ic->chunk);

            /* Adjust new counters */
            total = flb_input_chunk_total_size(ic->in);
            in->mem_chunks_size = total;

            return FLB_FALSE;
        }
    }

    return FLB_TRUE;
}

int flb_input_chunk_is_up(struct flb_input_chunk *ic)
{
    return cio_chunk_is_up(ic->chunk);

}

int flb_input_chunk_down(struct flb_input_chunk *ic)
{
    if (cio_chunk_is_up(ic->chunk) == CIO_TRUE) {
        return cio_chunk_down(ic->chunk);
    }

    return 0;
}

int flb_input_chunk_set_up(struct flb_input_chunk *ic)
{
    if (cio_chunk_is_up(ic->chunk) == CIO_FALSE) {
        return cio_chunk_up(ic->chunk);
    }

    return 0;
}


/* Append a RAW MessagPack buffer to the input instance */
int flb_input_chunk_append_raw(struct flb_input_instance *in,
                               const char *tag, size_t tag_len,
                               const void *buf, size_t buf_size)
{
    int ret;
    int set_down = FLB_FALSE;
    int min;
    size_t size;
    struct flb_input_chunk *ic;
    struct flb_storage_input *si;

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
     * the fixed instance tag or instance name.
     */
    if (!tag) {
        if (in->tag && in->tag_len > 0) {
            tag = in->tag;
            tag_len = in->tag_len;
        }
        else {
            tag = in->name;
            tag_len = strlen(in->name);
        }
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

    /* We got the chunk, validate if is 'up' or 'down' */
    ret = flb_input_chunk_is_up(ic);
    if (ret == FLB_FALSE) {
        ret = cio_chunk_up_force(ic->chunk);
        if (ret == -1) {
            flb_error("[input chunk] cannot retrieve temporal chunk");
            return -1;
        }
        set_down = FLB_TRUE;
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
    if (ic->total_records > 0) {
        flb_metrics_sum(FLB_METRIC_N_RECORDS, ic->added_records, in->metrics);
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
    if (size > FLB_INPUT_CHUNK_FS_MAX_SIZE) {
        cio_chunk_lock(ic->chunk);
    }

    /* Make sure the data was not filtered out and the buffer size is zero */
    if (size == 0) {
        flb_input_chunk_destroy(ic, FLB_TRUE);
        flb_input_chunk_set_limits(in);
        return 0;
    }
#ifdef FLB_HAVE_STREAM_PROCESSOR
    else if (in->config->stream_processor_ctx) {
        char *c_data;
        size_t c_size;

        /* Retrieve chunk (filtered) output content */
        cio_chunk_get_content(ic->chunk, &c_data, &c_size);

        /* Invoke stream processor */
        flb_sp_do(in->config->stream_processor_ctx,
                  in,
                  tag, tag_len,
                  c_data + ic->stream_off, c_size - ic->stream_off);
        ic->stream_off += (c_size - ic->stream_off);
    }
#endif

    if (set_down == FLB_TRUE) {
        cio_chunk_down(ic->chunk);
    }

    /*
     * If the instance is not routable, there is no need to keep the
     * content in the storage engine, just get rid of it.
     */
    if (in->routable == FLB_FALSE) {
        flb_input_chunk_destroy(ic, FLB_TRUE);
        return 0;
    }

    /* Update memory counters and adjust limits if any */
    flb_input_chunk_set_limits(in);

    /*
     * Check if we are overlimit and validate if is there any filesystem
     * storage type asociated to this input instance, if so, unload the
     * chunk content from memory to respect imposed limits.
     *
     * Calling cio_chunk_down() the memory map associated and the file
     * descriptor will be released. At any later time, it must be bring up
     * for I/O operations.
     */
    si = (struct flb_storage_input *) in->storage;
    if (flb_input_chunk_is_overlimit(in) == FLB_TRUE &&
        si->type == CIO_STORE_FS) {
        if (cio_chunk_is_up(ic->chunk) == CIO_TRUE) {
            /*
             * If we are already over limit, a sub-sequent data ingestion
             * might need a Chunk to write data in. As an optimization we
             * will put this Chunk down ONLY IF it has less than 1% of
             * it capacity as available space, otherwise keep it 'up' so
             * it available space can be used.
             */
            size = cio_chunk_get_content_size(ic->chunk);

            /* Do we have less than 1% available ? */
            min = (FLB_INPUT_CHUNK_FS_MAX_SIZE * 0.01);
            if (FLB_INPUT_CHUNK_FS_MAX_SIZE - size < min) {
                cio_chunk_down(ic->chunk);
            }
        }
        return 0;
    }

    flb_input_chunk_protect(in);
    return 0;
}

/* Retrieve a raw buffer from a dyntag node */
const void *flb_input_chunk_flush(struct flb_input_chunk *ic, size_t *size)
{
    int ret;
    char *buf = NULL;

    if (cio_chunk_is_up(ic->chunk) == CIO_FALSE) {
        ret = cio_chunk_up(ic->chunk);
        if (ret == -1) {
            return NULL;
        }
    }

    /*
     * msgpack-c internal use a raw buffer for it operations, since we
     * already appended data we just can take out the references to avoid
     * a new memory allocation and skip a copy operation.
     */
    ret = cio_chunk_get_content(ic->chunk, &buf, size);
    if (ret == -1) {
        flb_error("[input chunk] error retrieving chunk content");
        return NULL;
    }

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

flb_sds_t flb_input_chunk_get_name(struct flb_input_chunk *ic)
{
    struct cio_chunk *ch;

    ch = (struct cio_chunk *) ic->chunk;
    return ch->name;
}

int flb_input_chunk_get_tag(struct flb_input_chunk *ic,
                            const char **tag_buf, int *tag_len)
{
    int len;
    int ret;
    char *buf;

    ret = cio_meta_read(ic->chunk, &buf, &len);
    if (ret == -1) {
        return -1;
    }

    *tag_len = len;
    *tag_buf = buf;

    return ret;

}
