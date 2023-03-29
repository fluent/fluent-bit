/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Chunk I/O
 *  =========
 *  Copyright 2018 Eduardo Silva <eduardo@monkey.io>
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

#include <chunkio/chunkio_compat.h>
#include <chunkio/chunkio.h>
#include <chunkio/cio_version.h>
#include <chunkio/cio_file.h>
#include <chunkio/cio_memfs.h>
#include <chunkio/cio_log.h>
#include <chunkio/cio_error.h>

#include <string.h>

struct cio_chunk *cio_chunk_open(struct cio_ctx *ctx, struct cio_stream *st,
                                 const char *name, int flags, size_t size,
                                 int *err)
{
    int len;
    void *backend = NULL;
    struct cio_chunk *ch;

    if (!st) {
        cio_log_error(ctx, "[cio chunk] invalid stream");
        return NULL;
    }

    if (!name) {
        cio_log_error(ctx, "[cio chunk] invalid file name");
        return NULL;
    }

    len = strlen(name);
    if (len == 0) {
        cio_log_error(ctx, "[cio chunk] invalid file name");
        return NULL;
    }
#ifndef CIO_HAVE_BACKEND_FILESYSTEM
    if (st->type == CIO_STORE_FS) {
        cio_log_error(ctx, "[cio chunk] file system backend not supported");
        return NULL;
    }
#endif

    /* allocate chunk context */
    ch = malloc(sizeof(struct cio_chunk));
    if (!ch) {
        cio_errno();
        return NULL;
    }
    ch->name = strdup(name);
    ch->ctx = ctx;
    ch->st = st;
    ch->lock = CIO_FALSE;
    ch->tx_active = CIO_FALSE;
    ch->tx_crc = 0;
    ch->tx_content_length = 0;
    ch->backend = NULL;

    mk_list_add(&ch->_head, &st->chunks);

    cio_error_reset(ch);

    /* create backend context */
    if (st->type == CIO_STORE_FS) {
        backend = cio_file_open(ctx, st, ch, flags, size, err);
    }
    else if (st->type == CIO_STORE_MEM) {
        *err = CIO_OK;
        backend = cio_memfs_open(ctx, st, ch, flags, size);
    }

    if (!backend) {
        mk_list_del(&ch->_head);
        free(ch->name);
        free(ch);
        return NULL;
    }

    ch->backend = backend;

    /* Adjust counter */
    cio_chunk_counter_total_add(ctx);

    /* Link the chunk state to the proper stream list */
    if (cio_chunk_is_up(ch) == CIO_TRUE) {
        mk_list_add(&ch->_state_head, &st->chunks_up);
    }
    else {
        mk_list_add(&ch->_state_head, &st->chunks_down);
    }

    return ch;
}

void cio_chunk_close(struct cio_chunk *ch, int delete)
{
    int type;
    struct cio_ctx *ctx;

    if (!ch) {
        return;
    }

    cio_error_reset(ch);

    ctx = ch->ctx;
    type = ch->st->type;
    if (type == CIO_STORE_MEM) {
        cio_memfs_close(ch);
    }
    else if (type == CIO_STORE_FS) {
        cio_file_close(ch, delete);
    }

    mk_list_del(&ch->_head);
    mk_list_del(&ch->_state_head);
    free(ch->name);
    free(ch);

    /* Adjust counter */
    cio_chunk_counter_total_sub(ctx);
}

int cio_chunk_delete(struct cio_ctx *ctx, struct cio_stream *st, const char *name)
{
    int result;

    if (st == NULL) {
        cio_log_error(ctx, "[cio chunk] invalid stream");

        return CIO_ERROR;
    }

    if (name == NULL) {
        cio_log_error(ctx, "[cio chunk] invalid file name");

        return CIO_ERROR;
    }

    if (strlen(name) == 0) {
        cio_log_error(ctx, "[cio chunk] invalid file name");

        return CIO_ERROR;
    }

#ifndef CIO_HAVE_BACKEND_FILESYSTEM
    if (st->type == CIO_STORE_FS) {
        cio_log_error(ctx, "[cio chunk] file system backend not supported");

        return CIO_ERROR;
    }
#endif

    if (st->type == CIO_STORE_FS) {
        result = cio_file_delete(ctx, st, name);
    }
    else {
        result = CIO_ERROR;
    }

    return result;
}

/*
 * Write at a specific offset of the content area. Offset must be >= 0 and
 * less than current data length.
 */
int cio_chunk_write_at(struct cio_chunk *ch, off_t offset,
                       const void *buf, size_t count)
{
    int type;
    struct cio_memfs *mf;
    struct cio_file *cf;

    cio_error_reset(ch);

    type = ch->st->type;
    if (type == CIO_STORE_MEM) {
        mf = ch->backend;
        mf->buf_len = offset;
    }
    else if (type == CIO_STORE_FS) {
        cf = ch->backend;
        cf->data_size = offset;
        cf->crc_reset = CIO_TRUE;
    }

    /*
     * By default backends (fs, mem) appends data after the it last position,
     * so we just adjust the content size to the given offset.
     */
    return cio_chunk_write(ch, buf, count);
}

int cio_chunk_write(struct cio_chunk *ch, const void *buf, size_t count)
{
    int ret = 0;
    int type;

    cio_error_reset(ch);

    type = ch->st->type;
    if (type == CIO_STORE_MEM) {
        ret = cio_memfs_write(ch, buf, count);
    }
    else if (type == CIO_STORE_FS) {
        ret = cio_file_write(ch, buf, count);
    }

    return ret;
}

int cio_chunk_sync(struct cio_chunk *ch)
{
    int ret = 0;
    int type;

    cio_error_reset(ch);

    type = ch->st->type;
    if (type == CIO_STORE_FS) {
        ret = cio_file_sync(ch);
    }

    return ret;
}

int cio_chunk_get_content(struct cio_chunk *ch, char **buf, size_t *size)
{
    int ret = 0;
    int type;
    struct cio_memfs *mf;
    struct cio_file *cf;

    cio_error_reset(ch);

    type = ch->st->type;
    if (type == CIO_STORE_MEM) {
        mf = ch->backend;
        *size = mf->buf_len;
        *buf = mf->buf_data;
        return ret;
    }
    else if (type == CIO_STORE_FS) {
        cf = ch->backend;
        ret = cio_file_read_prepare(ch->ctx, ch);
        if (ret != CIO_OK) {
            return ret;
        }
        *size = cf->data_size;
        *buf = cio_file_st_get_content(cf->map);
        return ret;
    }

    return CIO_ERROR;
}

/* Using the content of the chunk, generate a copy using the heap */
int cio_chunk_get_content_copy(struct cio_chunk *ch,
                               void **out_buf, size_t *out_size)
{
    int type;

    cio_error_reset(ch);

    type = ch->st->type;
    if (type == CIO_STORE_MEM) {
        return cio_memfs_content_copy(ch, out_buf, out_size);
    }
    else if (type == CIO_STORE_FS) {
        return cio_file_content_copy(ch, out_buf, out_size);
    }

    return CIO_ERROR;
}

size_t cio_chunk_get_content_end_pos(struct cio_chunk *ch)
{
    int type;
    off_t pos = 0;
    struct cio_memfs *mf;
    struct cio_file *cf;

    cio_error_reset(ch);

    type = ch->st->type;
    if (type == CIO_STORE_MEM) {
        mf = ch->backend;
        pos = (off_t) (mf->buf_data + mf->buf_len);
    }
    else if (type == CIO_STORE_FS) {
        cf = ch->backend;
        pos = (off_t) (cio_file_st_get_content(cf->map) + cf->data_size);
    }

    return pos;
}

ssize_t cio_chunk_get_content_size(struct cio_chunk *ch)
{
    int type;
    struct cio_memfs *mf;
    struct cio_file *cf;

    cio_error_reset(ch);

    type = ch->st->type;
    if (type == CIO_STORE_MEM) {
        mf = ch->backend;
        return mf->buf_len;
    }
    else if (type == CIO_STORE_FS) {
        cf = ch->backend;
        return cf->data_size;
    }

    return -1;
}

ssize_t cio_chunk_get_real_size(struct cio_chunk *ch)
{
    int type;
    struct cio_memfs *mf;
    struct cio_file *cf;

    cio_error_reset(ch);

    type = ch->st->type;
    if (type == CIO_STORE_MEM) {
        mf = ch->backend;
        return mf->buf_len;
    }
    else if (type == CIO_STORE_FS) {
        cf = ch->backend;

        /* If the file is not open we need to explicitly get its size */
        if (cf->fs_size == 0) {
            return cio_file_real_size(cf);
        }

        return cf->fs_size;
    }

    return -1;
}

void cio_chunk_close_stream(struct cio_stream *st)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct cio_chunk *ch;

    mk_list_foreach_safe(head, tmp, &st->chunks) {
        ch = mk_list_entry(head, struct cio_chunk, _head);
        cio_chunk_close(ch, CIO_FALSE);
    }
}

char *cio_chunk_hash(struct cio_chunk *ch)
{
    if (ch->st->type == CIO_STORE_FS) {
        return cio_file_hash(ch->backend);
    }

    return NULL;
}

int cio_chunk_lock(struct cio_chunk *ch)
{
    cio_error_reset(ch);

    if (ch->lock == CIO_TRUE) {
        return CIO_ERROR;
    }

    ch->lock = CIO_TRUE;

    if (cio_chunk_is_up(ch) == CIO_TRUE) {
        return cio_chunk_sync(ch);
    }

    return CIO_OK;
}

int cio_chunk_unlock(struct cio_chunk *ch)
{
    cio_error_reset(ch);

    if (ch->lock == CIO_FALSE) {
        return CIO_ERROR;
    }

    ch->lock = CIO_FALSE;
    return CIO_OK;
}

int cio_chunk_is_locked(struct cio_chunk *ch)
{
    return ch->lock;
}

/*
 * Start a transaction context: it keep a state of the current calculated
 * CRC32 (if enabled) and the current number of bytes in the content
 * area.
 */
int cio_chunk_tx_begin(struct cio_chunk *ch)
{
    int type;
    struct cio_memfs *mf;
    struct cio_file *cf;

    cio_error_reset(ch);

    if (cio_chunk_is_locked(ch)) {
        return CIO_RETRY;
    }

    if (ch->tx_active == CIO_TRUE) {
        return CIO_OK;
    }

    ch->tx_active = CIO_TRUE;
    type = ch->st->type;
    if (type == CIO_STORE_MEM) {
        mf = ch->backend;
        ch->tx_crc = mf->crc_cur;
        ch->tx_content_length = mf->buf_len;
    }
    else if (type == CIO_STORE_FS) {
        cf = ch->backend;
        ch->tx_crc = cf->crc_cur;
        ch->tx_content_length = cf->data_size;
    }

    return CIO_OK;
}

/*
 * Commit transaction changes, reset transaction context and leave new
 * changes in place.
 */
int cio_chunk_tx_commit(struct cio_chunk *ch)
{
    int ret;

    cio_error_reset(ch);

    ret = cio_chunk_sync(ch);
    if (ret == -1) {
        return CIO_ERROR;
    }

    ch->tx_active = CIO_FALSE;
    return CIO_OK;
}

/*
 * Drop changes done since a transaction was initiated */
int cio_chunk_tx_rollback(struct cio_chunk *ch)
{
    int type;
    struct cio_memfs *mf;
    struct cio_file *cf;

    cio_error_reset(ch);

    if (ch->tx_active == CIO_FALSE) {
        return -1;
    }

    type = ch->st->type;
    if (type == CIO_STORE_MEM) {
        mf = ch->backend;
        mf->crc_cur = ch->tx_crc;
        mf->buf_len = ch->tx_content_length;
    }
    else if (type == CIO_STORE_FS) {
        cf = ch->backend;
        cf->crc_cur = ch->tx_crc;
        cf->data_size = ch->tx_content_length;
    }

    ch->tx_active = CIO_FALSE;
    return CIO_OK;
}

/*
 * Determinate if a Chunk content is available in memory for I/O operations. For
 * Memory backend this is always true, for Filesystem backend it checks if the
 * memory map exists and file descriptor is open.
 */
int cio_chunk_is_up(struct cio_chunk *ch)
{
    int type;
    struct cio_file *cf;

    type = ch->st->type;
    if (type == CIO_STORE_MEM) {
        return CIO_TRUE;
    }
    else if (type == CIO_STORE_FS) {
        cf = ch->backend;
        return cio_file_is_up(ch, cf);
    }

    return CIO_FALSE;
}

int cio_chunk_is_file(struct cio_chunk *ch)
{
    int type;

    type = ch->st->type;
    if (type == CIO_STORE_FS) {
        return CIO_TRUE;
    }

    return CIO_FALSE;
}

static inline void chunk_state_sync(struct cio_chunk *ch)
{
    struct cio_stream *st;

    if (!ch) {
        return;
    }

    mk_list_del(&ch->_state_head);
    st = ch->st;
    if (cio_chunk_is_up(ch) == CIO_TRUE) {
        mk_list_add(&ch->_state_head, &st->chunks_up);
    }
    else {
        mk_list_add(&ch->_state_head, &st->chunks_down);
    }
}

int cio_chunk_down(struct cio_chunk *ch)
{
    int ret;
    int type;

    cio_error_reset(ch);

    type = ch->st->type;
    if (type == CIO_STORE_FS) {
        ret = cio_file_down(ch);
        chunk_state_sync(ch);
        return ret;
    }

    return CIO_OK;
}

int cio_chunk_up(struct cio_chunk *ch)
{
    int ret;
    int type;

    cio_error_reset(ch);

    type = ch->st->type;
    if (type == CIO_STORE_FS) {
        ret = cio_file_up(ch);
        chunk_state_sync(ch);
        return ret;
    }

    return CIO_OK;
}

int cio_chunk_up_force(struct cio_chunk *ch)
{
    int ret;
    int type;

    cio_error_reset(ch);

    type = ch->st->type;
    if (type == CIO_STORE_FS) {
        ret = cio_file_up_force(ch);
        chunk_state_sync(ch);
        return ret;
    }

    return CIO_OK;
}

char *cio_version()
{
    return CIO_VERSION_STR;
}

/*
 * Counters API
 */

/* Increase the number of total chunks registered (+1) */
size_t cio_chunk_counter_total_add(struct cio_ctx *ctx)
{
    ctx->total_chunks++;
    return ctx->total_chunks;
}

/* Decrease the total number of chunks (-1) */
size_t cio_chunk_counter_total_sub(struct cio_ctx *ctx)
{
    ctx->total_chunks--;
    return ctx->total_chunks;
}

/* Increase the number of total chunks up in memory (+1) */
size_t cio_chunk_counter_total_up_add(struct cio_ctx *ctx)
{
    ctx->total_chunks_up++;
    return ctx->total_chunks_up;
}

/* Decrease the total number of chunks up in memory (-1) */
size_t cio_chunk_counter_total_up_sub(struct cio_ctx *ctx)
{
    ctx->total_chunks_up--;
    return ctx->total_chunks_up;
}
