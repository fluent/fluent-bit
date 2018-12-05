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

#include <chunkio/chunkio.h>
#include <chunkio/cio_file.h>
#include <chunkio/cio_memfs.h>
#include <chunkio/cio_log.h>

#include <string.h>

struct cio_chunk *cio_chunk_open(struct cio_ctx *ctx, struct cio_stream *st,
                                 const char *name, int flags, size_t size)
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

    mk_list_add(&ch->_head, &st->files);

    /* create backend context */
    if (st->type == CIO_STORE_FS) {
        backend = cio_file_open(ctx, st, ch, flags, size);
    }
    else if (st->type == CIO_STORE_MEM) {
        backend = cio_memfs_open(ctx, st, ch, flags, size);
    }

    if (!backend) {
        cio_log_error(ctx, "[cio chunk] error initializing backend file");
        free(ch->name);
        free(ch);
        return NULL;
    }

    ch->backend = backend;

    return ch;
}

void cio_chunk_close(struct cio_chunk *ch, int delete)
{
    int type;

    type = ch->st->type;
    if (type == CIO_STORE_FS) {
        cio_file_close(ch, delete);
    }
    else if (type == CIO_STORE_MEM) {
        cio_memfs_close(ch);
    }

    mk_list_del(&ch->_head);
    free(ch->name);
    free(ch);
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

    type = ch->st->type;
    if (type == CIO_STORE_FS) {
        cf = ch->backend;
        cf->data_size = offset;
    }
    else if (type == CIO_STORE_MEM) {
        mf = ch->backend;
        mf->buf_len = offset;
    }

    /*
     * By default backends (fs, mem) appends data after the it last position,
     * so we just adjust the content size to the given offset.
     */
    return cio_chunk_write(ch, buf, count);
}

int cio_chunk_write(struct cio_chunk *ch, const void *buf, size_t count)
{
    int ret;
    int type;

    type = ch->st->type;
    if (type == CIO_STORE_FS) {
        ret = cio_file_write(ch, buf, count);
    }
    else if (type == CIO_STORE_MEM) {
        ret = cio_memfs_write(ch, buf, count);
    }

    return ret;
}

int cio_chunk_sync(struct cio_chunk *ch)
{
    int ret = 0;
    int type;

    type = ch->st->type;
    if (type == CIO_STORE_FS) {
        ret = cio_file_sync(ch);
    }

    return ret;
}

void *cio_chunk_get_content(struct cio_chunk *ch, size_t *size)
{
    int type;
    struct cio_memfs *mf;
    struct cio_file *cf;

    type = ch->st->type;
    if (type == CIO_STORE_MEM) {
        mf = ch->backend;
        *size = mf->buf_len;
        return mf->buf_data;
    }
    else if (type == CIO_STORE_FS) {
        cf = ch->backend;
        *size = cf->data_size;
        return cio_file_st_get_content(cf->map);
    }

    return NULL;
}

size_t cio_chunk_get_content_end_pos(struct cio_chunk *ch)
{
    int type;
    off_t pos = 0;
    struct cio_memfs *mf;
    struct cio_file *cf;

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

void cio_chunk_close_stream(struct cio_stream *st)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct cio_chunk *ch;

    mk_list_foreach_safe(head, tmp, &st->files) {
        ch = mk_list_entry(head, struct cio_chunk, _head);
        if (st->type == CIO_STORE_FS) {
            cio_file_close(ch, CIO_FALSE);
        }
        else if (st->type == CIO_STORE_MEM) {
            cio_memfs_close(ch);
        }
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
    if (ch->lock == CIO_TRUE) {
        return -1;
    }

    ch->lock = CIO_TRUE;
    return 0;
}

int cio_chunk_unlock(struct cio_chunk *ch)
{
    if (ch->lock == CIO_FALSE) {
        return -1;
    }

    ch->lock = CIO_FALSE;
    return 0;
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

    if (cio_chunk_is_locked(ch)) {
        return -1;
    }

    if (ch->tx_active == CIO_TRUE) {
        return -1;
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

    return 0;
}

/*
 * Commit transaction changes, reset transaction context and leave new
 * changes in place.
 */
int cio_chunk_tx_commit(struct cio_chunk *ch)
{
    int ret;

    ret = cio_chunk_sync(ch);
    if (ret == -1) {
        return -1;
    }

    ch->tx_active = CIO_FALSE;
    return 0;
}

/*
 * Drop changes done since a transaction was initiated */
int cio_chunk_tx_rollback(struct cio_chunk *ch)
{
    int type;
    struct cio_memfs *mf;
    struct cio_file *cf;

    if (ch->tx_active == CIO_TRUE) {
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
    return 0;
}
