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

#define _GNU_SOURCE
#include <string.h>

#include <chunkio/chunkio_compat.h>
#include <chunkio/chunkio.h>
#include <chunkio/cio_file.h>
#include <chunkio/cio_file_st.h>
#include <chunkio/cio_memfs.h>
#include <chunkio/cio_stream.h>
#include <chunkio/cio_log.h>

/*
 * Metadata is an optional information stored before the content of each file
 * and can be used for different purposes. Manipulating metadata can have
 * some performance impacts depending on 'when' it's added and how often
 * is modified.
 *
 * For performance reasons, we suggest the metadata be stored before to write
 * any data to the content area, otherwise if metadata grows in terms of bytes
 * we need to move all the content data to a different position which is not
 * ideal.
 *
 * The caller might want to fix the performance penalties setting up some
 * empty metadata with specific sizes.
 */

int cio_meta_write(struct cio_chunk *ch, char *buf, size_t size)
{
    struct cio_memfs *mf;

    if (size > 65535) {
        return -1;
    }

    if (ch->st->type == CIO_STORE_MEM) {
        mf = (struct cio_memfs *) ch->backend;
        if (mf->meta_data) {
            free(mf->meta_data);
        }

        mf->meta_data = malloc(size);
        if (!mf->meta_data) {
            cio_errno();
            return -1;
        }
        memcpy(mf->meta_data, buf, size);
        mf->meta_len = size;
        return 0;
    }
    else if (ch->st->type == CIO_STORE_FS) {
        return cio_file_write_metadata(ch, buf, size);
    }
    return -1;
}

int cio_meta_size(struct cio_chunk *ch) {
    if (ch->st->type == CIO_STORE_MEM) {
        struct cio_memfs *mf = (struct cio_memfs *) ch->backend;
        return mf->meta_len;
    }
    else if (ch->st->type == CIO_STORE_FS) {
        if (cio_file_read_prepare(ch->ctx, ch)) {
            return -1;
        }
        struct cio_file *cf = ch->backend;
        return cio_file_st_get_meta_len(cf->map);
    }

    return -1;
}

int cio_meta_read(struct cio_chunk *ch, char **meta_buf, int *meta_len)
{
    int len;
    char *meta;
    struct cio_file *cf;
    struct cio_memfs *mf;

    /* In-memory type */
    if (ch->st->type == CIO_STORE_MEM) {
        mf = (struct cio_memfs *) ch->backend;

        /* no metadata */
        if (!mf->meta_data) {
            return -1;
        }

        *meta_buf = mf->meta_data;
        *meta_len = mf->meta_len;

        return 0;
    }
    else if (ch->st->type == CIO_STORE_FS) {
        if (cio_file_read_prepare(ch->ctx, ch)) {
            return -1;
        }

        cf = ch->backend;
        len = cio_file_st_get_meta_len(cf->map);
        if (len <= 0) {
            return -1;
        }

        meta = cio_file_st_get_meta(cf->map);
        *meta_buf = meta;
        *meta_len = len;

        return 0;
    }

    return -1;

}

int cio_meta_cmp(struct cio_chunk *ch, char *meta_buf, int meta_len)
{
    int len;
    char *meta;
    struct cio_file *cf = ch->backend;
    struct cio_memfs *mf;

    /* In-memory type */
    if (ch->st->type == CIO_STORE_MEM) {
        mf = (struct cio_memfs *) ch->backend;

        /* no metadata */
        if (!mf->meta_data) {
            return -1;
        }

        /* different lengths */
        if (mf->meta_len != meta_len) {
            return -1;
        }

        /* perfect match */
        if (memcmp(mf->meta_data, meta_buf, meta_len) == 0) {
            return 0;
        }

        return -1;
    }

    if (cio_file_read_prepare(ch->ctx, ch)) {
        return -1;
    }

    /* File system type */
    len = cio_file_st_get_meta_len(cf->map);
    if (len != meta_len) {
        return -1;
    }

    /* compare metadata */
    meta = cio_file_st_get_meta(cf->map);
    if (memcmp(meta, meta_buf, meta_len) == 0) {
        return 0;
    }

    return -1;
}
