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
#include <chunkio/cio_utils.h>
#include <chunkio/chunkio_compat.h>
#include <chunkio/cio_memfs.h>
#include <chunkio/cio_log.h>

#include <stdio.h>
#include <string.h>
#include <limits.h>

struct cio_memfs *cio_memfs_open(struct cio_ctx *ctx, struct cio_stream *st,
                                 struct cio_chunk *ch, int flags,
                                 size_t size)
{
    struct cio_memfs *mf;

    (void) flags;
    (void) ctx;
    (void) ch;
    (void) st;

    mf = calloc(1, sizeof(struct cio_memfs));
    if (!mf) {
        cio_errno();
        return NULL;
    }
    mf->crc_cur = cio_crc32_init();

    mf->buf_data = malloc(size);
    if (!mf->buf_data) {
        cio_errno();
        free(mf->name);
        free(mf);
        return NULL;
    }
    mf->buf_size = size;
    mf->buf_len = 0;
    mf->realloc_size = cio_getpagesize() * 8;

    return mf;
}

void cio_memfs_close(struct cio_chunk *ch)
{
    struct cio_memfs *mf = ch->backend;

    if (!mf) {
        return;
    }

    free(mf->name);
    free(mf->buf_data);
    free(mf->meta_data);
    free(mf);
}

int cio_memfs_write(struct cio_chunk *ch, const void *buf, size_t count)
{
    size_t av_size;
    size_t new_size;
    char *tmp;
    struct cio_memfs *mf = ch->backend;

    if (count == 0) {
        return 0;
    }

    /* Calculate available size */
    av_size = (mf->buf_size - mf->buf_len);
    if (av_size < count) {

        /* Suggest initial new size */
        new_size = mf->buf_size + mf->realloc_size;
        while (new_size < (mf->buf_len + count)) {
            new_size += mf->realloc_size;
        }

        tmp = realloc(mf->buf_data, new_size);
        if (!tmp) {
            cio_errno();
            return -1;
        }

        mf->buf_data = tmp;
        mf->buf_size = new_size;
    }

    memcpy(mf->buf_data + mf->buf_len, buf, count);
    mf->buf_len += count;

    return 0;
}

int cio_memfs_content_copy(struct cio_chunk *ch,
                           void **out_buf, size_t *out_size)
{
    char *buf;
    struct cio_memfs *mf = ch->backend;

    buf = malloc(mf->buf_len + 1);
    if (!buf) {
        cio_errno();
        return -1;
    }

    /* Copy the data and append an extra NULL byte */
    memcpy(buf, mf->buf_data, mf->buf_len);
    buf[mf->buf_len] = '\0';

    *out_buf = buf;
    *out_size = mf->buf_len;

    return 0;
}

void cio_memfs_scan_dump(struct cio_ctx *ctx, struct cio_stream *st)
{
    char tmp[PATH_MAX];
    struct mk_list *head;
    struct cio_memfs *mf;
    struct cio_chunk *ch;

    (void) ctx;

    mk_list_foreach(head, &st->chunks) {
        ch = mk_list_entry(head, struct cio_chunk, _head);
        mf = ch->backend;

        snprintf(tmp, sizeof(tmp) -1, "%s/%s", ch->st->name, ch->name);
        printf("        %-60s", tmp);
        printf("meta_len=%i, data_size=%zu\n", mf->meta_len, mf->buf_len);
    }
}
