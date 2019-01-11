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

    return mf;
}

void cio_memfs_close(struct cio_chunk *ch)
{
    struct cio_memfs *mf = ch->backend;

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
    av_size = mf->buf_size - mf->buf_len;
    if (count > av_size) {
        if (av_size + mf->realloc_size < count) {
            new_size = mf->buf_size + count;
        }
        else {
            new_size = mf->buf_size + mf->realloc_size;
        }

        /* Get a bigger buffer */
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

void cio_memfs_scan_dump(struct cio_ctx *ctx, struct cio_stream *st)
{
    char tmp[PATH_MAX];
    struct mk_list *head;
    struct cio_memfs *mf;
    struct cio_chunk *ch;

    mk_list_foreach(head, &st->files) {
        ch = mk_list_entry(head, struct cio_chunk, _head);
        mf = ch->backend;

        snprintf(tmp, sizeof(tmp) -1, "%s/%s", ch->st->name, ch->name);
        printf("        %-60s", tmp);
        printf("meta_len=%i, data_size=%lu\n", mf->meta_len, mf->buf_len);
    }
}
