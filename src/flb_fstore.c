/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2020 The Fluent Bit Authors
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
#include <fluent-bit/flb_fstore.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_sds.h>
#include <chunkio/chunkio.h>

static int log_cb(struct cio_ctx *ctx, int level, const char *file, int line,
                  char *str)
{
    if (level == CIO_LOG_ERROR) {
        flb_error("[fstore] %s", str);
    }
    else if (level == CIO_LOG_WARN) {
        flb_warn("[fstore] %s", str);
    }
    else if (level == CIO_LOG_INFO) {
        flb_info("[fstore] %s", str);
    }
    else if (level == CIO_LOG_DEBUG) {
        flb_debug("[fstore] %s", str);
    }

    return 0;
}

int flb_fstore_file_meta_set(struct flb_fstore *fs,
                               struct flb_fstore_file *fsf,
                               void *meta, size_t size)
{
    int ret;

    ret = cio_meta_write(fsf->chunk, meta, size);
    if (ret == -1) {
        flb_error("[fstore] could not write metadata to file: %s:%s",
                  fs->stream->name, fsf->chunk->name);
        return -1;
    }

    if (fsf->meta_buf) {
        flb_free(fsf->meta_buf);
    }

    fsf->meta_buf = flb_calloc(1, size + 1);
    if (!fsf->meta_buf) {
        flb_errno();
        flb_error("[fstore] could not cache metadata in file: %s:%s",
                  fs->stream->name, fsf->chunk->name);
        fsf->meta_size = 0;
        return -1;
    }
    memcpy(fsf->meta_buf, meta, size);
    fsf->meta_size = size;

    return 0;
}

struct flb_fstore_file *flb_fstore_file_create(struct flb_fstore *fs, char *name,
                                                   size_t size)
{
    int err;
    struct cio_chunk *chunk;
    struct flb_fstore_file *fsf;

    fsf = flb_calloc(1, sizeof(struct flb_fstore_file));
    if (!fsf) {
        flb_errno();
        return NULL;
    }
    fsf->name = flb_sds_create(name);
    if (!fsf->name) {
        flb_free(fsf);
        flb_error("[fstore] could not create file: %s:%s",
                  fs->stream->name, name);
        return NULL;
    }

    chunk = cio_chunk_open(fs->cio, fs->stream, name, CIO_OPEN, size, &err);
    if (!chunk) {
        flb_free(fsf);
        flb_error("[fstore] could not create file: %s:%s",
                  fs->stream->name, name);
        return NULL;
    }

    fsf->chunk = chunk;
    mk_list_add(&fsf->_head, &fs->files);

    return fsf;
}

/*
 * Set a file to inactive mode. Inactive means just to remove it reference from the
 * list.
 */
int flb_fstore_file_inactive(struct flb_fstore *fs,
                               struct flb_fstore_file *fsf)
{
    /* close the Chunk I/O reference, but don't delete the real file */
    cio_chunk_close(fsf->chunk, CIO_FALSE);

    /* release */
    mk_list_del(&fsf->_head);
    flb_sds_destroy(fsf->name);
    flb_free(fsf);

    return 0;
}

/* Delete a file (permantent deletion) */
int flb_fstore_file_delete(struct flb_fstore *fs,
                             struct flb_fstore_file *fsf)
{
    /* close the Chunk I/O reference, but don't delete it the real file */
    cio_chunk_close(fsf->chunk, CIO_TRUE);

    /* release */
    mk_list_del(&fsf->_head);
    if (fsf->meta_buf) {
        flb_free(fsf->meta_buf);
    }
    flb_sds_destroy(fsf->name);
    flb_free(fsf);

    return 0;
}

int flb_fstore_file_content_copy(struct flb_fstore *fs,
                                   struct flb_fstore_file *fsf,
                                   void **out_buf, size_t *out_size)
{
    int ret;

    ret = cio_chunk_get_content_copy(fsf->chunk, out_buf, out_size);
    if (ret == CIO_OK) {
        return 0;
    }

    return -1;
}

int flb_fstore_file_append(struct flb_fstore_file *fsf, void *data, size_t size)
{
    int ret;

    ret = cio_chunk_write(fsf->chunk, data, size);
    if (ret != CIO_OK) {
        flb_error("[fstore] could not write data to file %s", fsf->name);
        return -1;
    }

    return 0;
}

struct flb_fstore *flb_fstore_create(char *path, char *stream_name)
{
    int ret;
    int flags;
    struct cio_ctx *cio;
    struct cio_stream *stream;
    struct flb_fstore *fs;

    flags = CIO_OPEN;

    /* Create Chunk I/O context */
    cio = cio_create(path, log_cb, CIO_LOG_DEBUG, flags);
    if (!cio) {
        flb_error("[fstore] error initializing on '%s'", path);
        return NULL;
    }

    /* Load content from the file system if any */
    ret = cio_load(cio, NULL);
    if (ret == -1) {
        flb_error("[fstore] error scanning root path content: %s", path);
        cio_destroy(cio);
        return NULL;
    }

    fs = flb_malloc(sizeof(struct flb_fstore));
    if (!fs) {
        flb_errno();
        cio_destroy(cio);
        return NULL;
    }
    mk_list_init(&fs->files);

    /* create file-system based stream */
    stream = cio_stream_create(cio, stream_name, CIO_STORE_FS);
    if (!stream) {
        flb_error("[fstore] cannot create stream %s/%s", path, stream);
        cio_destroy(cio);
        return NULL;
    }
    fs->cio = cio;
    fs->stream = stream;

    return fs;
}

int flb_fstore_destroy(struct flb_fstore *fs)
{
    if (fs->cio) {
        cio_destroy(fs->cio);
    }
    flb_free(fs);
    return 0;
}
