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

/*
 * this function sets metadata into a fstore_file structure, note that it makes
 * it own copy of the data to set a NULL byte at the end.
 */
static int meta_set(struct flb_fstore_file *fsf, void *meta, size_t size)
{

    char *p;

    p = flb_calloc(1, size + 1);
    if (!p) {
        flb_errno();
        flb_error("[fstore] could not cache metadata in file: %s:%s",
                  fsf->stream->name, fsf->chunk->name);
        return -1;
    }

    if (fsf->meta_buf) {
        flb_free(fsf->meta_buf);
    }
    fsf->meta_buf = p;
    memcpy(fsf->meta_buf, meta, size);
    fsf->meta_size = size;

    return 0;
}

/* Set a file metadata */
int flb_fstore_file_meta_set(struct flb_fstore *fs,
                             struct flb_fstore_file *fsf,
                             void *meta, size_t size)
{
    int ret;
    int set_down = FLB_FALSE;

    /* Check if the chunk is up */
    if (cio_chunk_is_up(fsf->chunk) == CIO_FALSE) {
        ret = cio_chunk_up_force(fsf->chunk);
        if (ret != CIO_OK) {
            flb_error("[fstore] error loading up file chunk");
            return -1;
        }
        set_down = FLB_TRUE;
    }

    ret = cio_meta_write(fsf->chunk, meta, size);
    if (ret == -1) {
        flb_error("[fstore] could not write metadata to file: %s:%s",
                  fsf->stream->name, fsf->chunk->name);

        if (set_down == FLB_TRUE) {
            cio_chunk_down(fsf->chunk);
        }

        return -1;
    }

    if (set_down == FLB_TRUE) {
        cio_chunk_down(fsf->chunk);
    }

    return meta_set(fsf, meta, size);
}

/* Re-read Chunk I/O metadata into fstore file */
int flb_fstore_file_meta_get(struct flb_fstore *fs,
                             struct flb_fstore_file *fsf)
{
    int ret;
    int set_down = FLB_FALSE;
    char *meta_buf = NULL;
    int meta_size = 0;

    /* Check if the chunk is up */
    if (cio_chunk_is_up(fsf->chunk) == CIO_FALSE) {
        ret = cio_chunk_up_force(fsf->chunk);
        if (ret != CIO_OK) {
            flb_error("[fstore] error loading up file chunk");
            return -1;
        }
        set_down = FLB_TRUE;
    }

    ret = cio_meta_read(fsf->chunk, &meta_buf, &meta_size);
    if (ret == -1) {
        flb_error("[fstore] error reading file chunk metadata");
        if (set_down == FLB_TRUE) {
            cio_chunk_down(fsf->chunk);
        }
    }

    ret = meta_set(fsf, meta_buf, meta_size);
    if (ret == -1) {
        flb_free(meta_buf);
        if (set_down == FLB_TRUE) {
            cio_chunk_down(fsf->chunk);
        }
        return -1;
    }

    if (set_down == FLB_TRUE) {
        cio_chunk_down(fsf->chunk);
    }
    return 0;
}

/* Create a new file */
struct flb_fstore_file *flb_fstore_file_create(struct flb_fstore *fs,
                                               struct flb_fstore_stream *fs_stream,
                                               char *name, size_t size)
{
    int err;
    struct cio_chunk *chunk;
    struct flb_fstore_file *fsf;

    fsf = flb_calloc(1, sizeof(struct flb_fstore_file));
    if (!fsf) {
        flb_errno();
        return NULL;
    }
    fsf->stream = fs_stream->stream;

    fsf->name = flb_sds_create(name);
    if (!fsf->name) {
        flb_error("[fstore] could not create file: %s:%s",
                  fsf->stream->name, name);
        flb_free(fsf);
        return NULL;
    }

    chunk = cio_chunk_open(fs->cio, fs_stream->stream, name,
                           CIO_OPEN, size, &err);
    if (!chunk) {
        flb_error("[fstore] could not create file: %s:%s",
                  fsf->stream->name, name);
        flb_sds_destroy(fsf->name);
        flb_free(fsf);
        return NULL;
    }

    fsf->chunk = chunk;
    mk_list_add(&fsf->_head, &fs_stream->files);

    return fsf;
}

/* Lookup file on stream by using it name */
struct flb_fstore_file *flb_fstore_file_get(struct flb_fstore *fs,
                                            struct flb_fstore_stream *fs_stream,
                                            char *name, size_t size)
{
    struct mk_list *head;
    struct flb_fstore_file *fsf;

    mk_list_foreach(head, &fs_stream->files) {
        fsf = mk_list_entry(head, struct flb_fstore_file, _head);
        if (flb_sds_len(fsf->name) != size) {
            continue;
        }

        if (strncmp(fsf->name, name, size) == 0) {
            return fsf;
        }
    }

    return NULL;
}

/*
 * Set a file to inactive mode. Inactive means just to remove the reference
 * from the list.
 */
static int chunk_is_linked_to_stream(struct flb_fstore_file *fsf)
{
    struct mk_list *head;
    struct cio_chunk *chunk;

    if (fsf == NULL || fsf->chunk == NULL || fsf->stream == NULL) {
        return FLB_FALSE;
    }

    mk_list_foreach(head, &fsf->stream->chunks) {
        chunk = mk_list_entry(head, struct cio_chunk, _head);

        if (chunk == fsf->chunk) {
            return FLB_TRUE;
        }
    }

    return FLB_FALSE;
}

int flb_fstore_file_inactive(struct flb_fstore *fs,
                             struct flb_fstore_file *fsf)
{
    /* close the Chunk I/O reference, but don't delete the real file */
    if (chunk_is_linked_to_stream(fsf) == FLB_TRUE) {
        cio_chunk_close(fsf->chunk, CIO_FALSE);
        fsf->chunk = NULL;
    }

    /* release */
    mk_list_del(&fsf->_head);
    flb_sds_destroy(fsf->name);
    if (fsf->meta_buf) {
        flb_free(fsf->meta_buf);
    }
    flb_free(fsf);

    return 0;
}

/* Delete a file (permantent deletion) */
int flb_fstore_file_delete(struct flb_fstore *fs,
                           struct flb_fstore_file *fsf)
{
    /* close the Chunk I/O reference, but don't delete it the real file */
    if (chunk_is_linked_to_stream(fsf) == FLB_TRUE) {
        cio_chunk_close(fsf->chunk, CIO_TRUE);
        fsf->chunk = NULL;
    }

    /* release */
    mk_list_del(&fsf->_head);
    if (fsf->meta_buf) {
        flb_free(fsf->meta_buf);
    }
    flb_sds_destroy(fsf->name);
    flb_free(fsf);

    return 0;
}

/*
 * Set an output buffer that contains a copy of the file. Note that this buffer
 * needs to be freed by the caller (heap memory).
 */
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

/* Append data to an existing file */
int flb_fstore_file_append(struct flb_fstore_file *fsf, void *data, size_t size)
{
    int ret;
    int set_down = FLB_FALSE;

    /* Check if the chunk is up */
    if (cio_chunk_is_up(fsf->chunk) == CIO_FALSE) {
        ret = cio_chunk_up_force(fsf->chunk);
        if (ret != CIO_OK) {
            flb_error("[fstore] error loading up file chunk");
            return -1;
        }
        set_down = FLB_TRUE;
    }

    ret = cio_chunk_write(fsf->chunk, data, size);
    if (ret != CIO_OK) {
        flb_error("[fstore] could not write data to file %s", fsf->name);

        if (set_down == FLB_TRUE) {
            cio_chunk_down(fsf->chunk);
        }

        return -1;
    }

    if (set_down == FLB_TRUE) {
        cio_chunk_down(fsf->chunk);
    }

    return 0;
}

/*
 * Create a new stream, if it already exists, it returns the stream
 * reference.
 */
struct flb_fstore_stream *flb_fstore_stream_create(struct flb_fstore *fs,
                                                   char *stream_name)
{
    flb_sds_t path = NULL;
    struct mk_list *head;
    struct cio_ctx *ctx = NULL;
    struct cio_stream *stream = NULL;
    struct flb_fstore_stream *fs_stream = NULL;

    ctx = fs->cio;

    /* Check if the stream already exists in Chunk I/O */
    mk_list_foreach(head, &ctx->streams) {
        stream = mk_list_entry(head, struct cio_stream, _head);
        if (strcmp(stream->name, stream_name) == 0) {
            break;
        }
        stream = NULL;
    }

    /* If the stream exists, check if we have a fstore_stream reference */
    if (stream) {
        mk_list_foreach(head, &fs->streams) {
            fs_stream = mk_list_entry(head, struct flb_fstore_stream, _head);
            if (fs_stream->stream == stream) {
                break;
            }
            fs_stream = NULL;
        }

        /* The stream was found, just return the reference */
        if (fs_stream) {
            return fs_stream;
        }
    }

    if (!stream) {
        /* create file-system based stream */
        stream = cio_stream_create(fs->cio, stream_name, fs->store_type);
        if (!stream) {
            flb_error("[fstore] cannot create stream %s", stream_name);
            return NULL;
        }
    }

    fs_stream = flb_calloc(1, sizeof(struct flb_fstore_stream));
    if (!fs_stream) {
        flb_errno();
        cio_stream_destroy(stream);
        return NULL;
    }
    fs_stream->stream = stream;

    path = flb_sds_create_size(256);
    if (!path) {
        cio_stream_destroy(stream);
        flb_free(fs_stream);
        return NULL;
    }
    path = flb_sds_printf(&path, "%s/%s", fs->root_path, stream->name);
    fs_stream->path = path;
    fs_stream->name = stream->name;

    mk_list_init(&fs_stream->files);
    mk_list_add(&fs_stream->_head, &fs->streams);

    return fs_stream;
}

void flb_fstore_stream_destroy(struct flb_fstore_stream *stream, int delete)
{
    if (delete == FLB_TRUE) {
        cio_stream_delete(stream->stream);
    }

    /*
     * FYI: in this function we just release the fstore_stream context, the
     * underlaying cio_stream is closed when the main Chunk I/O is destroyed.
     */
    mk_list_del(&stream->_head);
    flb_sds_destroy(stream->path);
    flb_free(stream);
}

static int map_chunks(struct flb_fstore *ctx, struct flb_fstore_stream *fs_stream,
                      struct cio_stream *stream)
{
    struct mk_list *head;
    struct cio_chunk *chunk;
    struct flb_fstore_file *fsf;

    mk_list_foreach(head, &stream->chunks) {
        chunk = mk_list_entry(head, struct cio_chunk, _head);

        fsf = flb_calloc(1, sizeof(struct flb_fstore_file));
        if (!fsf) {
            flb_errno();
            return -1;
        }
        fsf->name = flb_sds_create(chunk->name);
        if (!fsf->name) {
            flb_free(fsf);
            flb_error("[fstore] could not create file: %s:%s",
                      stream->name, chunk->name);
            return -1;
        }

        fsf->stream = stream;
        fsf->chunk = chunk;

        /* load metadata */
        flb_fstore_file_meta_get(ctx, fsf);
        mk_list_add(&fsf->_head, &fs_stream->files);
    }

    return 0;
}

static int load_references(struct flb_fstore *fs)
{
    int ret;
    struct mk_list *head;
    struct cio_stream *stream;
    struct flb_fstore_stream *fs_stream;

    mk_list_foreach(head, &fs->cio->streams) {
        stream = mk_list_entry(head, struct cio_stream, _head);
        fs_stream = flb_fstore_stream_create(fs, stream->name);
        if (!fs_stream) {
            flb_error("[fstore] error loading stream reference: %s",
                      stream->name);
            return -1;
        }

        /* Map chunks */
        ret = map_chunks(fs, fs_stream, stream);
        if (ret == -1) {
            return -1;
        }
    }

    return 0;
}

struct flb_fstore *flb_fstore_create(char *path, int store_type)
{
    int ret;
    int flags;
    struct cio_ctx *cio;
    struct flb_fstore *fs;
    struct cio_options opts = {0};
    flags = CIO_OPEN;

    /* Create Chunk I/O context */
    cio_options_init(&opts);

    opts.root_path = path;
    opts.log_cb = log_cb;
    opts.flags = flags;
    opts.log_level = CIO_LOG_INFO;

    cio = cio_create(&opts);
    if (!cio) {
        flb_error("[fstore] error initializing on path '%s'", path);
        return NULL;
    }

    /* Load content from the file system if any */
    ret = cio_load(cio, NULL);
    if (ret == -1) {
        flb_error("[fstore] error scanning root path content: %s", path);
        cio_destroy(cio);
        return NULL;
    }

    fs = flb_calloc(1, sizeof(struct flb_fstore));
    if (!fs) {
        flb_errno();
        cio_destroy(cio);
        return NULL;
    }
    fs->cio = cio;
    fs->root_path = cio->options.root_path;
    fs->store_type = store_type;
    mk_list_init(&fs->streams);

    /* Map Chunk I/O streams and chunks into fstore context */
    load_references(fs);

    return fs;
}

int flb_fstore_destroy(struct flb_fstore *fs)
{
    int files = 0;
    int delete;
    struct mk_list *head;
    struct mk_list *f_head;
    struct mk_list *tmp;
    struct mk_list *f_tmp;
    struct flb_fstore_stream *fs_stream;
    struct flb_fstore_file *fsf;

    mk_list_foreach_safe(head, tmp, &fs->streams) {
        fs_stream = mk_list_entry(head, struct flb_fstore_stream, _head);

        /* delete file references */
        files = 0;
        mk_list_foreach_safe(f_head, f_tmp, &fs_stream->files) {
            fsf = mk_list_entry(f_head, struct flb_fstore_file, _head);
            flb_fstore_file_inactive(fs, fsf);
            files++;
        }

        if (files == 0) {
            delete = FLB_TRUE;
        }
        else {
            delete = FLB_FALSE;
        }

        flb_fstore_stream_destroy(fs_stream, delete);
    }

    if (fs->cio) {
        cio_destroy(fs->cio);
    }
    flb_free(fs);
    return 0;
}

void flb_fstore_dump(struct flb_fstore *fs)
{
    struct mk_list *head;
    struct mk_list *f_head;
    struct flb_fstore_stream *fs_stream;
    struct flb_fstore_file *fsf;

    printf("===== FSTORE DUMP =====\n");
    mk_list_foreach(head, &fs->streams) {
        fs_stream = mk_list_entry(head, struct flb_fstore_stream, _head);
        printf("- stream: %s\n", fs_stream->name);
        mk_list_foreach(f_head, &fs_stream->files) {
            fsf = mk_list_entry(f_head, struct flb_fstore_file, _head);
            printf("          %s/%s\n", fsf->stream->name, fsf->name);
        }
    }
    printf("\n");
}
