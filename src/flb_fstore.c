/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2021 The Fluent Bit Authors
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

/* remove file from files_up list */
static inline void files_up_remove(struct flb_fstore *fs,
                            struct flb_fstore_file *fsf)
{
    if (fsf->_cache_head.next == NULL) {
        return;
    }

    mk_list_del(&fsf->_cache_head);
    --fs->files_up_counter;
}

/*
 * this function adds files to an fstore files_up list to track files that are
 * mapped. the files_up list's order corresponds to how recent add is called on
 * the files in the files_up list. recent files last, least recent files are first.
 * max of max_chunks_up files allowed before eviction of least recently added file
 *
 * returns NULL or any file that is removed from the files_up list to maintian a max
 * max_chunks_up files
 */
static struct flb_fstore_file *files_up_add(struct flb_fstore *fs,
                         struct flb_fstore_file *fsf)
{
    struct flb_fstore_file *evict = NULL;

    /* check if already in files_up */
    if (fsf->_cache_head.next != NULL) {
        /* send to back of list; renew */
        files_up_remove(fs, fsf);
        files_up_add(fs, fsf);
        return NULL;
    }
 
    /* files_up cache full */
    if (fs->files_up_counter >= fs->cio->max_chunks_up) {
        /* evict oldest entry, first */
        evict = mk_list_entry(fs->files_up.next, struct flb_fstore_file, _cache_head);
        files_up_remove(fs, evict);
    }

    /* add to files_up list, last */
    mk_list_add(&fsf->_cache_head, &fs->files_up);
    ++fs->files_up_counter;
    return evict;
}

/*
 * book keeping & possible unmapping to be done before file brought up by cio_chunk_up()
 * lets down file if needed, fsf must be brought up soon after by caller
 * returns -1 on failure, 0 on success
 */
static int file_up_prep(struct flb_fstore *fs, /* previously files_up_make_room */
                         struct flb_fstore_file *fsf)
{
    struct flb_fstore_file *evict;
    int ret;

    evict = files_up_add(fs, fsf);
    if (evict != NULL) {
        /* let down file, unmap */
        ret = cio_chunk_down(evict->chunk);
        if (ret != CIO_OK) {
            flb_error("[fstore] error unmapping file chunk: %s:%s",
                      fsf->stream->name, fsf->chunk->name);
            return -1;
        }
    }
    return 0;
}

/*
 * this function memory maps a file if it is unmapped, changing the file's state to up
 * if it is down. if fsf->max_chunks_up files are up, a the least recently checked file
 * will be evicted
 * 
 * files_up record is reordered to put recently checked files last.
 */
static int file_up_if_down(struct flb_fstore *fs,
                            struct flb_fstore_file *fsf)
{
    int is_up;
    int ret;

    /* check if already in up_files list */
    is_up = fsf->_cache_head.next != NULL;

    ret = file_up_prep(fs, fsf);
    if (ret == -1) {
        flb_error("[fstore] error preparing for file up: %s:%s",
                      fsf->stream->name, fsf->chunk->name);
        return -1;
    }

    /* memory map chunk */
    if (!is_up) {
        ret = cio_chunk_up(fsf->chunk);
        if (ret != CIO_OK) {
            flb_error("[fstore] error mapping file chunk: %s:%s",
                      fsf->stream->name, fsf->chunk->name);
            return -1;
        }
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

    ret = file_up_if_down(fs, fsf);
    if (ret == -1) {
        flb_error("[fstore] file_meta_set could not bring up file: %s:%s",
                  fsf->stream->name, fsf->chunk->name);
        return -1;
    }

    ret = cio_meta_write(fsf->chunk, meta, size);
    if (ret == -1) {
        flb_error("[fstore] could not write metadata to file: %s:%s",
                  fsf->stream->name, fsf->chunk->name);
        return -1;
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

    file_up_prep(fs, fsf);
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
int flb_fstore_file_inactive(struct flb_fstore *fs,
                             struct flb_fstore_file *fsf)
{
    /* remove from up list */
    files_up_remove(fs, fsf);

    /* close the Chunk I/O reference, but don't delete the real file */
    if (fsf->chunk) {
        cio_chunk_close(fsf->chunk, CIO_FALSE);
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
    /* remove from up list */
    files_up_remove(fs, fsf);
    
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

/*
 * Set an output buffer that contains a copy of the file. Note that this buffer
 * needs to be freed by the caller (heap memory).
 */
int flb_fstore_file_content_copy(struct flb_fstore *fs,
                                 struct flb_fstore_file *fsf,
                                 void **out_buf, size_t *out_size)
{
    int ret;

    ret = file_up_if_down(fs, fsf);
    if (ret == -1) {
        flb_error("[fstore] file_content_copy could not bring up file: %s:%s",
                  fsf->stream->name, fsf->chunk->name);
        return -1;
    }

    ret = cio_chunk_get_content_copy(fsf->chunk, out_buf, out_size);
    if (ret == CIO_OK) {
        return 0;
    }

    return -1;
}

/* Append data to an existing file */
int flb_fstore_file_append(struct flb_fstore *fs,
                           struct flb_fstore_file *fsf,
                           void *data, size_t size)
{
    int ret;

    ret = file_up_if_down(fs, fsf);
    if (ret == -1) {
        flb_error("[fstore] file_append could not bring up file: %s:%s",
                  fsf->stream->name, fsf->chunk->name);
        return -1;
    }
    
    ret = cio_chunk_write(fsf->chunk, data, size);
    if (ret != CIO_OK) {
        flb_error("[fstore] could not write data to file %s", fsf->name);
        return -1;
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

void flb_fstore_stream_destroy(struct flb_fstore *fs,
                               struct flb_fstore_stream *stream,
                               int delete)
{   
    struct flb_fstore_file *fsf;
    struct mk_list *head;

    if (delete == FLB_TRUE) {
        cio_stream_delete(stream->stream);

        /* remove stream files from fstore files_up up list */
        mk_list_foreach(head, &stream->files) {
            fsf = mk_list_entry(head, struct flb_fstore_file, _head);
            files_up_remove(fs, fsf);
        }
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
    int ret;

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

        fsf->chunk = chunk;

        /* load metadata */
        flb_fstore_file_meta_get(ctx, fsf);
        mk_list_add(&fsf->_head, &fs_stream->files);

        /* add to up list */
        ret = cio_chunk_is_up(chunk);
        if (ret == CIO_TRUE) {
            files_up_add(ctx, fsf);
        }
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

    flags = CIO_OPEN;

    /* Create Chunk I/O context */
    cio = cio_create(path, log_cb, CIO_LOG_DEBUG, flags);
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
    fs->root_path = cio->root_path;
    fs->store_type = store_type;
    mk_list_init(&fs->streams);
    mk_list_init(&fs->files_up);
    fs->files_up_counter = 0;

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

        flb_fstore_stream_destroy(fs, fs_stream, delete);
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
    int is_up;

    printf("===== FSTORE DUMP =====\n");
    mk_list_foreach(head, &fs->streams) {
        fs_stream = mk_list_entry(head, struct flb_fstore_stream, _head);
        printf("- stream: %s\n", fs_stream->name);
        mk_list_foreach(f_head, &fs_stream->files) {
            fsf = mk_list_entry(f_head, struct flb_fstore_file, _head);
            is_up = cio_chunk_is_up(fsf->chunk);
            printf("          %s/%s (%s)\n", fsf->stream->name, fsf->name,
                   (is_up) ? "up" : "down");
        }
    }
    printf("\n");
}
