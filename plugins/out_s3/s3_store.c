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

#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_fstore.h>
#include <fluent-bit/flb_time.h>

#include "s3.h"
#include "s3_store.h"

/*
 * Simple and fast hashing algorithm to create keys in the local buffer
 */
static flb_sds_t gen_store_filename(const char *tag)
{
    int c;
    unsigned long hash = 5381;
    unsigned long hash2 = 5381;
    flb_sds_t hash_str;
    flb_sds_t tmp;
    struct flb_time tm;

    /* get current time */
    flb_time_get(&tm);

    /* compose hash */
    while ((c = *tag++)) {
        hash = ((hash << 5) + hash) + c; /* hash * 33 + c */
    }
    hash2 = (unsigned long) hash2 * tm.tm.tv_sec * tm.tm.tv_nsec;

    /* flb_sds_printf allocs if the incoming sds is not at least 64 bytes */
    hash_str = flb_sds_create_size(64);
    if (!hash_str) {
        flb_errno();
        return NULL;
    }
    tmp = flb_sds_printf(&hash_str, "%lu-%lu", hash, hash2);
    if (!tmp) {
        flb_errno();
        flb_sds_destroy(hash_str);
        return NULL;
    }
    hash_str = tmp;

    return hash_str;
}

/* Retrieve a candidate s3 local file using the tag */
struct s3_file *s3_store_file_get(struct flb_s3 *ctx, const char *tag,
                                  int tag_len)
{
    struct mk_list *head;
    struct flb_fstore_file *fsf = NULL;

    /*
     * Based in the current ctx->stream_name, locate a candidate file to
     * store the incoming data using as a lookup pattern the content Tag.
     */
    mk_list_foreach(head, &ctx->stream_active->files) {
        fsf = mk_list_entry(head, struct flb_fstore_file, _head);
        if (fsf->meta_size != tag_len) {
            fsf = NULL;
            continue;
        }

        /* compare meta and tag */
        if (strncmp((char *) fsf->meta_buf, tag, tag_len) == 0) {
            break;
        }

        /* not found, invalidate the reference */
        fsf = NULL;
    }

    if (!fsf) {
        return NULL;
    }

    return fsf->data;
}

/* Append data to a new or existing fstore file */
int s3_store_buffer_put(struct flb_s3 *ctx, struct s3_file *s3_file,
                        const char *tag, int tag_len,
                        char *data, size_t bytes)
{
    int ret;
    flb_sds_t name;
    struct flb_fstore_file *fsf;

    /* If no target file was found, create a new one */
    if (!s3_file) {
        name = gen_store_filename(tag);
        if (!name) {
            flb_plg_error(ctx->ins, "could not generate chunk file name");
            return -1;
        }

        /* Create the file */
        fsf = flb_fstore_file_create(ctx->fs, ctx->stream_active, name, bytes);
        if (!fsf) {
            flb_plg_error(ctx->ins, "could not create the file '%s' in the store",
                          name);
            flb_sds_destroy(name);
            return -1;
        }
        flb_sds_destroy(name);

        /* Write tag as metadata */
        ret = flb_fstore_file_meta_set(ctx->fs, fsf, (char *) tag, tag_len);
        if (ret == -1) {
            flb_plg_error(ctx->ins, "error writing tag metadata");
            return -1;
        }

        /* Allocate local context */
        s3_file = flb_calloc(1, sizeof(struct s3_file));
        if (!s3_file) {
            flb_errno();
            flb_plg_error(ctx->ins, "cannot allocate s3 file context");
            return -1;
        }
        s3_file->fsf = fsf;
        s3_file->create_time = time(NULL);

        /* Use fstore opaque 'data' reference to keep our context */
        fsf->data = s3_file;
    }
    else {
        fsf = s3_file->fsf;
    }

    /* Append data to the target file */
    ret = flb_fstore_file_append(fsf, data, bytes);
    if (ret != 0) {
        flb_plg_error(ctx->ins, "error writing data to local s3 file");
        return -1;
    }
    s3_file->size += bytes;

    return 0;
}

static int set_files_context(struct flb_s3 *ctx)
{
    struct mk_list *head;
    struct mk_list *f_head;
    struct flb_fstore_stream *fs_stream;
    struct flb_fstore_file *fsf;
    struct s3_file *s3_file;

    mk_list_foreach(head, &ctx->fs->streams) {
        fs_stream = mk_list_entry(head, struct flb_fstore_stream, _head);

        /* skip current stream since it's new */
        if (fs_stream == ctx->stream_active) {
            continue;
        }

        /* skip multi-upload */
        if (fs_stream == ctx->stream_upload) {
            continue;
        }

        mk_list_foreach(f_head, &fs_stream->files) {
            fsf = mk_list_entry(f_head, struct flb_fstore_file, _head);
            if (fsf->data) {
                continue;
            }

            /* Allocate local context */
            s3_file = flb_calloc(1, sizeof(struct s3_file));
            if (!s3_file) {
                flb_errno();
                flb_plg_error(ctx->ins, "cannot allocate s3 file context");
                continue;
            }
            s3_file->fsf = fsf;
            s3_file->create_time = time(NULL);

            /* Use fstore opaque 'data' reference to keep our context */
            fsf->data = s3_file;
        }
    }
}

/* Initialize filesystem storage for S3 plugin */
int s3_store_init(struct flb_s3 *ctx)
{
    time_t now;
    char tmp[64];
    struct tm *tm;
    struct flb_fstore *fs;
    struct flb_fstore_stream *fs_stream;

    /* Initialize the storage context */
    fs = flb_fstore_create(ctx->store_dir);
    if (!fs) {
        return -1;
    }
    ctx->fs = fs;

    /*
     * On every start we create a new stream, this stream in the file system
     * is directory with the name using the date like '2020-10-03T13:00:02'. So
     * all the 'new' data that is generated on this process is stored there.
     *
     * Note that previous data in similar directories from previous runs is
     * considered backlog data, in the S3 plugin we need to differenciate the
     * new v/s the older buffered data.
     *
     * Compose a stream name...
     */
    now = time(NULL);
    tm = localtime(&now);
    strftime(tmp, sizeof(tmp) - 1, "%Y-%m-%dT%H:%M:%S", tm);

    /* Create the stream */
    fs_stream = flb_fstore_stream_create(ctx->fs, tmp);
    if (!fs_stream) {
        /* Upon exception abort */
        flb_plg_error(ctx->ins, "could not initialize active stream: %s", tmp);
        flb_fstore_destroy(fs);
        ctx->fs = NULL;
        return -1;
    }
    ctx->stream_active = fs_stream;

    /* Multipart upload stream */
    fs_stream = flb_fstore_stream_create(ctx->fs, "multipart_upload_metadata");
    if (!fs_stream) {
        flb_plg_error(ctx->ins, "could not initialize multipart_upload stream");
        flb_fstore_destroy(fs);
        ctx->fs = NULL;
        return -1;
    }
    ctx->stream_upload = fs_stream;

    set_files_context(ctx);
    return 0;
}

int s3_store_exit(struct flb_s3 *ctx)
{
    struct mk_list *head;
    struct mk_list *f_head;
    struct flb_fstore_stream *fs_stream;
    struct flb_fstore_file *fsf;
    struct s3_file *s3_file;

    /* release local context on non-multi upload files */
    mk_list_foreach(head, &ctx->fs->streams) {
        fs_stream = mk_list_entry(head, struct flb_fstore_stream, _head);
        if (fs_stream == ctx->stream_upload) {
            continue;
        }

        mk_list_foreach(f_head, &fs_stream->files) {
            fsf = mk_list_entry(f_head, struct flb_fstore_file, _head);
            if (fsf->data != NULL) {
                s3_file = fsf->data;
                flb_sds_destroy(s3_file->file_path);
                flb_free(s3_file);
            }
        }
    }

    if (ctx->fs) {
        flb_fstore_destroy(ctx->fs);
    }
    return 0;
}

/*
 * Check if the store has data. This function is only used on plugin
 * initialization
 */
int s3_store_has_data(struct flb_s3 *ctx)
{
    struct mk_list *head;
    struct flb_fstore_stream *fs_stream;

    mk_list_foreach(head, &ctx->fs->streams) {
        /* skip multi upload stream */
        fs_stream = mk_list_entry(head, struct flb_fstore_stream, _head);
        if (fs_stream == ctx->stream_upload) {
            continue;
        }

        if (mk_list_size(&fs_stream->files) > 0) {
            return FLB_TRUE;
        }
    }

    return FLB_FALSE;
}

int s3_store_has_uploads(struct flb_s3 *ctx)
{
    if (mk_list_size(&ctx->stream_upload->files) > 0) {
        return FLB_TRUE;
    }

    return FLB_FALSE;
}

int s3_store_file_inactive(struct flb_s3 *ctx, struct s3_file *s3_file)
{
    int ret;
    struct flb_fstore_file *fsf;

    fsf = s3_file->fsf;
    flb_free(s3_file);
    ret = flb_fstore_file_inactive(ctx->fs, fsf);

    return ret;
}

int s3_store_file_delete(struct flb_s3 *ctx, struct s3_file *s3_file)
{
    struct flb_fstore_file *fsf;

    fsf = s3_file->fsf;

    /* permanent deletion */
    flb_fstore_file_delete(ctx->fs, fsf);
    flb_free(s3_file);

    return 0;
}

int s3_store_file_read(struct flb_s3 *ctx, struct s3_file *s3_file,
                               char **out_buf, size_t *out_size)
{
    int ret;

    ret = flb_fstore_file_content_copy(ctx->fs, s3_file->fsf,
                                       (void **) out_buf, out_size);
    return ret;
}

int s3_store_file_upload_read(struct flb_s3 *ctx, struct flb_fstore_file *fsf,
                              char **out_buf, size_t *out_size)
{
    int ret;

    ret = flb_fstore_file_content_copy(ctx->fs, fsf,
                                       (void **) out_buf, out_size);
    return ret;
}

struct flb_fstore_file *s3_store_file_upload_get(struct flb_s3 *ctx,
                                                 char *key, int key_len)
{
    struct mk_list *head;
    struct flb_fstore_file *fsf = NULL;

    mk_list_foreach(head, &ctx->stream_upload->files) {
        fsf = mk_list_entry(head, struct flb_fstore_file, _head);
        if (fsf->meta_buf == NULL) {
            continue;
        }

        if (fsf->meta_size != key_len ){
            continue;
        }

        if (memcmp(fsf->meta_buf, key, key_len) == 0) {
            break;
        }
        fsf = NULL;
    }

    return fsf;
}

int s3_store_file_upload_put(struct flb_s3 *ctx,
                             struct flb_fstore_file *fsf, flb_sds_t key,
                             flb_sds_t data)
{
    int ret;

    /* Write key as metadata */
    ret = flb_fstore_file_meta_set(ctx->fs, fsf,
                                   key, flb_sds_len(key));
    if (ret == -1) {
        flb_plg_error(ctx->ins, "error writing tag metadata");
        return -1;
    }

    /* Append data to the target file */
    ret = flb_fstore_file_append(fsf, data, flb_sds_len(data));
    if (ret != 0) {
        flb_plg_error(ctx->ins, "error writing data to local s3 file");
        return -1;
    }

    return 0;
}

int s3_store_file_upload_delete(struct flb_s3 *ctx, struct flb_fstore_file *fsf)
{
    /* permanent deletion */
    flb_fstore_file_delete(ctx->fs, fsf);
    return 0;
}

/* Always set an updated copy of metadata into the fs_store_file entry */
int s3_store_file_meta_get(struct flb_s3 *ctx, struct flb_fstore_file *fsf)
{
    return flb_fstore_file_meta_get(ctx->fs, fsf);
}

void s3_store_file_lock(struct s3_file *s3_file)
{
    s3_file->locked = FLB_TRUE;
}

void s3_store_file_unlock(struct s3_file *s3_file)
{
    s3_file->locked = FLB_FALSE;
}
