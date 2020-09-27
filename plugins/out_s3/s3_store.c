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
    mk_list_foreach(head, &ctx->fs->files) {
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
        fsf = flb_fstore_file_create(ctx->fs, name, bytes);
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

    return 0;
}

/* Initialize filesystem storage for S3 plugin */
int s3_store_init(struct flb_s3 *ctx)
{
    time_t now;
    char tmp[64];
    struct tm *tm;
    struct flb_fstore *fs;

    /* Compose a new stream name using 'local' date */
    now = time(NULL);
    tm = localtime(&now);
    strftime(tmp, sizeof(tmp) - 1, "%Y-%m-%dT%H:%M:%S", tm);

    fs = flb_fstore_create(ctx->store_dir, tmp);
    if (!fs) {
        return -1;
    }
    ctx->fs = fs;

    return 0;
}

int s3_store_exit(struct flb_s3 *ctx)
{
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
    return 0;
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

void s3_store_file_lock(struct s3_file *s3_file)
{
    s3_file->locked = FLB_TRUE;
}

void s3_store_file_unlock(struct s3_file *s3_file)
{
    s3_file->locked = FLB_FALSE;
}
