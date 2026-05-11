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
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_time.h>

#include "gcs.h"
#include "gcs_store.h"

static void normalize_stream_suffix(char *out, size_t out_size, const char *in)
{
    size_t i;
    char ch;

    if (!out || out_size == 0) {
        return;
    }

    if (!in) {
        out[0] = '\0';
        return;
    }

    for (i = 0; i < out_size - 1 && in[i] != '\0'; i++) {
        ch = in[i];
        if ((ch >= 'a' && ch <= 'z') ||
            (ch >= 'A' && ch <= 'Z') ||
            (ch >= '0' && ch <= '9') ||
            ch == '_' || ch == '-' || ch == '.') {
            out[i] = ch;
        }
        else {
            out[i] = '_';
        }
    }
    out[i] = '\0';
}

static flb_sds_t gen_store_filename(void)
{
    unsigned long hash;
    flb_sds_t hash_str;
    flb_sds_t tmp;
    struct flb_time tm;

    flb_time_get(&tm);

    hash = (unsigned long) tm.tm.tv_sec * tm.tm.tv_nsec;

    hash_str = flb_sds_create_size(64);
    if (!hash_str) {
        flb_errno();
        return NULL;
    }

    tmp = flb_sds_printf(&hash_str, "%lu", hash);
    if (!tmp) {
        flb_errno();
        flb_sds_destroy(hash_str);
        return NULL;
    }

    return tmp;
}

int gcs_store_init(struct flb_gcs *ctx)
{
    const char *instance_name;
    char stream_suffix[96];
    flb_sds_t stream_name;

    stream_name = flb_sds_create_size(64);
    if (!stream_name) {
       flb_errno();
       return -1;
    }

    ctx->fs = flb_fstore_create(ctx->store_dir, FLB_FSTORE_FS);
    if (!ctx->fs) {
        return -1;
    }

    instance_name = ctx->ins->alias ? ctx->ins->alias : ctx->ins->name;
    normalize_stream_suffix(stream_suffix, sizeof(stream_suffix), instance_name);

    flb_sds_printf(&stream_name, "gcs_upload_buffer_%s", stream_suffix);
    if (!stream_name) {
        flb_fstore_destroy(ctx->fs);
        ctx->fs = NULL;

        return -1;
    }

    ctx->fs_stream_name = stream_name;
    ctx->fs_stream = flb_fstore_stream_create(ctx->fs, ctx->fs_stream_name);
    if (!ctx->fs_stream) {
        flb_sds_destroy(ctx->fs_stream_name);
        ctx->fs_stream_name = NULL;
        flb_fstore_destroy(ctx->fs);
        ctx->fs = NULL;

        return -1;
    }

    return 0;
}

int gcs_store_exit(struct flb_gcs *ctx)
{
    if (ctx->fs_stream_name) {
        flb_sds_destroy(ctx->fs_stream_name);
        ctx->fs_stream_name = NULL;
    }

    if (ctx->fs) {
        flb_fstore_destroy(ctx->fs);
    }
    return 0;
}

int gcs_store_has_data(struct flb_gcs *ctx)
{
    if (!ctx || !ctx->fs_stream) {
        return FLB_FALSE;
    }
    return mk_list_size(&ctx->fs_stream->files) > 0 ? FLB_TRUE : FLB_FALSE;
}

struct gcs_file *gcs_store_file_get(struct flb_gcs *ctx, const char *tag, int tag_len)
{
    struct mk_list *head;
    struct flb_fstore_file *fsf;
    struct gcs_file *chunk;

    mk_list_foreach(head, &ctx->fs_stream->files) {
        fsf = mk_list_entry(head, struct flb_fstore_file, _head);
        if (fsf->meta_size != tag_len) {
            continue;
        }

        chunk = fsf->data;
        if (!chunk || chunk->locked == FLB_TRUE) {
            continue;
        }
        if (strncmp(fsf->meta_buf, tag, tag_len) == 0) {
            return chunk;
        }
    }
    return NULL;
}

int gcs_store_buffer_put(struct flb_gcs *ctx, struct gcs_file *chunk,
                         const char *tag, int tag_len, char *data, size_t bytes)
{
    int ret;
    flb_sds_t name;
    struct flb_fstore_file *fsf;
    size_t space_remaining;

    if (ctx->store_dir_limit_size > 0 &&
        ctx->current_buffer_size + bytes >= ctx->store_dir_limit_size) {
        flb_plg_error(ctx->ins,
                      "Buffer is full: current_buffer_size=%zu, new_data=%zu, "
                      "store_dir_limit_size=%zu bytes",
                      ctx->current_buffer_size, bytes, ctx->store_dir_limit_size);
        return -1;
    }

    if (!chunk) {
        if (ctx->store_chunk_limit > 0 &&
            mk_list_size(&ctx->fs_stream->files) >= ctx->store_chunk_limit) {
            flb_plg_error(ctx->ins,
                          "gcs local buffer chunk limit reached: limit=%d, dropping",
                          ctx->store_chunk_limit);
            return -1;
        }

        name = gen_store_filename();
        if (!name) {
            return -1;
        }
        fsf = flb_fstore_file_create(ctx->fs, ctx->fs_stream, name, bytes);
        flb_sds_destroy(name);
        if (!fsf) {
            return -1;
        }

        ret = flb_fstore_file_meta_set(ctx->fs, fsf, (char *) tag, tag_len);
        if (ret == -1) {
            flb_fstore_file_delete(ctx->fs, fsf);
            return -1;
        }
        chunk = flb_calloc(1, sizeof(struct gcs_file));
        if (!chunk) {
            flb_fstore_file_delete(ctx->fs, fsf);
            return -1;
        }
        chunk->fsf = fsf;
        chunk->create_time = time(NULL);
        fsf->data = chunk;
    }
    else {
        fsf = chunk->fsf;
    }

    ret = flb_fstore_file_append(fsf, data, bytes);
    if (ret != 0) {
        return -1;
    }

    chunk->size += bytes;
    ctx->current_buffer_size += bytes;

    if (ctx->store_dir_limit_size > 0) {
        space_remaining = ctx->store_dir_limit_size - ctx->current_buffer_size;
        if ((space_remaining * 20) < ctx->store_dir_limit_size) {
            flb_plg_warn(ctx->ins,
                         "Buffer is almost full: current_buffer_size=%zu, "
                         "store_dir_limit_size=%zu bytes",
                         ctx->current_buffer_size, ctx->store_dir_limit_size);
        }
    }
    return 0;
}

int gcs_store_file_read(struct flb_gcs *ctx, struct gcs_file *chunk,
                        char **out_buf, size_t *out_size)
{
    return flb_fstore_file_content_copy(ctx->fs, chunk->fsf, (void **) out_buf, out_size);
}

void gcs_store_file_lock(struct gcs_file *chunk)
{
    chunk->locked = FLB_TRUE;
}

void gcs_store_file_unlock(struct gcs_file *chunk)
{
    chunk->locked = FLB_FALSE;
}

int gcs_store_file_delete(struct flb_gcs *ctx, struct gcs_file *chunk)
{
    struct flb_fstore_file *fsf;

    if (!chunk) {
        return 0;
    }

    fsf = chunk->fsf;
    ctx->current_buffer_size -= chunk->size;
    flb_free(chunk);
    flb_fstore_file_delete(ctx->fs, fsf);

    return 0;
}
