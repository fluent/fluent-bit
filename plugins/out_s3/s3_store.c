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

#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_fstore.h>
#include <fluent-bit/flb_time.h>
#include <cfl/cfl_atomic.h>

#include <inttypes.h>

#include "s3.h"
#include "s3_store.h"

static int counter_add(uint64_t *counter, uint64_t increment,
                       uint64_t *new_value)
{
    uint64_t current_value;
    uint64_t updated_value;

    while (FLB_TRUE) {
        current_value = cfl_atomic_load(counter);
        if (increment > UINT64_MAX - current_value) {
            return -1;
        }

        updated_value = current_value + increment;
        if (cfl_atomic_compare_exchange(counter, current_value, updated_value)) {
            if (new_value != NULL) {
                *new_value = updated_value;
            }
            return 0;
        }
    }
}

static int counter_subtract(uint64_t *counter, uint64_t decrement,
                            uint64_t *previous_value)
{
    int underflow;
    uint64_t current_value;
    uint64_t updated_value;

    while (FLB_TRUE) {
        current_value = cfl_atomic_load(counter);
        underflow = current_value < decrement;
        if (underflow == FLB_TRUE) {
            updated_value = 0;
        }
        else {
            updated_value = current_value - decrement;
        }

        if (cfl_atomic_compare_exchange(counter, current_value, updated_value)) {
            if (previous_value != NULL) {
                *previous_value = current_value;
            }
            return underflow == FLB_TRUE ? -1 : 0;
        }
    }
}

static int buffer_size_reserve(struct flb_s3 *ctx, size_t bytes,
                               uint64_t *current_value,
                               uint64_t *new_value)
{
    uint64_t buffer_size;
    uint64_t updated_size;
    uint64_t increment;

    increment = (uint64_t) bytes;

    while (FLB_TRUE) {
        buffer_size = cfl_atomic_load(&ctx->current_buffer_size);
        if (current_value != NULL) {
            *current_value = buffer_size;
        }

        if (increment > UINT64_MAX - buffer_size) {
            return -1;
        }

        updated_size = buffer_size + increment;
        if (ctx->store_dir_limit_size > 0 &&
            updated_size >= (uint64_t) ctx->store_dir_limit_size) {
            if (ctx->uploader_gate_initialized && increment < ctx->store_dir_limit_size) {
                return S3_STORE_BUFFER_FULL;
            }
            return -1;
        }

        if (cfl_atomic_compare_exchange(&ctx->current_buffer_size,
                                        buffer_size, updated_size)) {
            if (new_value != NULL) {
                *new_value = updated_size;
            }
            return 0;
        }
    }
}

static int quarantine_size_reserve(struct flb_s3 *ctx, uint64_t bytes)
{
    uint64_t buffer_size;
    uint64_t updated_size;

    while (FLB_TRUE) {
        buffer_size = cfl_atomic_load(&ctx->quarantine_buffer_size);
        if (bytes > UINT64_MAX - buffer_size) {
            return -1;
        }

        updated_size = buffer_size + bytes;
        if (ctx->quarantine_dir_limit_size > 0 &&
            updated_size > (uint64_t) ctx->quarantine_dir_limit_size) {
            return -1;
        }

        if (cfl_atomic_compare_exchange(&ctx->quarantine_buffer_size,
                                        buffer_size, updated_size)) {
            return 0;
        }
    }
}

static void buffer_size_release(struct flb_s3 *ctx, uint64_t bytes)
{
    int ret;
    uint64_t previous_value;

    ret = counter_subtract(&ctx->current_buffer_size, bytes, &previous_value);
    if (ret < 0) {
        flb_plg_warn(ctx->ins,
                     "buffer accounting mismatch: current_buffer_size=%" PRIu64
                     ", reclaim_size=%" PRIu64 "; clamping to zero",
                     previous_value, bytes);
    }
}

static int s3_store_under_travis_ci()
{

    if (getenv("CI") != NULL && getenv("TRAVIS") != NULL) {
        return FLB_TRUE;
    }

    return FLB_FALSE;
}

/*
 * Simple and fast hashing algorithm to create keys in the local buffer
 */
static flb_sds_t gen_store_filename(const char *tag, uint64_t order)
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
    if (order > 0) {
        tmp = flb_sds_printf(&hash_str, "uploader-%020" PRIu64 "-%lu-%lu", order, hash, hash2);
    }
    else {
        tmp = flb_sds_printf(&hash_str, "%lu-%lu", hash, hash2);
    }
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
    struct mk_list *tmp;
    struct flb_fstore_file *fsf = NULL;
    struct s3_file *s3_file;

    /*
     * Based in the current ctx->stream_name, locate a candidate file to
     * store the incoming data using as a lookup pattern the content Tag.
     */
    mk_list_foreach_safe(head, tmp, &ctx->stream_active->files) {
        fsf = mk_list_entry(head, struct flb_fstore_file, _head);

        /* skip and warn on partially initialized chunks */
        if (fsf->data == NULL) {
            flb_plg_warn(ctx->ins, "BAD: found flb_fstore_file with NULL data reference, tag=%s, file=%s, will try to delete", tag, fsf->name);
            flb_fstore_file_delete(ctx->fs, fsf);
            fsf = NULL;
            continue;
        }

        if (fsf->meta_size != tag_len) {
            fsf = NULL;
            continue;
        }

        /* skip locked chunks */
        s3_file = fsf->data;
        if (s3_file->locked == FLB_TRUE || s3_file->sealed == FLB_TRUE) {
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

    s3_file = fsf->data;

    return s3_file;
}

/* Append data to a new or existing fstore file */
int s3_store_recover_append(struct flb_s3 *ctx)
{
    struct s3_file *file = ctx->rollback_file;
    off_t offset = (off_t) ctx->rollback_size;
    int restore_down;
    int ret;

    if (file == NULL) {
        return 0;
    }
    if (offset < 0 || (uint64_t) offset != ctx->rollback_size) {
        return -1;
    }
    restore_down = !cio_chunk_is_up(file->fsf->chunk);
    if (restore_down && cio_chunk_up_force(file->fsf->chunk) != CIO_OK) {
        return -1;
    }
    ret = cio_chunk_write_at(file->fsf->chunk, offset, NULL, 0);
    if (ret == CIO_OK) {
        ret = cio_chunk_sync(file->fsf->chunk);
    }
    if (restore_down) {
        cio_chunk_down(file->fsf->chunk);
    }
    if (ret != CIO_OK) {
        return -1;
    }
    buffer_size_release(ctx, s3_store_file_size_get(file) - ctx->rollback_size);
    cfl_atomic_store(&file->size, ctx->rollback_size);
    ctx->rollback_file = NULL;
    return 0;
}

int s3_store_buffer_put(struct flb_s3 *ctx, struct s3_file *s3_file,
                        const char *tag, int tag_len,
                        char *data, size_t bytes,
                        time_t file_first_log_time)
{
    int ret;
    int result;
    int restore_down = FLB_FALSE;
    flb_sds_t name;
    struct flb_fstore_file *fsf;
    uint64_t current_buffer_size;
    uint64_t new_buffer_size;
    uint64_t order = 0;
    uint64_t previous_size;
    off_t previous_offset;
    struct mk_list *head;
    struct s3_file *open_file;

    result = -1;
    ret = buffer_size_reserve(ctx, bytes, &current_buffer_size,
                              &new_buffer_size);
#ifdef FLB_HAVE_METRICS
    if (ctx->uploader_spool_full != NULL) {
        cmt_gauge_set(ctx->uploader_spool_full, cfl_time_now(), ret == S3_STORE_BUFFER_FULL, 1,
                      (char *[]) {(char *) flb_output_name(ctx->ins)});
    }
#endif
    if (ret < 0) {
        result = ret;
        if (ret == S3_STORE_BUFFER_FULL) {
            /* Open files of other tags can also be keeping this flush out. */
            mk_list_foreach(head, &ctx->stream_active->files) {
                fsf = mk_list_entry(head, struct flb_fstore_file, _head);
                open_file = fsf->data;
                if (open_file != NULL) {
                    open_file->sealed = FLB_TRUE;
                }
            }
            goto done;
        }
        flb_plg_error(ctx->ins,
                      "Buffer is full: current_buffer_size=%" PRIu64
                      ", new_data=%zu, store_dir_limit_size=%zu bytes",
                      current_buffer_size, bytes, ctx->store_dir_limit_size);
        goto done;
    }

    /* If no target file was found, create a new one */
    if (!s3_file) {
        if (ctx->uploader_gate_initialized) {
            if (ctx->uploader_file_order == UINT64_MAX) {
                buffer_size_release(ctx, bytes);
                goto done;
            }
            order = ++ctx->uploader_file_order;
        }
        name = gen_store_filename(tag, order);
        if (!name) {
            flb_plg_error(ctx->ins, "could not generate chunk file name");
            buffer_size_release(ctx, bytes);
            goto done;
        }

        /* Create the file */
        fsf = flb_fstore_file_create(ctx->fs, ctx->stream_active, name, bytes);
        if (!fsf) {
            flb_plg_error(ctx->ins, "could not create the file '%s' in the store",
                          name);
            flb_sds_destroy(name);
            buffer_size_release(ctx, bytes);
            goto done;
        }
        flb_sds_destroy(name);

        /* Write tag as metadata */
        ret = flb_fstore_file_meta_set(ctx->fs, fsf, (char *) tag, tag_len);
        if (ret == -1) {
            flb_plg_error(ctx->ins, "error writing tag metadata");
            flb_plg_warn(ctx->ins, "Deleting buffer file because metadata could not be written");
            flb_fstore_file_delete(ctx->fs, fsf);
            buffer_size_release(ctx, bytes);
            goto done;
        }

        /* Allocate local context */
        s3_file = flb_calloc(1, sizeof(struct s3_file));
        if (!s3_file) {
            flb_errno();
            flb_plg_error(ctx->ins, "cannot allocate s3 file context");
            flb_plg_warn(ctx->ins, "Deleting buffer file because S3 context creation failed");
            flb_fstore_file_delete(ctx->fs, fsf);
            buffer_size_release(ctx, bytes);
            goto done;
        }
        s3_file->fsf = fsf;
        s3_file->upload_scan_id = ctx->upload_scan_id;
        s3_file->first_log_time = file_first_log_time;
        s3_file->create_time = time(NULL);
        s3_file->order = order;

        /* Use fstore opaque 'data' reference to keep our context */
        fsf->data = s3_file;
    }
    else {
        fsf = s3_file->fsf;
    }

    /* Append data to the target file */
    if (ctx->uploader_gate_initialized && !cio_chunk_is_up(fsf->chunk)) {
        if (cio_chunk_up_force(fsf->chunk) != CIO_OK) {
            buffer_size_release(ctx, bytes);
            goto done;
        }
        restore_down = FLB_TRUE;
    }
    previous_size = s3_store_file_size_get(s3_file);
    ret = flb_fstore_file_append(fsf, data, bytes);
    if (ret != 0) {
        flb_plg_error(ctx->ins, "error writing data to local s3 file");
        buffer_size_release(ctx, bytes);
        goto done;
    }
    if (ctx->uploader_gate_initialized && cio_chunk_sync(fsf->chunk) != CIO_OK) {
        previous_offset = (off_t) previous_size;
        flb_plg_error(ctx->ins, "Cannot sync local S3 buffer %s", fsf->name);
        if (previous_offset >= 0 && (uint64_t) previous_offset == previous_size &&
            cio_chunk_write_at(fsf->chunk, previous_offset, NULL, 0) == CIO_OK &&
            cio_chunk_sync(fsf->chunk) == CIO_OK) {
            buffer_size_release(ctx, bytes);
        }
        else {
            /* The store could not roll back an unacknowledged append. */
            s3_uploader_storage_status(ctx, FLB_TRUE);
            ctx->rollback_file = s3_file;
            ctx->rollback_size = previous_size;
            s3_file->sealed = FLB_TRUE;
            counter_add(&s3_file->size, (uint64_t) bytes, NULL);
            flb_plg_error(ctx->ins, "Cannot roll back S3 buffer %s; suspending uploads",
                          fsf->name);
        }
        goto done;
    }
    ret = counter_add(&s3_file->size, (uint64_t) bytes, NULL);
    if (ret < 0) {
        flb_plg_error(ctx->ins, "local s3 file size accounting overflow");
    }

    /* if buffer is 95% full, warn user */
    if (ctx->store_dir_limit_size > 0 &&
        new_buffer_size > (uint64_t) ctx->store_dir_limit_size -
                          (ctx->store_dir_limit_size / 20)) {
        flb_plg_warn(ctx->ins,
                     "Buffer is almost full: current_buffer_size=%" PRIu64
                     ", store_dir_limit_size=%zu bytes",
                     new_buffer_size, ctx->store_dir_limit_size);
    }

    result = 0;

done:
    if (restore_down && cio_chunk_down(fsf->chunk) != CIO_OK) {
        flb_plg_warn(ctx->ins, "Cannot unmap S3 buffer %s", fsf->name);
    }
    return result;
}

static ssize_t restored_file_size_get(struct flb_s3 *ctx,
                                      struct flb_fstore_file *fsf)
{
    int ret;
    int restore_down;
    ssize_t file_size;

    restore_down = FLB_FALSE;

    if (cio_chunk_is_up(fsf->chunk) == CIO_FALSE) {
        ret = cio_chunk_up_force(fsf->chunk);
        if (ret != CIO_OK) {
            flb_plg_error(ctx->ins,
                          "cannot load restored S3 chunk '%s' to determine its size",
                          fsf->name);
            return -1;
        }
        restore_down = FLB_TRUE;
    }

    file_size = cio_chunk_get_content_size(fsf->chunk);

    if (restore_down == FLB_TRUE) {
        ret = cio_chunk_down(fsf->chunk);
        if (ret != CIO_OK) {
            flb_plg_warn(ctx->ins,
                         "cannot return restored S3 chunk '%s' to the down state",
                         fsf->name);
        }
    }

    return file_size;
}

int s3_store_retry_restore(struct flb_s3 *ctx, struct s3_file *file)
{
    ssize_t size;
    uint64_t now = flb_output_throttle_now_ms();

    if (now < file->restore_retry_at) {
        return -1;
    }
    file->restore_retry_at = now + 5000;
    if (file->size_unknown) {
        size = restored_file_size_get(ctx, file->fsf);
        if (size < 0 || counter_add(&ctx->current_buffer_size, (uint64_t) size, NULL) < 0) {
            return -1;
        }
        cfl_atomic_store(&file->size, (uint64_t) size);
        file->size_unknown = FLB_FALSE;
        ctx->unknown_spool_sizes--;
    }
    if (s3_store_file_meta_get(ctx, file->fsf) < 0 ||
        file->fsf->meta_buf == NULL || file->fsf->meta_size == 0) {
        return -1;
    }
    file->restore_retry_at = 0;
    return 0;
}

static int set_files_context(struct flb_s3 *ctx)
{
    struct mk_list *head;
    struct mk_list *f_head;
    struct flb_fstore_stream *fs_stream;
    struct flb_fstore_file *fsf;
    struct s3_file *s3_file;
    ssize_t file_size;
    struct s3_retry_state part;
    const char *prefix = "uploader-";
    char *order_end;
    uint64_t order;

    mk_list_foreach(head, &ctx->fs->streams) {
        fs_stream = mk_list_entry(head, struct flb_fstore_stream, _head);

        /* skip multi-upload */
        if (fs_stream == ctx->stream_upload ||
            (ctx->uploader_gate_initialized && strcmp(fs_stream->name, "sequence") == 0)) {
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
                if (ctx->uploader_gate_initialized) {
                    return -1;
                }
                continue;
            }
            s3_file->fsf = fsf;
            s3_file->first_log_time = time(NULL);
            s3_file->create_time = time(NULL);
            if (ctx->uploader_gate_initialized && fs_stream != ctx->stream_quarantine) {
                /* The new run can reuse the last stream name. Keep old payloads immutable. */
                s3_file->sealed = FLB_TRUE;
                if (strncmp(fsf->name, prefix, strlen(prefix)) == 0) {
                    order = strtoull(fsf->name + strlen(prefix), &order_end, 10);
                    if (*order_end == '-') {
                        s3_file->order = order;
                        if (order > ctx->uploader_file_order) {
                            ctx->uploader_file_order = order;
                        }
                    }
                }
                if (s3_uploader_state_read(ctx, "chunk", fsf->name, &s3_file->retry) < 0) {
                    flb_free(s3_file);
                    return -1;
                }
                memset(&part, 0, sizeof(part));
                if (s3_uploader_state_read(ctx, "part", fsf->name, &part) < 0) {
                    flb_sds_destroy(s3_file->retry.uri);
                    flb_free(s3_file);
                    return -1;
                }
                s3_file->part_upload_id = part.uri;
                s3_file->part_number = part.failures;
            }

            file_size = restored_file_size_get(ctx, fsf);
            if (ctx->uploader_gate_initialized && fs_stream != ctx->stream_quarantine &&
                (file_size < 0 || fsf->meta_buf == NULL || fsf->meta_size == 0)) {
                /* Retain its reservation and retry reading it without spending upload attempts. */
                flb_plg_error(ctx->ins, "Will retry reading buffer %s", fsf->name);
                fsf->data = s3_file;
                s3_file->sealed = FLB_TRUE;
                s3_file->restore_retry_at = flb_output_throttle_now_ms() + 5000;
                if (file_size < 0) {
                    s3_file->size_unknown = FLB_TRUE;
                    ctx->unknown_spool_sizes++;
                }
            }
            if (file_size > 0) {
                cfl_atomic_store(&s3_file->size, (uint64_t) file_size);

                if (fs_stream == ctx->stream_quarantine) {
                    if (counter_add(&ctx->quarantine_buffer_size,
                                    (uint64_t) file_size, NULL) < 0) {
                        cfl_atomic_store(&ctx->quarantine_buffer_size,
                                         UINT64_MAX);
                    }
                }
                else if (counter_add(&ctx->current_buffer_size,
                                     (uint64_t) file_size, NULL) < 0) {
                    cfl_atomic_store(&ctx->current_buffer_size, UINT64_MAX);
                }
            }

            /* Use fstore opaque 'data' reference to keep our context */
            fsf->data = s3_file;
        }
    }

    return 0;
}

/* Initialize filesystem storage for S3 plugin */
int s3_store_init(struct flb_s3 *ctx)
{
    int type;
    time_t now;
    char tmp[64];
    struct tm *tm;
    struct flb_fstore *fs;
    struct flb_fstore_stream *fs_stream;
    struct flb_fstore_file *file;
    struct mk_list *head;
    struct mk_list *tmp_head;
    struct mk_list *file_head;
    struct mk_list *file_tmp;

    if (s3_store_under_travis_ci() == FLB_TRUE) {
        type = FLB_FSTORE_MEM;
        flb_plg_warn(ctx->ins, "Travis CI test, using s3 store memory backend");
    }
    else {
        type = FLB_FSTORE_FS;
    }

    /* Initialize the storage context */
    fs = flb_fstore_create(ctx->buffer_dir, type);
    if (!fs) {
        return -1;
    }
    ctx->fs = fs;
    if (ctx->ins->throttle.enabled) {
        fs->cio->options.flags |= CIO_FULL_SYNC;
    }

    /*
     * The nested MessagePack root is not a schema-less stream. Detach it
     * without deleting files so empty-stream cleanup cannot remove its tree.
     */
    if (ctx->arrow_schema == NULL) {
        mk_list_foreach_safe(head, tmp_head, &fs->streams) {
            fs_stream = mk_list_entry(head, struct flb_fstore_stream, _head);
            if (strcmp(fs_stream->name, "msgpack") == 0) {
                mk_list_foreach_safe(file_head, file_tmp, &fs_stream->files) {
                    file = mk_list_entry(file_head, struct flb_fstore_file, _head);
                    flb_fstore_file_inactive(fs, file);
                }
                flb_fstore_stream_destroy(fs_stream, FLB_FALSE);
            }
        }
    }

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

#ifdef FLB_SYSTEM_WINDOWS
    /* Windows does not allow ':' in directory names */
    strftime(tmp, sizeof(tmp) - 1, "%Y-%m-%dT%H-%M-%S", tm);
#else
    strftime(tmp, sizeof(tmp) - 1, "%Y-%m-%dT%H:%M:%S", tm);
#endif

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

    /* Terminal quarantine stream */
    fs_stream = flb_fstore_stream_create(ctx->fs, "quarantine");
    if (!fs_stream) {
        flb_plg_error(ctx->ins, "could not initialize quarantine stream");
        flb_fstore_destroy(fs);
        ctx->fs = NULL;
        return -1;
    }
    ctx->stream_quarantine = fs_stream;

    if (s3_uploader_init(ctx) < 0) {
        return -1;
    }
    if (ctx->uploader_gate_initialized && s3_uploader_reconcile_files(ctx) < 0) {
        return -1;
    }
    return set_files_context(ctx);
}

int s3_store_exit(struct flb_s3 *ctx)
{
    struct mk_list *head;
    struct mk_list *tmp;
    struct mk_list *f_head;
    struct flb_fstore_stream *fs_stream;
    struct flb_fstore_file *fsf;
    struct s3_file *s3_file;

    if (!ctx->fs) {
        return 0;
    }

    /* release local context on non-multi upload files */
    mk_list_foreach_safe(head, tmp, &ctx->fs->streams) {
        fs_stream = mk_list_entry(head, struct flb_fstore_stream, _head);
        /* The sequence allocator lives in a subdirectory outside the chunk list.
         * An empty fstore stream would otherwise be deleted recursively on exit. */
        if (strcmp(fs_stream->name, "sequence") == 0 &&
            mk_list_is_empty(&fs_stream->files) == 0) {
            flb_fstore_stream_destroy(fs_stream, FLB_FALSE);
            ctx->stream_metadata = NULL;
            continue;
        }
        if (fs_stream == ctx->stream_upload) {
            continue;
        }

        mk_list_foreach(f_head, &fs_stream->files) {
            fsf = mk_list_entry(f_head, struct flb_fstore_file, _head);
            if (fsf->data != NULL) {
                s3_file = fsf->data;
                flb_sds_destroy(s3_file->file_path);
                flb_sds_destroy(s3_file->retry.uri);
                flb_sds_destroy(s3_file->part_upload_id);
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

    if (!ctx->fs) {
        return FLB_FALSE;
    }

    mk_list_foreach(head, &ctx->fs->streams) {
        /* skip multi upload stream */
        fs_stream = mk_list_entry(head, struct flb_fstore_stream, _head);
        if (fs_stream == ctx->stream_upload ||
            fs_stream == ctx->stream_quarantine) {
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
    if (!ctx || !ctx->stream_upload) {
        return FLB_FALSE;
    }

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
    flb_sds_destroy(s3_file->retry.uri);
    flb_sds_destroy(s3_file->part_upload_id);
    flb_free(s3_file);
    ret = flb_fstore_file_inactive(ctx->fs, fsf);

    return ret;
}

int s3_store_file_quarantine(struct flb_s3 *ctx, struct s3_file *s3_file)
{
    struct flb_fstore_file *fsf;
    struct flb_fstore_file *qfsf;
    void *buf;
    size_t size;
    int ret;

    fsf = s3_file->fsf;
    ret = flb_fstore_file_content_copy(ctx->fs, fsf, &buf, &size);
    if (ret < 0) {
        return -1;
    }

    ret = quarantine_size_reserve(ctx, (uint64_t) size);
    if (ret < 0) {
        flb_free(buf);
        return S3_STORE_QUARANTINE_FULL;
    }

    qfsf = flb_fstore_file_create(ctx->fs, ctx->stream_quarantine, fsf->name, size);
    if (qfsf == NULL) {
        flb_free(buf);
        counter_subtract(&ctx->quarantine_buffer_size, (uint64_t) size, NULL);
        return -1;
    }

    if (fsf->meta_buf != NULL && fsf->meta_size > 0) {
        ret = flb_fstore_file_meta_set(ctx->fs, qfsf, fsf->meta_buf, fsf->meta_size);
        if (ret < 0) {
            flb_free(buf);
            flb_fstore_file_delete(ctx->fs, qfsf);
            counter_subtract(&ctx->quarantine_buffer_size, (uint64_t) size, NULL);
            return -1;
        }
    }

    ret = flb_fstore_file_append(qfsf, buf, size);
    flb_free(buf);
    if (ret < 0) {
        flb_fstore_file_delete(ctx->fs, qfsf);
        counter_subtract(&ctx->quarantine_buffer_size, (uint64_t) size, NULL);
        return -1;
    }

    return s3_store_file_delete(ctx, s3_file);
}

uint64_t s3_store_file_size_get(struct s3_file *s3_file)
{
    return cfl_atomic_load(&s3_file->size);
}

int s3_store_file_delete(struct flb_s3 *ctx, struct s3_file *s3_file)
{
    struct flb_fstore_file *fsf;
    uint64_t file_size;
    flb_sds_t path;
    int ret;

    fsf = s3_file->fsf;
    file_size = s3_store_file_size_get(s3_file);
    if (ctx->uploader_gate_initialized) {
        s3_file->sealed = FLB_TRUE;
        if (s3_file->retry.failures != S3_CHUNK_RETIRING) {
            s3_file->retry.failures = S3_CHUNK_RETIRING;
            s3_file->retry.until_ms = 0;
            if (s3_uploader_state_write(ctx, "chunk", fsf->name, &s3_file->retry) < 0) {
                return -1;
            }
        }
        if (ctx->uploader_storage_failed) {
            return -1;
        }
        if (ctx->fs->store_type == FLB_FSTORE_FS) {
            /* On Windows the mapping must be closed before unlink. Keep the
             * file context and its reservation until removal is confirmed. */
            path = flb_sds_create_size(flb_sds_len(fsf->name) + strlen(ctx->fs->root_path) +
                                       strlen(fsf->stream->name) + 2);
            if (path == NULL) {
                return -1;
            }
            if (!flb_sds_printf(&path, "%s/%s/%s", ctx->fs->root_path, fsf->stream->name, fsf->name)) {
                flb_sds_destroy(path);
                return -1;
            }
            ret = 0;
            if (cio_chunk_is_up(fsf->chunk)) {
                ret = cio_chunk_down(fsf->chunk);
            }
            if (ret == 0 && unlink(path) < 0 && errno != ENOENT) {
                ret = -1;
            }
            flb_sds_destroy(path);
            if (ret != 0) {
                s3_file->retry.retry_at = flb_output_throttle_now_ms() + 5000;
                flb_plg_warn(ctx->ins, "Will retry removal of buffered file %s", fsf->name);
                return -1;
            }
        }
        s3_uploader_state_delete(ctx, "chunk", fsf->name);
        if (s3_file->part_upload_id != NULL) {
            s3_uploader_state_delete(ctx, "part", fsf->name);
        }
    }
    buffer_size_release(ctx, file_size);
    if (ctx->uploader_gate_initialized && ctx->fs->store_type == FLB_FSTORE_FS) {
        flb_fstore_file_inactive(ctx->fs, fsf);
    }
    else {
        flb_fstore_file_delete(ctx->fs, fsf);
    }
    flb_sds_destroy(s3_file->retry.uri);
    flb_sds_destroy(s3_file->part_upload_id);
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

        if (fsf->meta_size != key_len) {
            continue;
        }

        if (strncmp(fsf->meta_buf, key, key_len) == 0) {
            return fsf;
        }
    }

    return NULL;
}

/* param fsf can NULL if the file has not yet been created */
int s3_store_file_upload_put(struct flb_s3 *ctx,
                             struct flb_fstore_file *fsf, flb_sds_t key,
                             flb_sds_t data, int *needs_sync)
{
    int ret;
    int restore_down;
    int retry_sync = needs_sync != NULL && *needs_sync;
    flb_sds_t name;

    /* If no target file was found, create a new one */
    if (!fsf) {
        if (retry_sync) {
            return -1;
        }
        name = gen_store_filename(key, 0);
        if (!name) {
            flb_plg_error(ctx->ins, "could not generate chunk file name");
            return -1;
        }

        /* Create the file */
        fsf = flb_fstore_file_create(ctx->fs, ctx->stream_upload, name, flb_sds_len(data));
        if (!fsf) {
            flb_plg_error(ctx->ins, "could not create the file '%s' in the upload store",
                          name);
            flb_sds_destroy(name);
            return -1;
        }
        flb_sds_destroy(name);

        /* Write key as metadata */
        ret = flb_fstore_file_meta_set(ctx->fs, fsf,
                                    key, flb_sds_len(key));
        if (ret == -1) {
            flb_plg_error(ctx->ins, "error writing upload metadata");
            flb_plg_warn(ctx->ins, "Deleting s3 upload cache file because metadata could not be written");
            flb_fstore_file_delete(ctx->fs, fsf);
            return -1;
        }
    }

    /* Append data to the target file */
    restore_down = ctx->uploader_gate_initialized && !cio_chunk_is_up(fsf->chunk);
    if (restore_down && cio_chunk_up_force(fsf->chunk) != CIO_OK) {
        return -1;
    }
    ret = 0;
    if (!retry_sync) {
        ret = flb_fstore_file_append(fsf, data, flb_sds_len(data));
    }
    if (ret == 0 && ctx->uploader_gate_initialized) {
        ret = cio_chunk_sync(fsf->chunk);
        if (needs_sync != NULL) {
            *needs_sync = ret != CIO_OK;
        }
    }
    if ((restore_down || retry_sync) && ret == 0 && cio_chunk_down(fsf->chunk) != CIO_OK) {
        flb_plg_warn(ctx->ins, "Cannot unmap S3 manifest %s", fsf->name);
    }
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
