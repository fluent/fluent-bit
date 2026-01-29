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
#include <fluent-bit/flb_compat.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <chunkio/cio_file_st.h>
#include <stdint.h>

#include "s3.h"
#include "s3_store.h"

#define BUFFER_WARNING_THRESHOLD 0.8
#define META_HDR_VER 1
#define META_HDR_SIZE 9

/* Cross-platform path length constant */
#ifdef _WIN32
  #if defined(MAX_PATH)
    #define FLB_PATH_MAX MAX_PATH
  #elif defined(_MAX_PATH)
    #define FLB_PATH_MAX _MAX_PATH
  #else
    #define FLB_PATH_MAX 260  /* Conservative Windows default */
  #endif
#else
  #include <limits.h>
  #ifdef PATH_MAX
    #define FLB_PATH_MAX PATH_MAX
  #else
    #define FLB_PATH_MAX 4096  /* Reasonable POSIX fallback */
  #endif
#endif

static flb_sds_t generate_filename_hash(const char *tag)
{
    int c;
    unsigned long hash = 5381;
    unsigned long hash2 = 5381;
    flb_sds_t hash_str;
    flb_sds_t tmp;
    struct flb_time tm;

    flb_time_get(&tm);

    while ((c = *tag++)) {
        hash = ((hash << 5) + hash) + c;
    }
    hash2 = (unsigned long) hash2 + tm.tm.tv_sec + tm.tm.tv_nsec;

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

    return tmp;
}

static void get_tag_from_fsf(struct flb_fstore_file *fsf, char **out_tag, size_t *out_len)
{
    if (fsf->meta_size >= META_HDR_SIZE &&
        ((uint8_t *)fsf->meta_buf)[0] == META_HDR_VER) {
        *out_tag = (char *)fsf->meta_buf + META_HDR_SIZE;
        *out_len = fsf->meta_size - META_HDR_SIZE;
    }
    else {
        /* Legacy format: meta_buf IS the tag */
        *out_tag = (char *)fsf->meta_buf;
        *out_len = fsf->meta_size;
    }
}

struct s3_file *s3_store_file_get(struct flb_s3 *ctx, const char *tag, int tag_len)
{
    struct s3_file *s3_file;
    void *ptr;

    /* Optimized lookup using Hash Map */
    pthread_mutex_lock(&ctx->file_hash_lock);
    ptr = flb_hash_table_get_ptr(ctx->file_hash, tag, tag_len);
    if (ptr) {
        memcpy(&s3_file, ptr, sizeof(struct s3_file *));
        
        /* Verify it's not locked (though we shouldn't have locked files in hash if we manage correctly) */
        if (s3_file->locked == FLB_FALSE) {
            s3_file->locked = FLB_TRUE;
            pthread_mutex_unlock(&ctx->file_hash_lock);
            return s3_file;
        }
        else {
            pthread_mutex_unlock(&ctx->file_hash_lock);
            return NULL;
        }
    }
    else {
        pthread_mutex_unlock(&ctx->file_hash_lock);
    }

    return NULL;
}

static int check_buffer_space(struct flb_s3 *ctx, size_t new_bytes)
{
    size_t space_remaining;
    size_t new_total;

    if (ctx->store_dir_limit_size == 0) {
        return 0;
    }

    new_total = ctx->current_buffer_size + new_bytes;

    if (new_total >= ctx->store_dir_limit_size) {
        flb_plg_error(ctx->ins, "Buffer is full: current=%zu, new=%zu, limit=%zu bytes",
                     ctx->current_buffer_size, new_bytes, ctx->store_dir_limit_size);
        return -1;
    }

    space_remaining = ctx->store_dir_limit_size - new_total;
    if ((double)space_remaining / ctx->store_dir_limit_size < (1.0 - BUFFER_WARNING_THRESHOLD)) {
        flb_plg_warn(ctx->ins, "Buffer almost full: %zu/%zu bytes used",
                    new_total, ctx->store_dir_limit_size);
    }

    return 0;
}

static void cleanup_failed_file(struct flb_s3 *ctx,
                                 struct flb_fstore_file *fsf,
                                 struct s3_file *s3_file,
                                 const char *reason)
{
    flb_plg_warn(ctx->ins, "Deleting buffer file: %s", reason);

    if (s3_file) {
        if (s3_file->stream_path) {
            flb_sds_destroy(s3_file->stream_path);
        }
        flb_free(s3_file);
    }

    if (fsf) {
        flb_fstore_file_delete(ctx->fs, fsf);
    }
}

static struct s3_file *create_new_buffer_file(struct flb_s3 *ctx,
                                               const char *tag,
                                               int tag_len,
                                               size_t bytes,
                                               time_t file_first_log_time)
{
    flb_sds_t filename;
    struct flb_fstore_file *fsf;
    struct s3_file *s3_file = NULL;
    int ret;
    char *meta_buf;
    size_t meta_len;
    uint64_t ts_val;

    filename = generate_filename_hash(tag);
    if (!filename) {
        flb_plg_error(ctx->ins, "Failed to generate filename");
        return NULL;
    }

    fsf = flb_fstore_file_create(ctx->fs, ctx->stream_active, filename, bytes);
    flb_sds_destroy(filename);

    if (!fsf) {
        flb_plg_error(ctx->ins, "Failed to create file in store");
        return NULL;
    }

    /* Create metadata buffer with header [VER][TIMESTAMP][TAG] */
    meta_len = META_HDR_SIZE + tag_len;
    meta_buf = flb_malloc(meta_len);
    if (!meta_buf) {
        flb_errno();
        cleanup_failed_file(ctx, fsf, NULL, "metadata allocation failed");
        return NULL;
    }

    /* Pack metadata */
    meta_buf[0] = META_HDR_VER;
    ts_val = (uint64_t)file_first_log_time;
    /* Store in little-endian for simplicity (or network byte order if preferred) */
    /* Since this is local storage, native order is usually fine, but let's be consistent */
    memcpy(meta_buf + 1, &ts_val, sizeof(uint64_t));
    memcpy(meta_buf + META_HDR_SIZE, tag, tag_len);

    ret = flb_fstore_file_meta_set(ctx->fs, fsf, meta_buf, meta_len);
    flb_free(meta_buf);

    if (ret == -1) {
        cleanup_failed_file(ctx, fsf, NULL, "metadata write failed");
        return NULL;
    }

    s3_file = flb_calloc(1, sizeof(struct s3_file));
    if (!s3_file) {
        flb_errno();
        cleanup_failed_file(ctx, fsf, NULL, "S3 context allocation failed");
        return NULL;
    }

    s3_file->stream_path = flb_sds_create(ctx->stream_active->path);
    if (!s3_file->stream_path) {
        flb_errno();
        cleanup_failed_file(ctx, fsf, s3_file, "stream path allocation failed");
        return NULL;
    }

    s3_file->fsf = fsf;
    s3_file->first_log_time = file_first_log_time;
    s3_file->create_time = time(NULL);
    s3_file->size = 0;
    s3_file->locked = FLB_FALSE;

    fsf->data = s3_file;

    /* Add to hash table for O(1) lookup */
    pthread_mutex_lock(&ctx->file_hash_lock);
    ret = flb_hash_table_add(ctx->file_hash, tag, tag_len,
                             &s3_file, sizeof(struct s3_file *));
    pthread_mutex_unlock(&ctx->file_hash_lock);
    if (ret < 0) {
        cleanup_failed_file(ctx, fsf, s3_file, "file hash add failed");
        return NULL;
    }

    return s3_file;
}

int s3_store_buffer_put(struct flb_s3 *ctx,
                        struct s3_file *s3_file,
                        const char *tag,
                        int tag_len,
                        char *data,
                        size_t bytes,
                        time_t file_first_log_time)
{
    struct flb_fstore_file *fsf;
    int ret;
    int file_created = FLB_FALSE;

    ret = check_buffer_space(ctx, bytes);
    if (ret == -1) {
        return -1;
    }

    if (!s3_file) {
        s3_file = create_new_buffer_file(ctx, tag, tag_len, bytes, file_first_log_time);
        if (!s3_file) {
            return -1;
        }
        file_created = FLB_TRUE;
    }

    fsf = s3_file->fsf;

    ret = flb_fstore_file_append(fsf, data, bytes);
    if (ret != 0) {
        flb_plg_error(ctx->ins, "Failed to write data to file");
        if (file_created == FLB_TRUE) {
            /* Clean up the newly created file on append failure */
            s3_store_file_delete(ctx, s3_file);
        }
        return -1;
    }

    s3_file->size += bytes;
    ctx->current_buffer_size += bytes;

    return 0;
}

static size_t calculate_chunk_data_size(struct flb_s3 *ctx,
                                        const char *stream_path,
                                        const char *chunk_name,
                                        size_t meta_size)
{
    char chunk_path[FLB_PATH_MAX];
    int ret;

    if (!chunk_name || strlen(chunk_name) == 0) {
        return 0;
    }

    ret = snprintf(chunk_path, sizeof(chunk_path), "%s/%s", stream_path, chunk_name);
    if (ret < 0 || ret >= sizeof(chunk_path)) {
        flb_plg_warn(ctx->ins, "Chunk path too long");
        return 0;
    }

#ifdef FLB_SYSTEM_WINDOWS
    struct _stat st;
    if (_stat(chunk_path, &st) != 0) {
        return 0;
    }
#else
    struct stat st;
    if (stat(chunk_path, &st) != 0) {
        return 0;
    }
#endif

    if (st.st_size <= CIO_FILE_HEADER_MIN + meta_size) {
        return 0;
    }

    return st.st_size - CIO_FILE_HEADER_MIN - meta_size;
}

static struct s3_file *create_file_context(struct flb_s3 *ctx,
                                           struct flb_fstore_stream *fs_stream,
                                           struct flb_fstore_file *fsf)
{
    struct s3_file *s3_file;
    size_t chunk_size;

    s3_file = flb_calloc(1, sizeof(struct s3_file));
    if (!s3_file) {
        flb_errno();
        return NULL;
    }

    s3_file->stream_path = flb_sds_create(fs_stream->path);
    if (!s3_file->stream_path) {
        flb_errno();
        flb_free(s3_file);
        return NULL;
    }

    s3_file->fsf = fsf;
    s3_file->create_time = time(NULL);
    s3_file->locked = FLB_FALSE;

    /* Restore first_log_time from metadata if available */
    if (fsf->meta_size >= META_HDR_SIZE &&
        ((uint8_t *)fsf->meta_buf)[0] == META_HDR_VER) {
        uint64_t ts_val;
        memcpy(&ts_val, (char *)fsf->meta_buf + 1, sizeof(uint64_t));
        s3_file->first_log_time = (time_t)ts_val;
    }
    else {
        /* Legacy file or no metadata - use current time */
        s3_file->first_log_time = time(NULL);
    }

    if (fsf->chunk && fsf->chunk->name) {
        chunk_size = calculate_chunk_data_size(ctx, fs_stream->path,
                                               fsf->chunk->name, fsf->meta_size);
        s3_file->size = chunk_size;
        ctx->current_buffer_size += chunk_size;
    }
    else {
        s3_file->size = 0;
    }

    fsf->data = s3_file;

    return s3_file;
}

static int restore_stream_files(struct flb_s3 *ctx, struct flb_fstore_stream *fs_stream)
{
    struct mk_list *f_head;
    struct flb_fstore_file *fsf;
    struct s3_file *s3_file;

    if (!fs_stream->path) {
        flb_plg_warn(ctx->ins, "Stream has NULL path, skipping");
        return 0;
    }

    mk_list_foreach(f_head, &fs_stream->files) {
        fsf = mk_list_entry(f_head, struct flb_fstore_file, _head);

        if (fsf->data) {
            continue;
        }

        s3_file = create_file_context(ctx, fs_stream, fsf);
        if (!s3_file) {
            flb_plg_error(ctx->ins, "Failed to create file context");
            continue;
        }
    }

    return 0;
}

static int restore_buffered_files(struct flb_s3 *ctx)
{
    struct mk_list *head;
    struct flb_fstore_stream *fs_stream;

    mk_list_foreach(head, &ctx->fs->streams) {
        fs_stream = mk_list_entry(head, struct flb_fstore_stream, _head);

        if (fs_stream == ctx->stream_active || fs_stream == ctx->stream_metadata) {
            continue;
        }

        restore_stream_files(ctx, fs_stream);
    }

    return 0;
}

static flb_sds_t create_stream_name(void)
{
    time_t now;
    struct tm tm_buf;
    char tmp[64];

    now = time(NULL);

#ifdef FLB_SYSTEM_WINDOWS
    /* Windows: gmtime_s(struct tm*, const time_t*) */
    if (gmtime_s(&tm_buf, &now) != 0) {
        return NULL;
    }
#else
    /* POSIX: gmtime_r(const time_t*, struct tm*) */
    if (gmtime_r(&now, &tm_buf) == NULL) {
        return NULL;
    }
#endif
    /* Use Windows-safe format with hyphens for time separators
     * to ensure consistent stream names across all platforms */
    strftime(tmp, sizeof(tmp) - 1, "%Y-%m-%dT%H-%M-%S", &tm_buf);

    return flb_sds_create(tmp);
}

int s3_store_init(struct flb_s3 *ctx)
{
    int store_type;
    flb_sds_t stream_name;
    struct flb_fstore *fs;
    struct flb_fstore_stream *fs_stream;

    store_type = FLB_FSTORE_FS;

    fs = flb_fstore_create(ctx->buffer_dir, store_type);
    if (!fs) {
        flb_plg_error(ctx->ins, "Failed to create file store");
        return -1;
    }
    ctx->fs = fs;

    /* Initialize hash table for O(1) file lookup (tag -> active file) */
    ctx->file_hash = flb_hash_table_create(FLB_HASH_TABLE_EVICT_NONE, 4096, -1);
    if (!ctx->file_hash) {
        flb_plg_error(ctx->ins, "Failed to create file hash table");
        flb_fstore_destroy(fs);
        ctx->fs = NULL;
        return -1;
    }

    pthread_mutex_init(&ctx->file_hash_lock, NULL);

    stream_name = create_stream_name();
    if (!stream_name) {
        flb_plg_error(ctx->ins, "Failed to create stream name");
        pthread_mutex_destroy(&ctx->file_hash_lock);
        flb_hash_table_destroy(ctx->file_hash);
        flb_fstore_destroy(fs);
        ctx->fs = NULL;
        return -1;
    }

    fs_stream = flb_fstore_stream_create(ctx->fs, stream_name);
    flb_sds_destroy(stream_name);

    if (!fs_stream) {
        flb_plg_error(ctx->ins, "Failed to create active stream");
        pthread_mutex_destroy(&ctx->file_hash_lock);
        flb_hash_table_destroy(ctx->file_hash);
        flb_fstore_destroy(fs);
        ctx->fs = NULL;
        return -1;
    }

    ctx->stream_active = fs_stream;
    ctx->current_buffer_size = 0;

    restore_buffered_files(ctx);

    return 0;
}

int s3_store_exit(struct flb_s3 *ctx)
{
    struct mk_list *head;
    struct mk_list *f_head;
    struct flb_fstore_stream *fs_stream;
    struct flb_fstore_file *fsf;
    struct s3_file *s3_file;

    if (!ctx->fs) {
        return 0;
    }

    mk_list_foreach(head, &ctx->fs->streams) {
        fs_stream = mk_list_entry(head, struct flb_fstore_stream, _head);

        mk_list_foreach(f_head, &fs_stream->files) {
            fsf = mk_list_entry(f_head, struct flb_fstore_file, _head);

            if (fsf->data) {
                s3_file = fsf->data;
                if (s3_file->stream_path) {
                    flb_sds_destroy(s3_file->stream_path);
                }
                flb_free(s3_file);
                fsf->data = NULL;
            }
        }
    }

    flb_fstore_destroy(ctx->fs);
    ctx->fs = NULL;

    if (ctx->file_hash) {
        flb_hash_table_destroy(ctx->file_hash);
        ctx->file_hash = NULL;
        pthread_mutex_destroy(&ctx->file_hash_lock);
    }

    return 0;
}

int s3_store_has_data(struct flb_s3 *ctx)
{
    struct mk_list *head;
    struct flb_fstore_stream *fs_stream;

    if (!ctx->fs) {
        return FLB_FALSE;
    }

    mk_list_foreach(head, &ctx->fs->streams) {
        fs_stream = mk_list_entry(head, struct flb_fstore_stream, _head);

        if (mk_list_size(&fs_stream->files) > 0) {
            return FLB_TRUE;
        }
    }

    return FLB_FALSE;
}

int s3_store_file_inactive(struct flb_s3 *ctx, struct s3_file *s3_file)
{
    struct flb_fstore_file *fsf;
    char *tag;
    size_t tag_len;

    if (!s3_file) {
        return 0;
    }

    fsf = s3_file->fsf;

    /* Remove from hash table before destroying */
    get_tag_from_fsf(fsf, &tag, &tag_len);
    
    pthread_mutex_lock(&ctx->file_hash_lock);
    /* 
     * Use flb_hash_table_del instead of del_ptr to ensure removal.
     * We assume one active file per tag, so removing by key is safe.
     * Construct null-terminated string for del API.
     */
    char *tmp_tag = flb_calloc(1, tag_len + 1);
    if (tmp_tag) {
        memcpy(tmp_tag, tag, tag_len);
        flb_hash_table_del(ctx->file_hash, tmp_tag);
        flb_free(tmp_tag);
    }
    pthread_mutex_unlock(&ctx->file_hash_lock);

    /* Free allocated members before freeing the struct */
    if (s3_file->stream_path) {
        flb_sds_destroy(s3_file->stream_path);
    }

    fsf->data = NULL;
    flb_free(s3_file);

    return flb_fstore_file_inactive(ctx->fs, fsf);
}

int s3_store_file_delete(struct flb_s3 *ctx, struct s3_file *s3_file)
{
    struct flb_fstore_file *fsf;
    char *tag;
    size_t tag_len;

    if (!s3_file || !s3_file->fsf) {
        return 0;
    }

    fsf = s3_file->fsf;

    if (fsf->data != s3_file) {
        return 0;
    }

    /* Remove from hash table */
    get_tag_from_fsf(fsf, &tag, &tag_len);
    
    pthread_mutex_lock(&ctx->file_hash_lock);
    /* 
     * Use flb_hash_table_del instead of del_ptr to ensure removal.
     * We assume one active file per tag, so removing by key is safe.
     * Construct null-terminated string for del API.
     */
    char *tmp_tag = flb_calloc(1, tag_len + 1);
    if (tmp_tag) {
        memcpy(tmp_tag, tag, tag_len);
        flb_hash_table_del(ctx->file_hash, tmp_tag);
        flb_free(tmp_tag);
    }
    pthread_mutex_unlock(&ctx->file_hash_lock);

    fsf->data = NULL;
    if (ctx->current_buffer_size >= s3_file->size) {
        ctx->current_buffer_size -= s3_file->size;
    }
    else {
        ctx->current_buffer_size = 0;
        flb_plg_warn(ctx->ins, "buffer size underflow detected");
    }

    if (s3_file->stream_path) {
        flb_sds_destroy(s3_file->stream_path);
    }

    flb_fstore_file_delete(ctx->fs, fsf);
    flb_free(s3_file);

    return 0;
}

FILE *flb_chunk_file_open(const char *chunk_path)
{
    FILE *fp;
    unsigned char header[CIO_FILE_HEADER_MIN];
    uint16_t meta_len;
    long file_size;
    long current_pos;
    long remaining_bytes;

    fp = fopen(chunk_path, "rb");
    if (!fp) {
        flb_error("[s3_store] Failed to open chunk file: %s", chunk_path);
        return NULL;
    }

    if (fread(header, 1, CIO_FILE_HEADER_MIN, fp) != CIO_FILE_HEADER_MIN) {
        flb_error("[s3_store] Failed to read chunk header: %s", chunk_path);
        fclose(fp);
        return NULL;
    }

    if (header[0] != CIO_FILE_ID_00 || header[1] != CIO_FILE_ID_01) {
        flb_error("[s3_store] Invalid chunk magic bytes: 0x%02X 0x%02X in %s",
                 header[0], header[1], chunk_path);
        fclose(fp);
        return NULL;
    }

    meta_len = ((uint16_t)header[CIO_FILE_CONTENT_OFFSET] << 8) |
               (uint16_t)header[CIO_FILE_CONTENT_OFFSET + 1];

    if (meta_len > 0) {
        /* Get current position and file size to validate meta_len */
        current_pos = ftell(fp);
        if (current_pos < 0) {
            flb_error("[s3_store] Failed to get current position: %s", chunk_path);
            fclose(fp);
            return NULL;
        }

        if (fseek(fp, 0, SEEK_END) != 0) {
            flb_error("[s3_store] Failed to seek to end of file: %s", chunk_path);
            fclose(fp);
            return NULL;
        }

        file_size = ftell(fp);
        if (file_size < 0) {
            flb_error("[s3_store] Failed to get file size: %s", chunk_path);
            fclose(fp);
            return NULL;
        }

        /* Restore position after getting file size */
        if (fseek(fp, current_pos, SEEK_SET) != 0) {
            flb_error("[s3_store] Failed to restore file position: %s", chunk_path);
            fclose(fp);
            return NULL;
        }

        remaining_bytes = file_size - current_pos;
        if (meta_len > remaining_bytes) {
            flb_error("[s3_store] Invalid metadata length (%u bytes) exceeds "
                     "remaining file size (%ld bytes): %s",
                     (unsigned)meta_len, remaining_bytes, chunk_path);
            fclose(fp);
            return NULL;
        }

        /* Safe to seek now that we've validated meta_len */
        if (fseek(fp, (long)meta_len, SEEK_CUR) != 0) {
            flb_error("[s3_store] Failed to skip metadata (%u bytes): %s",
                     (unsigned)meta_len, chunk_path);
            fclose(fp);
            return NULL;
        }
    }

    return fp;
}

void s3_store_file_lock(struct s3_file *s3_file)
{
    if (s3_file) {
        s3_file->locked = FLB_TRUE;
    }
}

void s3_store_file_unlock(struct s3_file *s3_file)
{
    if (s3_file) {
        s3_file->locked = FLB_FALSE;
    }
}
