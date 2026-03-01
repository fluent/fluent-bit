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
#include <fluent-bit/flb_utils.h>

#include "s3.h"
#include "s3_multipart.h"
#include "s3_auth.h"
#include "s3_queue.h"
#include "s3_store.h"
#include "s3_blob.h"

/* Queue processing return codes */
#define S3_QUEUE_ENTRY_SUCCESS      1
#define S3_QUEUE_ENTRY_RETRY       -1
#define S3_QUEUE_ENTRY_INVALID      0

/* Upload failure handling codes */
#define S3_UPLOAD_ENTRY_DESTROYED   1
#define S3_UPLOAD_ENTRY_REQUEUE     0

/* Forward declarations for internal static helper functions */
static int is_queue_entry_valid(struct upload_queue *entry, struct flb_s3 *ctx);
static int upload_part_with_db_tracking(struct flb_s3 *ctx, struct upload_queue *entry);
static int upload_without_db_tracking(struct flb_s3 *ctx, struct upload_queue *entry);
static int handle_upload_failure(struct flb_s3 *ctx,
                                  struct upload_queue *entry,
                                  time_t now);
static int check_and_complete_multipart(struct flb_s3 *ctx, uint64_t file_id, const char *s3_key);
static int enqueue_file_parts_for_resume(struct flb_s3 *ctx,
                                          uint64_t file_id,
                                          const char *file_path,
                                          const char *upload_id,
                                          const char *s3_key,
                                          const char *tag,
                                          int tag_len);

/*
 * Unlocked version - caller must hold upload_queue_lock
 * Used when the caller already holds the lock (e.g., cb_s3_upload timer callback)
 */
int s3_queue_add_file_unlocked(struct flb_s3 *ctx,
                                       uint64_t file_id,
                                       struct s3_file *upload_file,
                                       const char *file_path,
                                       const char *tag,
                                       int tag_len)
{
    struct upload_queue *entry;
    flb_sds_t tag_copy;
    flb_sds_t path_copy = NULL;

    entry = flb_calloc(1, sizeof(struct upload_queue));
    if (!entry) {
        flb_errno();
        flb_plg_error(ctx->ins, "Failed to allocate memory for upload queue entry");
        return -1;
    }

    tag_copy = flb_sds_create_len(tag, tag_len);
    if (!tag_copy) {
        flb_errno();
        flb_free(entry);
        return -1;
    }

    if (file_id > 0 && file_path) {
        path_copy = flb_sds_create(file_path);
        if (!path_copy) {
            flb_errno();
            flb_sds_destroy(tag_copy);
            flb_free(entry);
            return -1;
        }
    }

    entry->file_id = file_id;
    entry->part_db_id = 0;  /* File-level mode */
    entry->part_id = 0;
    entry->upload_file = upload_file;
    entry->stream_path = path_copy;
    entry->offset_start = 0;
    entry->offset_end = 0;
    entry->s3_key = NULL;
    entry->upload_id = NULL;
    entry->tag = tag_copy;
    entry->tag_len = tag_len;
    entry->retry_counter = 0;
    entry->upload_time = time(NULL);
    entry->state = S3_STATE_UPLOAD_FILE;

    /* Caller must hold lock */
    mk_list_add(&entry->_head, &ctx->upload_queue);

    return 0;
}

/*
 * Queue add for uploads (public, acquires lock)
 * Supports two tracking modes:
 *   - file_id > 0: Database-tracked upload
 *   - file_id = 0: Non-database-tracked upload (log data only)
 */
int s3_queue_add_file(struct flb_s3 *ctx,
                      uint64_t file_id,
                      struct s3_file *upload_file,
                      const char *file_path,
                      const char *tag,
                      int tag_len)
{
    int ret;

    pthread_mutex_lock(&ctx->upload_queue_lock);
    ret = s3_queue_add_file_unlocked(ctx, file_id, upload_file, file_path, tag, tag_len);
    pthread_mutex_unlock(&ctx->upload_queue_lock);

    return ret;
}

int s3_queue_add_part(struct flb_s3 *ctx,
                      uint64_t file_id,
                      uint64_t part_db_id,
                      uint64_t part_id,
                      const char *file_path,
                      off_t offset_start,
                      off_t offset_end,
                      const char *s3_key,
                      const char *upload_id,
                      const char *tag,
                      int tag_len)
{
    struct upload_queue *entry;

    if (!file_path || !s3_key || !upload_id || !tag || tag_len <= 0) {
        return -1;
    }

    entry = flb_calloc(1, sizeof(struct upload_queue));
    if (!entry) {
        flb_errno();
        return -1;
    }

    entry->file_id = file_id;
    entry->part_db_id = part_db_id;
    entry->part_id = part_id;
    entry->upload_file = NULL;
    entry->offset_start = offset_start;
    entry->offset_end = offset_end;
    entry->retry_counter = 0;
    entry->upload_time = time(NULL);
    entry->state = S3_STATE_UPLOAD_PART;

    entry->stream_path = flb_sds_create(file_path);
    if (!entry->stream_path) {
        flb_errno();
        flb_free(entry);
        return -1;
    }

    entry->s3_key = flb_sds_create(s3_key);
    if (!entry->s3_key) {
        flb_errno();
        flb_sds_destroy(entry->stream_path);
        flb_free(entry);
        return -1;
    }

    entry->upload_id = flb_sds_create(upload_id);
    if (!entry->upload_id) {
        flb_errno();
        flb_sds_destroy(entry->stream_path);
        flb_sds_destroy(entry->s3_key);
        flb_free(entry);
        return -1;
    }

    entry->tag = flb_sds_create_len(tag, tag_len);
    if (!entry->tag) {
        flb_errno();
        flb_sds_destroy(entry->stream_path);
        flb_sds_destroy(entry->s3_key);
        flb_sds_destroy(entry->upload_id);
        flb_free(entry);
        return -1;
    }
    entry->tag_len = tag_len;

    pthread_mutex_lock(&ctx->upload_queue_lock);
    mk_list_add(&entry->_head, &ctx->upload_queue);
    pthread_mutex_unlock(&ctx->upload_queue_lock);

    return 0;
}

/*
 * Unlocked version - caller must hold upload_queue_lock
 * Used when the caller already holds the lock (e.g., cb_s3_upload timer callback)
 */
int s3_queue_add_pending_file_unlocked(struct flb_s3 *ctx,
                                               uint64_t file_id,
                                               const char *file_path,
                                               const char *tag,
                                               int tag_len)
{
    struct upload_queue *entry;

    entry = flb_calloc(1, sizeof(struct upload_queue));
    if (!entry) {
        flb_errno();
        return -1;
    }

    entry->file_id = file_id;
    entry->part_db_id = 0;
    entry->part_id = 0;
    entry->upload_file = NULL;
    entry->offset_start = 0;
    entry->offset_end = 0;
    entry->retry_counter = 0;
    entry->upload_time = time(NULL);
    entry->state = S3_STATE_INITIATE_MULTIPART;
    entry->s3_key = NULL;
    entry->upload_id = NULL;

    entry->stream_path = flb_sds_create(file_path);
    if (!entry->stream_path) {
        flb_errno();
        flb_free(entry);
        return -1;
    }

    entry->tag = flb_sds_create_len(tag, tag_len);
    if (!entry->tag) {
        flb_errno();
        flb_sds_destroy(entry->stream_path);
        flb_free(entry);
        return -1;
    }
    entry->tag_len = tag_len;

    /* Caller must hold lock */
    mk_list_add(&entry->_head, &ctx->upload_queue);

    return 0;
}

/*
 * Public version - acquires lock
 */
int s3_queue_add_pending_file(struct flb_s3 *ctx,
                               uint64_t file_id,
                               const char *file_path,
                               const char *tag,
                               int tag_len)
{
    int ret;

    pthread_mutex_lock(&ctx->upload_queue_lock);
    ret = s3_queue_add_pending_file_unlocked(ctx, file_id, file_path, tag, tag_len);
    pthread_mutex_unlock(&ctx->upload_queue_lock);

    return ret;
}

/*
 * Free queue entry memory without removing from list.
 * Used when the entry has already been removed from list by caller.
 */
void s3_queue_entry_destroy(struct flb_s3 *ctx, struct upload_queue *entry)
{
    if (!entry) {
        return;
    }

    if (entry->tag) {
        flb_sds_destroy(entry->tag);
    }

    if (entry->stream_path) {
        flb_sds_destroy(entry->stream_path);
    }

    if (entry->s3_key) {
        flb_sds_destroy(entry->s3_key);
    }

    if (entry->upload_id) {
        flb_sds_destroy(entry->upload_id);
    }

    flb_free(entry);
}

/*
 * Remove entry from list and free memory.
 * Used during cleanup/shutdown.
 */
int s3_queue_remove(struct flb_s3 *ctx, struct upload_queue *entry)
{
    if (!entry) {
        return -1;
    }

    mk_list_del(&entry->_head);
    s3_queue_entry_destroy(ctx, entry);
    return 0;
}

static int is_queue_entry_valid(struct upload_queue *entry, struct flb_s3 *ctx)
{
    /* Basic NULL checks */
    if (!entry || !entry->tag) {
        flb_plg_warn(ctx->ins, "Invalid queue entry: NULL entry or tag");
        return FLB_FALSE;
    }

    /* Check for invalid state: S3_STATE_UPLOAD_FILE with NULL upload_file */
    if (entry->state == S3_STATE_UPLOAD_FILE && entry->upload_file == NULL) {
        flb_plg_warn(ctx->ins, "Invalid queue entry: state is S3_STATE_UPLOAD_FILE but upload_file is NULL (tag=%s, file_id=%"PRIu64")",
                     entry->tag, entry->file_id);
        return FLB_FALSE;
    }

    /* Database-tracked upload (file_id > 0) - minimal checks */
    if (entry->file_id > 0) {
        /* Database-tracked: actual file state will be checked during upload */
        return FLB_TRUE;
    }

    /* Non-database-tracked upload (file_id == 0) - detailed checks needed */
    if (!entry->upload_file) {
        flb_plg_warn(ctx->ins, "Invalid non-database-tracked entry: missing upload_file (tag=%s)", entry->tag);
        return FLB_FALSE;
    }

    if (entry->upload_file->locked == FLB_FALSE) {
        flb_plg_warn(ctx->ins, "Invalid non-database-tracked entry: file not locked (tag=%s)", entry->tag);
        return FLB_FALSE;
    }

    if (entry->upload_file->size <= 0) {
        flb_plg_warn(ctx->ins, "Invalid non-database-tracked entry: zero size (tag=%s)", entry->tag);
        return FLB_FALSE;
    }

    return FLB_TRUE;
}

static int is_ready_to_upload(struct upload_queue *entry, time_t now)
{
    return (now >= entry->upload_time);
}

int s3_queue_buffer_chunk(void *out_context,
                          struct s3_file *upload_file,
                          flb_sds_t chunk,
                          int chunk_size,
                          const char *tag,
                          int tag_len,
                          time_t file_first_log_time)
{
    struct flb_s3 *ctx = out_context;
    int ret;

    ret = s3_store_buffer_put(ctx, upload_file, tag, tag_len,
                              chunk, (size_t)chunk_size, file_first_log_time);
    flb_sds_destroy(chunk);

    if (ret < 0) {
        flb_plg_warn(ctx->ins, "Failed to buffer chunk. "
                     "Data order preservation may be compromised");
        return -1;
    }

    return 0;
}

/*
 * Database-tracked upload: Upload individual part
 * - Uses part_db_id to track individual part upload
 * - Supports part-level resume after crash
 * - Updates database after each part upload
 */
static int upload_part_with_db_tracking(struct flb_s3 *ctx, struct upload_queue *entry)
{
    struct multipart_upload m_upload;
    flb_sds_t pre_signed_url = NULL;
    int ret;

    /* Check if exit is in progress */
    if (ctx->is_exiting == FLB_TRUE) {
        flb_plg_debug(ctx->ins, "Upload interrupted: exit in progress");
        return FLB_RETRY;
    }

    if (!entry->stream_path || !entry->s3_key || !entry->upload_id) {
        flb_plg_error(ctx->ins, "Part entry missing required fields");
        return -1;
    }

    /* Setup minimal multipart_upload structure */
    memset(&m_upload, 0, sizeof(m_upload));
    m_upload.s3_key = entry->s3_key;
    m_upload.upload_id = entry->upload_id;
    m_upload.part_number = (int)entry->part_id + 1;  /* AWS uses 1-based part numbers */
    m_upload.tag = entry->tag;

    /* Mark part as in_progress */
    if (ctx->blob_db.db) {
        flb_blob_db_file_part_in_progress(&ctx->blob_db, 1, entry->part_db_id);
    }

    /* Fetch presigned URL */
    ret = s3_auth_fetch_presigned_url(ctx, &pre_signed_url,
                                       S3_PRESIGNED_URL_UPLOAD_PART,
                                       entry->s3_key, entry->upload_id,
                                       m_upload.part_number);
    if (ret < 0) {
        flb_plg_error(ctx->ins, "Failed to fetch presigned URL for part upload");
        if (ctx->blob_db.db) {
            flb_blob_db_file_part_in_progress(&ctx->blob_db, 0, entry->part_db_id);
        }
        return FLB_RETRY;
    }

    /* Upload the part */
    struct s3_data_source src;
    src.type = S3_SOURCE_FILE;
    src.file.path = entry->stream_path;
    src.file.offset_start = entry->offset_start;
    src.file.offset_end = entry->offset_end;

    ret = s3_multipart_upload_part_from_source(ctx, &src, &m_upload, pre_signed_url);
    flb_sds_destroy(pre_signed_url);

    if (ret == 0) {
        /* Success - mark part as uploaded and save ETag */
        if (ctx->blob_db.db) {
            /* Save ETag to database */
            if (m_upload.part_number > 0 && m_upload.part_number <= 10000 &&
                m_upload.etags[m_upload.part_number - 1]) {
                flb_blob_db_file_part_update_remote_id(&ctx->blob_db, entry->part_db_id,
                                                        m_upload.etags[m_upload.part_number - 1]);
                /* Free the SDS string after it's been saved to database */
                flb_sds_destroy(m_upload.etags[m_upload.part_number - 1]);
                m_upload.etags[m_upload.part_number - 1] = NULL;
            }
            flb_blob_db_file_part_uploaded(&ctx->blob_db, entry->part_db_id);
        }

        /* Check if all parts are uploaded and complete if so */
        ret = check_and_complete_multipart(ctx, entry->file_id, entry->s3_key);
        if (ret < 0) {
            flb_plg_warn(ctx->ins, "Failed to complete multipart upload for file_id=%"PRIu64,
                        entry->file_id);
        }

        return FLB_OK;
    }
    else {
        /* Upload failed - clean up any allocated etag */
        if (m_upload.part_number > 0 && m_upload.part_number <= 10000 &&
            m_upload.etags[m_upload.part_number - 1]) {
            flb_sds_destroy(m_upload.etags[m_upload.part_number - 1]);
            m_upload.etags[m_upload.part_number - 1] = NULL;
        }

        flb_plg_warn(ctx->ins, "Failed to upload part %"PRIu64" of file_id=%"PRIu64,
                    entry->part_id, entry->file_id);

        if (ctx->blob_db.db) {
            flb_blob_db_file_part_in_progress(&ctx->blob_db, 0, entry->part_db_id);
        }

        return FLB_RETRY;
    }
}

/*
 * Non-database-tracked upload: Upload log data without database
 * - Uses upload_file pointer directly (fstore storage)
 * - Failed uploads retry from beginning
 * - Lower overhead for small files, no resume support
 */
static int upload_without_db_tracking(struct flb_s3 *ctx, struct upload_queue *entry)
{
    flb_sds_t buffer = NULL;
    size_t buffer_size;
    time_t file_first_log_time;
    int ret;

    file_first_log_time = entry->upload_file ?
                         entry->upload_file->first_log_time : time(NULL);

    /* Format chunk data */
    ret = s3_format_chunk(ctx, entry->upload_file, &buffer, &buffer_size);
    if (ret < 0) {
        return -1;
    }

    /* Handle empty output (success but no data) */
    if (buffer == NULL || buffer_size == 0) {
        flb_plg_debug(ctx->ins, "Queue entry produced no output data, removing from queue");
        s3_store_file_unlock(entry->upload_file);
        s3_store_file_delete(ctx, entry->upload_file);
        return 0;  /* Return 0 to indicate entry should be freed */
    }

    /* Upload to S3 */
    ret = s3_upload_file(ctx, buffer,
                        entry->tag, entry->tag_len, file_first_log_time);
    flb_sds_destroy(buffer);

    if (ret == FLB_OK) {
        if (entry->upload_file) {
            s3_store_file_delete(ctx, entry->upload_file);
        }
        return FLB_OK;
    }

    if (entry->upload_file) {
        s3_store_file_unlock(entry->upload_file);
        entry->upload_file->failures++;
    }

    return FLB_RETRY;
}

/*
 * Check if all parts are uploaded and complete multipart upload
 * Uses the s3_key from the part entry to ensure consistency with the upload
 */
static int check_and_complete_multipart(struct flb_s3 *ctx, uint64_t file_id, const char *s3_key)
{
    uint64_t db_file_id;
    cfl_sds_t file_path = NULL;
    cfl_sds_t part_ids = NULL;
    cfl_sds_t source = NULL;
    cfl_sds_t file_remote_id = NULL;
    cfl_sds_t file_tag = NULL;
    time_t file_created = 0;
    int part_count;
    struct multipart_upload m_upload;
    flb_sds_t pre_signed_url = NULL;
    int ret;
    int i;

    if (!ctx->blob_db.db) {
        return 0;
    }

    /* Check if file has all parts uploaded */
    cfl_sds_t db_file_s3_key = NULL;
    ret = flb_blob_db_file_fetch_oldest_ready(&ctx->blob_db,
                                               &db_file_id, &file_path,
                                               &part_ids, &source,
                                               &file_remote_id, &file_tag,
                                               &db_file_s3_key,
                                               &part_count, &file_created);
    if (ret != 1 || db_file_id != file_id) {
        /* Not ready or different file */
        if (file_path) {
            cfl_sds_destroy(file_path);
        }
        if (part_ids) {
            cfl_sds_destroy(part_ids);
        }
        if (source) {
            cfl_sds_destroy(source);
        }
        if (file_remote_id) {
            cfl_sds_destroy(file_remote_id);
        }
        if (file_tag) {
            cfl_sds_destroy(file_tag);
        }
        if (db_file_s3_key) {
            cfl_sds_destroy(db_file_s3_key);
        }
        return 0;
    }

    /* Setup multipart_upload structure */
    memset(&m_upload, 0, sizeof(m_upload));

    /*
     * CRITICAL FIX: Use s3_key from database file record (authoritative source).
     * The database s3_key column stores the actual key used during CreateMultipartUpload.
     * Fall back to the parameter (from part entry) only if database key is empty.
     */
    if (db_file_s3_key && cfl_sds_len(db_file_s3_key) > 0) {
        m_upload.s3_key = db_file_s3_key;
        db_file_s3_key = NULL;  /* Transfer ownership */
    }
    else {
        /* Fallback: use passed s3_key parameter (may be from part or regenerated) */
        if (db_file_s3_key) {
            cfl_sds_destroy(db_file_s3_key);
            db_file_s3_key = NULL;
        }
        m_upload.s3_key = flb_sds_create(s3_key);
        if (!m_upload.s3_key) {
            flb_plg_error(ctx->ins, "Failed to copy S3 key for complete");
            goto cleanup;
        }
    }

    m_upload.tag = flb_sds_create(file_tag);
    if (!m_upload.tag) {
        flb_plg_error(ctx->ins, "Failed to create tag copy");
        goto cleanup;
    }

    m_upload.upload_id = flb_sds_create(file_remote_id);
    if (!m_upload.upload_id) {
        flb_plg_error(ctx->ins, "Failed to create upload_id copy");
        goto cleanup;
    }

    m_upload.part_number = part_count;

    /* Validate part_count before allocating (AWS S3 max is 10000) */
    if (part_count <= 0 || part_count > 10000) {
        flb_plg_error(ctx->ins, "Invalid part_count=%d for file_id=%" PRIu64,
                     part_count, file_id);
        goto cleanup;
    }

    /* Fetch all ETags from database (already ordered by part_id via SQL ORDER BY) */
    flb_sds_t *remote_id_list = flb_calloc(part_count, sizeof(flb_sds_t));
    if (!remote_id_list) {
        goto cleanup;
    }

    int remote_id_count = 0;
    ret = flb_blob_db_file_fetch_part_ids(&ctx->blob_db, file_id,
                                          remote_id_list, part_count,
                                          &remote_id_count);
    if (ret < 0 || remote_id_count != part_count) {
        flb_plg_error(ctx->ins, "Failed to fetch part ETags");
        for (i = 0; i < remote_id_count; i++) {
            if (remote_id_list[i]) {
                flb_sds_destroy(remote_id_list[i]);
            }
        }
        flb_free(remote_id_list);
        goto cleanup;
    }

    /* Copy ETags to m_upload (already ordered by part_id from SQL query) */
    for (i = 0; i < remote_id_count && i < 10000; i++) {
        m_upload.etags[i] = remote_id_list[i];
    }
    flb_free(remote_id_list);

    /* Fetch presigned URL for complete */
    ret = s3_auth_fetch_presigned_url(ctx, &pre_signed_url,
                                       S3_PRESIGNED_URL_COMPLETE_MULTIPART,
                                       m_upload.s3_key, file_remote_id, 0);
    if (ret < 0) {
        flb_plg_error(ctx->ins, "Failed to fetch presigned URL for complete");
        goto cleanup;
    }

    /* Complete multipart upload */
    ret = s3_multipart_complete(ctx, &m_upload, pre_signed_url);
    flb_sds_destroy(pre_signed_url);
    pre_signed_url = NULL;

    if (ret == 0) {
        flb_plg_info(ctx->ins, "Completed multipart upload: file_id=%"PRIu64" (%d parts)",
                     file_id, part_count);

        /* Send success notification before deleting (only for blob files with valid source) */
        if (source && cfl_sds_len(source) > 0) {
            s3_blob_notify_delivery(ctx, ctx->ins->config, source, file_path, file_id, FLB_TRUE);
        }

        /* Delete file from database */
        flb_blob_db_file_delete(&ctx->blob_db, file_id);
    }
    else if (ret == S3_MULTIPART_ERROR_GENERAL) {
        flb_plg_error(ctx->ins, "Complete failed for file_id=%"PRIu64 ", aborting", file_id);

        int abort_ret = s3_auth_fetch_presigned_url(ctx, &pre_signed_url,
                                                     S3_PRESIGNED_URL_ABORT_MULTIPART,
                                                     m_upload.s3_key, m_upload.upload_id, 0);
        if (abort_ret >= 0 && pre_signed_url) {
            s3_multipart_abort(ctx, &m_upload, pre_signed_url);
            flb_sds_destroy(pre_signed_url);
        }
        else {
            s3_multipart_abort(ctx, &m_upload, NULL);
        }

        flb_blob_file_update_remote_id(&ctx->blob_db, file_id, "");
        flb_blob_db_file_reset_upload_states(&ctx->blob_db, file_id);
    }
    else {
        flb_plg_warn(ctx->ins, "Complete returned NoSuchUpload for file_id=%"PRIu64, file_id);
        flb_blob_file_update_remote_id(&ctx->blob_db, file_id, "");
        flb_blob_db_file_reset_upload_states(&ctx->blob_db, file_id);
    }

cleanup:
    if (m_upload.s3_key) {
        flb_sds_destroy(m_upload.s3_key);
    }
    if (m_upload.tag) {
        flb_sds_destroy(m_upload.tag);
    }
    if (m_upload.upload_id) {
        flb_sds_destroy(m_upload.upload_id);
    }
    for (i = 0; i < 10000; i++) {
        if (m_upload.etags[i]) {
            flb_sds_destroy(m_upload.etags[i]);
        }
    }
    if (file_path) {
        cfl_sds_destroy(file_path);
    }
    if (part_ids) {
        cfl_sds_destroy(part_ids);
    }
    if (source) {
        cfl_sds_destroy(source);
    }
    if (file_remote_id) {
        cfl_sds_destroy(file_remote_id);
    }
    if (file_tag) {
        cfl_sds_destroy(file_tag);
    }

    return (ret == 0) ? 0 : -1;
}

static int handle_upload_failure(struct flb_s3 *ctx,
                                   struct upload_queue *entry,
                                   time_t now)
{
    int limit = ctx->ins->retry_limit;

    /* Use specific limits based on operation type if configured */
    if (entry->state == S3_STATE_UPLOAD_PART) {
        if (ctx->part_delivery_attempt_limit > 0) {
            limit = ctx->part_delivery_attempt_limit;
        }
    }
    else if (entry->state == S3_STATE_UPLOAD_FILE ||
             entry->state == S3_STATE_INITIATE_MULTIPART) {
        if (ctx->file_delivery_attempt_limit > 0) {
            limit = ctx->file_delivery_attempt_limit;
        }
    }

    entry->retry_counter++;

    if (entry->retry_counter >= limit) {
        if (entry->file_id > 0) {
            flb_plg_warn(ctx->ins, "Database-tracked upload failed to send %d times (limit: %d), removing from queue",
                         entry->retry_counter, limit);
            /* Mark file as aborted in database */
            if (ctx->blob_db.db != NULL) {
                flb_blob_db_file_set_aborted_state(&ctx->blob_db, entry->file_id, 1);
            }
        }
        else {
            flb_plg_warn(ctx->ins, "Non-database-tracked upload failed to send %d times, "
                         "marking as inactive", entry->retry_counter);
            if (entry->upload_file) {
                s3_store_file_inactive(ctx, entry->upload_file);
            }
        }
        /* Entry already removed from list by caller, just free memory */
        s3_queue_entry_destroy(ctx, entry);
        return S3_UPLOAD_ENTRY_DESTROYED;
    }

    /* Schedule retry */
    entry->upload_time = now + 2 * entry->retry_counter;

    if (entry->file_id > 0) {
        /* Will retry */
    }
    else {
        if (entry->upload_file) {
            s3_store_file_lock(entry->upload_file);
        }
        /* 
         * FIX: Do NOT increment global retry_time.
         * Using global retry_time causes Head-of-Line blocking where one failing file
         * prevents ALL new files from being uploaded.
         * We rely on entry->upload_time (set above) for per-file backoff.
         */
        /* ctx->retry_time += 2 * entry->retry_counter; */
        ctx->upload_queue_success = FLB_FALSE;
    }

    return S3_UPLOAD_ENTRY_REQUEUE;
}

/*
 * Process a queue entry - public function called by timer callback
 * Returns: S3_QUEUE_ENTRY_SUCCESS on success (entry freed),
 *          S3_QUEUE_ENTRY_RETRY on failure (will retry),
 *          S3_QUEUE_ENTRY_INVALID if invalid (entry freed)
 */
int s3_queue_process_entry(struct flb_s3 *ctx,
                            struct upload_queue *entry,
                            time_t now)
{
    int ret;
    int failure_ret;

    if (!is_queue_entry_valid(entry, ctx)) {
        flb_plg_warn(ctx->ins, "Invalid queue entry, removing");
        s3_queue_entry_destroy(ctx, entry);
        return S3_QUEUE_ENTRY_INVALID;
    }

    if (!is_ready_to_upload(entry, now)) {
        return S3_QUEUE_ENTRY_RETRY;
    }

    switch (entry->state) {
    case S3_STATE_INITIATE_MULTIPART:
        ret = s3_initiate_multipart_upload(ctx, entry->file_id,
                                           entry->stream_path,
                                           entry->tag, entry->tag_len);
        if (ret == 0) {
            s3_queue_entry_destroy(ctx, entry);
            return S3_QUEUE_ENTRY_SUCCESS;
        }

        /* Only update DB state if database is enabled */
        if (ctx->blob_db.db != NULL) {
            /* CRITICAL FIX: Increment delivery_attempts before marking as aborted.
             * Without this, the file would be retried infinitely during recovery
             * since delivery_attempts would remain at 0. */
            uint64_t new_attempts = entry->retry_counter + 1;
            flb_blob_db_file_delivery_attempts(&ctx->blob_db, entry->file_id, new_attempts);
            flb_blob_db_file_set_aborted_state(&ctx->blob_db, entry->file_id, 1);
        }
        s3_queue_entry_destroy(ctx, entry);
        return S3_QUEUE_ENTRY_INVALID;

    case S3_STATE_UPLOAD_PART:
        ret = upload_part_with_db_tracking(ctx, entry);
        if (ret == FLB_OK) {
            s3_queue_entry_destroy(ctx, entry);
            return S3_QUEUE_ENTRY_SUCCESS;
        }
        break;

    case S3_STATE_UPLOAD_FILE:
        ret = upload_without_db_tracking(ctx, entry);
        if (ret == FLB_OK) {
            s3_queue_entry_destroy(ctx, entry);
            ctx->retry_time = 0;
            ctx->upload_queue_success = FLB_TRUE;
            return S3_QUEUE_ENTRY_SUCCESS;
        }
        break;

    default:
        flb_plg_error(ctx->ins, "Unknown queue entry state: %d", entry->state);
        s3_queue_entry_destroy(ctx, entry);
        return S3_QUEUE_ENTRY_INVALID;
    }

    /* Handle failure for upload cases (PART and FILE) */
    failure_ret = handle_upload_failure(ctx, entry, now);
    if (failure_ret == S3_UPLOAD_ENTRY_DESTROYED) {
        return S3_QUEUE_ENTRY_INVALID;
    }
    return S3_QUEUE_ENTRY_RETRY;
}


/*
 * Phase 3: Rebuild queue from persistent storage
 * Scans all pending files and enqueues them for upload
 */
static int rebuild_queue_from_storage(struct flb_s3 *ctx)
{
    int blob_files = 0;
    int log_files = 0;
    int total = 0;

    /* Database-tracked: Scan database for all pending files */
    if (ctx->blob_db.db != NULL) {
        /* Scan for all files needing recovery (includes ready-to-complete files) */
        blob_files = s3_queue_recover_from_database(ctx);

        if (blob_files > 0) {
            total += blob_files;
        }
        else if (blob_files < 0) {
            flb_plg_error(ctx->ins, "Phase 3: database scan error");
        }
    }

    /* Non-database-tracked: Scan fstore for buffered chunks */
    if (ctx->fs && ctx->has_old_buffers == FLB_TRUE) {
        log_files = s3_queue_recover_from_fstore(ctx);

        if (log_files > 0) {
            total += log_files;
        }
    }

    return total;
}

/*
 * Simplified recovery interface - Three-phase architecture
 * Phase 0: Global cleanup (reset zombie parts once)
 * Phase 1: State transitions (stale → pending, aborted → pending/delete)
 * Phase 2: Queue rebuild (scan storage and enqueue)
 */
int s3_queue_recover_all(struct flb_s3 *ctx, struct flb_config *config)
{
    int ret;
    int lock_ret;
    int total_enqueued = 0;

    flb_plg_info(ctx->ins, "Starting 3-phase recovery");

    /* Phase 0: Global cleanup - reset all zombie parts once */
    if (ctx->blob_db.db != NULL) {
        lock_ret = flb_blob_db_lock(&ctx->blob_db);
        if (lock_ret != 0) {
            flb_plg_error(ctx->ins, "Phase 0: Failed to acquire blob DB lock (ret=%d)", lock_ret);
            return -1;
        }

        ret = flb_blob_db_reset_zombie_parts(&ctx->blob_db);

        lock_ret = flb_blob_db_unlock(&ctx->blob_db);
        if (lock_ret != 0) {
            flb_plg_warn(ctx->ins, "Phase 0: Failed to release blob DB lock (ret=%d)", lock_ret);
        }

        if (ret < 0) {
            flb_plg_error(ctx->ins, "Phase 0: zombie cleanup failed");
            return -1;
        }
        flb_plg_debug(ctx->ins, "Phase 0: zombie parts reset complete");
    }

    /* Phase 1: State transitions (stale, aborted) */
    if (ctx->blob_db.db != NULL) {
        ret = s3_blob_recover_state(ctx, config);
        if (ret < 0) {
            flb_plg_error(ctx->ins, "Phase 1: state transitions failed");
            return -1;
        }
    }

    /* Phase 2: Rebuild queue from storage */
    total_enqueued = rebuild_queue_from_storage(ctx);

    if (total_enqueued < 0) {
        flb_plg_error(ctx->ins, "Phase 2 failed");
        return -1;
    }

    if (total_enqueued > 0) {
        flb_plg_info(ctx->ins, "Recovery complete: enqueued %d file(s)", total_enqueued);
    }
    else {
        flb_plg_info(ctx->ins, "Recovery complete: no buffered data found");
    }

    return total_enqueued;
}

/* Resume file upload using stored or generated s3_key */
static int resume_file_upload(struct flb_s3 *ctx,
                               uint64_t file_id,
                               const char *file_path,
                               const char *remote_id,
                               const char *stored_s3_key,
                               const char *tag,
                               int tag_len)
{
    flb_sds_t s3_key = NULL;
    const char *key_to_use;
    int ret;
    int enqueued;

    /* Check file exists */
    if (flb_s3_access(file_path, F_OK) != 0) {
        flb_plg_error(ctx->ins, "File deleted: %s (file_id=%" PRIu64 ")",
                     file_path, file_id);
        flb_blob_db_file_delete(&ctx->blob_db, file_id);
        return -1;
    }

    /* Fast path: use stored s3_key (no validation) */
    if (stored_s3_key && stored_s3_key[0] != '\0') {
        key_to_use = stored_s3_key;
        flb_plg_debug(ctx->ins, "Resume: using stored s3_key for file_id=%" PRIu64, file_id);
    }
    else {
        /* Legacy path: generate and validate */
        s3_key = flb_get_s3_key(ctx->s3_key_format, time(NULL), tag,
                                ctx->tag_delimiters, ctx->seq_index, file_path);
        if (!s3_key) {
            flb_plg_error(ctx->ins, "Failed to generate S3 key");
            flb_blob_db_file_parts_in_progress(&ctx->blob_db, file_id, 0);
            return -1;
        }

        ret = s3_multipart_check_upload_exists(ctx, s3_key, remote_id);

        if (ret == 1) {
            key_to_use = s3_key;
            flb_plg_debug(ctx->ins, "Resume: validated legacy upload for file_id=%" PRIu64, file_id);
        }
        else if (ret == 0) {
            flb_plg_warn(ctx->ins, "Upload expired for file_id=%" PRIu64 ", will recreate", file_id);
            flb_blob_db_file_parts_in_progress(&ctx->blob_db, file_id, 0);
            flb_sds_destroy(s3_key);
            return 0;
        }
        else {
            flb_plg_warn(ctx->ins, "Validation failed (transient) for file_id=%" PRIu64
                        ", will retry", file_id);
            flb_blob_db_file_parts_in_progress(&ctx->blob_db, file_id, 0);
            flb_sds_destroy(s3_key);
            return -1;
        }
    }

    enqueued = enqueue_file_parts_for_resume(ctx, file_id, file_path,
                                             remote_id, key_to_use,
                                             tag, tag_len);

    if (enqueued > 0) {
        if (s3_key) {
            flb_sds_destroy(s3_key);
        }
        return enqueued;
    }

    /*
     * If no parts were enqueued, all parts may already be uploaded.
     * Check if the upload is ready for completion.
     */
    ret = check_and_complete_multipart(ctx, file_id, key_to_use);
    
    /* Now safe to destroy s3_key after check_and_complete_multipart returns */
    if (s3_key) {
        flb_sds_destroy(s3_key);
    }
    if (ret == 0) {
        /* Successfully completed - return success but 0 enqueued since completion happened directly */
        return 0;
    }

    /* Not ready for completion or completion failed - treat as error */
    flb_blob_db_file_parts_in_progress(&ctx->blob_db, file_id, 0);
    return -1;
}

/* Create new multipart upload for file */
static int create_new_upload(struct flb_s3 *ctx,
                              uint64_t file_id,
                              const char *file_path,
                              const char *tag,
                              int tag_len,
                              int part_count)
{
    int ret;

    flb_blob_file_update_remote_id(&ctx->blob_db, file_id, "");
    flb_blob_db_file_reset_upload_states(&ctx->blob_db, file_id);

    ret = s3_initiate_multipart_upload(ctx, file_id, file_path, tag, tag_len);
    if (ret < 0) {
        flb_plg_error(ctx->ins, "Failed to create upload for file_id=%" PRIu64, file_id);
        flb_blob_db_file_set_aborted_state(&ctx->blob_db, file_id, 1);
        return -1;
    }

    return part_count;
}

/* Scan database and enqueue pending files for recovery */
int s3_queue_recover_from_database(struct flb_s3 *ctx)
{
    uint64_t file_id;
    cfl_sds_t file_path = NULL;
    cfl_sds_t destination = NULL;
    cfl_sds_t remote_id = NULL;
    cfl_sds_t tag = NULL;
    cfl_sds_t stored_s3_key = NULL;
    cfl_sds_t part_ids = NULL;
    cfl_sds_t source = NULL;
    time_t file_created = 0;
    int part_count;
    int total_enqueued = 0;
    int total_completed = 0;
    int ret;

    if (!ctx->blob_db.db) {
        return 0;
    }

    /* First, handle files that are ready to complete (all parts uploaded) */
    while (1) {
        cfl_sds_t file_s3_key = NULL;
        ret = flb_blob_db_file_fetch_oldest_ready(&ctx->blob_db,
                                                   &file_id, &file_path,
                                                   &part_ids, &source,
                                                   &remote_id, &tag,
                                                   &file_s3_key,
                                                   &part_count, &file_created);
        if (ret != 1) {
            break;  /* No more ready files */
        }

        /* Use stored s3_key from database if available, otherwise generate */
        flb_sds_t s3_key = NULL;
        if (file_s3_key && cfl_sds_len(file_s3_key) > 0) {
            /* Prefer stored key from database s3_key column */
            s3_key = flb_sds_create(file_s3_key);
            if (s3_key) {
                flb_plg_debug(ctx->ins, "Recovery: using stored s3_key for ready file_id=%" PRIu64, file_id);
            }
        }
        
        if (!s3_key) {
            /* Fallback: generate s3_key */
            s3_key = flb_get_s3_key(ctx->s3_key_format, file_created, tag,
                                    ctx->tag_delimiters, ctx->seq_index, file_path);
        }
        
        if (!s3_key) {
            flb_plg_warn(ctx->ins, "Recovery: failed to get/generate s3_key for ready file_id=%" PRIu64,
                        file_id);
            goto ready_cleanup;
        }

        /* Try to complete the multipart upload using upload_id from remote_id */
        ret = check_and_complete_multipart(ctx, file_id, s3_key);
        if (ret == 0) {
            total_completed++;
            flb_plg_debug(ctx->ins, "Recovery: completed ready file_id=%" PRIu64, file_id);
        }
        else {
            flb_plg_warn(ctx->ins, "Recovery: failed to complete ready file_id=%" PRIu64, file_id);
        }

        flb_sds_destroy(s3_key);

ready_cleanup:
        if (file_path) cfl_sds_destroy(file_path);
        if (part_ids) cfl_sds_destroy(part_ids);
        if (source) cfl_sds_destroy(source);
        if (remote_id) cfl_sds_destroy(remote_id);
        if (tag) cfl_sds_destroy(tag);
        if (file_s3_key) cfl_sds_destroy(file_s3_key);

        file_path = NULL;
        part_ids = NULL;
        source = NULL;
        remote_id = NULL;
        tag = NULL;
    }

    if (total_completed > 0) {
        flb_plg_info(ctx->ins, "Recovery: completed %d ready file(s)", total_completed);
    }

    /* Then handle files with unuploaded parts */
    while (1) {
        /* Get next pending file */
        ret = flb_blob_db_file_get_next_pending(&ctx->blob_db,
                                                 &file_id, &file_path,
                                                 &destination, &remote_id,
                                                 &tag, &stored_s3_key,
                                                 &part_count);
        if (ret <= 0) {
            break;  /* No more files or error */
        }

        /* Skip if endpoint mismatch - reset in_progress before skipping */
        if (!destination || !ctx->endpoint || strcmp(destination, ctx->endpoint) != 0) {
            flb_plg_debug(ctx->ins, "Skipping file_id=%" PRIu64 " due to endpoint mismatch",
                         file_id);
            /* Reset in_progress flag so the file isn't hidden until zombie cleanup */
            flb_blob_db_file_parts_in_progress(&ctx->blob_db, file_id, 0);
            goto cleanup;
        }

        /* Mark parts as in_progress to prevent re-query */
        if (flb_blob_db_file_parts_in_progress(&ctx->blob_db, file_id, 1) < 0) {
            flb_plg_error(ctx->ins, "Failed to mark parts in_progress for file_id=%" PRIu64, file_id);
            goto cleanup;
        }

        /* Try to resume or create new upload */
        if (remote_id && cfl_sds_len(remote_id) > 0) {
            /* Has upload_id - try resume */
            ret = resume_file_upload(ctx, file_id, file_path, remote_id,
                                    stored_s3_key, tag, cfl_sds_len(tag));
            if (ret > 0) {
                total_enqueued += ret;
            }
            else if (ret == 0) {
                /* Resume failed (upload expired) - create new */
                ret = create_new_upload(ctx, file_id, file_path, tag,
                                       cfl_sds_len(tag), part_count);
                if (ret > 0) {
                    total_enqueued += ret;
                }
            }
        }
        else {
            /* No upload_id - create new */
            ret = create_new_upload(ctx, file_id, file_path, tag,
                                   cfl_sds_len(tag), part_count);
            if (ret > 0) {
                total_enqueued += ret;
            }
        }

cleanup:
        /* Cleanup allocated strings */
        if (file_path) cfl_sds_destroy(file_path);
        if (destination) cfl_sds_destroy(destination);
        if (remote_id) cfl_sds_destroy(remote_id);
        if (tag) cfl_sds_destroy(tag);
        if (stored_s3_key) cfl_sds_destroy(stored_s3_key);

        file_path = NULL;
        destination = NULL;
        remote_id = NULL;
        tag = NULL;
        stored_s3_key = NULL;
    }

    if (total_enqueued > 0) {
        flb_plg_info(ctx->ins, "Recovery: enqueued %d part(s) from database", total_enqueued);
    }

    return total_enqueued;
}

/* Enqueue unuploaded parts for resume */
static int enqueue_file_parts_for_resume(struct flb_s3 *ctx,
                                          uint64_t file_id,
                                          const char *file_path,
                                          const char *upload_id,
                                          const char *s3_key,
                                          const char *tag,
                                          int tag_len)
{
    uint64_t *part_db_ids = NULL;
    uint64_t *part_nums = NULL;
    off_t *offset_starts = NULL;
    off_t *offset_ends = NULL;
    int part_count = 0;
    int enqueued = 0;
    int ret;
    int i;

    /* Get all parts for this file */
    ret = flb_blob_db_file_fetch_all_parts(&ctx->blob_db, file_id,
                                            &part_db_ids, &part_nums,
                                            &offset_starts, &offset_ends,
                                            &part_count);
    if (ret < 0 || part_count == 0) {
        return -1;
    }

    /* Enqueue only unuploaded parts */
    for (i = 0; i < part_count; i++) {
        /* Check if this part is already uploaded */
        int uploaded = 0;

        ret = flb_blob_db_file_part_check_uploaded(&ctx->blob_db, part_db_ids[i], &uploaded);
        if (ret < 0) {
            flb_plg_warn(ctx->ins, "Failed to check upload status for part_id=%" PRIu64, part_db_ids[i]);
            enqueued = -1;
            break;
        }

        /* Skip already uploaded parts */
        if (uploaded == 1) {
            continue;
        }

        /* Enqueue this part - use stored s3_key directly */
        ret = s3_queue_add_part(ctx, file_id, part_db_ids[i], part_nums[i],
                               file_path, offset_starts[i], offset_ends[i],
                               s3_key, upload_id,
                               tag, tag_len);
        if (ret == 0) {
            enqueued++;
        }
    }

    /* Cleanup */
    if (part_db_ids) flb_free(part_db_ids);
    if (part_nums) flb_free(part_nums);
    if (offset_starts) flb_free(offset_starts);
    if (offset_ends) flb_free(offset_ends);

    if (enqueued < 0) {
        /* Reset in_progress flag to allow future recovery attempts */
        (void) flb_blob_db_file_parts_in_progress(&ctx->blob_db, file_id, 0);
        return -1;
    }
    return enqueued;
}

/* Recover buffered files from fstore during restart (non-database-tracked log data) */
int s3_queue_recover_from_fstore(struct flb_s3 *ctx)
{
    struct s3_file *chunk;
    struct flb_fstore_file *fsf;
    struct flb_fstore_stream *fs_stream;
    struct mk_list *s_head;
    struct mk_list *head;
    struct mk_list *tmp;
    int total_files = 0;
    int ret;

    if (!ctx->fs) {
        return 0;
    }

    /* Iterate through all streams */
    mk_list_foreach(s_head, &ctx->fs->streams) {
        fs_stream = mk_list_entry(s_head, struct flb_fstore_stream, _head);

        /* Skip metadata stream */
        if (fs_stream == ctx->stream_metadata) {
            continue;
        }

        /* Process all files in this stream */
        mk_list_foreach_safe(head, tmp, &fs_stream->files) {
            fsf = mk_list_entry(head, struct flb_fstore_file, _head);
            chunk = fsf->data;

            if (!chunk) {
                continue;
            }

            if (chunk->locked == FLB_TRUE) {
                continue;
            }

            if (chunk->failures >= ctx->ins->retry_limit) {
                flb_plg_warn(ctx->ins,
                             "Chunk failed %d times, marking inactive (tag=%s)",
                             chunk->failures, (char*)fsf->meta_buf);
                s3_store_file_inactive(ctx, chunk);
                continue;
            }

            /* Add to worker queue (non-database-tracked: file_id=0) */
            s3_store_file_lock(chunk);
            ret = s3_queue_add_file(ctx, 0, chunk, NULL,
                                    (const char*)fsf->meta_buf,
                                    fsf->meta_size);
            if (ret == 0) {
                total_files++;
            }
            else {
                s3_store_file_unlock(chunk);
            }
        }
    }

    return total_files;
}