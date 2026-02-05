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
#include <fluent-bit/flb_input_blob.h>
#include <fluent-bit/flb_log_event_decoder.h>
#include <fluent-bit/flb_notification.h>
#include <fluent-bit/flb_plugin.h>
#include <sys/stat.h>
#include <inttypes.h>
#include "s3.h"
#include "s3_multipart.h"
#include "s3_blob.h"
#include "s3_store.h"
#include "s3_stream.h"
#include "s3_auth.h"
#include "s3_queue.h"

/* Forward declarations */
static int recover_stale_files(struct flb_s3 *ctx);
static int handle_aborted_files(struct flb_s3 *ctx, struct flb_config *config);


static int abort_multipart_upload(struct flb_s3 *ctx,
                                   cfl_sds_t file_tag,
                                   cfl_sds_t file_path,
                                   cfl_sds_t file_remote_id,
                                   cfl_sds_t s3_key)
{
    struct multipart_upload *m_upload;
    flb_sds_t pre_signed_url = NULL;
    flb_sds_t key_to_use = NULL;
    int ret;

    /* Validate file_remote_id to prevent crashes */
    if (!file_remote_id || cfl_sds_len(file_remote_id) == 0) {
        flb_plg_warn(ctx->ins, "abort multipart requested without upload_id");
        return -1;
    }

    /*
     * When s3_key is provided (from database), use it directly.
     * This is critical because regenerating the key may produce a different
     * value if s3_key_format contains time variables (e.g., %Y/%m/%d/%H/%M).
     * The key must match the original object key from CreateMultipartUpload.
     */
    if (s3_key && cfl_sds_len(s3_key) > 0) {
        /* Use stored s3_key - this is the correct key */
        key_to_use = flb_sds_create(s3_key);
        if (!key_to_use) {
            flb_plg_error(ctx->ins, "Failed to allocate s3_key for abort");
            return -1;
        }
    }
    else {
        /*
         * Without the original s3_key, we cannot reliably abort the multipart upload.
         * Regenerating keys using current time is unreliable and dangerous (could target wrong object).
         * Log error and return failure - better to leak an upload part on S3 than risk data corruption.
         */
        flb_plg_error(ctx->ins, "Cannot abort multipart upload: missing s3_key for upload_id=%s. "
                      "Manual cleanup on S3 may be required.", file_remote_id);
        return -1;
    }

    /* Allocate minimal multipart_upload struct for abort operation */
    m_upload = flb_calloc(1, sizeof(struct multipart_upload));
    if (!m_upload) {
        flb_errno();
        flb_sds_destroy(key_to_use);
        return -1;
    }

    m_upload->s3_key = key_to_use;
    m_upload->upload_id = flb_sds_create(file_remote_id);
    if (!m_upload->upload_id) {
        flb_plg_error(ctx->ins, "Could not allocate upload id copy");
        flb_sds_destroy(m_upload->s3_key);
        flb_free(m_upload);
        return -1;
    }

    ret = s3_auth_fetch_presigned_url(ctx, &pre_signed_url,
                                       S3_PRESIGNED_URL_ABORT_MULTIPART,
                                       m_upload->s3_key, m_upload->upload_id, 0);
    if (ret < 0) {
        if (pre_signed_url) {
            flb_sds_destroy(pre_signed_url);
        }
        flb_sds_destroy(m_upload->s3_key);
        flb_sds_destroy(m_upload->upload_id);
        flb_free(m_upload);
        return -1;
    }

    ret = s3_multipart_abort(ctx, m_upload, pre_signed_url);
    flb_sds_destroy(pre_signed_url);
    flb_sds_destroy(m_upload->s3_key);
    flb_sds_destroy(m_upload->upload_id);
    flb_free(m_upload);

    return ret;
}

int s3_blob_notify_delivery(struct flb_s3 *ctx,
                                struct flb_config *config,
                                cfl_sds_t source,
                                cfl_sds_t file_path,
                                uint64_t file_id,
                                int success)
{
    struct flb_blob_delivery_notification *notification;
    int ret;

    notification = flb_calloc(1, sizeof(struct flb_blob_delivery_notification));
    if (!notification) {
        flb_plg_error(ctx->ins, "failed to allocate delivery notification");
        return -1;
    }

    notification->base.dynamically_allocated = FLB_TRUE;
    notification->base.notification_type = FLB_NOTIFICATION_TYPE_BLOB_DELIVERY;
    notification->base.destructor = flb_input_blob_delivery_notification_destroy;
    notification->success = success;
    notification->path = cfl_sds_create(file_path);
    if (!notification->path) {
        flb_plg_error(ctx->ins, "failed to allocate path for delivery notification");
        flb_free(notification);
        return -1;
    }

    ret = flb_notification_enqueue(FLB_PLUGIN_INPUT, source,
                                    &notification->base, config);
    if (ret != 0) {
        flb_plg_error(ctx->ins, "notification delivery failed for '%s' (id=%" PRIu64 ")",
                      file_path, file_id);
        flb_notification_cleanup(&notification->base);
        return -1;
    }

    return 0;
}

/*
 * Phase 2: State transitions for special states (STALE, ABORTED)
 * This function handles states that need special operations before being re-queued:
 * - STALE: Files with old last_delivery_attempt, may need multipart abort
 * - ABORTED: Files that failed upload, need retry decision
 *
 * Note: This does NOT enqueue files. Phase 3 (rebuild_queue_from_storage) handles that.
 */
int s3_blob_recover_state(struct flb_s3 *ctx, struct flb_config *config)
{
    int ret;

    if (!ctx->blob_db.db) {
        return 0;
    }

    flb_plg_debug(ctx->ins, "recovery: phase 2 - processing special states (stale/aborted)");

    ret = flb_blob_db_lock(&ctx->blob_db);
    if (ret != 0) {
        flb_plg_error(ctx->ins, "Failed to acquire blob DB lock (ret=%d)", ret);
        return -1;
    }

    /* Handle STALE → PENDING transitions */
    recover_stale_files(ctx);

    /* Handle ABORTED → PENDING or DELETE transitions */
    handle_aborted_files(ctx, config);

    ret = flb_blob_db_unlock(&ctx->blob_db);
    if (ret != 0) {
        flb_plg_warn(ctx->ins, "Failed to release blob DB lock (ret=%d)", ret);
    }

    return 0;
}

static int recover_stale_files(struct flb_s3 *ctx)
{
    uint64_t file_id;
    cfl_sds_t file_path = NULL;
    cfl_sds_t file_remote_id = NULL;
    cfl_sds_t file_tag = NULL;
    int part_count;
    int ret;
    int stale_count = 0;

    while (1) {
        ret = flb_blob_db_file_get_next_stale(&ctx->blob_db, &file_id, &file_path,
                                              ctx->upload_parts_freshness_threshold,
                                              &file_remote_id, &file_tag, &part_count);

        if (ret != 1) {
            break;
        }

        flb_plg_info(ctx->ins, "Stale file detected, resetting upload state "
                     "(file_id=%" PRIu64 ", parts=%d)", file_id, part_count);

        if (part_count > 1) {
            /* 
             * For stale files, we don't have the stored s3_key available here.
             * abort_multipart_upload requires s3_key to safely abort.
             * Since we can't abort, we skip it to avoid noisy errors.
             * Manual cleanup might be required for these stale parts.
             */
            flb_plg_warn(ctx->ins, "Stale multipart upload (file_id=%" PRIu64 ", parts=%d) "
                         "cannot be aborted without s3_key. Manual S3 cleanup may be required.",
                         file_id, part_count);
        }

        flb_blob_file_update_remote_id(&ctx->blob_db, file_id, "");
        flb_blob_db_file_reset_upload_states(&ctx->blob_db, file_id);
        flb_blob_db_file_set_aborted_state(&ctx->blob_db, file_id, 0);

        cfl_sds_destroy(file_remote_id);
        cfl_sds_destroy(file_path);
        cfl_sds_destroy(file_tag);

        file_remote_id = NULL;
        file_path = NULL;
        file_tag = NULL;
        stale_count++;
    }

    if (stale_count > 0) {
        flb_plg_info(ctx->ins, "Recovered %d stale file(s)", stale_count);
    }

    return 0;
}

static int handle_aborted_files(struct flb_s3 *ctx, struct flb_config *config)
{
    uint64_t file_id;
    uint64_t file_delivery_attempts;
    cfl_sds_t file_path = NULL;
    cfl_sds_t source = NULL;
    cfl_sds_t file_remote_id = NULL;
    cfl_sds_t file_tag = NULL;
    cfl_sds_t s3_key = NULL;
    int part_count;
    int ret;
    int upload_valid;
    int aborted_count = 0;
    int retry_resume_count = 0;
    int retry_fresh_count = 0;
    int discarded_count = 0;

    while (1) {
        ret = flb_blob_db_file_get_next_aborted(&ctx->blob_db, &file_id,
                                                &file_delivery_attempts,
                                                &file_path, &source,
                                                &file_remote_id, &file_tag,
                                                &s3_key, &part_count);

        if (ret != 1) {
            break;
        }

        aborted_count++;

        if (ctx->file_delivery_attempt_limit != FLB_OUT_RETRY_UNLIMITED &&
            file_delivery_attempts < ctx->file_delivery_attempt_limit) {
            /* Distinguish between two retry scenarios */
            if (file_remote_id && strlen(file_remote_id) > 0) {
                /* Scenario A: Has upload_id - validate before deciding */
                
                /* 
                 * Strict validation: Only use stored s3_key.
                 * If s3_key is missing, we cannot reliably validate or resume, so we must start fresh.
                 */
                if (s3_key && strlen(s3_key) > 0) {
                    flb_plg_debug(ctx->ins, "Validating upload_id for file_id=%" PRIu64, file_id);
                    upload_valid = s3_multipart_check_upload_exists(ctx, s3_key, file_remote_id);
                }
                else {
                    flb_plg_warn(ctx->ins,
                        "No stored s3_key for file_id=%" PRIu64 ", "
                        "cannot validate upload_id. Assuming invalid and starting fresh.",
                        file_id);
                    upload_valid = 0;
                }

                if (upload_valid == 1) {
                    /* Upload ID is valid - keep for resume */
                    flb_plg_info(ctx->ins,
                        "Upload ID validated (still exists), will resume upload "
                        "(file_id=%" PRIu64 ")", file_id);
                    retry_resume_count++;
                }
                else {
                    /* 
                     * Upload ID invalid (0) or check failed (-1) or no key.
                     * In all cases, safest path is to start fresh.
                     */
                    if (upload_valid == 0) {
                        flb_plg_info(ctx->ins,
                            "Upload ID no longer valid (expired or aborted), "
                            "will create fresh upload (file_id=%" PRIu64 ")", file_id);
                    }
                    else {
                         flb_plg_warn(ctx->ins,
                            "Cannot validate upload_id (network error or missing key), "
                            "assuming invalid for safety (file_id=%" PRIu64 ")", file_id);
                    }

                    flb_blob_file_update_remote_id(&ctx->blob_db, file_id, "");
                    flb_blob_db_file_reset_upload_states(&ctx->blob_db, file_id);
                    retry_fresh_count++;
                }
            }
            else {
                /* Scenario B: No upload_id - fresh start needed */
                /* Reset all parts to start fresh */
                flb_blob_db_file_reset_upload_states(&ctx->blob_db, file_id);
                retry_fresh_count++;
            }

            /* Clear aborted flag to allow retry */
            flb_blob_db_file_set_aborted_state(&ctx->blob_db, file_id, 0);
        }
        else {
            discarded_count++;

            /* Abort the multipart upload before deleting */
            if (part_count > 1 && file_remote_id && strlen(file_remote_id) > 0) {
                /* Use stored s3_key from database (passed from flb_blob_db_file_get_next_aborted) */
                ret = abort_multipart_upload(ctx, file_tag, file_path, file_remote_id, s3_key);
                if (ret != 0) {
                    flb_plg_warn(ctx->ins,
                        "Failed to abort multipart upload for discarded file "
                        "(file_id=%" PRIu64 ", path=%s, upload_id=%s, parts=%d, ret=%d)",
                        file_id, file_path, file_remote_id, part_count, ret);
                }
            }

            flb_blob_db_file_delete(&ctx->blob_db, file_id);
            s3_blob_notify_delivery(ctx, config, source, file_path, file_id, FLB_FALSE);
        }

        cfl_sds_destroy(file_remote_id);
        cfl_sds_destroy(file_path);
        cfl_sds_destroy(source);
        cfl_sds_destroy(file_tag);
        cfl_sds_destroy(s3_key);

        file_remote_id = NULL;
        file_path = NULL;
        source = NULL;
        file_tag = NULL;
        s3_key = NULL;
    }

    if (aborted_count > 0) {
        flb_plg_info(ctx->ins,
            "Processed %d aborted file(s): %d resume (valid upload_id), "
            "%d fresh start (invalid/no upload_id), %d discarded",
            aborted_count, retry_resume_count, retry_fresh_count, discarded_count);
    }

    return 0;
}

int s3_blob_register_parts(struct flb_s3 *ctx, uint64_t file_id, size_t total_size)
{
    size_t offset_start = 0;
    size_t offset_end;
    size_t actual_part_size;
    int64_t parts = 1;
    int64_t id;
    int ret;

    /* Use unified upload_chunk_size parameter for all upload types */
    actual_part_size = flb_s3_calculate_optimal_part_size(
        ctx->upload_chunk_size,
        total_size
    );

    while (offset_start < total_size) {
        offset_end = offset_start + actual_part_size;
        if (offset_end > total_size) {
            offset_end = total_size;
        }

        ret = flb_blob_db_file_part_insert(&ctx->blob_db, file_id, parts,
                                           offset_start, offset_end, &id);
        if (ret < 0) {
            flb_plg_error(ctx->ins, "cannot insert blob file part into database");
            return -1;
        }

        offset_start = offset_end;
        parts++;
    }

    return parts - 1;
}

/*
 * Process blob events in flush callback
 *
 * ARCHITECTURE FIX:
 * The flush callback runs in a coroutine context with limited stack (37KB).
 * We should ONLY do lightweight operations here:
 * 1. Parse event and extract metadata
 * 2. Persist metadata to database
 * 3. Return immediately
 *
 * Heavy operations (CreateMultipartUpload, API calls) should be deferred
 * to the timer callback which runs in a proper thread context.
 */
int s3_blob_process_events(struct flb_s3 *ctx, struct flb_event_chunk *event_chunk)
{
    struct flb_log_event_decoder log_decoder;
    struct flb_log_event log_event;
    cfl_sds_t file_path = NULL;
    cfl_sds_t source = NULL;
    size_t file_size;
    int64_t file_id;
    msgpack_object map;
    int ret;
    int processed = 0;

    if (!ctx->blob_db.db) {
        flb_plg_error(ctx->ins, "Cannot process blob without database");
        return -1;
    }

    ret = flb_log_event_decoder_init(&log_decoder, (char *)event_chunk->data,
                                     event_chunk->size);
    if (ret != FLB_EVENT_DECODER_SUCCESS) {
        flb_plg_error(ctx->ins, "Log event decoder initialization error: %i", ret);
        return -1;
    }

    while (flb_log_event_decoder_next(&log_decoder, &log_event) ==
           FLB_EVENT_DECODER_SUCCESS) {
        map = *log_event.body;
        ret = flb_input_blob_file_get_info(map, &source, &file_path, &file_size);
        if (ret == -1) {
            flb_plg_error(ctx->ins, "cannot get file info from blob record");
            /* Defensively free any partial allocations to prevent leaks */
            if (source) {
                cfl_sds_destroy(source);
                source = NULL;
            }
            if (file_path) {
                cfl_sds_destroy(file_path);
                file_path = NULL;
            }
            continue;
        }

        /* 1. Insert file metadata into database */
        file_id = flb_blob_db_file_insert(&ctx->blob_db, event_chunk->tag, source,
                                          ctx->endpoint, file_path, file_size);
        if (file_id < 0) {
            flb_plg_error(ctx->ins, "cannot insert blob file: %s (size=%zu)",
                          file_path, file_size);
            cfl_sds_destroy(file_path);
            cfl_sds_destroy(source);
            continue;
        }

        /* 2. Register parts for this file */
        ret = s3_blob_register_parts(ctx, file_id, file_size);
        if (ret == -1) {
            flb_plg_error(ctx->ins, "cannot register blob file parts: %s", file_path);
            flb_blob_db_file_delete(&ctx->blob_db, file_id);
            cfl_sds_destroy(file_path);
            cfl_sds_destroy(source);
            continue;
        }

        ret = s3_queue_add_pending_file(ctx, file_id, file_path,
                                        event_chunk->tag, strlen(event_chunk->tag));
        if (ret < 0) {
            flb_plg_error(ctx->ins, "Failed to enqueue pending file");
            flb_blob_db_file_delete(&ctx->blob_db, file_id);
            cfl_sds_destroy(file_path);
            cfl_sds_destroy(source);
            continue;
        }

        cfl_sds_destroy(file_path);
        cfl_sds_destroy(source);
        file_path = NULL;
        source = NULL;
        processed++;
    }

    flb_log_event_decoder_destroy(&log_decoder);

    if (processed > 0) {
        flb_plg_debug(ctx->ins, "Registered %d blob file(s), will upload via timer", processed);
    }

    return 0;
}