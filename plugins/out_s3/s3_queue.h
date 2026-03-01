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

#ifndef FLB_OUT_S3_QUEUE_H
#define FLB_OUT_S3_QUEUE_H

#include "s3.h"
#include <sys/types.h>  /* for off_t */

void s3_queue_entry_destroy(struct flb_s3 *ctx, struct upload_queue *entry);

int s3_queue_remove(struct flb_s3 *ctx, struct upload_queue *entry);

int s3_queue_buffer_chunk(void *out_context, struct s3_file *upload_file,
                          flb_sds_t chunk, int chunk_size,
                          const char *tag, int tag_len,
                          time_t file_first_log_time);

/*
 * Queue add for uploads
 * Supports two tracking modes:
 *   - file_id == 0: Non-database-tracked upload (log data only, fstore storage)
 *   - file_id > 0: Database-tracked upload (log data: fstore + DB, blob files: disk + DB)
 */
int s3_queue_add_file(struct flb_s3 *ctx,
                      uint64_t file_id,
                      struct s3_file *upload_file,
                      const char *file_path,
                      const char *tag,
                      int tag_len);

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
                      int tag_len);

int s3_queue_add_pending_file(struct flb_s3 *ctx,
                               uint64_t file_id,
                               const char *file_path,
                               const char *tag,
                               int tag_len);

/*
 * Unlocked versions - caller must hold upload_queue_lock
 * Used when the caller already holds the lock (e.g., cb_s3_upload timer callback)
 */
int s3_queue_add_file_unlocked(struct flb_s3 *ctx,
                                uint64_t file_id,
                                struct s3_file *upload_file,
                                const char *file_path,
                                const char *tag,
                                int tag_len);

int s3_queue_add_pending_file_unlocked(struct flb_s3 *ctx,
                                        uint64_t file_id,
                                        const char *file_path,
                                        const char *tag,
                                        int tag_len);

/*
 * Process a queue entry (called by timer callback)
 * Returns: 1 on success, -1 on failure (will retry), 0 if invalid (removed)
 */
int s3_queue_process_entry(struct flb_s3 *ctx,
                            struct upload_queue *entry,
                            time_t now);

/*
 * Unified recovery interface - Three-phase architecture
 * Phase 0: Cleanup dirty states (zombie parts reset)
 * Phase 1: State transitions (stale → pending, aborted → pending/delete)
 * Phase 2: Queue rebuild (scan storage and enqueue all pending files)
 *
 * Handles both database-tracked and non-database-tracked uploads.
 */
int s3_queue_recover_all(struct flb_s3 *ctx, struct flb_config *config);

/* Internal recovery functions (can also be called independently if needed) */
int s3_queue_recover_from_database(struct flb_s3 *ctx);
int s3_queue_recover_from_fstore(struct flb_s3 *ctx);

#endif