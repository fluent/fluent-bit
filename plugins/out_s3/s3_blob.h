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

#ifndef FLB_OUT_S3_BLOB_H
#define FLB_OUT_S3_BLOB_H

#include <fluent-bit/flb_output_plugin.h>
#include "s3.h"

/* Register blob file parts in database */
int s3_blob_register_parts(struct flb_s3 *ctx, uint64_t file_id, size_t total_size);

/* Process blob chunk event */
int s3_blob_process_events(struct flb_s3 *ctx, struct flb_event_chunk *event_chunk);

/* Recovery: process and cleanup stale/aborted files */
int s3_blob_recover_state(struct flb_s3 *ctx, struct flb_config *config);

/* Send delivery notification to input plugin */
int s3_blob_notify_delivery(struct flb_s3 *ctx,
                                        struct flb_config *config,
                                        cfl_sds_t source,
                                        cfl_sds_t file_path,
                                        uint64_t file_id,
                                        int success);

#endif
