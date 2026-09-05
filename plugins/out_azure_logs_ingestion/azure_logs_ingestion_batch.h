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

#ifndef FLB_OUT_AZURE_LOGS_INGESTION_BATCH_H
#define FLB_OUT_AZURE_LOGS_INGESTION_BATCH_H

#include <stddef.h>
#include <fluent-bit/flb_sds.h>

struct flb_az_li;
struct flb_event_chunk;
struct flb_output_flush;

int az_li_batch_init(struct flb_az_li *ctx);
int az_li_batch_start_uploader(struct flb_az_li *ctx);
void az_li_batch_destroy(struct flb_az_li *ctx);
int az_li_batch_admit_chunk(struct flb_az_li *ctx,
                            struct flb_output_flush *out_flush,
                            struct flb_event_chunk *event_chunk,
                            flb_sds_t *records, size_t record_count);

#endif
