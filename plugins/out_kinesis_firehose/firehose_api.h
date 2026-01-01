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

#ifndef FLB_OUT_CLOUDWATCH_API
#define FLB_OUT_CLOUDWATCH_API

#define PUT_RECORD_BATCH_PAYLOAD_SIZE    4194304
#define MAX_EVENTS_PER_PUT               500
#define MAX_EVENT_SIZE                   1024000
#define MAX_B64_EVENT_SIZE               1365336  /* ceil(1024000 / 3) * 4 */

/* number of characters needed to 'start' a PutRecordBatch payload */
#define PUT_RECORD_BATCH_HEADER_LEN      42
/* number of characters needed per record in a PutRecordBatch payload */
#define PUT_RECORD_BATCH_PER_RECORD_LEN   12
/* number of characters needed to 'end' a PutRecordBatch payload */
#define PUT_RECORD_BATCH_FOOTER_LEN      4

#include "firehose.h"

void flush_destroy(struct flush *buf);

int process_and_send_records(struct flb_firehose *ctx, struct flush *buf,
                             const char *data, size_t bytes,
                             struct flb_config *config);

int put_record_batch(struct flb_firehose *ctx, struct flush *buf,
                     size_t payload_size, int num_records);

#endif
