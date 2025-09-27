/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2024 The Fluent Bit Authors
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

#ifndef FLB_OUT_KINESIS_API
#define FLB_OUT_KINESIS_API

#define PUT_RECORDS_PAYLOAD_SIZE         5242880
#define MAX_EVENTS_PER_PUT               500
#define MAX_EVENT_SIZE                   1048556 /* 1048576 - 20 bytes for partition key */
#define MAX_B64_EVENT_SIZE               1365336  /* ceil(1024000 / 3) * 4 */

/* number of characters needed to 'start' a PutRecords payload */
#define PUT_RECORDS_HEADER_LEN      30
/* number of characters needed per record in a PutRecords payload */
#define PUT_RECORDS_PER_RECORD_LEN  48
/* number of characters needed to 'end' a PutRecords payload */
#define PUT_RECORDS_FOOTER_LEN      4

#include "kinesis.h"

void kinesis_flush_destroy(struct flush *buf);

int process_and_send_to_kinesis(struct flb_kinesis *ctx, struct flush *buf,
                                const char *data, size_t bytes,
                                struct flb_config *config);

int put_records(struct flb_kinesis *ctx, struct flush *buf,
                     size_t payload_size, int num_records);

#endif
