/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2021 The Fluent Bit Authors
 *  Copyright (C) 2015-2018 Treasure Data Inc.
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

#ifndef FLB_ENGINE_DISPATCH_H
#define FLB_ENGINE_DISPATCH_H

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_task.h>

/* FLB_DISPATCHER_RESERVED_CHUNK_MINIMUM defines a lower boundary for the number
 * of releasable chunks.
 *
 * FLB_DISPATCHER_RESERVED_STORAGE_SPACE as defined ensures that the system is
 * able to ingest N bytes without exceeding the limits (in this PoCs case 10 MB).
 *
 * In the real world these souldn't be constants but rather settings and the
 * storage space setting should be higher than 10 megabytes, especially when
 * the ingestion volume is rather large.
*/

#define FLB_DISPATCHER_RESERVED_CHUNK_MINIMUM    5
#define FLB_DISPATCHER_RESERVED_STORAGE_SPACE    (20 * 1000000)

int flb_engine_dispatch(uint64_t id, struct flb_input_instance *in,
                        struct flb_config *config);
int flb_engine_dispatch_retry(struct flb_task_retry *retry,
                              struct flb_config *config);
#endif
