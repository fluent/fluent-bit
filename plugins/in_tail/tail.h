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

#ifndef FLB_TAIL_H
#define FLB_TAIL_H

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_input.h>

/* Internal return values */
#define FLB_TAIL_ERROR  -1
#define FLB_TAIL_OK      0
#define FLB_TAIL_WAIT    1
#define FLB_TAIL_BUSY    2

/* Consuming mode */
#define FLB_TAIL_STATIC  0  /* Data is being consumed through read(2) */
#define FLB_TAIL_EVENT   1  /* Data is being consumed through inotify */

/* Database */
#define FLB_TAIL_DB_ID_NONE  0  /* File not in database or deleted */

/* Config */
#define FLB_TAIL_CHUNK              "32768"   /* buffer chunk = 32KB      */
#define FLB_TAIL_REFRESH                 60   /* refresh every 60 seconds */
#define FLB_TAIL_ROTATE_WAIT             "5"  /* time to monitor after rotation */
#define FLB_TAIL_STATIC_BATCH_SIZE      "50M" /* static batch size */
#define FLB_TAIL_EVENT_BATCH_SIZE       "50M" /* event batch size */

int in_tail_collect_event(void *file, struct flb_config *config);

#endif
