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


#ifndef FLB_STD_TIMESTAMP_H
#define FLB_STD_TIMESTAMP_H

#include "stackdriver.h"
#include <fluent-bit/flb_time.h>

typedef enum {
    TIMESTAMP_NOT_PRESENT = 0,
    FORMAT_TIMESTAMP_OBJECT = 1,
    FORMAT_TIMESTAMP_DUO_FIELDS = 2
} timestamp_status;

/*
 * Currently support two formats of time-related fields
 *      - "timestamp":{"seconds", "nanos"}
 *      - "timestampSeconds"/"timestampNanos"
 *
 * If timestamp field is not existed, return TIMESTAMP_NOT_PRESENT
 * If timestamp format is "timestamp":{"seconds", "nanos"},
 * set the time and return FORMAT_TIMESTAMP
 *
 * If timestamp format is "timestampSeconds"/"timestampNanos",
 * set the time and return FORMAT_TIMESTAMPSECONDS
 */
timestamp_status extract_timestamp(msgpack_object *obj,
                                   struct flb_time *tms);


#endif
