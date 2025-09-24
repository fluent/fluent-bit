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

#ifndef FLB_LOG_EVENT_H
#define FLB_LOG_EVENT_H

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_sds.h>

#include <msgpack.h>

#define FLB_LOG_EVENT_FORMAT_UNKNOWN        0
#define FLB_LOG_EVENT_FORMAT_DEFAULT        FLB_LOG_EVENT_FORMAT_FLUENT_BIT_V2
#define FLB_LOG_EVENT_FORMAT_FORWARD_LEGACY 1
#define FLB_LOG_EVENT_FORMAT_FORWARD        2
#define FLB_LOG_EVENT_FORMAT_FLUENT_BIT_V1  FLB_LOG_EVENT_FORMAT_FORWARD
#define FLB_LOG_EVENT_FORMAT_FLUENT_BIT_V2  4

#define FLB_LOG_EVENT_NORMAL              (int32_t)  0
#define FLB_LOG_EVENT_GROUP_START         (int32_t) -1
#define FLB_LOG_EVENT_GROUP_END           (int32_t) -2

struct flb_log_event {
    msgpack_object  *group_attributes;
    msgpack_object  *group_metadata;
    msgpack_object  *raw_timestamp;
    struct flb_time  timestamp;
    msgpack_object  *metadata;
    int              format;
    msgpack_object  *body;
    msgpack_object  *root;
};

#endif
