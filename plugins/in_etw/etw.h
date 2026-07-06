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

#ifndef FLB_IN_ETW_H
#define FLB_IN_ETW_H

#include <fluent-bit/flb_compat.h>
#include <fluent-bit/flb_input_plugin.h>

#include <windows.h>
#include <evntrace.h>
#include <tdh.h>

#define FLB_IN_ETW_DEFAULT_SESSION_NAME "fluent-bit-event-tracing-windows"
#define FLB_IN_ETW_DEFAULT_LEVEL        "5"
#define FLB_IN_ETW_DEFAULT_MATCH_ANY    "0xffffffffffffffff"
#define FLB_IN_ETW_DEFAULT_MATCH_ALL    "0"
#define FLB_IN_ETW_DEFAULT_BUFFER_SIZE  "64"
#define FLB_IN_ETW_DEFAULT_MIN_BUFFERS  "4"
#define FLB_IN_ETW_DEFAULT_MAX_BUFFERS  "32"
#define FLB_IN_ETW_DEFAULT_FLUSH_TIMER  "1"

struct flb_etw {
    flb_sds_t provider_guid_str;
    flb_sds_t provider_name;
    flb_sds_t session_name;
    flb_sds_t match_any_keyword_str;
    flb_sds_t match_all_keyword_str;
    int level;
    int buffer_size;
    int minimum_buffers;
    int maximum_buffers;
    int flush_timer;

    GUID provider_guid;
    ULONGLONG match_any_keyword;
    ULONGLONG match_all_keyword;
    GUID session_guid;
    WCHAR *session_name_wide;
    EVENT_TRACE_PROPERTIES *properties;
    TRACEHANDLE session;
    TRACEHANDLE trace;

    LONG exiting;
    LONG paused;
    LONG append_errors;
    LONG query_errors;
    int thread_created;
    int loss_metrics_collector_id;
    pthread_t thread;

    struct cmt_gauge *cmt_events_lost;
    struct cmt_gauge *cmt_realtime_buffers_lost;
    struct flb_input_instance *ins;
};

#endif
