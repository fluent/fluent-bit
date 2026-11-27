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

#ifndef FLB_LOG_VIEW_H
#define FLB_LOG_VIEW_H

#include <fluent-bit/flb_info.h>
#include <cfl/cfl.h>
#include <cfl/cfl_view.h>

/*
 * Log record views
 * ----------------
 * What a processor receives for one log record when the data source supports
 * views. Each map is NULL unless the source exposes it for this record.
 */
#define FLB_LOG_VIEW_OTEL_LOG_ATTRIBUTES  (1 << 0)

struct flb_log_view {
    struct cfl_view *otel_log_attributes;
};

/* Runs the consumers of a record view. Nonzero aborts the batch. */
struct flb_log_view_editor {
    int (*cb_record) (void *data, struct flb_log_view *record);
    void *data;
};

#endif
