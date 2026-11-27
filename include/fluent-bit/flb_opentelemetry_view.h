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

#ifndef FLB_OPENTELEMETRY_VIEW_H
#define FLB_OPENTELEMETRY_VIEW_H

#include <fluent-bit/flb_log_view.h>
#include <fluent-bit/flb_opentelemetry.h>

/*
 * EXPERIMENTAL: CFL map views over OTLP protobuf logs.
 *
 * Every function reads an encoded message in place. Views borrow from the
 * input buffer, which must stay valid and unmodified during the call, and are
 * only valid inside the editor callback of the record they describe.
 * Errors are 0, EINVAL for malformed input, ENOMEM, or ECANCELED when the
 * editor fails.
 */

/*
 * Load the attributes of one encoded LogRecord into 'view', which the caller
 * initialized. No editor runs. The entries borrow from 'record' until the
 * view is reset, loaded again or destroyed, so the record bytes stay valid
 * and unmodified for that long. Returns 0, or -1 for a malformed record: the
 * view then holds the attributes read up to that point and is only good for
 * a reset, another load or cfl_view_destroy().
 */
int flb_opentelemetry_log_record_view_load(struct cfl_view *view,
                                           const void *record, size_t size);

/*
 * Read-only pass over an ExportLogsServiceRequest: the editor sees every log
 * record and nothing is written. Edits made to the views are discarded.
 */
int flb_opentelemetry_logs_proto_view_scan(const void *data, size_t size,
                                           const struct flb_log_view_editor *editor,
                                           size_t *records);

/*
 * Rewrite an ExportLogsServiceRequest with the edits the editor makes to each
 * log record. Unedited records and every field outside the attributes are
 * copied as encoded; the output is owned by the caller (flb_free). When
 * 'modified' reports zero records the input can be forwarded instead.
 */
int flb_opentelemetry_logs_proto_view_transform(const void *data, size_t size,
                                                const struct flb_log_view_editor *editor,
                                                void **out_buf, size_t *out_size,
                                                size_t *records, size_t *modified);

/*
 * MessagePack log records and the buffer that holds them, kept across calls.
 * 'charged' is the size of the records before the editor changed them, which
 * is what a size limit on the request counts.
 */
struct flb_opentelemetry_log_buffer {
    char *data;
    size_t size;
    size_t charged;
    size_t capacity;
    size_t records;
};

/* The request is left to the unpacking decoder: nothing was produced. */
#define FLB_OTEL_LOGS_VIEW_FALLBACK  1
/*
 * A consumer of the record views failed: nothing was produced either, and the
 * caller decides what a failed edit means for the request.
 */
#define FLB_OTEL_LOGS_VIEW_CANCELED  2

/*
 * FLB_TRUE when a request of 'size' bytes cannot be charged more than 'budget'
 * by flb_opentelemetry_protobuf_validate_with_budget(). The conversion below
 * applies the structural rules of that validation itself, so a caller that
 * validates requests before decoding them can leave such a request to it.
 */
int flb_opentelemetry_logs_proto_view_within_budget(size_t size, size_t budget);

/*
 * Convert an encoded ExportLogsServiceRequest to the MessagePack log records
 * flb_opentelemetry_logs_protobuf_to_msgpack() produces, reading it in place.
 * With an editor, the attributes of each record are edited through a view
 * before they are written. Returns zero, or one of the codes above.
 */
int flb_opentelemetry_logs_proto_view_to_msgpack(
        const void *payload, size_t size,
        const struct flb_opentelemetry_logs_decode_options *options,
        const struct flb_log_view_editor *editor,
        struct flb_opentelemetry_log_buffer *output);

#endif
