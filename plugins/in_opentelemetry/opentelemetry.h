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

#ifndef FLB_IN_OPENTELEMETRY_H
#define FLB_IN_OPENTELEMETRY_H

#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_utils.h>

#include <fluent-bit/http_server/flb_http_server.h>

#define HTTP_BUFFER_MAX_SIZE    "4M"
#define HTTP_BUFFER_CHUNK_SIZE  "512K"

struct flb_opentelemetry {
    int successful_response_code;
    flb_sds_t listen;
    flb_sds_t tcp_port;
    const char *tag_key;
    int raw_traces;
    int  tag_from_uri;
    flb_sds_t logs_metadata_key;
    flb_sds_t logs_body_key;
    int profile_support_enabled;
    int encode_profiles_as_log;

    struct flb_input_instance *ins;

    struct flb_http_server http_server;
};

static inline int opentelemetry_uses_worker_ingress_queue(
    struct flb_opentelemetry *ctx)
{
    return ctx->http_server.workers > 1;
}

static inline int opentelemetry_ingest_logs(struct flb_opentelemetry *ctx,
                                            const char *tag,
                                            size_t tag_len,
                                            const void *buf,
                                            size_t buf_size)
{
    if (opentelemetry_uses_worker_ingress_queue(ctx)) {
        return flb_input_ingress_queue_log(ctx->ins, tag, tag_len, buf, buf_size);
    }

    return flb_input_log_append(ctx->ins, tag, tag_len, buf, buf_size);
}

static inline int opentelemetry_ingest_logs_take(struct flb_opentelemetry *ctx,
                                                 const char *tag,
                                                 size_t tag_len,
                                                 void *buf,
                                                 size_t buf_size,
                                                 size_t allocation_size)
{
    if (opentelemetry_uses_worker_ingress_queue(ctx)) {
        return flb_input_ingress_queue_log_take(ctx->ins,
                                                tag,
                                                tag_len,
                                                buf,
                                                buf_size,
                                                allocation_size);
    }

    return flb_input_log_append(ctx->ins, tag, tag_len, buf, buf_size);
}

static inline int opentelemetry_ingest_metrics(struct flb_opentelemetry *ctx,
                                               const char *tag,
                                               size_t tag_len,
                                               struct cmt *cmt)
{
    if (opentelemetry_uses_worker_ingress_queue(ctx)) {
        return flb_input_ingress_queue_metrics(ctx->ins, tag, tag_len, cmt);
    }

    return flb_input_metrics_append(ctx->ins, tag, tag_len, cmt);
}

static inline int opentelemetry_ingest_traces(struct flb_opentelemetry *ctx,
                                              const char *tag,
                                              size_t tag_len,
                                              struct ctrace *ctr)
{
    if (opentelemetry_uses_worker_ingress_queue(ctx)) {
        return flb_input_ingress_queue_traces(ctx->ins, tag, tag_len, ctr);
    }

    return flb_input_trace_append(ctx->ins, tag, tag_len, ctr);
}

static inline int opentelemetry_ingest_profiles(struct flb_opentelemetry *ctx,
                                                const char *tag,
                                                size_t tag_len,
                                                struct cprof *profile)
{
    if (opentelemetry_uses_worker_ingress_queue(ctx)) {
        return flb_input_ingress_queue_profiles(ctx->ins, tag, tag_len, profile);
    }

    return flb_input_profiles_append(ctx->ins, tag, tag_len, profile);
}

#endif
