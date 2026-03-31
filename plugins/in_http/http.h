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

#ifndef FLB_IN_HTTP_H
#define FLB_IN_HTTP_H

#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_log_event_encoder.h>
#include <fluent-bit/flb_record_accessor.h>
#include <fluent-bit/flb_oauth2_jwt.h>

#include <fluent-bit/http_server/flb_http_server.h>

#define HTTP_BUFFER_MAX_SIZE    "4M"
#define HTTP_BUFFER_CHUNK_SIZE  "512K"
#define REMOTE_ADDR_KEY         "REMOTE_ADDR"

struct flb_http {
    int successful_response_code;
    flb_sds_t listen;
    flb_sds_t tcp_port;
    flb_sds_t tag_key;
    struct flb_record_accessor *ra_tag_key;

    /* Success HTTP headers */
    struct mk_list *success_headers;

    struct flb_log_event_encoder log_encoder;

    struct flb_input_instance *ins;

    int add_remote_addr;
    const char *remote_addr_key;

    struct flb_http_server http_server;

    struct flb_oauth2_jwt_cfg oauth2_cfg;
    struct flb_oauth2_jwt_ctx *oauth2_ctx;

};

static inline int http_uses_worker_ingress_queue(struct flb_http *ctx)
{
    return ctx->http_server.workers > 1;
}

static inline int http_ingest_logs(struct flb_http *ctx,
                                   const char *tag,
                                   size_t tag_len,
                                   const void *buf,
                                   size_t buf_size)
{
    if (http_uses_worker_ingress_queue(ctx)) {
        return flb_input_ingress_queue_log(ctx->ins, tag, tag_len, buf, buf_size);
    }

    return flb_input_log_append(ctx->ins, tag, tag_len, buf, buf_size);
}


#endif
