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

#ifndef FLB_IN_PROM_RW_H
#define FLB_IN_PROM_RW_H

#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_utils.h>

#include <fluent-bit/http_server/flb_http_server.h>

#define HTTP_BUFFER_MAX_SIZE    "4M"
#define HTTP_BUFFER_CHUNK_SIZE  "512K"

struct flb_prom_remote_write {
    int successful_response_code;
    flb_sds_t listen;
    flb_sds_t tcp_port;
    int  tag_from_uri;

    struct flb_input_instance *ins;

    /* HTTP URI */
    char *uri;

    struct flb_http_server http_server;
};

static inline int prom_rw_uses_worker_ingress_queue(
    struct flb_prom_remote_write *ctx)
{
    return ctx->http_server.workers > 1;
}

static inline int prom_rw_ingest_metrics(struct flb_prom_remote_write *ctx,
                                         const char *tag,
                                         size_t tag_len,
                                         struct cmt *cmt)
{
    if (prom_rw_uses_worker_ingress_queue(ctx)) {
        return flb_input_ingress_queue_metrics(ctx->ins, tag, tag_len, cmt);
    }

    return flb_input_metrics_append(ctx->ins, tag, tag_len, cmt);
}


#endif
