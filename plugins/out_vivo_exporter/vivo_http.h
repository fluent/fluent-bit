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

#ifndef FLB_VIVO_EXPORTER_HTTP_H
#define FLB_VIVO_EXPORTER_HTTP_H

#include <fluent-bit/flb_output_plugin.h>
#include <monkey/mk_lib.h>

#include "vivo.h"

#define VIVO_STREAM_START_ID    "Vivo-Stream-Start-ID"
#define VIVO_STREAM_END_ID      "Vivo-Stream-End-ID"
#define VIVO_STREAM_NEXT_ID     "Vivo-Stream-Next-ID"

struct vivo_stream;

/* HTTP response payload received through a Message Queue */
struct vivo_http_buf {
    int users;
    char *buf_data;
    size_t buf_size;
    struct mk_list _head;
};

/* Vivo HTTP Server context */
struct vivo_http {
    mk_ctx_t *ctx;                /* Monkey HTTP Context */
    int vid;                      /* Virtual host ID */
    int qid_metrics;              /* Queue ID for Metrics buffer */
    struct flb_config *config;    /* Fluent Bit context */
};

struct vivo_http *vivo_http_server_create(struct vivo_exporter *ctx,
                                          const char *listen,
                                          int tcp_port,
                                          struct flb_config *config);
void vivo_http_server_destroy(struct vivo_http *ph);

int vivo_http_server_start(struct vivo_http *ph);
int vivo_http_server_stop(struct vivo_http *ph);

int vivo_http_server_mq_push_metrics(struct vivo_http *ph,
                                     void *data, size_t size);

void vivo_http_serve_content(mk_request_t *request, struct vivo_stream *vs);

#endif
