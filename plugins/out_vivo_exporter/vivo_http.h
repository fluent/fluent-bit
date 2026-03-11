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
#include <fluent-bit/http_server/flb_http_server.h>

#include "vivo.h"

#define VIVO_STREAM_START_ID    "Vivo-Stream-Start-ID"
#define VIVO_STREAM_END_ID      "Vivo-Stream-End-ID"
#define VIVO_STREAM_NEXT_ID     "Vivo-Stream-Next-ID"

struct vivo_stream;

/* Vivo HTTP Server context */
struct vivo_http {
    struct flb_http_server server;
    struct flb_config *config;
};

struct vivo_http *vivo_http_server_create(struct vivo_exporter *ctx,
                                          struct flb_config *config);
void vivo_http_server_destroy(struct vivo_http *ph);

int vivo_http_server_start(struct vivo_http *ph);
int vivo_http_server_stop(struct vivo_http *ph);

int vivo_http_server_mq_push_metrics(struct vivo_http *ph,
                                     void *data, size_t size);

#endif
