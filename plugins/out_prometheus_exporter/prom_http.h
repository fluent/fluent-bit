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

#ifndef FLB_PROMETHEUS_EXPORTER_HTTP_H
#define FLB_PROMETHEUS_EXPORTER_HTTP_H

#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_pthread.h>
#include <fluent-bit/http_server/flb_http_server.h>

#include "prom.h"

/* Prom HTTP Server context */
struct prom_http {
    struct flb_http_server server;
    pthread_mutex_t metrics_mutex;
    cfl_sds_t metrics_payload;
    struct flb_config *config;
};

struct prom_http *prom_http_server_create(struct prom_exporter *ctx,
                                          struct flb_config *config);
void prom_http_server_destroy(struct prom_http *ph);

int prom_http_server_start(struct prom_http *ph);
int prom_http_server_stop(struct prom_http *ph);

int prom_http_server_mq_push_metrics(struct prom_http *ph,
                                     void *data, size_t size);

#endif
