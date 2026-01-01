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
#include <monkey/mk_lib.h>

#include "prom.h"

/* HTTP response payload received through a Message Queue */
struct prom_http_buf {
    int users;
    char *buf_data;
    size_t buf_size;
    struct mk_list _head;
};

/* Prom HTTP Server context */
struct prom_http {
    mk_ctx_t *ctx;                /* Monkey HTTP Context */
    int vid;                      /* Virtual host ID */
    int qid_metrics;              /* Queue ID for Metrics buffer */
    struct flb_config *config;    /* Fluent Bit context */
};

struct prom_http *prom_http_server_create(struct prom_exporter *ctx,
                                          const char *listen,
                                          int tcp_port,
                                          struct flb_config *config);
void prom_http_server_destroy(struct prom_http *ph);

int prom_http_server_start(struct prom_http *ph);
int prom_http_server_stop(struct prom_http *ph);

int prom_http_server_mq_push_metrics(struct prom_http *ph,
                                     void *data, size_t size);

#endif
