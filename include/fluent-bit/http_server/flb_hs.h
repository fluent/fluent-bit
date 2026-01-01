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

#ifndef FLB_HS_MAIN_H
#define FLB_HS_MAIN_H

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_sds.h>
#include <monkey/mk_lib.h>

/*
 * HTTP buffers that contains certain cached data to be used
 * by end-points.
 */
struct flb_hs_buf {
    int users;
    flb_sds_t data;
    void *raw_data;
    size_t raw_size;
    struct mk_list _head;
};

struct flb_hs {
    mk_ctx_t *ctx;             /* Monkey HTTP Context */
    int vid;                   /* Virtual Host ID     */
    int qid_metrics;           /* Metrics Message Queue ID    */
    int qid_metrics_v2;        /* Metrics Message Queue ID for /api/v2 */
    int qid_storage;           /* Storage Message Queue ID    */
    int qid_health;            /* health Message Queue ID    */

    pthread_t tid;             /* Server Thread */
    struct flb_config *config; /* Fluent Bit context */

    /* end-point: root */
    size_t ep_root_size;
    char *ep_root_buf;
};

struct flb_hs *flb_hs_create(const char *listen, const char *tcp_port,
                             struct flb_config *config);
int flb_hs_push_health_metrics(struct flb_hs *hs, void *data, size_t size);
int flb_hs_push_pipeline_metrics(struct flb_hs *hs, void *data, size_t size);
int flb_hs_push_metrics(struct flb_hs *hs, void *data, size_t size);
int flb_hs_push_storage_metrics(struct flb_hs *hs, void *data, size_t size);

int flb_hs_destroy(struct flb_hs *ctx);
int flb_hs_start(struct flb_hs *hs);

#endif
