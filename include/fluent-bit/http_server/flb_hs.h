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
#include <fluent-bit/flb_network.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/http_server/flb_http_server.h>
#include <monkey/mk_core.h>

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

struct flb_health_check_metrics_counter {
    int error_limit;
    int error_counter;
    int retry_failure_limit;
    int retry_failure_counter;
    int period_limit;
    int period_counter;
};

struct flb_hs_hc_buf {
    int users;
    int error_count;
    int retry_failure_count;
    struct mk_list _head;
};

enum flb_hs_route_match_type {
    FLB_HS_ROUTE_EXACT = 0,
    FLB_HS_ROUTE_PREFIX = 1
};

struct flb_hs;

typedef int (*flb_hs_endpoint_callback)(
                struct flb_hs *hs,
                struct flb_http_request *request,
                struct flb_http_response *response);

struct flb_hs_route {
    const char *path;
    int match_type;
    flb_hs_endpoint_callback callback;
    struct mk_list _head;
};

struct flb_hs {
    struct flb_http_server server;
    struct flb_net_setup net_setup;
    struct flb_config *config;
    struct mk_list routes;
    struct mk_list health_metrics;
    struct flb_health_check_metrics_counter health_counter;

    struct flb_hs_buf metrics;
    struct flb_hs_buf metrics_v2;
    struct flb_hs_buf storage_metrics;

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
int flb_hs_register_endpoint(struct flb_hs *hs,
                             const char *path,
                             int match_type,
                             flb_hs_endpoint_callback callback);

#endif
