/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2024 The Fluent Bit Authors
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

#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_kv.h>
#include <fluent-bit/flb_record_accessor.h>
#include <fluent-bit/flb_pthread.h>
#include "doris.h"
#include "doris_conf.h"

void *report(void *c) {
    struct flb_out_doris *ctx = (struct flb_out_doris *) c;
    
    size_t init_time = cfl_time_now() / 1000000000L;
    size_t last_time = init_time;
    size_t last_bytes = ctx->reporter->total_bytes;
    size_t last_rows = ctx->reporter->total_rows;

    size_t cur_time, cur_bytes, cur_rows, total_time, total_speed_mbps, total_speed_rps;
    size_t inc_bytes, inc_rows, inc_time, inc_speed_mbps, inc_speed_rps;

    flb_plg_info(ctx->ins, "Start progress reporter with interval %d", ctx->log_progress_interval);
    
    while (ctx->log_progress_interval > 0) {
        sleep(ctx->log_progress_interval);

        cur_time = cfl_time_now() / 1000000000L;
        cur_bytes =  ctx->reporter->total_bytes;
        cur_rows =  ctx->reporter->total_rows;
        total_time = cur_time - init_time;
        total_speed_mbps = cur_bytes / 1024 / 1024 / total_time;
        total_speed_rps = cur_rows / total_time;

        inc_bytes = cur_bytes - last_bytes;
		inc_rows = cur_rows - last_rows;
		inc_time = cur_time - last_time;
		inc_speed_mbps = inc_bytes / 1024 / 1024 / inc_time;
		inc_speed_rps = inc_rows / inc_time;

        flb_plg_info(ctx->ins, "total %zu MB %zu ROWS, total speed %zu MB/s %zu R/s, last %zu seconds speed %zu MB/s %zu R/s",
			         cur_bytes/1024/1024, cur_rows, total_speed_mbps, total_speed_rps,
			         inc_time, inc_speed_mbps, inc_speed_rps);
        
        last_time = cur_time;
		last_bytes = cur_bytes;
		last_rows = cur_rows;
    }

    return NULL;
}

struct flb_out_doris *flb_doris_conf_create(struct flb_output_instance *ins,
                                            struct flb_config *config)
{
    int ret;
    int io_flags = 0;
    const char *tmp;
    struct flb_upstream *upstream;
    struct flb_out_doris *ctx = NULL;
    struct flb_doris_progress_reporter *reporter = NULL;

    /* Allocate plugin context */
    ctx = flb_calloc(1, sizeof(struct flb_out_doris));
    if (!ctx) {
        flb_errno();
        return NULL;
    }
    ctx->ins = ins;

    ret = flb_output_config_map_set(ins, (void *) ctx);
    if (ret == -1) {
        flb_free(ctx);
        return NULL;
    }

    /* Set default network configuration */
    flb_output_net_default("127.0.0.1", 8030, ins);

    /* Validate */ 
    if (!ctx->user) {
        flb_plg_error(ins, "user is not set");
    }
    if (!ctx->database) {
        flb_plg_error(ins, "database is not set");
    }
    if (!ctx->table) {
        flb_plg_error(ins, "table is not set");
    }

    /* Check if SSL/TLS is enabled */
#ifdef FLB_HAVE_TLS
    if (ins->use_tls == FLB_TRUE) {
        io_flags = FLB_IO_TLS;
    }
    else {
        io_flags = FLB_IO_TCP;
    }
#else
    io_flags = FLB_IO_TCP;
#endif

    if (ins->host.ipv6 == FLB_TRUE) {
        io_flags |= FLB_IO_IPV6;
    }

    /* Prepare an upstream handler */
    upstream = flb_upstream_create(config,
                                   ins->host.name,
                                   ins->host.port,
                                   io_flags, ins->tls);

    if (!upstream) {
        flb_free(ctx);
        return NULL;
    }

    /* url: /api/{database}/{table}/_stream_load */
    snprintf(ctx->uri, sizeof(ctx->uri) - 1, "/api/%s/%s/_stream_load", ctx->database, ctx->table);

    /* Date key */
    ctx->date_key = ctx->time_key;
    tmp = flb_output_get_property("time_key", ins);
    if (tmp) {
        /* Just check if we have to disable it */
        if (flb_utils_bool(tmp) == FLB_FALSE) {
            ctx->date_key = NULL;
        }
    }

    ctx->u = upstream;
    ctx->host = ins->host.name;
    ctx->port = ins->host.port;

    /* Set instance flags into upstream */
    flb_output_upstream_set(ctx->u, ins);

    /* create and start the progress reporter */
    if (ctx->log_progress_interval > 0) {
        reporter = flb_calloc(1, sizeof(struct flb_doris_progress_reporter));
        if (!reporter) {
            flb_plg_error(ins, "failed to create progress reporter");
            flb_doris_conf_destroy(ctx);
            return NULL;
        }
        reporter->total_bytes = 0;
        reporter->total_rows = 0;
        reporter->failed_rows = 0;
        ctx->reporter = reporter;

        if(pthread_create(&ctx->reporter_thread, NULL, report, (void *) ctx)) {
            flb_plg_error(ins, "failed to create progress reporter");
            flb_doris_conf_destroy(ctx);
            return NULL;
        }
    }

    return ctx;
}

void flb_doris_conf_destroy(struct flb_out_doris *ctx)
{
    if (!ctx) {
        return;
    }

    if (ctx->u) {
        flb_upstream_destroy(ctx->u);
    }

    if (ctx->reporter) {
        pthread_cancel(ctx->reporter_thread);
        flb_free(ctx->reporter);
    }

    flb_free(ctx);
}
