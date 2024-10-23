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
#include "doris.h"
#include "doris_conf.h"

struct flb_out_doris *flb_doris_conf_create(struct flb_output_instance *ins,
                                            struct flb_config *config)
{
    int ret;
    int io_flags = 0;
    struct flb_upstream *upstream;
    struct flb_out_doris *ctx = NULL;

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

    ctx->u = upstream;
    ctx->host = ins->host.name;
    ctx->port = ins->host.port;

    /* Set instance flags into upstream */
    flb_output_upstream_set(ctx->u, ins);

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

    flb_free(ctx);
}
