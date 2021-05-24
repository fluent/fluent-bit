/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2021 The Fluent Bit Authors
 *  Copyright (C) 2015-2018 Treasure Data Inc.
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

#include "prom.h"
#include "prom_http.h"

static int cb_prom_init(struct flb_output_instance *ins,
                        struct flb_config *config,
                        void *data)
{
    int ret;
    struct prom_exporter *ctx;

    ctx = flb_calloc(1, sizeof(struct prom_exporter));
    if (!ctx) {
        flb_errno();
        return -1;
    }
    ctx->ins = ins;
    flb_output_set_context(ins, ctx);

    /* Load config map */
    ret = flb_output_config_map_set(ins, (void *) ctx);
    if (ret == -1) {
        return -1;
    }

    /* HTTP Server context */
    ctx->http = prom_http_server_create(ctx,
                                        ctx->listen, ctx->tcp_port, config);
    if (!ctx->http) {
        flb_plg_error(ctx->ins, "could not initialize HTTP server, aborting");
        flb_free(ctx);
        return -1;
    }

    /* Start HTTP Server */
    ret = prom_http_server_start(ctx->http);
    if (ret == -1) {
        return -1;
    }

    flb_plg_info(ctx->ins, "listening iface=%s tcp_port=%s",
                 ctx->listen, ctx->tcp_port, config);
    return 0;
}

static void cb_prom_flush(const void *data, size_t bytes,
                          const char *tag, int tag_len,
                          struct flb_input_instance *ins, void *out_context,
                          struct flb_config *config)
{
    int ret;
    struct prom_exporter *ctx = out_context;

    ret = prom_http_server_mq_push_metrics(ctx->http, (char *) data, bytes);
    if (ret != 0) {
        FLB_OUTPUT_RETURN(FLB_ERROR);
    }

    FLB_OUTPUT_RETURN(FLB_OK);
}

static int cb_prom_exit(void *data, struct flb_config *config)
{
    struct prom_exporter *ctx = data;
    struct prom_http *ph = ctx->http;
    if (ph) {
        prom_http_server_destroy(ph);
    }
    return 0;
}

/* Configuration properties map */
static struct flb_config_map config_map[] = {
    {
     FLB_CONFIG_MAP_STR, "listen", "0.0.0.0",
     0, FLB_TRUE, offsetof(struct prom_exporter, listen),
     "Listener network interface."
    },
    {
     FLB_CONFIG_MAP_STR, "port", "2021",
     0, FLB_TRUE, offsetof(struct prom_exporter, tcp_port),
     "TCP port for listening for HTTP connections."
    },
    /* EOF */
    {0}
};

/* Plugin reference */
struct flb_output_plugin out_prometheus_exporter_plugin = {
    .name        = "prometheus_exporter",
    .description = "Prometheus Exporter",
    .cb_init     = cb_prom_init,
    .cb_flush    = cb_prom_flush,
    .cb_exit     = cb_prom_exit,
    .config_map  = config_map,
    .flags       = FLB_OUTPUT_NET,
};
