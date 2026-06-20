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

#include <fluent-bit/flb_input_plugin.h>

#include "prom_rw.h"
#include "prom_rw_config.h"

/* default HTTP port for prometheus remote write */
#define PROMETHEUS_REMOTE_WRITE_HTTP_PORT    8080

struct flb_prom_remote_write *prom_rw_config_create(struct flb_input_instance *ins)
{
    int ret;
    char port[8];
    struct flb_prom_remote_write *ctx;

    ctx = flb_calloc(1, sizeof(struct flb_prom_remote_write));
    if (!ctx) {
        flb_errno();
        return NULL;
    }
    ctx->ins = ins;

    /* Load the config map */
    ret = flb_input_config_map_set(ins, (void *) ctx);
    if (ret == -1) {
        flb_free(ctx);
        return NULL;
    }

    /* Listen interface (if not set, defaults to 0.0.0.0:80) */
    flb_input_net_default_listener("0.0.0.0", PROMETHEUS_REMOTE_WRITE_HTTP_PORT, ins);

    ctx->listen = flb_strdup(ins->host.listen);
    snprintf(port, sizeof(port) - 1, "%d", ins->host.port);
    ctx->tcp_port = flb_strdup(port);

    return ctx;
}

int prom_rw_config_destroy(struct flb_prom_remote_write *ctx)
{
    if (ctx == NULL) {
        return 0;
    }

    flb_http_server_destroy(&ctx->http_server);

    flb_free(ctx->listen);
    flb_free(ctx->tcp_port);
    flb_free(ctx);

    return 0;
}
