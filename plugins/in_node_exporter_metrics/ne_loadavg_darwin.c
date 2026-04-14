/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2023-2026 The Fluent Bit Authors
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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_input_plugin.h>

#include "ne.h"

/* Setup metrics contexts */
static int ne_loadavg_configure(struct flb_ne *ctx)
{
    struct cmt_gauge *g;

    /* loadavg 1m */
    g = cmt_gauge_create(ctx->cmt, "node", "", "load1",
                         "1m load average.",
                         0, NULL);
    ctx->lavg_1 = g;

    /* loadavg 5m */
    g = cmt_gauge_create(ctx->cmt, "node", "", "load5",
                         "5m load average.",
                         0, NULL);
    ctx->lavg_5 = g;

    /* loadavg 15m */
    g = cmt_gauge_create(ctx->cmt, "node", "", "load15",
                         "15m load average.",
                         0, NULL);
    ctx->lavg_15 = g;

    return 0;
}

static int loadavg_update(struct flb_ne *ctx)
{
    int ret;
    double loadavg[3];
    uint64_t ts;

    ts = cfl_time_now();

    ret = getloadavg(loadavg, 3);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "failed to retrieve loadavg");
        return -1;
    }

    /* Confirm the count of the values from getloadavg */
    if (ret >= 3) {
        /* 1m */
        cmt_gauge_set(ctx->lavg_1, ts, loadavg[0], 0, NULL);

        /* 5m */
        cmt_gauge_set(ctx->lavg_5, ts, loadavg[1], 0, NULL);

        /* 15m */
        cmt_gauge_set(ctx->lavg_15, ts, loadavg[2], 0, NULL);
    }

    return 0;
}

static int ne_loadavg_init(struct flb_ne *ctx)
{
    ne_loadavg_configure(ctx);
    return 0;
}

static int ne_loadavg_update(struct flb_input_instance *ins, struct flb_config *config, void *in_context)
{
    struct flb_ne *ctx = (struct flb_ne *)in_context;

    loadavg_update(ctx);
    return 0;
}

struct flb_ne_collector loadavg_collector = {
    .name = "loadavg",
    .cb_init = ne_loadavg_init,
    .cb_update = ne_loadavg_update,
    .cb_exit = NULL
};
