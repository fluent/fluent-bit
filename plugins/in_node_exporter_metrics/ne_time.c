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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_input_plugin.h>

#include "ne.h"
#include "ne_utils.h"

static int time_configure(struct flb_ne *ctx)
{
    struct cmt_gauge *g;

    g = cmt_gauge_create(ctx->cmt, "node", "", "time_seconds",
                         "System time in seconds since epoch (1970).",
                         0, NULL);
    ctx->time = g;
    return 0;
}

static int time_update(struct flb_ne *ctx)
{
    double val;
    uint64_t ts;

    ts = cfl_time_now();
    val = ((double) ts) / 1e9;
    cmt_gauge_set(ctx->time, ts, val, 0, NULL);

    return 0;
}

static int ne_time_init(struct flb_ne *ctx)
{
    time_configure(ctx);
    return 0;
}

static int ne_time_update(struct flb_input_instance *ins, struct flb_config *config, void *in_context)
{
    struct flb_ne *ctx = (struct flb_ne *)in_context;

    time_update(ctx);
    return 0;
}

struct flb_ne_collector time_collector = {
    .name = "time",
    .cb_init = ne_time_init,
    .cb_update = ne_time_update,
    .cb_exit = NULL
};
