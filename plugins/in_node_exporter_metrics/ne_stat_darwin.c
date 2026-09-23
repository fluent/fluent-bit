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

#include <sys/sysctl.h>
#include <sys/time.h>

#include "ne.h"

static int ne_stat_init(struct flb_ne *ctx)
{
    ctx->st_boot_time = cmt_gauge_create(ctx->cmt, "node", "", "boot_time_seconds",
                                         "Unix time of last boot, including microseconds.",
                                         0, NULL);
    if (ctx->st_boot_time == NULL) {
        flb_plg_error(ctx->ins, "failed to create gauge node_boot_time_seconds");
        return -1;
    }

    return 0;
}

static int ne_stat_update(struct flb_input_instance *ins,
                          struct flb_config *config, void *in_context)
{
    int ret;
    size_t value_size;
    double value;
    uint64_t ts;
    struct timeval boot_time;
    struct flb_ne *ctx;

    (void) ins;
    (void) config;

    ctx = in_context;
    value_size = sizeof(boot_time);
    ret = sysctlbyname("kern.boottime", &boot_time, &value_size, NULL, 0);
    if (ret != 0) {
        flb_plg_error(ctx->ins, "failed to read kern.boottime");
        return -1;
    }

    value = (double) boot_time.tv_sec + ((double) boot_time.tv_usec / 1000000.0);
    ts = cfl_time_now();
    cmt_gauge_set(ctx->st_boot_time, ts, value, 0, NULL);

    return 0;
}

struct flb_ne_collector stat_collector = {
    .name = "stat",
    .cb_init = ne_stat_init,
    .cb_update = ne_stat_update,
    .cb_exit = NULL
};
