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

#define _GNU_SOURCE

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_input_plugin.h>

#include "ne.h"
#include "ne_utils.h"

#include <unistd.h>
#include <sys/utsname.h>

static int uname_configure(struct flb_ne *ctx)
{
    struct cmt_gauge *g;

    g = cmt_gauge_create(ctx->cmt, "node", "uname", "info",
                         "Labeled system information as provided by the uname system call.",
                         6, (char *[])
                         {
                             "sysname",
                             "release",
                             "version",
                             "machine",
                             "nodename",
                             "domainname"
                         });
    if (!g) {
        return -1;
    }
    ctx->uname = g;
    return 0;
}

static int uname_update(struct flb_ne *ctx)
{
    int ret;
    uint64_t ts;
    struct utsname u = {0};


    uname(&u);

    ts = cfl_time_now();
    ret = cmt_gauge_set(ctx->uname, ts, 1, 6,
                        (char *[]) {
                            u.sysname,
                            u.release,
                            u.version,
                            u.machine,
                            u.nodename,
                            u.domainname});
    return ret;
}

static int ne_uname_init(struct flb_ne *ctx)
{
    uname_configure(ctx);
    return 0;
}

static int ne_uname_update(struct flb_input_instance *ins, struct flb_config *config, void *in_context)
{
    struct flb_ne *ctx = (struct flb_ne *)in_context;

    uname_update(ctx);
    return 0;
}

struct flb_ne_collector uname_collector = {
    .name = "uname",
    .cb_init = ne_uname_init,
    .cb_update = ne_uname_update,
    .cb_exit = NULL
};
