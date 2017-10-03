/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2017 Treasure Data Inc.
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
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/http_server/flb_hs.h>

#include <monkey/mk_lib.h>

#define FLB_BANNER "Fluent Bit HTTP Test!\n"

static void cb_root(mk_request_t *request, void *data)
{
    mk_http_status(request, 200);
    mk_http_send(request, FLB_BANNER, sizeof(FLB_BANNER) - 1, NULL);
    mk_http_done(request);
}

struct flb_hs *flb_hs_create(char *tcp_port)
{
    int vid;
    struct flb_hs *hs;

    hs = flb_malloc(sizeof(struct flb_hs));
    if (!hs) {
        flb_errno();
        return NULL;
    }

    /* Create HTTP server context */
    hs->ctx = mk_create();
    if (!hs->ctx) {
        flb_error("[http_server] could not create context");
        flb_free(hs);
        return NULL;
    }

    mk_config_set(hs->ctx, "Listen", tcp_port, NULL);
    vid = mk_vhost_create(hs->ctx, NULL);
    mk_vhost_set(hs->ctx, vid,
                 "Name", "fluent-bit",
                 NULL);
    mk_vhost_handler(hs->ctx, vid, "/", cb_root, NULL);

    return hs;
}

static void http_service(void *data)
{
    struct flb_hs *hs = data;

    mk_start(hs->ctx);
}

int flb_hs_start(struct flb_hs *hs)
{
    int ret;

    ret = mk_utils_worker_spawn(http_service, hs, &hs->tid);
    if (ret == -1) {
        return -1;
    }

    return 0;
}

int flb_hs_destroy(struct flb_hs *ctx)
{
    flb_free(ctx);
    return 0;
}
