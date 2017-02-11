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
#include <fluent-bit/flb_http_client.h>

#include "kube_meta.h"

int flb_kube_meta_fetch(struct flb_kube *ctx)
{
    struct flb_upstream_conn *u_conn;
    struct flb_http_client *c;

    /* Get an upstream TCP connection */
    u_conn = flb_upstream_conn_get(ctx->upstream);
    if (!u_conn) {
        return -1;
    }

    /* HTTP Client instance setup */
    c = flb_http_client(u_conn, FLB_HTTP_GET, "/v1/FIXME",
                        NULL, 0, NULL, 0, NULL);
    return 0;
}
