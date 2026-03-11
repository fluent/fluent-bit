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
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_sds.h>
#include "storage.h"

#include <fluent-bit/flb_http_server.h>
#include <fluent-bit/http_server/flb_hs_utils.h>
#include <msgpack.h>

/* Return the newest storage metrics buffer */
static struct flb_hs_buf *storage_metrics_get_latest(struct flb_hs *hs)
{
    if (hs->storage_metrics.data == NULL) {
        return NULL;
    }
    return &hs->storage_metrics;
}

/* API: expose built-in storage metrics /api/v1/storage */
static int cb_storage(struct flb_hs *hs,
                      struct flb_http_request *request,
                      struct flb_http_response *response)
{
    struct flb_hs_buf *buf;

    (void) request;

    buf = storage_metrics_get_latest(hs);
    if (!buf) {
        flb_http_response_set_status(response, 404);
        return flb_http_response_commit(response);
    }

    buf->users++;

    flb_hs_response_set_payload(response, 200,
                                FLB_HS_CONTENT_TYPE_JSON,
                                buf->data, flb_sds_len(buf->data));

    buf->users--;
    return 0;
}

/* Perform registration */
int api_v1_storage_metrics(struct flb_hs *hs)
{
    return flb_hs_register_endpoint(hs, "/api/v1/storage",
                                    FLB_HS_ROUTE_EXACT, cb_storage);
}
