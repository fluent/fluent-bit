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

#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_http_server.h>
#include <fluent-bit/http_server/flb_hs_utils.h>

#include "../v1/health.h"
#include <msgpack.h>

#include "health.h"

static int cb_health(struct flb_hs *hs,
                     struct flb_http_request *request,
                     struct flb_http_response *response)
{
    int status_code;
    size_t out_size;
    flb_sds_t out_buf;
    msgpack_packer mp_pck;
    msgpack_sbuffer mp_sbuf;
    struct flb_hs_health_state state;

    (void) request;

    if (flb_hs_health_state_get(hs, &state) != 0) {
        flb_http_response_set_status(response, 500);
        return flb_http_response_commit(response);
    }

    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    msgpack_pack_map(&mp_pck, 6);
    msgpack_pack_str(&mp_pck, 6);
    msgpack_pack_str_body(&mp_pck, "status", 6);

    if (state.healthy == FLB_TRUE) {
        msgpack_pack_str(&mp_pck, 2);
        msgpack_pack_str_body(&mp_pck, "ok", 2);
        status_code = 200;
    }
    else {
        msgpack_pack_str(&mp_pck, 5);
        msgpack_pack_str_body(&mp_pck, "error", 5);
        status_code = 500;
    }

    msgpack_pack_str(&mp_pck, 6);
    msgpack_pack_str_body(&mp_pck, "errors", 6);
    msgpack_pack_int64(&mp_pck, state.errors);

    msgpack_pack_str(&mp_pck, 14);
    msgpack_pack_str_body(&mp_pck, "retries_failed", 14);
    msgpack_pack_int64(&mp_pck, state.retries_failed);

    msgpack_pack_str(&mp_pck, 11);
    msgpack_pack_str_body(&mp_pck, "error_limit", 11);
    msgpack_pack_int64(&mp_pck, state.error_limit);

    msgpack_pack_str(&mp_pck, 19);
    msgpack_pack_str_body(&mp_pck, "retry_failure_limit", 19);
    msgpack_pack_int64(&mp_pck, state.retry_failure_limit);

    msgpack_pack_str(&mp_pck, 12);
    msgpack_pack_str_body(&mp_pck, "period_limit", 12);
    msgpack_pack_int64(&mp_pck, state.period_limit);

    out_buf = flb_msgpack_raw_to_json_sds(mp_sbuf.data, mp_sbuf.size, FLB_TRUE);
    msgpack_sbuffer_destroy(&mp_sbuf);
    if (out_buf == NULL) {
        flb_http_response_set_status(response, 500);
        return flb_http_response_commit(response);
    }

    out_size = flb_sds_len(out_buf);
    flb_hs_response_set_payload(response, status_code,
                                FLB_HS_CONTENT_TYPE_JSON,
                                out_buf, out_size);
    flb_sds_destroy(out_buf);

    return 0;
}

int api_v2_health(struct flb_hs *hs)
{
    return flb_hs_register_endpoint(hs, "/api/v2/health",
                                    FLB_HS_ROUTE_EXACT, cb_health);
}
