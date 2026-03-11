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
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_filter.h>
#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_version.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_lib.h>
#include <fluent-bit/flb_reload.h>
#include <fluent-bit/http_server/flb_hs_utils.h>
#include "reload.h"

#include <signal.h>

#include <fluent-bit/flb_http_server.h>

static int handle_reload_request(struct flb_http_response *response,
                                 struct flb_config *config)
{
    int ret;
    flb_sds_t out_buf;
    size_t out_size;
    msgpack_packer mp_pck;
    msgpack_sbuffer mp_sbuf;
    int http_status = 200;

    /* initialize buffers */
    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    msgpack_pack_map(&mp_pck, 2);
    msgpack_pack_str(&mp_pck, 6);
    msgpack_pack_str_body(&mp_pck, "reload", 6);

#ifdef FLB_SYSTEM_WINDOWS
    if (config->enable_hot_reload != FLB_TRUE) {
        msgpack_pack_str(&mp_pck, 11);
        msgpack_pack_str_body(&mp_pck, "not enabled", 11);
        msgpack_pack_str(&mp_pck, 6);
        msgpack_pack_str_body(&mp_pck, "status", 6);
        msgpack_pack_int64(&mp_pck, -1);
    }
    else if (config->hot_reloading == FLB_TRUE) {
        msgpack_pack_str(&mp_pck, 11);
        msgpack_pack_str_body(&mp_pck, "in progress", 11);
        msgpack_pack_str(&mp_pck, 6);
        msgpack_pack_str_body(&mp_pck, "status", 6);
        msgpack_pack_int64(&mp_pck, -2);
        http_status =  400;
    }
    else {
        ret = GenerateConsoleCtrlEvent(1 /* CTRL_BREAK_EVENT_1 */, 0);
        if (ret == 0) {
            msgpack_sbuffer_destroy(&mp_sbuf);
            flb_http_response_set_status(response, 500);
            return flb_http_response_commit(response);
        }

        msgpack_pack_str(&mp_pck, 4);
        msgpack_pack_str_body(&mp_pck, "done", 4);
        msgpack_pack_str(&mp_pck, 6);
        msgpack_pack_str_body(&mp_pck, "status", 6);
        msgpack_pack_int64(&mp_pck, ret);
    }
#else
    if (config->enable_hot_reload != FLB_TRUE) {
        msgpack_pack_str(&mp_pck, 11);
        msgpack_pack_str_body(&mp_pck, "not enabled", 11);
        msgpack_pack_str(&mp_pck, 6);
        msgpack_pack_str_body(&mp_pck, "status", 6);
        msgpack_pack_int64(&mp_pck, -1);
    }
    else if (config->hot_reloading == FLB_TRUE) {
        msgpack_pack_str(&mp_pck, 11);
        msgpack_pack_str_body(&mp_pck, "in progress", 11);
        msgpack_pack_str(&mp_pck, 6);
        msgpack_pack_str_body(&mp_pck, "status", 6);
        msgpack_pack_int64(&mp_pck, -2);
        http_status =  400;
    }
    else {
        ret = kill(getpid(), SIGHUP);
        if (ret != 0) {
            msgpack_sbuffer_destroy(&mp_sbuf);
            flb_http_response_set_status(response, 500);
            return flb_http_response_commit(response);
        }

        msgpack_pack_str(&mp_pck, 4);
        msgpack_pack_str_body(&mp_pck, "done", 4);
        msgpack_pack_str(&mp_pck, 6);
        msgpack_pack_str_body(&mp_pck, "status", 6);
        msgpack_pack_int64(&mp_pck, ret);
    }

#endif

    /* Export to JSON */
    out_buf = flb_msgpack_raw_to_json_sds(mp_sbuf.data, mp_sbuf.size, FLB_TRUE);
    msgpack_sbuffer_destroy(&mp_sbuf);
    if (!out_buf) {
        flb_http_response_set_status(response, 500);
        return flb_http_response_commit(response);
    }
    out_size = flb_sds_len(out_buf);

    flb_hs_response_set_payload(response, http_status,
                                FLB_HS_CONTENT_TYPE_JSON,
                                out_buf, out_size);

    flb_sds_destroy(out_buf);
    return 0;
}

static int handle_get_reload_status(struct flb_http_response *response,
                                    struct flb_config *config)
{
    flb_sds_t out_buf;
    size_t out_size;
    msgpack_packer mp_pck;
    msgpack_sbuffer mp_sbuf;

    /* initialize buffers */
    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    msgpack_pack_map(&mp_pck, 1);
    msgpack_pack_str(&mp_pck, 16);
    msgpack_pack_str_body(&mp_pck, "hot_reload_count", 16);
    msgpack_pack_int64(&mp_pck, config->hot_reloaded_count);

    /* Export to JSON */
    out_buf = flb_msgpack_raw_to_json_sds(mp_sbuf.data, mp_sbuf.size, FLB_TRUE);
    msgpack_sbuffer_destroy(&mp_sbuf);
    if (!out_buf) {
        flb_http_response_set_status(response, 500);
        return flb_http_response_commit(response);
    }
    out_size = flb_sds_len(out_buf);

    flb_hs_response_set_payload(response, 200,
                                FLB_HS_CONTENT_TYPE_JSON,
                                out_buf, out_size);

    flb_sds_destroy(out_buf);
    return 0;
}

static int cb_reload(struct flb_hs *hs,
                     struct flb_http_request *request,
                     struct flb_http_response *response)
{
    struct flb_config *config = hs->config;

    if (request->method == HTTP_METHOD_POST ||
        request->method == HTTP_METHOD_PUT) {
        return handle_reload_request(response, config);
    }
    else if (request->method == HTTP_METHOD_GET) {
        return handle_get_reload_status(response, config);
    }

    flb_http_response_set_status(response, 400);
    return flb_http_response_commit(response);
}

/* Perform registration */
int api_v2_reload(struct flb_hs *hs)
{
    return flb_hs_register_endpoint(hs, "/api/v2/reload",
                                    FLB_HS_ROUTE_EXACT, cb_reload);
}
