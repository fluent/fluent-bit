/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2024 The Fluent Bit Authors
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
#include "reload.h"

#include <signal.h>

#include <fluent-bit/flb_http_server.h>

static void handle_reload_request(mk_request_t *request, struct flb_config *config)
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
        flb_reload_signal_reload(config);
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
        ret = flb_reload_signal_reload(config);
        if (ret != 0) {
            mk_http_status(request, 500);
            mk_http_done(request);
            return;
        }

        msgpack_pack_str(&mp_pck, 4);
        msgpack_pack_str_body(&mp_pck, "done", 4);
        msgpack_pack_str(&mp_pck, 6);
        msgpack_pack_str_body(&mp_pck, "status", 6);
        msgpack_pack_int64(&mp_pck, ret);
    }

#endif

    /* Export to JSON */
    out_buf = flb_msgpack_raw_to_json_sds(mp_sbuf.data, mp_sbuf.size);
    msgpack_sbuffer_destroy(&mp_sbuf);
    if (!out_buf) {
        mk_http_status(request, 400);
        mk_http_done(request);
        return;
    }
    out_size = flb_sds_len(out_buf);

    mk_http_status(request, http_status);
    flb_hs_add_content_type_to_req(request, FLB_HS_CONTENT_TYPE_JSON);
    mk_http_send(request, out_buf, out_size, NULL);
    mk_http_done(request);

    flb_sds_destroy(out_buf);
}

static void handle_get_reload_status(mk_request_t *request, struct flb_config *config)
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
    out_buf = flb_msgpack_raw_to_json_sds(mp_sbuf.data, mp_sbuf.size);
    msgpack_sbuffer_destroy(&mp_sbuf);
    if (!out_buf) {
        mk_http_status(request, 400);
        mk_http_done(request);
        return;
    }
    out_size = flb_sds_len(out_buf);

    mk_http_status(request, 200);
    flb_hs_add_content_type_to_req(request, FLB_HS_CONTENT_TYPE_JSON);
    mk_http_send(request, out_buf, out_size, NULL);
    mk_http_done(request);

    flb_sds_destroy(out_buf);
}

static void cb_reload(mk_request_t *request, void *data)
{
    struct flb_hs *hs = data;
    struct flb_config *config = hs->config;

    if (request->method == MK_METHOD_POST ||
        request->method == MK_METHOD_PUT) {
        handle_reload_request(request, config);
    }
    else if (request->method == MK_METHOD_GET) {
        handle_get_reload_status(request, config);
    }
    else {
        mk_http_status(request, 400);
        mk_http_done(request);
    }
}

/* Perform registration */
int api_v2_reload(struct flb_hs *hs)
{
    mk_vhost_handler(hs->ctx, hs->vid, "/api/v2/reload", cb_reload, hs);

    return 0;
}
