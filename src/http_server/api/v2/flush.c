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

#include <string.h>

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_engine.h>
#include <fluent-bit/http_server/flb_hs_utils.h>
#include <cfl/cfl_atomic.h>
#include "flush.h"

#include <fluent-bit/flb_http_server.h>

/* Bounded wait for the engine thread to acknowledge a dispatched flush */
#define FLB_HS_FLUSH_ACK_TIMEOUT_MS 2000

static int wait_for_flush_ack(uint64_t *acked, uint64_t ticket, int timeout_ms)
{
    int waited_ms = 0;
    const int interval_ms = 2;

    while (cfl_atomic_load(acked) < ticket) {
        if (waited_ms >= timeout_ms) {
            return FLB_FALSE;
        }
        flb_time_msleep(interval_ms);
        waited_ms += interval_ms;
    }

    return FLB_TRUE;
}

static int handle_flush_request(struct flb_http_request *request,
                                struct flb_http_response *response,
                                struct flb_config *config)
{
    int ret;
    int acked;
    int reschedule_retries;
    uint64_t ticket;
    flb_sds_t out_buf;
    size_t out_size;
    msgpack_packer mp_pck;
    msgpack_sbuffer mp_sbuf;
    int http_status;

    reschedule_retries = request->query_string != NULL &&
        strstr(request->query_string, "reschedule_retries=true") != NULL;

    do {
        ticket = cfl_atomic_load(&config->flush_now_count);
    } while (cfl_atomic_compare_exchange(&config->flush_now_count,
                                         ticket, ticket + 1) == 0);
    ++ticket;

    ret = flb_engine_flush_request(config, reschedule_retries);
    if (ret == -1) {
        flb_http_response_set_status(response, 500);
        return flb_http_response_commit(response);
    }

    acked = wait_for_flush_ack(&config->flush_now_acked, ticket,
                               FLB_HS_FLUSH_ACK_TIMEOUT_MS);

    /* initialize buffers */
    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    msgpack_pack_map(&mp_pck, 3);
    msgpack_pack_str(&mp_pck, 5);
    msgpack_pack_str_body(&mp_pck, "flush", 5);

    if (acked == FLB_TRUE) {
        http_status = 200;
        msgpack_pack_str(&mp_pck, 10);
        msgpack_pack_str_body(&mp_pck, "dispatched", 10);
    }
    else {
        /* dispatch was requested but not acknowledged within the timeout */
        http_status = 503;
        msgpack_pack_str(&mp_pck, 7);
        msgpack_pack_str_body(&mp_pck, "timeout", 7);
    }

    msgpack_pack_str(&mp_pck, 16);
    msgpack_pack_str_body(&mp_pck, "flush_now_ticket", 16);
    msgpack_pack_uint64(&mp_pck, ticket);

    msgpack_pack_str(&mp_pck, 15);
    msgpack_pack_str_body(&mp_pck, "flush_now_acked", 15);
    msgpack_pack_uint64(&mp_pck, cfl_atomic_load(&config->flush_now_acked));

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

static int handle_get_flush_status(struct flb_http_response *response,
                                   struct flb_config *config)
{
    flb_sds_t out_buf;
    size_t out_size;
    uint64_t acked;
    uint64_t count;
    msgpack_packer mp_pck;
    msgpack_sbuffer mp_sbuf;

    /* Ensures acked and count are coherent with one another */
    do {
        acked = cfl_atomic_load(&config->flush_now_acked);
        count = cfl_atomic_load(&config->flush_now_count);
    } while (acked != cfl_atomic_load(&config->flush_now_acked));

    /* initialize buffers */
    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    msgpack_pack_map(&mp_pck, 2);

    msgpack_pack_str(&mp_pck, 15);
    msgpack_pack_str_body(&mp_pck, "flush_now_count", 15);
    msgpack_pack_uint64(&mp_pck, count);

    msgpack_pack_str(&mp_pck, 15);
    msgpack_pack_str_body(&mp_pck, "flush_now_acked", 15);
    msgpack_pack_uint64(&mp_pck, acked);

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

static int cb_flush(struct flb_hs *hs,
                    struct flb_http_request *request,
                    struct flb_http_response *response)
{
    struct flb_config *config = hs->config;

    if (request->method == HTTP_METHOD_POST ||
        request->method == HTTP_METHOD_PUT) {
        return handle_flush_request(request, response, config);
    }
    else if (request->method == HTTP_METHOD_GET) {
        return handle_get_flush_status(response, config);
    }

    flb_http_response_set_status(response, 405);
    flb_http_response_set_header(response, "Allow", 5, "GET, POST, PUT", 14);
    return flb_http_response_commit(response);
}

/* Perform registration */
int api_v2_flush(struct flb_hs *hs)
{
    return flb_hs_register_endpoint(hs, "/api/v2/flush",
                                    FLB_HS_ROUTE_EXACT, cb_flush);
}
