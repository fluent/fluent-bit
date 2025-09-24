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
#include <fluent-bit/flb_http_server.h>
#include <fluent-bit/flb_mem.h>

#define FLB_UPTIME_ONEDAY  86400
#define FLB_UPTIME_ONEHOUR  3600
#define FLB_UPTIME_ONEMINUTE  60

/* Append human-readable uptime */
static void uptime_hr(time_t uptime, msgpack_packer *mp_pck)
{
    int len;
    int days;
    int hours;
    int minutes;
    int seconds;
    long int upmind;
    long int upminh;
    char buf[256];

    /* days */
    days = uptime / FLB_UPTIME_ONEDAY;
    upmind = uptime - (days * FLB_UPTIME_ONEDAY);

    /* hours */
    hours = upmind / FLB_UPTIME_ONEHOUR;
    upminh = upmind - hours * FLB_UPTIME_ONEHOUR;

    /* minutes */
    minutes = upminh / FLB_UPTIME_ONEMINUTE;
    seconds = upminh - minutes * FLB_UPTIME_ONEMINUTE;

    len = snprintf(buf, sizeof(buf) - 1,
                   "Fluent Bit has been running: "
                   " %i day%s, %i hour%s, %i minute%s and %i second%s",
                   days, (days > 1) ? "s" : "", hours,                  \
                   (hours > 1) ? "s" : "", minutes,                     \
                   (minutes > 1) ? "s" : "", seconds, \
                   (seconds > 1) ? "s" : "");
    msgpack_pack_str(mp_pck, 9);
    msgpack_pack_str_body(mp_pck, "uptime_hr", 9);
    msgpack_pack_str(mp_pck, len);
    msgpack_pack_str_body(mp_pck, buf, len);
}

/* API: List all built-in plugins */
static void cb_uptime(mk_request_t *request, void *data)
{
    flb_sds_t out_buf;
    size_t out_size;
    time_t uptime;
    msgpack_packer mp_pck;
    msgpack_sbuffer mp_sbuf;
    struct flb_hs *hs = data;
    struct flb_config *config = hs->config;

    /* initialize buffers */
    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    msgpack_pack_map(&mp_pck, 2);
    msgpack_pack_str(&mp_pck, 10);
    msgpack_pack_str_body(&mp_pck, "uptime_sec", 10);

    uptime = time(NULL) - config->init_time;
    msgpack_pack_uint64(&mp_pck, uptime);

    uptime_hr(uptime, &mp_pck);

    /* Export to JSON */
    out_buf = flb_msgpack_raw_to_json_sds(mp_sbuf.data, mp_sbuf.size, FLB_TRUE);
    msgpack_sbuffer_destroy(&mp_sbuf);
    if (!out_buf) {
        return;
    }
    out_size = flb_sds_len(out_buf);

    mk_http_status(request, 200);
    flb_hs_add_content_type_to_req(request, FLB_HS_CONTENT_TYPE_JSON);
    mk_http_send(request, out_buf, out_size, NULL);
    mk_http_done(request);

    flb_sds_destroy(out_buf);
}

/* Perform registration */
int api_v1_uptime(struct flb_hs *hs)
{
    mk_vhost_handler(hs->ctx, hs->vid, "/api/v1/uptime", cb_uptime, hs);
    return 0;
}
