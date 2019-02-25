/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019      The Fluent Bit Authors
 *  Copyright (C) 2015-2018 Treasure Data Inc.
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
#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_http_client.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_time.h>
#include <msgpack.h>

#include "splunk.h"
#include "splunk_conf.h"

static int cb_splunk_init(struct flb_output_instance *ins,
                          struct flb_config *config, void *data)
{
    struct flb_splunk *ctx;

    ctx = flb_splunk_conf_create(ins, config);
    if (!ctx) {
        flb_error("[out_splunk] configuration failed");
        return -1;
    }

    flb_output_set_context(ins, ctx);
    return 0;
}

int splunk_format(void *in_buf, size_t in_bytes,
                  char **out_buf, size_t *out_size,
                  struct flb_splunk *ctx)
{
    int i;
    int map_size;
    size_t off = 0;
    double t;
    struct flb_time tm;
    msgpack_unpacked result;
    msgpack_object root;
    msgpack_object *obj;
    msgpack_object map;
    msgpack_object k;
    msgpack_object v;
    msgpack_sbuffer mp_sbuf;
    msgpack_packer mp_pck;
    flb_sds_t tmp;
    flb_sds_t record;
    flb_sds_t json_out;

    json_out = flb_sds_create_size(in_bytes * 1.5);
    if (!json_out) {
        flb_errno();
        return -1;
    }

    /* Iterate the original buffer and perform adjustments */
    msgpack_unpacked_init(&result);

    while (msgpack_unpack_next(&result, in_buf, in_bytes, &off) == MSGPACK_UNPACK_SUCCESS) {
        root = result.data;

        /* Get timestamp */
        flb_time_pop_from_msgpack(&tm, &result, &obj);
        t = flb_time_to_double(&tm);

        /* Create temporal msgpack buffer */
        msgpack_sbuffer_init(&mp_sbuf);
        msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

        map = root.via.array.ptr[1];
        map_size = map.via.map.size;

        if (ctx->splunk_send_raw == FLB_TRUE) {
            msgpack_pack_map(&mp_pck, 1 + map_size /* time + all k/v */);
        } else {
            msgpack_pack_map(&mp_pck, 2 /* time + event */);
        }

        /* Append the time key */
        msgpack_pack_str(&mp_pck, sizeof(FLB_SPLUNK_DEFAULT_TIME) -1);
        msgpack_pack_str_body(&mp_pck,
                              FLB_SPLUNK_DEFAULT_TIME,
                              sizeof(FLB_SPLUNK_DEFAULT_TIME) - 1);
        msgpack_pack_double(&mp_pck, t);

        if (ctx->splunk_send_raw == FLB_FALSE) {
            /* Add k/v pairs under the key 'event' instead of to the top level object */
            msgpack_pack_str(&mp_pck, sizeof(FLB_SPLUNK_DEFAULT_EVENT) -1);
            msgpack_pack_str_body(&mp_pck,
                                  FLB_SPLUNK_DEFAULT_EVENT,
                                  sizeof(FLB_SPLUNK_DEFAULT_EVENT) - 1);
            msgpack_pack_map(&mp_pck, map_size);
        }

        /* Append k/v */
        for (i = 0; i < map_size; i++) {
            k = map.via.map.ptr[i].key;
            v = map.via.map.ptr[i].val;

            msgpack_pack_object(&mp_pck, k);
            msgpack_pack_object(&mp_pck, v);
        }

        record = flb_msgpack_raw_to_json_sds(mp_sbuf.data, mp_sbuf.size);
        if (!record) {
            flb_errno();
            msgpack_sbuffer_destroy(&mp_sbuf);
            msgpack_unpacked_destroy(&result);
            flb_sds_destroy(json_out);
            return -1;
        }

        tmp = flb_sds_cat(json_out, record, flb_sds_len(record));
        flb_sds_destroy(record);
        if (tmp) {
            json_out = tmp;
        }
        else {
            flb_errno();
            msgpack_sbuffer_destroy(&mp_sbuf);
            msgpack_unpacked_destroy(&result);
            flb_sds_destroy(json_out);
            return -1;
        }
        msgpack_sbuffer_destroy(&mp_sbuf);
    }

    *out_buf = json_out;
    *out_size = flb_sds_len(json_out);

    return 0;
}

static void cb_splunk_flush(void *data, size_t bytes,
                            char *tag, int tag_len,
                            struct flb_input_instance *i_ins,
                            void *out_context,
                            struct flb_config *config)
{
    int ret;
    size_t b_sent;
    char *buf_data;
    size_t buf_size;
    struct flb_splunk *ctx = out_context;
    struct flb_upstream_conn *u_conn;
    struct flb_http_client *c;
    flb_sds_t payload;
    (void) i_ins;
    (void) config;

    /* Get upstream connection */
    u_conn = flb_upstream_conn_get(ctx->u);
    if (!u_conn) {
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }

    /* Convert binary logs into a JSON payload */
    ret = splunk_format(data, bytes, &buf_data, &buf_size, ctx);
    if (ret == -1) {
        flb_upstream_conn_release(u_conn);
        FLB_OUTPUT_RETURN(FLB_ERROR);
    }
    payload = (flb_sds_t) buf_data;

    /* Compose HTTP Client request */
    c = flb_http_client(u_conn, FLB_HTTP_POST, FLB_SPLUNK_DEFAULT_URI,
                        buf_data, buf_size, NULL, 0, NULL, 0);
    flb_http_buffer_size(c, FLB_HTTP_DATA_SIZE_MAX);
    flb_http_add_header(c, "User-Agent", 10, "Fluent-Bit", 10);

    flb_http_add_header(c, "Authorization", 13,
                        ctx->auth_header, flb_sds_len(ctx->auth_header));
    ret = flb_http_do(c, &b_sent);
    if (ret != 0) {
        flb_warn("[out_splunk] http_do=%i", ret);
        goto retry;
    }
    else {
        if (c->resp.status != 200) {
            if (c->resp.payload_size > 0) {
                flb_warn("[out_splunk] http_status=%i:\n%s",
                         c->resp.status, c->resp.payload);
            }
            else {
                flb_warn("[out_splunk] http_status=%i", c->resp.status);
            }
            goto retry;
        }
    }

    /* Cleanup */
    flb_http_client_destroy(c);
    flb_sds_destroy(payload);
    flb_upstream_conn_release(u_conn);
    FLB_OUTPUT_RETURN(FLB_OK);

    /* Issue a retry */
 retry:
    flb_http_client_destroy(c);
    flb_sds_destroy(payload);
    flb_upstream_conn_release(u_conn);
    FLB_OUTPUT_RETURN(FLB_RETRY);
}

static int cb_splunk_exit(void *data, struct flb_config *config)
{
    struct flb_splunk *ctx = data;

    flb_splunk_conf_destroy(ctx);
    return 0;
}

struct flb_output_plugin out_splunk_plugin = {
    .name         = "splunk",
    .description  = "Send events to Splunk HTTP Event Collector",
    .cb_init      = cb_splunk_init,
    .cb_flush     = cb_splunk_flush,
    .cb_exit      = cb_splunk_exit,

    /* Plugin flags */
    .flags          = FLB_OUTPUT_NET | FLB_IO_OPT_TLS,
};
