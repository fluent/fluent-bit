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
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_http_client.h>
#include <msgpack.h>

#include "kafka.h"
#include "kafka_conf.h"

/*
 * Convert the internal Fluent Bit data representation to the required
 * one by Kafka REST Proxy.
 */
static char *kafka_rest_format(void *data, size_t bytes,
                               char *tag, int tag_len, size_t *out_size,
                               struct flb_kafka_rest *ctx)
{
    int i;
    int ret;
    int len;
    int arr_size = 0;
    int map_size;
    size_t s;
    size_t off = 0;
    char time_formatted[256];
    msgpack_unpacked result;
    msgpack_object root;
    msgpack_object map;
    msgpack_object *obj;
    msgpack_object key;
    msgpack_object val;
    char *json_buf;
    size_t json_size;
    struct tm tm;
    struct flb_time tms;
    msgpack_sbuffer mp_sbuf;
    msgpack_packer mp_pck;

    /* Init temporal buffers */
    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    /* Iterate the original buffer and perform adjustments */
    msgpack_unpacked_init(&result);

    /* Count number of entries */
    while (msgpack_unpack_next(&result, data, bytes, &off) == MSGPACK_UNPACK_SUCCESS) {
        arr_size++;
    }
    msgpack_unpacked_destroy(&result);
    off = 0;

    /* Root map */
    msgpack_pack_map(&mp_pck, 1);
    msgpack_pack_str(&mp_pck, 7);
    msgpack_pack_str_body(&mp_pck, "records", 7);

    msgpack_pack_array(&mp_pck, arr_size);

    /* Iterate and compose array content */
    msgpack_unpacked_init(&result);
    while (msgpack_unpack_next(&result, data, bytes, &off) == MSGPACK_UNPACK_SUCCESS) {
        root = result.data;

        map = root.via.array.ptr[1];
        map_size = 1;

        flb_time_pop_from_msgpack(&tms, &result, &obj);

        if (ctx->partition >= 0) {
            map_size++;
        }

        if (ctx->message_key != NULL) {
            map_size++;
        }

        msgpack_pack_map(&mp_pck, map_size);
        if (ctx->partition >= 0) {
            msgpack_pack_str(&mp_pck, 9);
            msgpack_pack_str_body(&mp_pck, "partition", 9);
            msgpack_pack_int64(&mp_pck, ctx->partition);
        }


        if (ctx->message_key != NULL) {
            msgpack_pack_str(&mp_pck, 3);
            msgpack_pack_str_body(&mp_pck, "key", 3);
            msgpack_pack_str(&mp_pck, ctx->message_key_len);
            msgpack_pack_str_body(&mp_pck, ctx->message_key, ctx->message_key_len);
        }

        /* Value Map Size */
        map_size = map.via.map.size;
        map_size++;
        if (ctx->include_tag_key == FLB_TRUE) {
            map_size++;
        }

        msgpack_pack_str(&mp_pck, 5);
        msgpack_pack_str_body(&mp_pck, "value", 5);

        msgpack_pack_map(&mp_pck, map_size);

        /* Time key and time formatted */
        msgpack_pack_str(&mp_pck, ctx->time_key_len);
        msgpack_pack_str_body(&mp_pck, ctx->time_key, ctx->time_key_len);

        /* Format the time */
        gmtime_r(&tms.tm.tv_sec, &tm);
        s = strftime(time_formatted, sizeof(time_formatted) - 1,
                     ctx->time_key_format, &tm);
        len = snprintf(time_formatted + s, sizeof(time_formatted) - 1 - s,
                       ".%09" PRIu64 "Z", (uint64_t) tms.tm.tv_nsec);
        s += len;
        msgpack_pack_str(&mp_pck, s);
        msgpack_pack_str_body(&mp_pck, time_formatted, s);

        /* Tag Key */
        if (ctx->include_tag_key == FLB_TRUE) {
            msgpack_pack_str(&mp_pck, ctx->tag_key_len);
            msgpack_pack_str_body(&mp_pck, ctx->tag_key, ctx->tag_key_len);
            msgpack_pack_str(&mp_pck, tag_len);
            msgpack_pack_str_body(&mp_pck, tag, tag_len);
        }

        for (i = 0; i < map.via.map.size; i++) {
            key = map.via.map.ptr[i].key;
            val = map.via.map.ptr[i].val;

            msgpack_pack_object(&mp_pck, key);
            msgpack_pack_object(&mp_pck, val);
        }
    }
    msgpack_unpacked_destroy(&result);

    /* Convert to JSON */
    ret = flb_msgpack_raw_to_json_str(mp_sbuf.data, mp_sbuf.size,
                                      &json_buf, &json_size);
    msgpack_sbuffer_destroy(&mp_sbuf);
    if (ret != 0) {
        return NULL;
    }

    *out_size = json_size;
    return json_buf;
}

static int cb_kafka_init(struct flb_output_instance *ins,
                         struct flb_config *config,
                         void *data)
{
    (void) ins;
    (void) config;
    (void) data;
    struct flb_kafka_rest *ctx;

    ctx = flb_kafka_conf_create(ins, config);
    if (!ctx) {
        flb_error("[out_kafka_rest] cannot initialize plugin");
        return -1;
    }

    flb_debug("[out_kafka_rest] host=%s port=%i",
              ins->host.name, ins->host.port);
    flb_output_set_context(ins, ctx);

    return 0;
}

static void cb_kafka_flush(void *data, size_t bytes,
                           char *tag, int tag_len,
                           struct flb_input_instance *i_ins,
                           void *out_context,
                           struct flb_config *config)
{
    int ret;
    char *js;
    size_t js_size;
    size_t b_sent;
    struct flb_http_client *c;
    struct flb_upstream_conn *u_conn;
    struct flb_kafka_rest *ctx = out_context;
    (void) i_ins;
    (void) tag;
    (void) tag_len;

    /* Get upstream connection */
    u_conn = flb_upstream_conn_get(ctx->u);
    if (!u_conn) {
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }

    /* Convert format */
    js = kafka_rest_format(data, bytes, tag, tag_len, &js_size, ctx);
    if (!js) {
        flb_upstream_conn_release(u_conn);
        FLB_OUTPUT_RETURN(FLB_ERROR);
    }

    /* Compose HTTP Client request */
    c = flb_http_client(u_conn, FLB_HTTP_POST, ctx->uri,
                        js, js_size, NULL, 0, NULL, 0);
    flb_http_add_header(c, "User-Agent", 10, "Fluent-Bit", 10);
    flb_http_add_header(c,
                        "Content-Type", 12,
                        "application/vnd.kafka.json.v2+json", 34);

    if (ctx->http_user && ctx->http_passwd) {
        flb_http_basic_auth(c, ctx->http_user, ctx->http_passwd);
    }

    ret = flb_http_do(c, &b_sent);
    if (ret != 0) {
        flb_warn("[out_kafka_rest] http_do=%i", ret);
        goto retry;
    }
    else {
        /* The request was issued successfully, validate the 'error' field */
        flb_debug("[out_kafka_rest] HTTP Status=%i", c->resp.status);
        if (c->resp.status != 200) {
            if (c->resp.payload_size > 0) {
                flb_debug("[out_kafka_rest] Kafka REST response\n%s",
                          c->resp.payload);
            }
            goto retry;
        }

        if (c->resp.payload_size > 0) {
            flb_debug("[out_kafka_rest] Kafka REST response\n%s",
                      c->resp.payload);
        }
        else {
            goto retry;
        }
    }

    /* Cleanup */
    flb_http_client_destroy(c);
    flb_free(js);
    flb_upstream_conn_release(u_conn);
    FLB_OUTPUT_RETURN(FLB_OK);

    /* Issue a retry */
 retry:
    flb_http_client_destroy(c);
    flb_free(js);
    flb_upstream_conn_release(u_conn);
    FLB_OUTPUT_RETURN(FLB_RETRY);
}

int cb_kafka_exit(void *data, struct flb_config *config)
{
    struct flb_kafka_rest *ctx = data;

    flb_kafka_conf_destroy(ctx);
    return 0;
}

struct flb_output_plugin out_kafka_rest_plugin = {
    .name         = "kafka-rest",
    .description  = "Kafka REST Proxy",
    .cb_init      = cb_kafka_init,
    .cb_flush     = cb_kafka_flush,
    .cb_exit      = cb_kafka_exit,
    .flags        = FLB_OUTPUT_NET | FLB_IO_OPT_TLS,
};
