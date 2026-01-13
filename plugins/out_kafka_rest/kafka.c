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

#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_http_client.h>
#include <fluent-bit/flb_config_map.h>
#include <fluent-bit/flb_log_event_decoder.h>
#include <msgpack.h>

#include "kafka.h"
#include "kafka_conf.h"

static struct flb_config_map config_map[] = {
    {
     FLB_CONFIG_MAP_STR, "message_key", NULL,
     0, FLB_TRUE, offsetof(struct flb_kafka_rest, message_key),
     "Specify a message key. "
    },

    {
     FLB_CONFIG_MAP_STR, "time_key", NULL,
     0, FLB_TRUE, offsetof(struct flb_kafka_rest, time_key),
     "Specify the name of the field that holds the record timestamp. "
    },

    {
     FLB_CONFIG_MAP_STR, "topic", "fluent-bit",
     0, FLB_TRUE, offsetof(struct flb_kafka_rest, topic),
     "Specify the kafka topic. "
    },

    {
     FLB_CONFIG_MAP_STR, "url_path", NULL,
     0, FLB_TRUE, offsetof(struct flb_kafka_rest, url_path),
     "Specify an optional HTTP URL path for the target web server, e.g: /something"
    },

    {
     FLB_CONFIG_MAP_DOUBLE, "partition", "-1",
     0, FLB_TRUE, offsetof(struct flb_kafka_rest, partition),
     "Specify kafka partition number. "
    },

    {
     FLB_CONFIG_MAP_STR, "time_key_format", FLB_KAFKA_TIME_KEYF,
     0, FLB_TRUE, offsetof(struct flb_kafka_rest, time_key_format),
     "Specify the format of the timestamp. "
    },

    {
     FLB_CONFIG_MAP_BOOL, "include_tag_key", "false",
     0, FLB_TRUE, offsetof(struct flb_kafka_rest, include_tag_key),
     "Specify whether to append tag name to final record. "
    },

    {
     FLB_CONFIG_MAP_STR, "tag_key", "_flb-key",
     0, FLB_TRUE, offsetof(struct flb_kafka_rest, tag_key),
     "Specify the key name of the record if include_tag_key is enabled. "
    },
    {
     FLB_CONFIG_MAP_BOOL, "avro_http_header", "false",
     0, FLB_TRUE, offsetof(struct flb_kafka_rest, avro_http_header),
     "Specify if the format has avro header in http request"
    },
    {
     FLB_CONFIG_MAP_STR, "http_user", NULL,
     0, FLB_TRUE, offsetof(struct flb_kafka_rest, http_user),
     "Set HTTP auth user"
    },
    {
     FLB_CONFIG_MAP_STR, "http_passwd", "",
     0, FLB_TRUE, offsetof(struct flb_kafka_rest, http_passwd),
     "Set HTTP auth password"
    },
    /* EOF */
    {0}
};
/*
 * Convert the internal Fluent Bit data representation to the required
 * one by Kafka REST Proxy.
 */
static flb_sds_t kafka_rest_format(const void *data, size_t bytes,
                                   const char *tag, int tag_len,
                                   size_t *out_size,
                                   struct flb_kafka_rest *ctx,
                                   struct flb_config *config)
{
    int i;
    int len;
    int arr_size = 0;
    int map_size;
    size_t s;
    flb_sds_t out_buf;
    char time_formatted[256];
    msgpack_object map;
    msgpack_object key;
    msgpack_object val;
    struct tm tm;
    msgpack_sbuffer mp_sbuf;
    msgpack_packer mp_pck;
    struct flb_log_event_decoder log_decoder;
    struct flb_log_event log_event;
    int ret;

    ret = flb_log_event_decoder_init(&log_decoder, (char *) data, bytes);

    if (ret != FLB_EVENT_DECODER_SUCCESS) {
        flb_plg_error(ctx->ins,
                      "Log event decoder initialization error : %d", ret);

        return NULL;
    }

    /* Init temporary buffers */
    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    /* Count number of entries */
    arr_size = flb_mp_count(data, bytes);

    /* Root map */
    msgpack_pack_map(&mp_pck, 1);
    msgpack_pack_str(&mp_pck, 7);
    msgpack_pack_str_body(&mp_pck, "records", 7);

    msgpack_pack_array(&mp_pck, arr_size);

    /* Iterate and compose array content */
    while ((ret = flb_log_event_decoder_next(
                    &log_decoder,
                    &log_event)) == FLB_EVENT_DECODER_SUCCESS) {
        map = *log_event.body;
        map_size = 1;

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
        gmtime_r(&log_event.timestamp.tm.tv_sec, &tm);
        s = strftime(time_formatted, sizeof(time_formatted) - 1,
                     ctx->time_key_format, &tm);
        len = snprintf(time_formatted + s, sizeof(time_formatted) - 1 - s,
                       ".%09" PRIu64 "Z", (uint64_t) log_event.timestamp.tm.tv_nsec);
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
    flb_log_event_decoder_destroy(&log_decoder);

    /* Convert to JSON */
    out_buf = flb_msgpack_raw_to_json_sds(mp_sbuf.data, mp_sbuf.size,
                                          config->json_escape_unicode);
    msgpack_sbuffer_destroy(&mp_sbuf);
    if (!out_buf) {
        return NULL;
    }

    *out_size = flb_sds_len(out_buf);

    return out_buf;
}

static int cb_kafka_init(struct flb_output_instance *ins,
                         struct flb_config *config,
                         void *data)
{
    (void) ins;
    (void) config;
    (void) data;
    struct flb_kafka_rest *ctx;

    ctx = flb_kr_conf_create(ins, config);
    if (!ctx) {
        flb_plg_error(ins, "cannot initialize plugin");
        return -1;
    }

    flb_plg_debug(ctx->ins, "host=%s port=%i",
                  ins->host.name, ins->host.port);
    flb_output_set_context(ins, ctx);

    return 0;
}

static void cb_kafka_flush(struct flb_event_chunk *event_chunk,
                           struct flb_output_flush *out_flush,
                           struct flb_input_instance *i_ins,
                           void *out_context,
                           struct flb_config *config)
{
    int ret;
    flb_sds_t js;
    size_t js_size;
    size_t b_sent;
    struct flb_http_client *c;
    struct flb_connection *u_conn;
    struct flb_kafka_rest *ctx = out_context;
    (void) i_ins;

    /* Get upstream connection */
    u_conn = flb_upstream_conn_get(ctx->u);
    if (!u_conn) {
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }

    /* Convert format */
    js = kafka_rest_format(event_chunk->data, event_chunk->size,
                           event_chunk->tag, flb_sds_len(event_chunk->tag),
                           &js_size, ctx, config);
    if (!js) {
        flb_upstream_conn_release(u_conn);
        FLB_OUTPUT_RETURN(FLB_ERROR);
    }

    /* Compose HTTP Client request */
    c = flb_http_client(u_conn, FLB_HTTP_POST, ctx->uri,
                        js, js_size, NULL, 0, NULL, 0);
    flb_http_add_header(c, "User-Agent", 10, "Fluent-Bit", 10);
    if (ctx->avro_http_header == FLB_TRUE) {
        flb_http_add_header(c,
                            "Content-Type", 12,
                            "application/vnd.kafka.avro.v2+json", 34);
    }
    else {
        flb_http_add_header(c,
                            "Content-Type", 12,
                            "application/vnd.kafka.json.v2+json", 34);
    }
    
    if (ctx->http_user && ctx->http_passwd) {
        flb_http_basic_auth(c, ctx->http_user, ctx->http_passwd);
    }

    ret = flb_http_do(c, &b_sent);
    if (ret != 0) {
        flb_plg_warn(ctx->ins, "http_do=%i", ret);
        goto retry;
    }
    else {
        /* The request was issued successfully, validate the 'error' field */
        flb_plg_debug(ctx->ins, "HTTP Status=%i", c->resp.status);
        if (c->resp.status != 200) {
            if (c->resp.payload_size > 0) {
                flb_plg_debug(ctx->ins, "Kafka REST response\n%s",
                              c->resp.payload);
            }
            goto retry;
        }

        if (c->resp.payload_size > 0) {
            flb_plg_debug(ctx->ins, "Kafka REST response\n%s",
                          c->resp.payload);
        }
        else {
            goto retry;
        }
    }

    /* Cleanup */
    flb_http_client_destroy(c);
    flb_sds_destroy(js);
    flb_upstream_conn_release(u_conn);
    FLB_OUTPUT_RETURN(FLB_OK);

    /* Issue a retry */
 retry:
    flb_http_client_destroy(c);
    flb_sds_destroy(js);
    flb_upstream_conn_release(u_conn);
    FLB_OUTPUT_RETURN(FLB_RETRY);
}

static int cb_kafka_exit(void *data, struct flb_config *config)
{
    struct flb_kafka_rest *ctx = data;

    flb_kr_conf_destroy(ctx);
    return 0;
}

struct flb_output_plugin out_kafka_rest_plugin = {
    .name         = "kafka-rest",
    .description  = "Kafka REST Proxy",
    .cb_init      = cb_kafka_init,
    .cb_flush     = cb_kafka_flush,
    .cb_exit      = cb_kafka_exit,
    .config_map   = config_map,
    .flags        = FLB_OUTPUT_NET | FLB_IO_OPT_TLS,
};
