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

#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_io.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_http_client.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_time.h>

#include <msgpack.h>

#include "datadog.h"
#include "datadog_conf.h"

static int cb_datadog_init(struct flb_output_instance *ins,
                           struct flb_config *config, void *data)
{
    struct flb_out_datadog *ctx = NULL;
    (void) data;

    ctx = flb_datadog_conf_create(ins, config);
    if (!ctx) {
        return -1;
    }

    /* Set the plugin context */
    flb_output_set_context(ins, ctx);
    return 0;
}

static int64_t timestamp_format(const struct flb_time* tms) {
    int64_t timestamp = 0;
    /* Format the time, use milliseconds precision not nanoseconds */
    timestamp = tms->tm.tv_sec * 1000;
    timestamp += tms->tm.tv_nsec/1000000;
    /* round up if necessary */
    if (tms->tm.tv_nsec % 1000000 >= 500000) {
        ++timestamp;
    }
    return timestamp;
}

static void dd_msgpack_pack_key_value_str(msgpack_packer* mp_pck,
                                          const char *key, size_t key_size,
                                          const char *val, size_t val_size)
{
    msgpack_pack_str(mp_pck, key_size);
    msgpack_pack_str_body(mp_pck, key, key_size);
    msgpack_pack_str(mp_pck, val_size);
    msgpack_pack_str_body(mp_pck,val, val_size);
}

static int dd_compare_msgpack_obj_key_with_str(const msgpack_object obj, const char *key, size_t key_size) {
    if (obj.via.str.size == key_size && memcmp(obj.via.str.ptr,key, key_size) == 0) {
        return FLB_TRUE;
    }

    return FLB_FALSE;
}

static int datadog_format(const void *data, size_t bytes,
                          const char *tag, int tag_len,
                          char **out_data, size_t *out_size,
                          struct flb_out_datadog *ctx)
{
    /* for msgpack global structs */
    size_t off = 0;   
    int array_size = 0;
    msgpack_unpacked result;
    msgpack_sbuffer mp_sbuf;
    msgpack_packer mp_pck;
    /* for sub msgpack objs */
    int map_size;
    struct flb_time tms;
    int64_t timestamp;
    msgpack_object *obj;
    msgpack_object map;
    msgpack_object root;
    msgpack_object k;
    msgpack_object v;
    /* output buffer */
    flb_sds_t out_buf;

    /* Count number of records */
    msgpack_unpacked_init(&result);
    while (msgpack_unpack_next(&result, data, bytes, &off) == MSGPACK_UNPACK_SUCCESS) {
        array_size++;
    }
    msgpack_unpacked_destroy(&result);
    msgpack_unpacked_init(&result);

    /* Create temporal msgpack buffer */
    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    /* Prepare array for all entries */
    msgpack_pack_array(&mp_pck, array_size);

    off = 0;
    while (msgpack_unpack_next(&result, data, bytes, &off) == MSGPACK_UNPACK_SUCCESS) {
        root = result.data;

        /* Get timestamp and object */
        flb_time_pop_from_msgpack(&tms, &result, &obj);
        timestamp = timestamp_format(&tms);

        map = root.via.array.ptr[1];
        map_size = map.via.map.size;

        /* build new object(map) with additional space for datadog entries */
        msgpack_pack_map(&mp_pck, ctx->nb_additional_entries + map_size);

        /* timestamp */
        msgpack_pack_str(&mp_pck, flb_sds_len(ctx->json_date_key));
        msgpack_pack_str_body(&mp_pck,
                              ctx->json_date_key,
                              flb_sds_len(ctx->json_date_key));
        msgpack_pack_int64(&mp_pck, timestamp);

        /* include_tag_key */
        if (ctx->include_tag_key == FLB_TRUE) {
            dd_msgpack_pack_key_value_str(&mp_pck,
                                          ctx->tag_key, flb_sds_len(ctx->tag_key),
                                          tag, tag_len);
        }

        /* dd_source */
        if (ctx->dd_source != NULL) {
            dd_msgpack_pack_key_value_str(&mp_pck,
                                          FLB_DATADOG_DD_SOURCE_KEY, sizeof(FLB_DATADOG_DD_SOURCE_KEY) -1,
                                          ctx->dd_source, flb_sds_len(ctx->dd_source));
        }

        /* dd_service */
        if (ctx->dd_service != NULL) {
            dd_msgpack_pack_key_value_str(&mp_pck,
                                          FLB_DATADOG_DD_SERVICE_KEY, sizeof(FLB_DATADOG_DD_SERVICE_KEY) -1,
                                          ctx->dd_service, flb_sds_len(ctx->dd_service));
        }

        /* Append initial object k/v */
        int i = 0;
        for (i = 0; i < map_size; i++) {
            k = map.via.map.ptr[i].key;
            v = map.via.map.ptr[i].val;
            /* Mapping between input keys to specific datadog keys */
            if (ctx->dd_message_key != NULL && dd_compare_msgpack_obj_key_with_str(k, ctx->dd_message_key, flb_sds_len(ctx->dd_message_key)) == FLB_TRUE) {
                msgpack_pack_str(&mp_pck, sizeof(FLB_DATADOG_DD_MESSAGE_KEY)-1);
                msgpack_pack_str_body(&mp_pck, FLB_DATADOG_DD_MESSAGE_KEY, sizeof(FLB_DATADOG_DD_MESSAGE_KEY)-1);
            } else {
                msgpack_pack_object(&mp_pck, k);
            }

            msgpack_pack_object(&mp_pck, v);
        }

        /* dd_tags */
        if (ctx->dd_tags != NULL) {
            dd_msgpack_pack_key_value_str(&mp_pck,
                                          FLB_DATADOG_DD_TAGS_KEY, sizeof(FLB_DATADOG_DD_TAGS_KEY) -1,
                                          ctx->dd_tags, flb_sds_len(ctx->dd_tags));
        }
    }

    /* Convert from msgpack to JSON */
    out_buf = flb_msgpack_raw_to_json_sds(mp_sbuf.data, mp_sbuf.size);
    msgpack_sbuffer_destroy(&mp_sbuf);

    if (!out_buf) {
        flb_error("[out_datadog] error formatting JSON payload");
        msgpack_unpacked_destroy(&result);
        return -1;
    }

    *out_data = out_buf;
    *out_size = flb_sds_len(out_buf);
    /* Cleanup */
    msgpack_unpacked_destroy(&result);

    return 0;
}

static void cb_datadog_flush(const void *data, size_t bytes,
                             const char *tag, int tag_len,
                             struct flb_input_instance *i_ins,
                             void *out_context,
                             struct flb_config *config)
{
    struct flb_out_datadog *ctx = out_context;
    struct flb_upstream_conn *upstream_conn;
    struct flb_http_client *client;

    flb_sds_t payload_buf;
    size_t payload_size = 0;
    size_t b_sent;
    int ret = FLB_ERROR;

    /* Get upstream connection */
    upstream_conn = flb_upstream_conn_get(ctx->upstream);
    if (!upstream_conn) {
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }

    /* Convert input data into a Datadog JSON payload */
    ret = datadog_format(data, bytes, tag, tag_len, &payload_buf, &payload_size, ctx);
    if (ret == -1) {
        flb_upstream_conn_release(upstream_conn);
        FLB_OUTPUT_RETURN(FLB_ERROR);
    }

    /* Create HTTP client context */
    client = flb_http_client(upstream_conn, FLB_HTTP_POST, ctx->uri,
                             payload_buf, payload_size,
                             ctx->host, ctx->port,
                             NULL, 0);
    if (!client) {
        flb_upstream_conn_release(upstream_conn);
        FLB_OUTPUT_RETURN(FLB_ERROR);
    }

    flb_http_add_header(client, "User-Agent", 10, "Fluent-Bit", 10);
    flb_http_add_header(client,
                        FLB_DATADOG_CONTENT_TYPE, sizeof(FLB_DATADOG_CONTENT_TYPE) - 1,
                        FLB_DATADOG_MIME_JSON, sizeof(FLB_DATADOG_MIME_JSON) - 1);
    /* TODO: Append other headers if needed*/
    
    /* finaly send the query */
    ret = flb_http_do(client, &b_sent);
    if (ret == 0) {
        if (client->resp.status < 200 || client->resp.status > 205) {
            flb_error("[out_datadog] %s%s:%i HTTP status=%i",
                      ctx->scheme, ctx->host, ctx->port, client->resp.status);
            ret = FLB_RETRY;
        }
        else {
            if (client->resp.payload) {
                flb_info("[out_datadog] %s%s, port=%i, HTTP status=%i payload=%s",
                         ctx->scheme, ctx->host, ctx->port,
                         client->resp.status, client->resp.payload);
            }
            else {
                flb_info("[out_datadog] %s%s, port=%i, HTTP status=%i",
                         ctx->scheme, ctx->host, ctx->port,
                         client->resp.status);
            }
            ret = FLB_OK;
        }
    }
    else {
        flb_error("[out_datadog] could not flush records to %s:%i (http_do=%i)",
                  ctx->host, ctx->port, ret);
        ret = FLB_RETRY;
    }

    /* Destroy HTTP client context */
    flb_sds_destroy(payload_buf);
    flb_http_client_destroy(client);
    flb_upstream_conn_release(upstream_conn);

    FLB_OUTPUT_RETURN(ret);
}


static int cb_datadog_exit(void *data, struct flb_config *config)
{
    struct flb_out_datadog *ctx = data;
 
    flb_datadog_conf_destroy(ctx);
    return 0;
}

struct flb_output_plugin out_datadog_plugin = {
    .name         = "datadog",
    .description  = "Send events to DataDog HTTP Event Collector",
    .cb_init      = cb_datadog_init,
    .cb_flush     = cb_datadog_flush,
    .cb_exit      = cb_datadog_exit,
    /* Plugin flags */
    .flags        = FLB_OUTPUT_NET | FLB_IO_OPT_TLS,
};