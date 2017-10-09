/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2017 Treasure Data Inc.
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
#include <fluent-bit/flb_http_client.h>
#include <fluent-bit/flb_time.h>
#include <msgpack.h>

#include <stdio.h>

#include "influxdb.h"
#include "influxdb_bulk.h"

/*
 * Convert the internal Fluent Bit data representation to the required one
 * by InfluxDB.
 */
static char *influxdb_format(char *tag, int tag_len,
                             void *data, size_t bytes, int *out_size,
                             struct flb_influxdb_config *ctx)
{
    int i;
    int ret;
    int n_size;
    uint64_t seq = 0;
    size_t off = 0;
    char *buf;
    char *str = NULL;
    size_t str_size;
    char tmp[128];
    msgpack_unpacked result;
    msgpack_object root;
    msgpack_object map;
    msgpack_object *obj;
    struct flb_time tm;
    struct influxdb_bulk *bulk;


    /* Iterate the original buffer and perform adjustments */
    msgpack_unpacked_init(&result);

    /* Perform some format validation */
    ret = msgpack_unpack_next(&result, data, bytes, &off);
    if (!ret) {
        return NULL;
    }

    /* We 'should' get an array */
    if (result.data.type != MSGPACK_OBJECT_ARRAY) {
        /*
         * If we got a different format, we assume the caller knows what he is
         * doing, we just duplicate the content in a new buffer and cleanup.
         */
        return NULL;
    }

    root = result.data;
    if (root.via.array.size == 0) {
        return NULL;
    }

    /* Create the bulk composer */
    bulk = influxdb_bulk_create();
    if (!bulk) {
        return NULL;
    }

    off = 0;
    msgpack_unpacked_destroy(&result);
    msgpack_unpacked_init(&result);
    while (msgpack_unpack_next(&result, data, bytes, &off)) {
        if (result.data.type != MSGPACK_OBJECT_ARRAY) {
            continue;
        }

        /* Each array must have two entries: time and record */
        root = result.data;
        if (root.via.array.size != 2) {
            continue;
        }


        flb_time_pop_from_msgpack(&tm, &result, &obj);
        map    = root.via.array.ptr[1];
        n_size = map.via.map.size + 1;

        seq = ctx->seq;
        if (ctx->seq + 1 >= 100000) {
            seq = 1;
        }
        else {
            ctx->seq++;
        }

        ret = influxdb_bulk_append_header(bulk,
                                          tag, tag_len,
                                          seq,
                                          ctx->seq_name, ctx->seq_len);
        if (ret == -1) {
            influxdb_bulk_destroy(bulk);
            msgpack_unpacked_destroy(&result);
            return NULL;
        }

        for (i = 0; i < n_size - 1; i++) {
            msgpack_object *k = &map.via.map.ptr[i].key;
            msgpack_object *v = &map.via.map.ptr[i].val;

            if (k->type != MSGPACK_OBJECT_BIN && k->type != MSGPACK_OBJECT_STR) {
                continue;
            }

            int quote = FLB_FALSE;

            /* key */
            char *key = NULL;
            int key_len;

            /* val */
            char *val = NULL;
            int val_len;

            if (k->type == MSGPACK_OBJECT_STR) {
                key = (char *) k->via.str.ptr;
                key_len = k->via.str.size;
            }
            else {
                key = (char *) k->via.bin.ptr;
                key_len = k->via.bin.size;
            }

            /* Store value */
            if (v->type == MSGPACK_OBJECT_NIL) {
                /* Missing values are Null by default in InfluxDB */
                continue;
            }
            else if (v->type == MSGPACK_OBJECT_BOOLEAN) {
                if (v->via.boolean) {
                    val = "TRUE";
                    val_len = 4;
                }
                else {
                    val = "FALSE";
                    val_len = 5;
                }
            }
            else if (v->type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
                val = tmp;
                val_len = snprintf(tmp, sizeof(tmp) - 1, "%" PRIu64, v->via.u64);
            }
            else if (v->type == MSGPACK_OBJECT_NEGATIVE_INTEGER) {
                val = tmp;
                val_len = snprintf(tmp, sizeof(tmp) - 1, "%" PRId64, v->via.i64);
            }
            else if (v->type == MSGPACK_OBJECT_FLOAT) {
                val = tmp;
                val_len = snprintf(tmp, sizeof(tmp) - 1, "%f", v->via.f64);
            }
            else if (v->type == MSGPACK_OBJECT_STR) {
                /* String value */
                quote   = FLB_TRUE;
                val     = (char *) v->via.str.ptr;
                val_len = v->via.str.size;
            }
            else if (v->type == MSGPACK_OBJECT_BIN) {
                /* Bin value */
                quote   = FLB_TRUE;
                val     = (char *) v->via.bin.ptr;
                val_len = v->via.bin.size;
            }

            if (!val || !key) {
                continue;
            }

            /* is this a string ? */
            if (quote == FLB_TRUE) {
                ret = flb_utils_write_str_buf(val, val_len,
                                              &str, &str_size);
                if (ret == -1) {
                    flb_errno();
                    influxdb_bulk_destroy(bulk);
                    msgpack_unpacked_destroy(&result);
                    return NULL;
                }

                val = str;
                val_len = str_size;
            }

            /* Append key/value data into the bulk */
            ret = influxdb_bulk_append_kv(bulk,
                                          key, key_len,
                                          val, val_len,
                                          i, quote);

            if (quote == FLB_TRUE) {
                flb_free(str);
                str_size = 0;
            }

            if (ret == -1) {
                flb_error("[out_influxdb] cannot append key/value");
                influxdb_bulk_destroy(bulk);
                msgpack_unpacked_destroy(&result);
                return NULL;
            }
        }

        /* Append the timestamp */
        ret = influxdb_bulk_append_timestamp(bulk, &tm);
        if (ret == -1) {
            flb_error("[out_influxdb] cannot append timestamp");
            influxdb_bulk_destroy(bulk);
            msgpack_unpacked_destroy(&result);
            return NULL;
        }
    }

    msgpack_unpacked_destroy(&result);

    *out_size = bulk->len;
    buf = bulk->ptr;

    /*
     * Note: we don't destroy the bulk as we need to keep the allocated
     * buffer with the data. Instead we just release the bulk context and
     * return the bulk->ptr buffer
     */
    flb_free(bulk);

    return buf;
}

int cb_influxdb_init(struct flb_output_instance *ins, struct flb_config *config,
                     void *data)
{
    int io_flags = 0;
    char *tmp;
    struct flb_upstream *upstream;
    struct flb_influxdb_config *ctx;

    /* Get network configuration */
    if (!ins->host.name) {
        ins->host.name = flb_strdup(FLB_INFLUXDB_HOST);
    }

    if (ins->host.port == 0) {
        ins->host.port = FLB_INFLUXDB_PORT;
    }

    /* Allocate plugin context */
    ctx = flb_malloc(sizeof(struct flb_influxdb_config));
    if (!ctx) {
        flb_errno();
        return -1;
    }

    if (ins->use_tls == FLB_TRUE) {
        io_flags = FLB_IO_TLS;
    }
    else {
        io_flags = FLB_IO_TCP;
    }

    /* database */
    tmp = flb_output_get_property("database", ins);
    if (!tmp) {
        ctx->db_name = flb_strdup("fluentbit");
    }
    else {
        ctx->db_name = flb_strdup(tmp);
    }
    ctx->db_len = strlen(ctx->db_name);

    /* sequence tag */
    tmp = flb_output_get_property("sequence_tag", ins);
    if (!tmp) {
        ctx->seq_name = flb_strdup("_seq");
    }
    else {
        ctx->seq_name = flb_strdup(tmp);
    }
    ctx->seq_len = strlen(ctx->seq_name);

    snprintf(ctx->uri, sizeof(ctx->uri) - 1, "/write?db=%s&precision=n", ctx->db_name);

    if (ins->host.ipv6 == FLB_TRUE) {
        io_flags |= FLB_IO_IPV6;
    }

    /* Prepare an upstream handler */
    upstream = flb_upstream_create(config,
                                   ins->host.name,
                                   ins->host.port,
                                   io_flags,
                                   &ins->tls);
    if (!upstream) {
        flb_free(ctx);
        return -1;
    }
    ctx->u   = upstream;
    ctx->seq = 0;

    flb_debug("[out_influxdb] host=%s port=%i", ins->host.name, ins->host.port);
    flb_output_set_context(ins, ctx);

    return 0;
}

void cb_influxdb_flush(void *data, size_t bytes,
                       char *tag, int tag_len,
                       struct flb_input_instance *i_ins,
                       void *out_context,
                       struct flb_config *config)
{
    int ret;
    int bytes_out;
    size_t b_sent;
    char *pack;
    struct flb_upstream_conn *u_conn;
    struct flb_http_client *c;
    struct flb_influxdb_config *ctx = out_context;

    /* Convert format */
    pack = influxdb_format(tag, tag_len, data, bytes, &bytes_out, ctx);
    if (!pack) {
        FLB_OUTPUT_RETURN(FLB_ERROR);
    }

    /* Get upstream connection */
    u_conn = flb_upstream_conn_get(ctx->u);
    if (!u_conn) {
        flb_free(pack);
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }

    /* Compose HTTP Client request */
    c = flb_http_client(u_conn, FLB_HTTP_POST, ctx->uri,
                        pack, bytes_out, NULL, 0, NULL, 0);
    flb_http_add_header(c, "User-Agent", 10, "Fluent-Bit", 10);

    ret = flb_http_do(c, &b_sent);
    if (ret == 0) {
        if (c->resp.payload_size > 0) {
            flb_debug("[out_influxdb] http_do=%i http_status=%i\n%s",
                      ret, c->resp.status, c->resp.payload);
        }
        else {
            flb_debug("[out_influxdb] http_do=%i http_status=%i",
                      ret, c->resp.status);
        }
    }
    else {
        flb_debug("[out_influxdb] http_do=%i", ret);
    }

    flb_http_client_destroy(c);

    flb_free(pack);

    /* Release the connection */
    flb_upstream_conn_release(u_conn);

    FLB_OUTPUT_RETURN(FLB_OK);
}

int cb_influxdb_exit(void *data, struct flb_config *config)
{
    struct flb_influxdb_config *ctx = data;

    flb_upstream_destroy(ctx->u);
    flb_free(ctx->db_name);
    flb_free(ctx->seq_name);
    flb_free(ctx);

    return 0;
}

struct flb_output_plugin out_influxdb_plugin = {
    .name         = "influxdb",
    .description  = "InfluxDB Time Series",
    .cb_init      = cb_influxdb_init,
    .cb_pre_run     = NULL,
    .cb_flush     = cb_influxdb_flush,
    .cb_exit      = cb_influxdb_exit,
    .flags        = FLB_OUTPUT_NET | FLB_IO_OPT_TLS,
};
