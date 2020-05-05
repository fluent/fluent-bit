/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2020 The Fluent Bit Authors
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

#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_http_client.h>
#include <fluent-bit/flb_time.h>
#include <msgpack.h>

#include <stdio.h>

#include "influxdb.h"
#include "influxdb_bulk.h"

/*
 * Returns FLB_TRUE if the specified value is true, otherwise FLB_FALSE
 */
static int bool_value(const char *v);

/*
 * Returns FLB_TRUE when the specified key is in Tag_Keys list,
 * otherwise FLB_FALSE
 */
static int is_tagged_key(struct flb_influxdb *ctx,
                         const char *key, int kl, int type);

/*
 * Increments the timestamp when it is duplicated
 */
static void influxdb_tsmod(struct flb_time *ts, struct flb_time *dupe,
                           struct flb_time *last) {
    if (flb_time_equal(ts, last) || flb_time_equal(ts, dupe)) {
        ++dupe->tm.tv_nsec;
        flb_time_copy(last, ts);
        flb_time_copy(ts, dupe);
    }
    else {
        flb_time_copy(last, ts);
        flb_time_copy(dupe, ts);
    }
}

/*
 * Convert the internal Fluent Bit data representation to the required one
 * by InfluxDB.
 */
static char *influxdb_format(const char *tag, int tag_len,
                             const void *data, size_t bytes, int *out_size,
                             struct flb_influxdb *ctx)
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
    struct influxdb_bulk *bulk = NULL;
    struct influxdb_bulk *bulk_head = NULL;
    struct influxdb_bulk *bulk_body = NULL;


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
        goto error;
    }

    bulk_head = influxdb_bulk_create();
    if (!bulk_head) {
        goto error;
    }

    bulk_body = influxdb_bulk_create();
    if (!bulk_body) {
        goto error;
    }

    off = 0;
    msgpack_unpacked_destroy(&result);
    msgpack_unpacked_init(&result);
    while (msgpack_unpack_next(&result, data, bytes, &off) == MSGPACK_UNPACK_SUCCESS) {
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

        ret = influxdb_bulk_append_header(bulk_head,
                                          tag, tag_len,
                                          seq,
                                          ctx->seq_name, ctx->seq_len);
        if (ret == -1) {
            goto error;
        }

        for (i = 0; i < n_size - 1; i++) {
            msgpack_object *k = &map.via.map.ptr[i].key;
            msgpack_object *v = &map.via.map.ptr[i].val;

            if (k->type != MSGPACK_OBJECT_BIN && k->type != MSGPACK_OBJECT_STR) {
                continue;
            }

            int quote = FLB_FALSE;

            /* key */
            const char *key = NULL;
            int key_len;

            /* val */
            const char *val = NULL;
            int val_len;

            if (k->type == MSGPACK_OBJECT_STR) {
                key = k->via.str.ptr;
                key_len = k->via.str.size;
            }
            else {
                key = k->via.bin.ptr;
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
            else if (v->type == MSGPACK_OBJECT_FLOAT || v->type == MSGPACK_OBJECT_FLOAT32) {
                val = tmp;
                val_len = snprintf(tmp, sizeof(tmp) - 1, "%f", v->via.f64);
            }
            else if (v->type == MSGPACK_OBJECT_STR) {
                /* String value */
                quote   = FLB_TRUE;
                val     = v->via.str.ptr;
                val_len = v->via.str.size;
            }
            else if (v->type == MSGPACK_OBJECT_BIN) {
                /* Bin value */
                quote   = FLB_TRUE;
                val     = v->via.bin.ptr;
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
                    goto error;
                }

                val = str;
                val_len = str_size;
            }

            if (is_tagged_key(ctx, key, key_len, v->type)) {
                /* Append key/value data into the bulk_head */
                ret = influxdb_bulk_append_kv(bulk_head,
                                              key, key_len,
                                              val, val_len,
                                              false);
            }
            else {
                /* Append key/value data into the bulk_body */
                ret = influxdb_bulk_append_kv(bulk_body,
                                              key, key_len,
                                              val, val_len,
                                              quote);
            }

            if (quote == FLB_TRUE) {
                flb_free(str);
                str_size = 0;
            }

            if (ret == -1) {
                flb_plg_error(ctx->ins, "cannot append key/value");
                goto error;
            }
        }

        /* Check have data fields */
        if (bulk_body->len > 0) {
            /* Modify timestamp in avoidance of duplication */
            influxdb_tsmod(&tm, &ctx->ts_dupe, &ctx->ts_last);
            /* Append the timestamp */
            ret = influxdb_bulk_append_timestamp(bulk_body, &tm);
            if (ret == -1) {
                flb_plg_error(ctx->ins, "cannot append timestamp");
                goto error;
            }

            /* Append collected data to final bulk */
            if (influxdb_bulk_append_bulk(bulk, bulk_head, '\n') != 0 ||
                influxdb_bulk_append_bulk(bulk, bulk_body, ' ') != 0) {
                goto error;
            }
        } 
        else {
            flb_plg_warn(ctx->ins, "skip send record, "
                         "since no record available "
                         "or all fields are tagged in record");
            /* Following records maybe ok, so continue processing */
        }

        /* Reset bulk_head and bulk_body */
        bulk_head->len = 0;
        bulk_body->len = 0;
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
    influxdb_bulk_destroy(bulk_head);
    influxdb_bulk_destroy(bulk_body);

    return buf;

error:
    if (bulk != NULL) {
        influxdb_bulk_destroy(bulk);
    }
    if (bulk_head != NULL) {
        influxdb_bulk_destroy(bulk_head);
    }
    if (bulk_body != NULL) {
        influxdb_bulk_destroy(bulk_body);
    }
    msgpack_unpacked_destroy(&result);
    return NULL;
}

static int cb_influxdb_init(struct flb_output_instance *ins, struct flb_config *config,
                            void *data)
{
    int io_flags = 0;
    const char *tmp;
    struct flb_upstream *upstream;
    struct flb_influxdb *ctx;

    /* Set default network configuration */
    flb_output_net_default(FLB_INFLUXDB_HOST, FLB_INFLUXDB_PORT, ins);

    /* Allocate plugin context */
    ctx = flb_calloc(1, sizeof(struct flb_influxdb));
    if (!ctx) {
        flb_errno();
        return -1;
    }
    ctx->ins = ins;

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
    else if (strcmp(tmp, "off") == 0) {
        ctx->seq_name = flb_strdup("");
    }
    else {
        ctx->seq_name = flb_strdup(tmp);
    }
    ctx->seq_len = strlen(ctx->seq_name);

    snprintf(ctx->uri, sizeof(ctx->uri) - 1, "/write?db=%s&precision=n", ctx->db_name);

    if (ins->host.ipv6 == FLB_TRUE) {
        io_flags |= FLB_IO_IPV6;
    }

    /* HTTP Auth */
    tmp = flb_output_get_property("http_user", ins);
    if (tmp) {
        ctx->http_user = flb_strdup(tmp);

        tmp = flb_output_get_property("http_passwd", ins);
        if (tmp) {
            ctx->http_passwd = flb_strdup(tmp);
        }
        else {
            ctx->http_passwd = flb_strdup("");
        }
    }

    /* Auto_Tags */
    tmp = flb_output_get_property("auto_tags", ins);
    if (tmp) {
        ctx->auto_tags = bool_value(tmp);
    }
    else {
        ctx->auto_tags = FLB_FALSE;
    }

    /* Tag_Keys */
    tmp = flb_output_get_property("tag_keys", ins);
    if (tmp) {
        ctx->tag_keys = flb_utils_split(tmp, ' ', 256);
    }
    else {
        ctx->tag_keys = NULL;
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

    flb_time_zero(&ctx->ts_dupe);
    flb_time_zero(&ctx->ts_last);

    flb_plg_debug(ctx->ins, "host=%s port=%i", ins->host.name, ins->host.port);
    flb_output_set_context(ins, ctx);

    return 0;
}

static void cb_influxdb_flush(const void *data, size_t bytes,
                              const char *tag, int tag_len,
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
    struct flb_influxdb *ctx = out_context;

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

    if (ctx->http_user && ctx->http_passwd) {
        flb_http_basic_auth(c, ctx->http_user, ctx->http_passwd);
    }

    ret = flb_http_do(c, &b_sent);
    if (ret == 0) {
        if (c->resp.status != 200 && c->resp.status != 204) {
            if (c->resp.payload_size > 0) {
                flb_plg_error(ctx->ins, "http_status=%i\n%s",
                              c->resp.status, c->resp.payload);
            }
            else {
                flb_plg_debug(ctx->ins, "http_status=%i",
                              c->resp.status);
            }
        }
        flb_plg_debug(ctx->ins, "http_do=%i OK", ret);
    }
    else {
        flb_plg_warn(ctx->ins, "http_do=%i", ret);
    }

    flb_http_client_destroy(c);

    flb_free(pack);

    /* Release the connection */
    flb_upstream_conn_release(u_conn);

    FLB_OUTPUT_RETURN(FLB_OK);
}

static int cb_influxdb_exit(void *data, struct flb_config *config)
{
    struct flb_influxdb *ctx = data;

    if (ctx->http_user) {
        flb_free(ctx->http_user);
    }
    if (ctx->http_passwd) {
        flb_free(ctx->http_passwd);
    }
    if (ctx->tag_keys) {
        flb_utils_split_free(ctx->tag_keys);
    }

    flb_upstream_destroy(ctx->u);
    flb_free(ctx->db_name);
    flb_free(ctx->seq_name);
    flb_free(ctx);

    return 0;
}

int bool_value(const char *v)
{
    if (strcasecmp(v, "true") == 0) {
        return FLB_TRUE;
    }
    else if (strcasecmp(v, "on") == 0) {
        return FLB_TRUE;
    }
    else if (strcasecmp(v, "yes") == 0) {
        return FLB_TRUE;
    }

    return FLB_FALSE;
}

int is_tagged_key(struct flb_influxdb *ctx, const char *key, int kl, int type)
{
    if (type == MSGPACK_OBJECT_STR) {
        if (ctx->auto_tags) {
            return FLB_TRUE;
        }
    }

    struct mk_list *head;
    struct flb_split_entry *entry;

    if (ctx->tag_keys) {
        mk_list_foreach(head, ctx->tag_keys) {
            entry = mk_list_entry(head, struct flb_split_entry, _head);
            if (kl == entry->len && strncmp(key, entry->value, kl) == 0) {
                return FLB_TRUE;
            }
        }
    }

    return FLB_FALSE;
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
