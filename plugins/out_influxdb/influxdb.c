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

#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_http_client.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_metrics.h>
#include <fluent-bit/flb_log_event_decoder.h>

#include <msgpack.h>

#include "influxdb.h"
#include "influxdb_bulk.h"

#include <stdio.h>

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
static int influxdb_format(struct flb_config *config,
                           struct flb_input_instance *ins,
                           void *plugin_context,
                           void *flush_ctx,
                           int event_type,
                           const char *tag, int tag_len,
                           const void *data, size_t bytes,
                           void **out_data, size_t *out_size)
{
    int i;
    int ret;
    int n_size;
    uint64_t seq = 0;
    char *str = NULL;
    size_t str_size;
    char tmp[128];
    int prefix_match = 0;
    int prefix_offset = 0;
    msgpack_object map;
    struct flb_time tm;
    struct influxdb_bulk *bulk = NULL;
    struct influxdb_bulk *bulk_head = NULL;
    struct influxdb_bulk *bulk_body = NULL;
    struct flb_log_event_decoder log_decoder;
    struct flb_log_event log_event;
    struct flb_influxdb *ctx = plugin_context;

    ret = flb_log_event_decoder_init(&log_decoder, (char *) data, bytes);

    if (ret != FLB_EVENT_DECODER_SUCCESS) {
        flb_plg_error(ctx->ins,
                      "Log event decoder initialization error : %d", ret);

        return -1;
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

    while ((ret = flb_log_event_decoder_next(
                    &log_decoder,
                    &log_event)) == FLB_EVENT_DECODER_SUCCESS) {
        flb_time_copy(&tm, &log_event.timestamp);

        map    = *log_event.body;
        n_size = map.via.map.size + 1;

        seq = ctx->seq;
        if (ctx->seq + 1 >= 100000) {
            seq = 1;
        }
        else {
            ctx->seq++;
        }

        /* Find the overlap betwen the tag and a given prefix (to be removed):
        If the prefix matches the tag for exactly the length of the prefix and
        the tag is longer than the prefix, we have a valid match. */
        prefix_offset = 0;
        prefix_match = strncmp(tag, ctx->prefix, ctx->prefix_len);
        if (prefix_match == 0) {
            if (tag_len > ctx->prefix_len) {
                prefix_offset = ctx->prefix_len;
            }
        }

        /* Read the tag offset by the length of the prefix to remove it. */
        ret = influxdb_bulk_append_header(bulk_head,
                                          tag + prefix_offset,
                                          tag_len - prefix_offset,
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
                if (ctx->use_influxdb_integer) {
                    val_len = snprintf(tmp, sizeof(tmp) - 1, "%" PRIu64 "i", v->via.u64);
                }
                else {
                    val_len = snprintf(tmp, sizeof(tmp) - 1, "%" PRIu64, v->via.u64);
                }
            }
            else if (v->type == MSGPACK_OBJECT_NEGATIVE_INTEGER) {
                val = tmp;
                if (ctx->use_influxdb_integer) {
                    val_len = snprintf(tmp, sizeof(tmp) - 1, "%" PRId64 "i", v->via.i64);
                }
                else {
                    val_len = snprintf(tmp, sizeof(tmp) - 1, "%" PRId64, v->via.i64);
                }
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
                                              &str, &str_size,
                                              config->json_escape_unicode);
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

    flb_log_event_decoder_destroy(&log_decoder);

    *out_data = bulk->ptr;
    *out_size = bulk->len;

    /*
     * Note: we don't destroy the bulk as we need to keep the allocated
     * buffer with the data. Instead we just release the bulk context and
     * return the bulk->ptr buffer
     */
    flb_free(bulk);
    influxdb_bulk_destroy(bulk_head);
    influxdb_bulk_destroy(bulk_body);

    return 0;

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

    flb_log_event_decoder_destroy(&log_decoder);

    return -1;
}

static int cb_influxdb_init(struct flb_output_instance *ins, struct flb_config *config,
                            void *data)
{
    int ret;
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

    /* Register context with plugin instance */
    flb_output_set_context(ins, ctx);

    /*
     * This plugin instance uses the HTTP client interface, let's register
     * it debugging callbacks.
     */
    flb_output_set_http_debug_callbacks(ins);

    /* Load config map */
    ret = flb_output_config_map_set(ins, (void *) ctx);
    if (ret == -1) {
        return -1;
    }

    if (ins->use_tls == FLB_TRUE) {
        io_flags = FLB_IO_TLS;
    }
    else {
        io_flags = FLB_IO_TCP;
    }

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

    /* prefix to be removed from the tag */
    tmp = flb_output_get_property("strip_prefix", ins);
    if (!tmp) {
        ctx->prefix = flb_strdup("");
    } else {
        ctx->prefix = flb_strdup(tmp);
    }
    ctx->prefix_len = strlen(ctx->prefix);

    if (ctx->custom_uri) {
        /* custom URI endpoint (e.g: Grafana */
        if (ctx->custom_uri[0] != '/') {
            flb_plg_error(ctx->ins,
                          "'custom_uri' value must start wih a forward slash '/'");
            return -1;
        }
        snprintf(ctx->uri, sizeof(ctx->uri) - 1, "%s", ctx->custom_uri);
    }
    else if (ctx->bucket) {
        /* bucket: api v2 */
        snprintf(ctx->uri, sizeof(ctx->uri) - 1,
                 "/api/v2/write?org=%s&bucket=%s&precision=ns",
                 ctx->organization, ctx->bucket);
    }
    else {
        snprintf(ctx->uri, sizeof(ctx->uri) - 1,
                 "/write?db=%s&precision=n",
                 ctx->database);
    }

    if (ins->host.ipv6 == FLB_TRUE) {
        io_flags |= FLB_IO_IPV6;
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
                                   ins->tls);
    if (!upstream) {
        flb_free(ctx);
        return -1;
    }
    ctx->u   = upstream;
    ctx->seq = 0;
    flb_output_upstream_set(ctx->u, ins);

    flb_time_zero(&ctx->ts_dupe);
    flb_time_zero(&ctx->ts_last);

    flb_plg_debug(ctx->ins, "host=%s port=%i", ins->host.name, ins->host.port);

    return 0;
}

static int format_metrics(struct flb_output_instance *ins,
                          const void *data, size_t bytes,
                          char **out_buf, size_t *out_size)
{
    int ret;
    size_t off = 0;
    cfl_sds_t text;
    struct cmt *cmt = NULL;

    /* get cmetrics context */
    ret = cmt_decode_msgpack_create(&cmt, (char *) data, bytes, &off);
    if (ret != 0) {
        flb_plg_error(ins, "could not process metrics payload");
        return -1;
    }

    /* convert to text representation */
    text = cmt_encode_influx_create(cmt);
    if (!text) {
        cmt_destroy(cmt);
        return -1;
    }

    /* destroy cmt context */
    cmt_destroy(cmt);

    *out_buf = text;
    *out_size = flb_sds_len(text);

    return 0;
}

static void cb_influxdb_flush(struct flb_event_chunk *event_chunk,
                              struct flb_output_flush *out_flush,
                              struct flb_input_instance *i_ins,
                              void *out_context,
                              struct flb_config *config)
{
    int ret;
    int out_ret = FLB_OK;
    int is_metric = FLB_FALSE;
    size_t b_sent;
    size_t bytes_out;
    void *out_buf;
    char *pack;
    char tmp[128];
    struct mk_list *head;
    struct flb_connection *u_conn;
    struct flb_http_client *c;
    struct flb_config_map_val *mv;
    struct flb_slist_entry *key = NULL;
    struct flb_slist_entry *val = NULL;
    struct flb_influxdb *ctx = out_context;

    /* Convert format: metrics / logs */
    if (event_chunk->type == FLB_EVENT_TYPE_METRICS) {
        /* format metrics */
        ret = format_metrics(ctx->ins,
                             (char *) event_chunk->data,
                             event_chunk->size,
                             &pack, &bytes_out);
        if (ret == -1) {
            FLB_OUTPUT_RETURN(FLB_ERROR);
        }
        is_metric = FLB_TRUE;
    }
    else {
        /* format logs */
        ret = influxdb_format(config, i_ins,
                              ctx, NULL,
                              event_chunk->type,
                              event_chunk->tag, flb_sds_len(event_chunk->tag),
                              event_chunk->data, event_chunk->size,
                              &out_buf, &bytes_out);
        if (ret != 0) {
            FLB_OUTPUT_RETURN(FLB_ERROR);
        }

        pack = (char *) out_buf;
    }

    /* Get upstream connection */
    u_conn = flb_upstream_conn_get(ctx->u);
    if (!u_conn) {
        if (is_metric) {
            cmt_encode_influx_destroy(pack);
        }
        else {
            flb_free(pack);
        }
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }

    /* Compose HTTP Client request */
    c = flb_http_client(u_conn, FLB_HTTP_POST, ctx->uri,
                        pack, bytes_out, NULL, 0, NULL, 0);
    flb_http_add_header(c, "User-Agent", 10, "Fluent-Bit", 10);

    if (ctx->http_token) {
        ret = snprintf(tmp, sizeof(tmp) - 1, "Token %s", ctx->http_token);
        flb_http_add_header(c, FLB_HTTP_HEADER_AUTH, sizeof FLB_HTTP_HEADER_AUTH - 1, tmp, ret);
    }
    else if (ctx->http_user && ctx->http_passwd) {
        flb_http_basic_auth(c, ctx->http_user, ctx->http_passwd);
    }

    /* Append custom headers if any */
    flb_config_map_foreach(head, mv, ctx->headers) {
        key = mk_list_entry_first(mv->val.list, struct flb_slist_entry, _head);
        val = mk_list_entry_last(mv->val.list, struct flb_slist_entry, _head);

        flb_http_add_header(c,
                            key->str, flb_sds_len(key->str),
                            val->str, flb_sds_len(val->str));
    }

    /* Map debug callbacks */
    flb_http_client_debug(c, ctx->ins->callback);

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
        flb_plg_error(ctx->ins, "http_do=%i", ret);
        out_ret = FLB_RETRY;
    }

    flb_http_client_destroy(c);

    if (is_metric) {
        cmt_encode_influx_destroy(pack);
    }
    else {
        flb_free(pack);
    }

    /* Release the connection */
    flb_upstream_conn_release(u_conn);

    FLB_OUTPUT_RETURN(out_ret);
}

static int cb_influxdb_exit(void *data, struct flb_config *config)
{
    struct flb_influxdb *ctx = data;

    if (!ctx) {
        return 0;
    }

    if (ctx->tag_keys) {
        flb_utils_split_free(ctx->tag_keys);
    }

    if (ctx->seq_name) {
        flb_free(ctx->seq_name);
    }

    if (ctx->prefix) {
        flb_free(ctx->prefix);
    }

    flb_upstream_destroy(ctx->u);
    flb_free(ctx);

    return 0;
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

/* Configuration properties map */
static struct flb_config_map config_map[] = {
    {
     FLB_CONFIG_MAP_STR, "database", "fluentbit",
     0, FLB_TRUE, offsetof(struct flb_influxdb, database),
     "Set the database name."
    },
    {
     FLB_CONFIG_MAP_STR, "bucket", NULL,
     0, FLB_TRUE, offsetof(struct flb_influxdb, bucket),
     "Specify the bucket name, used on InfluxDB API v2."
    },

    {
     FLB_CONFIG_MAP_STR, "org", "fluent",
     0, FLB_TRUE, offsetof(struct flb_influxdb, organization),
     "Set the Organization name."
    },

    {
     FLB_CONFIG_MAP_STR, "sequence_tag", NULL,
     0, FLB_FALSE, 0,
     "Specify the sequence tag."
    },

    {
     FLB_CONFIG_MAP_STR, "uri", NULL,
     0, FLB_TRUE, offsetof(struct flb_influxdb, custom_uri),
     "Specify a custom URI endpoint (must start with '/')."
    },

    {
     FLB_CONFIG_MAP_STR, "http_user", NULL,
     0, FLB_TRUE, offsetof(struct flb_influxdb, http_user),
     "HTTP Basic Auth username."
    },

    {
     FLB_CONFIG_MAP_STR, "http_passwd", "",
     0, FLB_TRUE, offsetof(struct flb_influxdb, http_passwd),
     "HTTP Basic Auth password."
    },

    {
     FLB_CONFIG_MAP_STR, "http_token", NULL,
     0, FLB_TRUE, offsetof(struct flb_influxdb, http_token),
     "Set InfluxDB HTTP Token API v2."
    },

    {
     FLB_CONFIG_MAP_SLIST_1, "http_header", NULL,
     FLB_CONFIG_MAP_MULT, FLB_TRUE, offsetof(struct flb_influxdb, headers),
     "Add a HTTP header key/value pair. Multiple headers can be set"
    },

    {
     FLB_CONFIG_MAP_BOOL, "auto_tags", "false",
     0, FLB_TRUE, offsetof(struct flb_influxdb, auto_tags),
     "Automatically tag keys where value is string."
    },

    {
     FLB_CONFIG_MAP_BOOL, "tag_keys", NULL,
     0, FLB_FALSE, 0,
     "Space separated list of keys that needs to be tagged."
    },

    {
     FLB_CONFIG_MAP_BOOL, "add_integer_suffix", "false",
     0, FLB_TRUE, offsetof(struct flb_influxdb, use_influxdb_integer),
     "Use influxdb line protocol's integer type suffix."
    },

    {
     FLB_CONFIG_MAP_STR, "strip_prefix", NULL,
     0, FLB_FALSE, 0,
     "Prefix to be removed from the record tag when writing influx measurements."
    },

    /* EOF */
    {0}
};

struct flb_output_plugin out_influxdb_plugin = {
    .name         = "influxdb",
    .description  = "InfluxDB Time Series",
    .cb_init      = cb_influxdb_init,
    .cb_pre_run     = NULL,
    .cb_flush     = cb_influxdb_flush,
    .cb_exit      = cb_influxdb_exit,
    .config_map   = config_map,
    .test_formatter.callback = influxdb_format,
    .flags        = FLB_OUTPUT_NET | FLB_IO_OPT_TLS,
    .event_type   = FLB_OUTPUT_LOGS | FLB_OUTPUT_METRICS
};
