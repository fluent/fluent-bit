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
#include <fluent-bit/flb_version.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_http_client.h>
#include <fluent-bit/flb_ra_key.h>
#include <fluent-bit/record_accessor/flb_ra_parser.h>
#include <fluent-bit/flb_mp.h>

#include <ctype.h>

#include "loki.h"

static void flb_loki_kv_init(struct mk_list *list)
{
    mk_list_init(list);
}

static inline void normalize_cat(struct flb_ra_parser *rp, flb_sds_t name)
{
    int sub;
    int len;
    char tmp[64];
    struct mk_list *s_head;
    struct flb_ra_key *key;
    struct flb_ra_subentry *entry;

    /* Iterate record accessor keys */
    key = rp->key;
    if (rp->type == FLB_RA_PARSER_STRING) {
        flb_sds_cat(name, key->name, flb_sds_len(key->name));
    }
    else if (rp->type == FLB_RA_PARSER_KEYMAP) {
        flb_sds_cat(name, key->name, flb_sds_len(key->name));

        if (mk_list_size(key->subkeys) > 0) {
            flb_sds_cat(name, "_", 1);
        }

        sub = 0;
        mk_list_foreach(s_head, key->subkeys) {
            entry = mk_list_entry(s_head, struct flb_ra_subentry, _head);

            if (sub > 0) {
                flb_sds_cat(name, "_", 1);
            }
            if (entry->type == FLB_RA_PARSER_STRING) {
                flb_sds_cat(name, entry->str, flb_sds_len(entry->str));
            }
            else if (entry->type == FLB_RA_PARSER_ARRAY_ID) {
                len = snprintf(tmp, sizeof(tmp) -1, "%d",
                               entry->array_id);
                flb_sds_cat(name, tmp, len);
            }
            sub++;
        }
    }
}

static flb_sds_t normalize_ra_key_name(struct flb_loki *ctx,
                                       struct flb_record_accessor *ra)
{
    int c = 0;
    flb_sds_t name;
    struct mk_list *head;
    struct flb_ra_parser *rp;

    name = flb_sds_create_size(128);
    if (!name) {
        return NULL;
    }

    mk_list_foreach(head, &ra->list) {
        rp = mk_list_entry(head, struct flb_ra_parser, _head);
        if (c > 0) {
            flb_sds_cat(name, "_", 1);
        }
        normalize_cat(rp, name);
        c++;
    }

    return name;
}

int flb_loki_kv_append(struct flb_loki *ctx, char *key, char *val)
{
    int ra_count = 0;
    int k_len;
    struct flb_loki_kv *kv;

    if (!key) {
        return -1;
    }

    if (!val && key[0] != '$') {
        return -1;
    }

    kv = flb_calloc(1, sizeof(struct flb_loki_kv));
    if (!kv) {
        flb_errno();
        return -1;
    }

    k_len = strlen(key);
    if (key[0] == '$' && k_len >= 2 && isdigit(key[1])) {
        flb_plg_error(ctx->ins,
                      "key name for record accessor cannot start with a number: %s",
                      key);
        return -1;
    }

    kv->key = flb_sds_create(key);
    if (!kv->key) {
        flb_free(kv);
        return -1;
    }

    /*
     * If the key starts with a '$', it means its a record accessor pattern and
     * the key value pair will be formed using the key name and it proper value.
     */
    if (key[0] == '$' && val == NULL) {
        kv->ra_key = flb_ra_create(key, FLB_TRUE);
        if (!kv->ra_key) {
            flb_plg_error(ctx->ins,
                          "invalid key record accessor pattern for key '%s'",
                          key);
            flb_sds_destroy(kv->key);
            flb_free(kv);
            return -1;
        }

        /* Normalize 'key name' using record accessor pattern */
        kv->key_normalized = normalize_ra_key_name(ctx, kv->ra_key);
        if (!kv->key_normalized) {
            flb_plg_error(ctx->ins,
                          "could not normalize key pattern name '%s'\n",
                          kv->ra_key->pattern);
            flb_sds_destroy(kv->key);
            flb_free(kv);
            return -1;
        }
        ra_count++;
    }
    else if (val[0] == '$') {
        /* create a record accessor context */
        kv->val_type = FLB_LOKI_KV_RA;
        kv->ra_val = flb_ra_create(val, FLB_TRUE);
        if (!kv->ra_val) {
            flb_plg_error(ctx->ins,
                          "invalid record accessor pattern for key '%s': %s",
                          key, val);
            flb_sds_destroy(kv->key);
            flb_free(kv);
            return -1;
        }
        ra_count++;
    }
    else {
        kv->val_type = FLB_LOKI_KV_STR;
        kv->str_val = flb_sds_create(val);
        if (!kv->str_val) {
            flb_sds_destroy(kv->key);
            flb_free(kv);
            return -1;
        }
    }
    mk_list_add(&kv->_head, &ctx->labels_list);

    /* return the number of record accessor values */
    return ra_count;
}

static void flb_loki_kv_exit(struct flb_loki *ctx)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_loki_kv *kv;

    mk_list_foreach_safe(head, tmp, &ctx->labels_list) {
        kv = mk_list_entry(head, struct flb_loki_kv, _head);

        /* unlink */
        mk_list_del(&kv->_head);

        /* destroy key and value */
        flb_sds_destroy(kv->key);
        if (kv->val_type == FLB_LOKI_KV_STR) {
            flb_sds_destroy(kv->str_val);
        }
        else if (kv->val_type == FLB_LOKI_KV_RA) {
            flb_ra_destroy(kv->ra_val);
        }

        if (kv->ra_key) {
            flb_ra_destroy(kv->ra_key);
        }

        if (kv->key_normalized) {
            flb_sds_destroy(kv->key_normalized);
        }

        flb_free(kv);
    }
}

static flb_sds_t pack_labels(struct flb_loki *ctx, msgpack_packer *mp_pck,
                             char *tag, int tag_len,
                             msgpack_object *map)
{
    int i;
    flb_sds_t ra_val;
    struct mk_list *head;
    struct flb_ra_value *rval = NULL;
    struct flb_loki_kv *kv;
    msgpack_object k;
    msgpack_object v;
    struct flb_mp_map_header mh;


    /* Initialize dynamic map header */
    flb_mp_map_header_init(&mh, mp_pck);

    mk_list_foreach(head, &ctx->labels_list) {
        kv = mk_list_entry(head, struct flb_loki_kv, _head);

        /* record accessor key/value pair */
        if (kv->ra_key != NULL && kv->ra_val == NULL) {
            ra_val = flb_ra_translate(kv->ra_key, tag, tag_len, *(map), NULL);
            if (!ra_val || flb_sds_len(ra_val) == 0) {
                /* if no value is retruned or if it's empty, just skip it */
                flb_plg_warn(ctx->ins,
                             "empty record accessor key translation for pattern: %s",
                             kv->ra_key->pattern);
            }
            else {
                /* Pack the key and value */
                flb_mp_map_header_append(&mh);

                /* We skip the first '$' character since it won't be valid in Loki */
                msgpack_pack_str(mp_pck, flb_sds_len(kv->key_normalized));
                msgpack_pack_str_body(mp_pck,
                                      kv->key_normalized,
                                      flb_sds_len(kv->key_normalized));

                msgpack_pack_str(mp_pck, flb_sds_len(ra_val));
                msgpack_pack_str_body(mp_pck, ra_val, flb_sds_len(ra_val));
            }

            if (ra_val) {
                flb_sds_destroy(ra_val);
            }
            continue;
        }

        /*
         * The code is a bit duplicated to be able to manage the exception of an
         * invalid or empty value, on that case the k/v is skipped.
         */
        if (kv->val_type == FLB_LOKI_KV_STR) {
            flb_mp_map_header_append(&mh);
            msgpack_pack_str(mp_pck, flb_sds_len(kv->key));
            msgpack_pack_str_body(mp_pck, kv->key, flb_sds_len(kv->key));
            msgpack_pack_str(mp_pck, flb_sds_len(kv->str_val));
            msgpack_pack_str_body(mp_pck, kv->str_val, flb_sds_len(kv->str_val));
        }
        else if (kv->val_type == FLB_LOKI_KV_RA) {
            /* record accessor type */
            ra_val = flb_ra_translate(kv->ra_val, tag, tag_len, *(map), NULL);
            if (!ra_val || flb_sds_len(ra_val) == 0) {
                flb_plg_warn(ctx->ins, "could not translate record accessor");
            }
            else {
                flb_mp_map_header_append(&mh);
                msgpack_pack_str(mp_pck, flb_sds_len(kv->key));
                msgpack_pack_str_body(mp_pck, kv->key, flb_sds_len(kv->key));
                msgpack_pack_str(mp_pck, flb_sds_len(ra_val));
                msgpack_pack_str_body(mp_pck, ra_val, flb_sds_len(ra_val));
            }

            if (ra_val) {
                flb_sds_destroy(ra_val);
            }
        }
    }

    if (ctx->auto_kubernetes_labels == FLB_TRUE) {
        rval = flb_ra_get_value_object(ctx->ra_k8s, *map);
        if (rval && rval->o.type == MSGPACK_OBJECT_MAP) {
            for (i = 0; i < rval->o.via.map.size; i++) {
                k = rval->o.via.map.ptr[i].key;
                v = rval->o.via.map.ptr[i].val;

                if (k.type != MSGPACK_OBJECT_STR || v.type != MSGPACK_OBJECT_STR) {
                    continue;
                }

                /* append the key/value pair */
                flb_mp_map_header_append(&mh);
                msgpack_pack_str(mp_pck, k.via.str.size);
                msgpack_pack_str_body(mp_pck, k.via.str.ptr,  k.via.str.size);
                msgpack_pack_str(mp_pck, v.via.str.size);
                msgpack_pack_str_body(mp_pck, v.via.str.ptr,  v.via.str.size);
            }
            flb_ra_key_value_destroy(rval);
        }
    }

    /* Check if we added any label, if no one has been set, set the defaul 'job' */
    if (mh.entries == 0) {
        /* pack the default entry */
        flb_mp_map_header_append(&mh);
        msgpack_pack_str(mp_pck, 3);
        msgpack_pack_str_body(mp_pck, "job", 3);
        msgpack_pack_str(mp_pck, 10);
        msgpack_pack_str_body(mp_pck, "fluent-bit", 10);
    }
    flb_mp_map_header_end(&mh);
    return 0;
}

static int parse_labels(struct flb_loki *ctx)
{
    int ret;
    int ra_used = 0;
    char *p;
    flb_sds_t key;
    flb_sds_t val;
    struct mk_list *head;
    struct flb_slist_entry *entry;

    flb_loki_kv_init(&ctx->labels_list);

    if (ctx->labels) {
        mk_list_foreach(head, ctx->labels) {
            entry = mk_list_entry(head, struct flb_slist_entry, _head);

            /* record accessor label key ? */
            if (entry->str[0] == '$') {
                ret = flb_loki_kv_append(ctx, entry->str, NULL);
                if (ret == -1) {
                    return -1;
                }
                else if (ret > 0) {
                    ra_used++;
                }
                continue;
            }

            p = strchr(entry->str, '=');
            if (!p) {
                flb_plg_error(ctx->ins, "invalid key value pair on '%s'",
                              entry->str);
                return -1;
            }

            key = flb_sds_create_size((p - entry->str) + 1);
            flb_sds_cat(key, entry->str, p - entry->str);
            val = flb_sds_create(p + 1);
            if (!key) {
                flb_plg_error(ctx->ins,
                              "invalid key value pair on '%s'",
                              entry->str);
                return -1;
            }
            if (!val || flb_sds_len(val) == 0) {
                flb_plg_error(ctx->ins,
                              "invalid key value pair on '%s'",
                              entry->str);
                flb_sds_destroy(key);
                return -1;
            }

            ret = flb_loki_kv_append(ctx, key, val);
            flb_sds_destroy(key);
            flb_sds_destroy(val);

            if (ret == -1) {
                return -1;
            }
            else if (ret > 0) {
                ra_used++;
            }
        }
    }

    /* Append label keys set in the configuration */
    if (ctx->label_keys) {
        mk_list_foreach(head, ctx->label_keys) {
            entry = mk_list_entry(head, struct flb_slist_entry, _head);
            if (entry->str[0] != '$') {
                flb_plg_error(ctx->ins,
                              "invalid label key, the name must start with '$'");
                return -1;
            }

            ret = flb_loki_kv_append(ctx, entry->str, NULL);
            if (ret == -1) {
                return -1;
            }
            else if (ret > 0) {
                ra_used++;
            }
        }
    }

    if (ctx->auto_kubernetes_labels == FLB_TRUE) {
        ctx->ra_k8s = flb_ra_create("$kubernetes['labels']", FLB_TRUE);
        if (!ctx->ra_k8s) {
            flb_plg_error(ctx->ins,
                          "could not create record accessor for Kubernetes labels");
            return -1;
        }
    }

    /*
     * If the variable 'ra_used' is greater than zero, means that record accessor is
     * being used to compose the stream labels.
     */
    ctx->ra_used = ra_used;
    return 0;
}

static void loki_config_destroy(struct flb_loki *ctx)
{
    if (ctx->u) {
        flb_upstream_destroy(ctx->u);
    }

    if (ctx->ra_k8s) {
        flb_ra_destroy(ctx->ra_k8s);
    }
    flb_loki_kv_exit(ctx);
    flb_free(ctx);
}

static struct flb_loki *loki_config_create(struct flb_output_instance *ins,
                                           struct flb_config *config)
{
    int ret;
    int io_flags = 0;
    struct flb_loki *ctx;
    struct flb_upstream *upstream;

    /* Create context */
    ctx = flb_calloc(1, sizeof(struct flb_loki));
    if (!ctx) {
        flb_errno();
        return NULL;
    }
    ctx->ins = ins;
    flb_loki_kv_init(&ctx->labels_list);

    /* Register context with plugin instance */
    flb_output_set_context(ins, ctx);

    /* Set networking defaults */
    flb_output_net_default(FLB_LOKI_HOST, FLB_LOKI_PORT, ins);

    /* Load config map */
    ret = flb_output_config_map_set(ins, (void *) ctx);
    if (ret == -1) {
        return NULL;
    }

    /* Parse labels */
    ret = parse_labels(ctx);
    if (ret == -1) {
        return NULL;
    }

    /* use TLS ? */
    if (ins->use_tls == FLB_TRUE) {
        io_flags = FLB_IO_TLS;
    }
    else {
        io_flags = FLB_IO_TCP;
    }

    if (ins->host.ipv6 == FLB_TRUE) {
        io_flags |= FLB_IO_IPV6;
    }

    /* Create Upstream connection context */
    upstream = flb_upstream_create(config,
                                   ins->host.name,
                                   ins->host.port,
                                   io_flags,
                                   &ins->tls);
    if (!upstream) {
        return NULL;
    }
    ctx->u = upstream;
    ctx->tcp_port = ins->host.port;
    ctx->tcp_host = ins->host.name;

    return ctx;
}

/*
 * Convert struct flb_tm timestamp value to nanoseconds and then it pack it as
 * a string.
 */
static void pack_timestamp(msgpack_packer *mp_pck, struct flb_time *tms)
{
    int len;
    char buf[64];
    uint64_t nanosecs;

    /* convert to nanoseconds */
    nanosecs = ((tms->tm.tv_sec * 1000000000L) + tms->tm.tv_nsec);

    /* format as a string */
    len = snprintf(buf, sizeof(buf) - 1, "%" PRIu64, nanosecs);

    /* pack the value */
    msgpack_pack_str(mp_pck, len);
    msgpack_pack_str_body(mp_pck, buf, len);
}

static int pack_record(msgpack_packer *mp_pck, msgpack_object *rec)
{
    int len;
    char *line;

    line = flb_msgpack_to_json_str(1024, rec);
    if (!line) {
        return -1;
    }
    len = strlen(line);
    msgpack_pack_str(mp_pck, len);
    msgpack_pack_str_body(mp_pck, line, len);
    flb_free(line);
    return 0;
}

/* Initialization callback */
static int cb_loki_init(struct flb_output_instance *ins,
                        struct flb_config *config, void *data)
{
    struct flb_loki *ctx;

    /* Create plugin context */
    ctx = loki_config_create(ins, config);
    if (!ctx) {
        flb_plg_error(ins, "cannot initialize configuration");
        return -1;
    }

    /*
     * This plugin instance uses the HTTP client interface, let's register
     * it debugging callbacks.
     */
    flb_output_set_http_debug_callbacks(ins);

    flb_plg_info(ins,
                 "configured, hostname=%s:%i",
                 ctx->tcp_host, ctx->tcp_port);
    return 0;
}

static flb_sds_t loki_compose_payload(struct flb_loki *ctx,
                                      char *tag, int tag_len,
                                      const void *data, size_t bytes)
{
    int mp_ok = MSGPACK_UNPACK_SUCCESS;
    int total_records;
    size_t off = 0;
    flb_sds_t json;
    struct flb_time tms;
    msgpack_unpacked result;
    msgpack_packer mp_pck;
    msgpack_sbuffer mp_sbuf;
    msgpack_object *obj;

    /*
     * Fluent Bit uses Loki API v1 to push records in JSON format, this
     * is the expected structure:
     *
     * {
     *   "streams": [
     *     {
     *       "stream": {
     *         "label": "value"
     *       },
     *       "values": [
     *         [ "<unix epoch in nanoseconds>", "<log line>" ],
     *         [ "<unix epoch in nanoseconds>", "<log line>" ]
     *       ]
     *     }
     *   ]
     * }
     */

    /* Count number of records */
    total_records = flb_mp_count(data, bytes);

    /* Initialize msgpack buffers */
    msgpack_unpacked_init(&result);
    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    /* Main map */
    msgpack_pack_map(&mp_pck, 1);

    /* streams */
    msgpack_pack_str(&mp_pck, 7);
    msgpack_pack_str_body(&mp_pck, "streams", 7);

    if (ctx->ra_used == 0 && ctx->auto_kubernetes_labels == FLB_FALSE) {
        /*
         * If labels are cached, there is no record accessor or custom
         * keys, so it's safe to put one main stream and attach all the
         * values.
         */
         msgpack_pack_array(&mp_pck, 1);

         /* map content: streams['stream'] & streams['values'] */
         msgpack_pack_map(&mp_pck, 2);

         /* streams['stream'] */
         msgpack_pack_str(&mp_pck, 6);
         msgpack_pack_str_body(&mp_pck, "stream", 6);

         /* Pack stream labels */
         pack_labels(ctx, &mp_pck, tag, tag_len, obj);

        /* streams['values'] */
         msgpack_pack_str(&mp_pck, 6);
         msgpack_pack_str_body(&mp_pck, "values", 6);
         msgpack_pack_array(&mp_pck, total_records);

         /* Iterate each record and pack it */
         while (msgpack_unpack_next(&result, data, bytes, &off) == mp_ok) {
             /* Retrive timestamp of the record */
             flb_time_pop_from_msgpack(&tms, &result, &obj);

             msgpack_pack_array(&mp_pck, 2);

             /* Append the timestamp */
             pack_timestamp(&mp_pck, &tms);
             pack_record(&mp_pck, obj);
         }
    }
    else {
        /*
         * Here there are no cached labels and the labels are composed by
         * each record content. To simplify the operation just create
         * one stream per record.
         */
        msgpack_pack_array(&mp_pck, total_records);

         /* Iterate each record and pack it */
         while (msgpack_unpack_next(&result, data, bytes, &off) == mp_ok) {
             /* Retrive timestamp of the record */
             flb_time_pop_from_msgpack(&tms, &result, &obj);

             /* map content: streams['stream'] & streams['values'] */
             msgpack_pack_map(&mp_pck, 2);

             /* streams['stream'] */
             msgpack_pack_str(&mp_pck, 6);
             msgpack_pack_str_body(&mp_pck, "stream", 6);

             /* Pack stream labels */
             pack_labels(ctx, &mp_pck, tag, tag_len, obj);

             /* streams['values'] */
             msgpack_pack_str(&mp_pck, 6);
             msgpack_pack_str_body(&mp_pck, "values", 6);
             msgpack_pack_array(&mp_pck, 1);

             msgpack_pack_array(&mp_pck, 2);

             /* Append the timestamp */
             pack_timestamp(&mp_pck, &tms);
             pack_record(&mp_pck, obj);
         }
    }

    json = flb_msgpack_raw_to_json_sds(mp_sbuf.data, mp_sbuf.size);

    msgpack_sbuffer_destroy(&mp_sbuf);
    msgpack_unpacked_destroy(&result);

    return json;
}

static void cb_loki_flush(const void *data, size_t bytes,
                          const char *tag, int tag_len,
                          struct flb_input_instance *i_ins,
                          void *out_context,
                          struct flb_config *config)
{
    int ret;
    int out_ret = FLB_OK;
    size_t b_sent;
    flb_sds_t payload = NULL;
    struct flb_loki *ctx = out_context;
    struct flb_upstream_conn *u_conn;
    struct flb_http_client *c;

    /* Format the data to the expected Newrelic Payload */
    payload = loki_compose_payload(ctx, (char *) tag, tag_len, data, bytes);
    if (!payload) {
        flb_plg_error(ctx->ins, "cannot compose request payload");
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }

    /* Lookup an available connection context */
    u_conn = flb_upstream_conn_get(ctx->u);
    if (!u_conn) {
        flb_plg_error(ctx->ins, "no upstream connections available");
        flb_sds_destroy(payload);
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }

    /* Create HTTP client context */
    c = flb_http_client(u_conn, FLB_HTTP_POST, FLB_LOKI_URI,
                        payload, flb_sds_len(payload),
                        ctx->tcp_host, ctx->tcp_port,
                        NULL, 0);
    if (!c) {
        flb_plg_error(ctx->ins, "cannot create HTTP client context");
        flb_sds_destroy(payload);
        flb_upstream_conn_release(u_conn);
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }


    /* Set callback context to the HTTP client context */
    flb_http_set_callback_context(c, ctx->ins->callback);

    /* User Agent */
    flb_http_add_header(c, "User-Agent", 10, "Fluent-Bit", 10);

    /* Add Content-Type header */
    flb_http_add_header(c,
                        FLB_LOKI_CT, sizeof(FLB_LOKI_CT) - 1,
                        FLB_LOKI_CT_JSON, sizeof(FLB_LOKI_CT_JSON) - 1);

    /* Add X-Scope-OrgID header */
    if (ctx->tenant_id) {
        flb_http_add_header(c,
                            FLB_LOKI_HEADER_SCOPE, sizeof(FLB_LOKI_HEADER_SCOPE) - 1,
                            ctx->tenant_id, flb_sds_len(ctx->tenant_id));
    }

    /* Send HTTP request */
    ret = flb_http_do(c, &b_sent);
    flb_sds_destroy(payload);

    /* Validate HTTP client return status */
    if (ret == 0) {
        /*
         * Only allow the following HTTP status:
         *
         * - 200: OK
         * - 201: Created
         * - 202: Accepted
         * - 203: no authorative resp
         * - 204: No Content
         * - 205: Reset content
         *
         */
        if (c->resp.status < 200 || c->resp.status > 205) {
            if (c->resp.payload) {
                flb_plg_error(ctx->ins, "%s:%i, HTTP status=%i\n%s",
                              ctx->tcp_host, ctx->tcp_port, c->resp.status,
                              c->resp.payload);
            }
            else {
                flb_plg_error(ctx->ins, "%s:%i, HTTP status=%i",
                              ctx->tcp_host, ctx->tcp_port, c->resp.status);
            }
            out_ret = FLB_RETRY;
        }
        else {
            if (c->resp.payload) {
                flb_plg_info(ctx->ins, "%s:%i, HTTP status=%i\n%s",
                             ctx->tcp_host, ctx->tcp_port,
                             c->resp.status, c->resp.payload);
            }
            else {
                flb_plg_info(ctx->ins, "%s:%i, HTTP status=%i",
                             ctx->tcp_host, ctx->tcp_port,
                             c->resp.status);
            }
        }
    }
    else {
        flb_plg_error(ctx->ins, "could not flush records to %s:%i (http_do=%i)",
                      ctx->tcp_host, ctx->tcp_port, ret);
        out_ret = FLB_RETRY;
    }

    flb_http_client_destroy(c);
    flb_upstream_conn_release(u_conn);
    FLB_OUTPUT_RETURN(out_ret);
}

static int cb_loki_exit(void *data, struct flb_config *config)
{
    struct flb_loki *ctx = data;

    if (!ctx) {
        return 0;
    }

    loki_config_destroy(ctx);
    return 0;
}

/* Configuration properties map */
static struct flb_config_map config_map[] = {
    {
     FLB_CONFIG_MAP_STR, "tenant_id", NULL,
     0, FLB_TRUE, offsetof(struct flb_loki, tenant_id),
     "Tenant ID used by default to push logs to Loki. If omitted or empty "
     "it assumes Loki is running in single-tenant mode and no X-Scope-OrgID "
     "header is sent."
    },

    {
     FLB_CONFIG_MAP_CLIST, "labels", NULL,
     0, FLB_TRUE, offsetof(struct flb_loki, labels),
     "labels for API requests. If no value is set, the default label is 'job=fluent-bit'"
    },

    {
     FLB_CONFIG_MAP_BOOL, "auto_kubernetes_labels", "false",
     0, FLB_TRUE, offsetof(struct flb_loki, auto_kubernetes_labels),
     "If set to true, it will add all Kubernetes labels to Loki labels.",
    },

    {
     FLB_CONFIG_MAP_CLIST, "label_keys", NULL,
     0, FLB_TRUE, offsetof(struct flb_loki, label_keys),
     "Comma separated list of keys to use as stream labels."
    },

    /* EOF */
    {0}
};

/* Plugin reference */
struct flb_output_plugin out_loki_plugin = {
    .name        = "loki",
    .description = "Loki",
    .cb_init     = cb_loki_init,
    .cb_flush    = cb_loki_flush,
    .cb_exit     = cb_loki_exit,
    .config_map  = config_map,
    .flags       = FLB_OUTPUT_NET | FLB_IO_OPT_TLS | FLB_OUTPUT_NO_MULTIPLEX,
};
