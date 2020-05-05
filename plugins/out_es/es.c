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
#include <fluent-bit/flb_network.h>
#include <fluent-bit/flb_http_client.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_signv4.h>
#include <msgpack.h>

#include <time.h>

#include "es.h"
#include "es_conf.h"
#include "es_bulk.h"
#include "murmur3.h"

struct flb_output_plugin out_es_plugin;

#ifdef FLB_HAVE_SIGNV4
static flb_sds_t add_aws_auth(struct flb_elasticsearch *ctx,
                              struct flb_http_client *c, char *region)
{
    flb_sds_t signature = NULL;
    char *access_key = NULL;
    char *secret_key = NULL;
    char *session_token = NULL;
    int ret;

    flb_plg_debug(ctx->ins, "Signing request with AWS Sigv4");

    /* Amazon ES Sigv4 does not allow the host header to include the port */
    ret = flb_http_strip_port_from_host(c);
    if (ret < 0) {
        flb_plg_error(ctx->ins, "could not strip port from host for sigv4");
        return NULL;
    }

    /* AWS credentials */
    access_key = getenv("AWS_ACCESS_KEY_ID");
    if (!access_key || strlen(access_key) < 1) {
        flb_plg_error(ctx->ins, "'AWS_ACCESS_KEY_ID' not set");
        return NULL;
    }

    secret_key = getenv("AWS_SECRET_ACCESS_KEY");
    if (!access_key || strlen(access_key) < 1) {
        flb_plg_error(ctx->ins, "'AWS_SECRET_ACCESS_KEY' not set");
        return NULL;
    }

    session_token = getenv("AWS_SESSION_TOKEN");

    signature = flb_signv4_do(c, FLB_TRUE, FLB_TRUE, time(NULL),
                              access_key, region, "es",
                              secret_key, session_token);
    if (!signature) {
        flb_plg_error(ctx->ins, "could not sign request with sigv4");
        return NULL;
    }
    return signature;
}
#endif /* FLB_HAVE_SIGNV4 */

static inline int es_pack_map_content(msgpack_packer *tmp_pck,
                                      msgpack_object map,
                                      struct flb_elasticsearch *ctx)
{
    int i;
    char *ptr_key = NULL;
    char buf_key[256];
    msgpack_object *k;
    msgpack_object *v;

    for (i = 0; i < map.via.map.size; i++) {
        k = &map.via.map.ptr[i].key;
        v = &map.via.map.ptr[i].val;
        ptr_key = NULL;

        /* Store key */
        const char *key_ptr = NULL;
        size_t key_size = 0;

        if (k->type == MSGPACK_OBJECT_BIN) {
            key_ptr  = k->via.bin.ptr;
            key_size = k->via.bin.size;
        }
        else if (k->type == MSGPACK_OBJECT_STR) {
            key_ptr  = k->via.str.ptr;
            key_size = k->via.str.size;
        }

        if (key_size < (sizeof(buf_key) - 1)) {
            memcpy(buf_key, key_ptr, key_size);
            buf_key[key_size] = '\0';
            ptr_key = buf_key;
        }
        else {
            /* Long map keys have a performance penalty */
            ptr_key = flb_malloc(key_size + 1);
            if (!ptr_key) {
                flb_errno();
                return -1;
            }

            memcpy(ptr_key, key_ptr, key_size);
            ptr_key[key_size] = '\0';
        }

        /*
         * Sanitize key name, Elastic Search 2.x don't allow dots
         * in field names:
         *
         *   https://goo.gl/R5NMTr
         */
        if (ctx->replace_dots == FLB_TRUE) {
            char *p   = ptr_key;
            char *end = ptr_key + key_size;
            while (p != end) {
                if (*p == '.') *p = '_';
                p++;
            }
        }

        /* Append the key */
        msgpack_pack_str(tmp_pck, key_size);
        msgpack_pack_str_body(tmp_pck, ptr_key, key_size);

        /* Release temporal key if was allocated */
        if (ptr_key && ptr_key != buf_key) {
            flb_free(ptr_key);
        }
        ptr_key = NULL;

        /*
         * The value can be any data type, if it's a map we need to
         * sanitize to avoid dots.
         */
        if (v->type == MSGPACK_OBJECT_MAP) {
            msgpack_pack_map(tmp_pck, v->via.map.size);
            es_pack_map_content(tmp_pck, *v, ctx);
        }
        else {
            msgpack_pack_object(tmp_pck, *v);
        }
    }

    return 0;
}

/*
 * Convert the internal Fluent Bit data representation to the required
 * one by Elasticsearch.
 *
 * 'Sadly' this process involves to convert from Msgpack to JSON.
 */
static char *elasticsearch_format(const void *data, size_t bytes,
                                  const char *tag, int tag_len, int *out_size,
                                  struct flb_elasticsearch *ctx)
{
    int ret;
    int len;
    int map_size;
    int index_len = 0;
    size_t s = 0;
    size_t off = 0;
    char *p;
    char *buf;
    char *es_index;
    char logstash_index[256];
    char time_formatted[256];
    char index_formatted[256];
    char es_uuid[37];
    flb_sds_t out_buf;
    msgpack_unpacked result;
    msgpack_object root;
    msgpack_object map;
    msgpack_object *obj;
    char j_index[ES_BULK_HEADER];
    struct es_bulk *bulk;
    struct tm tm;
    struct flb_time tms;
    msgpack_sbuffer tmp_sbuf;
    msgpack_packer tmp_pck;
    uint16_t hash[8];
    const char *es_index_custom;
    int es_index_custom_len;
    int i;
    msgpack_object key;
    msgpack_object val;

    /* Iterate the original buffer and perform adjustments */
    msgpack_unpacked_init(&result);

    /* Perform some format validation */
    ret = msgpack_unpack_next(&result, data, bytes, &off);
    if (ret != MSGPACK_UNPACK_SUCCESS) {
        msgpack_unpacked_destroy(&result);
        return NULL;
    }

    /* We 'should' get an array */
    if (result.data.type != MSGPACK_OBJECT_ARRAY) {
        /*
         * If we got a different format, we assume the caller knows what he is
         * doing, we just duplicate the content in a new buffer and cleanup.
         */
        msgpack_unpacked_destroy(&result);
        return NULL;
    }

    root = result.data;
    if (root.via.array.size == 0) {
        return NULL;
    }

    /* Create the bulk composer */
    bulk = es_bulk_create();
    if (!bulk) {
        return NULL;
    }

    off = 0;

    msgpack_unpacked_destroy(&result);
    msgpack_unpacked_init(&result);

    /* Copy logstash prefix if logstash format is enabled */
    if (ctx->logstash_format == FLB_TRUE) {
        memcpy(logstash_index, ctx->logstash_prefix, flb_sds_len(ctx->logstash_prefix));
        logstash_index[flb_sds_len(ctx->logstash_prefix)] = '\0';
    }

    /*
     * If logstash format and id generation are disabled, pre-generate
     * the index line for all records.
     *
     * The header stored in 'j_index' will be used for the all records on
     * this payload.
     */
    if (ctx->logstash_format == FLB_FALSE && ctx->generate_id == FLB_FALSE) {
        flb_time_get(&tms);
        gmtime_r(&tms.tm.tv_sec, &tm);
        strftime(index_formatted, sizeof(index_formatted) - 1,
                 ctx->index, &tm);
        es_index = index_formatted;

        index_len = snprintf(j_index,
                             ES_BULK_HEADER,
                             ES_BULK_INDEX_FMT,
                             es_index, ctx->type);
    }

    /*
     * Some broken clients may have time drift up to year 1970
     * this will generate corresponding index in Elasticsearch
     * in order to prevent generating millions of indexes
     * we can set to always use current time for index generation
     */
    if (ctx->current_time_index == FLB_TRUE) {
        flb_time_get(&tms);
    }

    /* Iterate each record and do further formatting */
    while (msgpack_unpack_next(&result, data, bytes, &off) == MSGPACK_UNPACK_SUCCESS) {
        if (result.data.type != MSGPACK_OBJECT_ARRAY) {
            continue;
        }

        /* Each array must have two entries: time and record */
        root = result.data;
        if (root.via.array.size != 2) {
            continue;
        }

        /* Only pop time from record if current_time_index is disabled */
        if (ctx->current_time_index == FLB_FALSE) {
            flb_time_pop_from_msgpack(&tms, &result, &obj);
        }

        /*
         * Timestamp: Elasticsearch only support fractional seconds in
         * milliseconds unit, not nanoseconds, so we take our nsec value and
         * change it representation.
         */
        tms.tm.tv_nsec = (tms.tm.tv_nsec / 1000000);

        map   = root.via.array.ptr[1];
        map_size = map.via.map.size;

        es_index_custom_len = 0;
        if (ctx->logstash_prefix_key) {
            for (i = 0; i < map_size; i++) {
                key = map.via.map.ptr[i].key;
                if (key.type != MSGPACK_OBJECT_STR) {
                    continue;
                }
                if (key.via.str.size != flb_sds_len(ctx->logstash_prefix_key)) {
                    continue;
                }
                if (strncmp(key.via.str.ptr, ctx->logstash_prefix_key,
                            flb_sds_len(ctx->logstash_prefix_key)) != 0) {
                    continue;
                }
                val = map.via.map.ptr[i].val;
                if (val.type != MSGPACK_OBJECT_STR) {
                    continue;
                }
                if (val.via.str.size >= 128) {
                    continue;
                }
                es_index_custom = val.via.str.ptr;
                es_index_custom_len = val.via.str.size;
                memcpy(logstash_index, es_index_custom, es_index_custom_len);
                logstash_index[es_index_custom_len] = '\0';
                break;
            }
        }

        /* Create temporal msgpack buffer */
        msgpack_sbuffer_init(&tmp_sbuf);
        msgpack_packer_init(&tmp_pck, &tmp_sbuf, msgpack_sbuffer_write);

        if (ctx->include_tag_key == FLB_TRUE) {
            map_size++;
        }

        /* Set the new map size */
        msgpack_pack_map(&tmp_pck, map_size + 1);

        /* Append the time key */
        msgpack_pack_str(&tmp_pck, flb_sds_len(ctx->time_key));
        msgpack_pack_str_body(&tmp_pck, ctx->time_key, flb_sds_len(ctx->time_key));

        /* Format the time */
        gmtime_r(&tms.tm.tv_sec, &tm);
        s = strftime(time_formatted, sizeof(time_formatted) - 1,
                     ctx->time_key_format, &tm);
        len = snprintf(time_formatted + s, sizeof(time_formatted) - 1 - s,
                       ".%03" PRIu64 "Z", (uint64_t) tms.tm.tv_nsec);

        s += len;
        msgpack_pack_str(&tmp_pck, s);
        msgpack_pack_str_body(&tmp_pck, time_formatted, s);

        es_index = ctx->index;
        if (ctx->logstash_format == FLB_TRUE) {
            /* Compose Index header */
            if (es_index_custom_len > 0) {
                p = logstash_index + es_index_custom_len;
            } else {
                p = logstash_index + flb_sds_len(ctx->logstash_prefix);
            }
            *p++ = '-';

            len = p - logstash_index;
            s = strftime(p, sizeof(logstash_index) - len - 1,
                         ctx->logstash_dateformat, &tm);
            p += s;
            *p++ = '\0';
            es_index = logstash_index;
            if (ctx->generate_id == FLB_FALSE) {
                index_len = snprintf(j_index,
                                     ES_BULK_HEADER,
                                     ES_BULK_INDEX_FMT,
                                     es_index, ctx->type);
            }
        }
        else if (ctx->current_time_index == FLB_TRUE) {
            /* Make sure we handle index time format for index */
            strftime(index_formatted, sizeof(index_formatted) - 1,
                     ctx->index, &tm);
            es_index = index_formatted;
        }

        /* Tag Key */
        if (ctx->include_tag_key == FLB_TRUE) {
            msgpack_pack_str(&tmp_pck, flb_sds_len(ctx->tag_key));
            msgpack_pack_str_body(&tmp_pck, ctx->tag_key, flb_sds_len(ctx->tag_key));
            msgpack_pack_str(&tmp_pck, tag_len);
            msgpack_pack_str_body(&tmp_pck, tag, tag_len);
        }

        /*
         * The map_content routine iterate over each Key/Value pair found in
         * the map and do some sanitization for the key names.
         *
         * Elasticsearch have a restriction that key names cannot contain
         * a dot; if some dot is found, it's replaced with an underscore.
         */
        ret = es_pack_map_content(&tmp_pck, map, ctx);
        if (ret == -1) {
            msgpack_unpacked_destroy(&result);
            msgpack_sbuffer_destroy(&tmp_sbuf);
            es_bulk_destroy(bulk);
            return NULL;
        }

        if (ctx->generate_id == FLB_TRUE) {
            MurmurHash3_x64_128(tmp_sbuf.data, tmp_sbuf.size, 42, hash);
            snprintf(es_uuid, sizeof(es_uuid),
                     "%04x%04x-%04x-%04x-%04x-%04x%04x%04x",
                     hash[0], hash[1], hash[2], hash[3],
                     hash[4], hash[5], hash[6], hash[7]);
            index_len = snprintf(j_index,
                                 ES_BULK_HEADER,
                                 ES_BULK_INDEX_FMT_ID,
                                 es_index, ctx->type, es_uuid);
        }

        /* Convert msgpack to JSON */
        out_buf = flb_msgpack_raw_to_json_sds(tmp_sbuf.data, tmp_sbuf.size);
        msgpack_sbuffer_destroy(&tmp_sbuf);
        if (!out_buf) {
            msgpack_unpacked_destroy(&result);
            es_bulk_destroy(bulk);
            return NULL;
        }

        ret = es_bulk_append(bulk, j_index, index_len,
                             out_buf, flb_sds_len(out_buf));
        flb_sds_destroy(out_buf);
        if (ret == -1) {
            /* We likely ran out of memory, abort here */
            msgpack_unpacked_destroy(&result);
            *out_size = 0;
            es_bulk_destroy(bulk);
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
    if (ctx->trace_output) {
        fwrite(buf, 1, *out_size, stdout);
        fflush(stdout);
    }
    return buf;
}

static int cb_es_init(struct flb_output_instance *ins,
                      struct flb_config *config,
                      void *data)
{
    struct flb_elasticsearch *ctx;

    ctx = flb_es_conf_create(ins, config);
    if (!ctx) {
        flb_plg_error(ins, "cannot initialize plugin");
        return -1;
    }

    flb_plg_debug(ctx->ins, "host=%s port=%i uri=%s index=%s type=%s",
                  ins->host.name, ins->host.port, ctx->uri,
                  ctx->index, ctx->type);

    flb_output_set_context(ins, ctx);
    return 0;
}

static int elasticsearch_error_check(struct flb_elasticsearch *ctx,
                                     struct flb_http_client *c)
{
    int i;
    int ret;
    int check = FLB_TRUE;
    int root_type;
    char *out_buf;
    size_t off = 0;
    size_t out_size;
    msgpack_unpacked result;
    msgpack_object root;
    msgpack_object key;
    msgpack_object val;

    /*
     * Check if our payload is complete: there is such situations where
     * the Elasticsearch HTTP response body is bigger than the HTTP client
     * buffer so payload can be incomplete.
     */
    /* Convert JSON payload to msgpack */
    ret = flb_pack_json(c->resp.payload, c->resp.payload_size,
                        &out_buf, &out_size, &root_type);
    if (ret == -1) {
        /* Is this an incomplete HTTP Request ? */
        if (c->resp.payload_size <= 0) {
            return FLB_TRUE;
        }

        /* Lookup error field */
        if (strstr(c->resp.payload, "\"errors\":false,\"items\":[")) {
            return FLB_FALSE;
        }

        flb_plg_error(ctx->ins, "could not pack/validate JSON response\n%s",
                      c->resp.payload);
        return FLB_TRUE;
    }

    /* Lookup error field */
    msgpack_unpacked_init(&result);
    ret = msgpack_unpack_next(&result, out_buf, out_size, &off);
    if (ret != MSGPACK_UNPACK_SUCCESS) {
        flb_plg_error(ctx->ins, "Cannot unpack response to find error\n%s",
                      c->resp.payload);
        return FLB_TRUE;
    }

    root = result.data;
    if (root.type != MSGPACK_OBJECT_MAP) {
        flb_plg_error(ctx->ins, "unexpected payload type=%i",
                      root.type);
        check = FLB_TRUE;
        goto done;
    }

    for (i = 0; i < root.via.map.size; i++) {
        key = root.via.map.ptr[i].key;
        if (key.type != MSGPACK_OBJECT_STR) {
            flb_plg_error(ctx->ins, "unexpected key type=%i",
                          key.type);
            check = FLB_TRUE;
            goto done;
        }

        if (key.via.str.size != 6) {
            continue;
        }

        if (strncmp(key.via.str.ptr, "errors", 6) == 0) {
            val = root.via.map.ptr[i].val;
            if (val.type != MSGPACK_OBJECT_BOOLEAN) {
                flb_plg_error(ctx->ins, "unexpected 'error' value type=%i",
                              val.type);
                check = FLB_TRUE;
                goto done;
            }

            /* If error == false, we are OK (no errors = FLB_FALSE) */
            if (val.via.boolean) {
                /* there is an error */
                check = FLB_TRUE;
                goto done;
            }
            else {
                /* no errors */
                check = FLB_FALSE;
                goto done;
            }
        }
    }

 done:
    flb_free(out_buf);
    msgpack_unpacked_destroy(&result);
    return check;
}

static void cb_es_flush(const void *data, size_t bytes,
                        const char *tag, int tag_len,
                        struct flb_input_instance *i_ins, void *out_context,
                        struct flb_config *config)
{
    int ret;
    int bytes_out;
    char *pack;
    size_t b_sent;
    struct flb_elasticsearch *ctx = out_context;
    struct flb_upstream_conn *u_conn;
    struct flb_http_client *c;
    flb_sds_t signature = NULL;
    (void) i_ins;
    (void) tag;
    (void) tag_len;

    /* Get upstream connection */
    u_conn = flb_upstream_conn_get(ctx->u);
    if (!u_conn) {
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }

    /* Convert format */
    pack = elasticsearch_format(data, bytes, tag, tag_len, &bytes_out, ctx);
    if (!pack) {
        flb_upstream_conn_release(u_conn);
        FLB_OUTPUT_RETURN(FLB_ERROR);
    }

    /* Compose HTTP Client request */
    c = flb_http_client(u_conn, FLB_HTTP_POST, ctx->uri,
                        pack, bytes_out, NULL, 0, NULL, 0);

    flb_http_buffer_size(c, ctx->buffer_size);

#ifndef FLB_HAVE_SIGNV4
    flb_http_add_header(c, "User-Agent", 10, "Fluent-Bit", 10);
#endif

    flb_http_add_header(c, "Content-Type", 12, "application/x-ndjson", 20);

    if (ctx->http_user && ctx->http_passwd) {
        flb_http_basic_auth(c, ctx->http_user, ctx->http_passwd);
    }

#ifdef FLB_HAVE_SIGNV4
    if (ctx->has_aws_auth == FLB_TRUE) {
        /* User agent for AWS tools must start with "aws-" */
        flb_http_add_header(c, "User-Agent", 10, "aws-fluent-bit-plugin", 21);
        signature = add_aws_auth(ctx, c, ctx->aws_region);
        if (!signature) {
            goto retry;
        }
    }
    else {
        flb_http_add_header(c, "User-Agent", 10, "Fluent-Bit", 10);
    }
#endif

    ret = flb_http_do(c, &b_sent);
    if (ret != 0) {
        flb_plg_warn(ctx->ins, "http_do=%i URI=%s", ret, ctx->uri);
        goto retry;
    }
    else {
        /* The request was issued successfully, validate the 'error' field */
        flb_plg_debug(ctx->ins, "HTTP Status=%i URI=%s", c->resp.status, ctx->uri);
        if (c->resp.status != 200 && c->resp.status != 201) {
            if (c->resp.payload_size > 0) {
                flb_plg_error(ctx->ins, "HTTP status=%i URI=%s, response:\n%s\n",
                              c->resp.status, ctx->uri, c->resp.payload);
            }
            else {
                flb_plg_error(ctx->ins, "HTTP status=%i URI=%s",
                              c->resp.status, ctx->uri);
            }
            goto retry;
        }

        if (c->resp.payload_size > 0) {
            /*
             * Elasticsearch payload should be JSON, we convert it to msgpack
             * and lookup the 'error' field.
             */
            ret = elasticsearch_error_check(ctx, c);
            if (ret == FLB_TRUE) {
                /* we got an error */
                if (ctx->trace_error) {
                    /*
                     * If trace_error is set, trace the actual
                     * input/output to Elasticsearch that caused the problem.
                     */
                    flb_plg_debug(ctx->ins, "error caused by: Input\n%s\n",
                                   pack);
                    flb_plg_error(ctx->ins, "error: Output\n%s",
                                  c->resp.payload);
                }
                goto retry;
            }
            else {
                flb_plg_debug(ctx->ins, "Elasticsearch response\n%s",
                              c->resp.payload);
            }
        }
        else {
            goto retry;
        }
    }

    /* Cleanup */
    flb_http_client_destroy(c);
    flb_free(pack);
    flb_upstream_conn_release(u_conn);
    if (signature) {
        flb_sds_destroy(signature);
    }
    FLB_OUTPUT_RETURN(FLB_OK);

    /* Issue a retry */
 retry:
    flb_http_client_destroy(c);
    flb_free(pack);
    flb_upstream_conn_release(u_conn);
    FLB_OUTPUT_RETURN(FLB_RETRY);
}

static int cb_es_exit(void *data, struct flb_config *config)
{
    struct flb_elasticsearch *ctx = data;

    flb_es_conf_destroy(ctx);
    return 0;
}

/* Configuration properties map */
static struct flb_config_map config_map[] = {
    {
     FLB_CONFIG_MAP_STR, "index", FLB_ES_DEFAULT_INDEX,
     0, FLB_TRUE, offsetof(struct flb_elasticsearch, index),
     NULL
    },
    {
     FLB_CONFIG_MAP_STR, "type", FLB_ES_DEFAULT_TYPE,
     0, FLB_TRUE, offsetof(struct flb_elasticsearch, type),
     NULL
    },

    /* HTTP Authentication */
    {
     FLB_CONFIG_MAP_STR, "http_user", NULL,
     0, FLB_TRUE, offsetof(struct flb_elasticsearch, http_user),
     NULL
    },
    {
     FLB_CONFIG_MAP_STR, "http_passwd", "",
     0, FLB_TRUE, offsetof(struct flb_elasticsearch, http_passwd),
     NULL
    },

    /* AWS Authentication */
#ifdef FLB_HAVE_SIGNV4
    {
     FLB_CONFIG_MAP_BOOL, "aws_auth", "false",
     0, FLB_TRUE, offsetof(struct flb_elasticsearch, has_aws_auth),
     NULL
    },
    {
     FLB_CONFIG_MAP_STR, "aws_region", "",
     0, FLB_TRUE, offsetof(struct flb_elasticsearch, aws_region),
     NULL
    },
#endif

    /* Logstash compatibility */
    {
     FLB_CONFIG_MAP_BOOL, "logstash_format", "false",
     0, FLB_TRUE, offsetof(struct flb_elasticsearch, logstash_format),
     NULL
    },
    {
     FLB_CONFIG_MAP_STR, "logstash_prefix", FLB_ES_DEFAULT_PREFIX,
     0, FLB_TRUE, offsetof(struct flb_elasticsearch, logstash_prefix),
     NULL
    },
    {
     FLB_CONFIG_MAP_STR, "logstash_prefix_key", NULL,
     0, FLB_TRUE, offsetof(struct flb_elasticsearch, logstash_prefix_key),
     NULL
    },
    {
     FLB_CONFIG_MAP_STR, "logstash_dateformat", FLB_ES_DEFAULT_TIME_FMT,
     0, FLB_TRUE, offsetof(struct flb_elasticsearch, logstash_dateformat),
     NULL
    },

    /* Custom Time and Tag keys */
    {
     FLB_CONFIG_MAP_STR, "time_key", FLB_ES_DEFAULT_TIME_KEY,
     0, FLB_TRUE, offsetof(struct flb_elasticsearch, time_key),
     NULL
    },
    {
     FLB_CONFIG_MAP_STR, "time_key_format", FLB_ES_DEFAULT_TIME_KEYF,
     0, FLB_TRUE, offsetof(struct flb_elasticsearch, time_key_format),
     NULL
    },
    {
     FLB_CONFIG_MAP_BOOL, "include_tag_key", "false",
     0, FLB_TRUE, offsetof(struct flb_elasticsearch, include_tag_key),
     NULL
    },
    {
     FLB_CONFIG_MAP_STR, "tag_key", FLB_ES_DEFAULT_TAG_KEY,
     0, FLB_TRUE, offsetof(struct flb_elasticsearch, tag_key),
     NULL
    },
    {
     FLB_CONFIG_MAP_SIZE, "buffer_size", FLB_ES_DEFAULT_HTTP_MAX,
     0, FLB_TRUE, offsetof(struct flb_elasticsearch, buffer_size),
     NULL
    },

    /* Elasticsearch specifics */
    {
     FLB_CONFIG_MAP_STR, "path", NULL,
     0, FLB_FALSE, 0,
     NULL
    },
    {
     FLB_CONFIG_MAP_STR, "pipeline", NULL,
     0, FLB_FALSE, 0,
     NULL
    },
    {
     FLB_CONFIG_MAP_BOOL, "generate_id", "false",
     0, FLB_TRUE, offsetof(struct flb_elasticsearch, generate_id),
     NULL
    },
    {
     FLB_CONFIG_MAP_BOOL, "replace_dots", "false",
     0, FLB_TRUE, offsetof(struct flb_elasticsearch, replace_dots),
     NULL
    },

    {
     FLB_CONFIG_MAP_BOOL, "current_time_index", "false",
     0, FLB_TRUE, offsetof(struct flb_elasticsearch, current_time_index),
     NULL
    },

    /* Trace */
    {
     FLB_CONFIG_MAP_BOOL, "trace_output", "false",
     0, FLB_TRUE, offsetof(struct flb_elasticsearch, trace_output),
     NULL
    },
    {
     FLB_CONFIG_MAP_BOOL, "trace_error", "false",
     0, FLB_TRUE, offsetof(struct flb_elasticsearch, trace_error),
     NULL
    },

    /* EOF */
    {0}
};

/* Plugin reference */
struct flb_output_plugin out_es_plugin = {
    .name           = "es",
    .description    = "Elasticsearch",
    .cb_init        = cb_es_init,
    .cb_pre_run     = NULL,
    .cb_flush       = cb_es_flush,
    .cb_exit        = cb_es_exit,
    .config_map     = config_map,

    /* Plugin flags */
    .flags          = FLB_OUTPUT_NET | FLB_IO_OPT_TLS,
};
