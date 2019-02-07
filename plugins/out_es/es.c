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
#include <fluent-bit/flb_network.h>
#include <fluent-bit/flb_http_client.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_time.h>
#include <msgpack.h>

#include <time.h>

#include "es.h"
#include "es_conf.h"
#include "es_bulk.h"
#include "murmur3.h"

struct flb_output_plugin out_es_plugin;

static inline void es_pack_map_content(msgpack_packer *tmp_pck,
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
        char *key_ptr = NULL;
        size_t key_size = 0;

        if (k->type == MSGPACK_OBJECT_BIN) {
            key_ptr  = (char *) k->via.bin.ptr;
            key_size = k->via.bin.size;
        }
        else if (k->type == MSGPACK_OBJECT_STR) {
            key_ptr  = (char *) k->via.str.ptr;
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
}

/*
 * Convert the internal Fluent Bit data representation to the required
 * one by Elasticsearch.
 *
 * 'Sadly' this process involves to convert from Msgpack to JSON.
 */
static char *elasticsearch_format(void *data, size_t bytes,
                                  char *tag, int tag_len, int *out_size,
                                  struct flb_elasticsearch *ctx)
{
    int ret;
    int len;
    int map_size;
    int index_len;
    size_t s;
    size_t off = 0;
    char *p;
    char *buf;
    char *es_index;
    char logstash_index[256];
    char time_formatted[256];
    char es_uuid[37];
    msgpack_unpacked result;
    msgpack_object root;
    msgpack_object map;
    msgpack_object *obj;
    char *json_buf;
    size_t json_size;
    char j_index[ES_BULK_HEADER];
    struct es_bulk *bulk;
    struct tm tm;
    struct flb_time tms;
    msgpack_sbuffer tmp_sbuf;
    msgpack_packer tmp_pck;
    uint16_t hash[8];

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

    if (ctx->logstash_format == FLB_TRUE) {
        memcpy(logstash_index, ctx->logstash_prefix, ctx->logstash_prefix_len);
        logstash_index[ctx->logstash_prefix_len] = '\0';
    }

    /* If logstash format and id generation is disabled, pre-generate index line for all records. */
    if (ctx->logstash_format == FLB_FALSE && ctx->generate_id == FLB_FALSE) {
        index_len = snprintf(j_index,
                             ES_BULK_HEADER,
                             ES_BULK_INDEX_FMT,
                             ctx->index, ctx->type);
    }

    while (msgpack_unpack_next(&result, data, bytes, &off) == MSGPACK_UNPACK_SUCCESS) {
        if (result.data.type != MSGPACK_OBJECT_ARRAY) {
            continue;
        }

        /* Each array must have two entries: time and record */
        root = result.data;
        if (root.via.array.size != 2) {
            continue;
        }

        /*
         * Timestamp: Elasticsearch only support fractional seconds in
         * milliseconds unit, not nanoseconds, so we take our nsec value and
         * change it representation.
         */
        flb_time_pop_from_msgpack(&tms, &result, &obj);
        tms.tm.tv_nsec = (tms.tm.tv_nsec / 1000000);

        map   = root.via.array.ptr[1];
        map_size = map.via.map.size;

        /* Create temporal msgpack buffer */
        msgpack_sbuffer_init(&tmp_sbuf);
        msgpack_packer_init(&tmp_pck, &tmp_sbuf, msgpack_sbuffer_write);

        if (ctx->include_tag_key == FLB_TRUE) {
            map_size++;
        }

        /* Set the new map size */
        msgpack_pack_map(&tmp_pck, map_size + 1);

        /* Append the time key */
        msgpack_pack_str(&tmp_pck, ctx->time_key_len);
        msgpack_pack_str_body(&tmp_pck, ctx->time_key, ctx->time_key_len);

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
            p = logstash_index + ctx->logstash_prefix_len;
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

        /* Tag Key */
        if (ctx->include_tag_key == FLB_TRUE) {
            msgpack_pack_str(&tmp_pck, ctx->tag_key_len);
            msgpack_pack_str_body(&tmp_pck, ctx->tag_key, ctx->tag_key_len);
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
        es_pack_map_content(&tmp_pck, map, ctx);

        if (ctx->generate_id == FLB_TRUE) {
            MurmurHash3_x64_128(tmp_sbuf.data, tmp_sbuf.size, 42, hash);
            snprintf(es_uuid, sizeof(es_uuid), "%04x%04x-%04x-%04x-%04x-%04x%04x%04x",
                     hash[0], hash[1], hash[2], hash[3], hash[4], hash[5], hash[6], hash[7]);
            index_len = snprintf(j_index,
                                 ES_BULK_HEADER,
                                 ES_BULK_INDEX_FMT_ID,
                                 es_index, ctx->type, es_uuid);
        }

        /* Convert msgpack to JSON */
        ret = flb_msgpack_raw_to_json_str(tmp_sbuf.data, tmp_sbuf.size,
                                          &json_buf, &json_size);
        msgpack_sbuffer_destroy(&tmp_sbuf);
        if (ret != 0) {
            msgpack_unpacked_destroy(&result);
            es_bulk_destroy(bulk);
            return NULL;
        }

        /* Append JSON on Index buf */
        ret = es_bulk_append(bulk, j_index, index_len, json_buf, json_size);
        flb_free(json_buf);
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
        printf("%s", buf);
        fflush(stdout);
    }
    return buf;
}

int cb_es_init(struct flb_output_instance *ins,
               struct flb_config *config,
               void *data)
{
    struct flb_elasticsearch *ctx;

    ctx = flb_es_conf_create(ins, config);
    if (!ctx) {
        flb_error("[out_es] cannot initialize plugin");
        return -1;
    }

    flb_debug("[out_es] host=%s port=%i index=%s type=%s",
              ins->host.name, ins->host.port,
              ctx->index, ctx->type);

    flb_output_set_context(ins, ctx);
    return 0;
}

static int elasticsearch_error_check(struct flb_http_client *c)
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

        flb_error("[out_es] could not pack/validate JSON response\n%s",
                  c->resp.payload);
        return FLB_TRUE;
    }

    /* Lookup error field */
    msgpack_unpacked_init(&result);
    ret = msgpack_unpack_next(&result, out_buf, out_size, &off);
    if (ret == MSGPACK_UNPACK_SUCCESS) {
        return FLB_TRUE;
    }

    root = result.data;
    if (root.type != MSGPACK_OBJECT_MAP) {
        flb_error("[out_es] unexpected payload type=%i",
                  root.type);
        check = FLB_TRUE;
        goto done;
    }

    for (i = 0; i < root.via.map.size; i++) {
        key = root.via.map.ptr[i].key;
        if (key.type != MSGPACK_OBJECT_STR) {
            flb_error("[out_es] unexpected key type=%i",
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
                flb_error("[out_es] unexpected 'error' value type=%i",
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

void cb_es_flush(void *data, size_t bytes,
                 char *tag, int tag_len,
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

    flb_http_add_header(c, "User-Agent", 10, "Fluent-Bit", 10);
    flb_http_add_header(c, "Content-Type", 12, "application/x-ndjson", 20);

    if (ctx->http_user && ctx->http_passwd) {
        flb_http_basic_auth(c, ctx->http_user, ctx->http_passwd);
    }

    ret = flb_http_do(c, &b_sent);
    if (ret != 0) {
        flb_warn("[out_es] http_do=%i", ret);
        goto retry;
    }
    else {
        /* The request was issued successfully, validate the 'error' field */
        flb_debug("[out_es] HTTP Status=%i", c->resp.status);
        if (c->resp.status != 200) {
            goto retry;
        }

        if (c->resp.payload_size > 0) {
            /*
             * Elasticsearch payload should be JSON, we convert it to msgpack
             * and lookup the 'error' field.
             */
            ret = elasticsearch_error_check(c);
            if (ret == FLB_TRUE) {
                /* we got an error */
                flb_warn("[out_es] Elasticsearch error\n%s",
                         c->resp.payload);
                goto retry;
            }
            else {
                flb_debug("[out_es Elasticsearch response\n%s",
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
    FLB_OUTPUT_RETURN(FLB_OK);

    /* Issue a retry */
 retry:
    flb_http_client_destroy(c);
    flb_free(pack);
    flb_upstream_conn_release(u_conn);
    FLB_OUTPUT_RETURN(FLB_RETRY);
}

int cb_es_exit(void *data, struct flb_config *config)
{
    struct flb_elasticsearch *ctx = data;

    flb_es_conf_destroy(ctx);
    return 0;
}

/* Plugin reference */
struct flb_output_plugin out_es_plugin = {
    .name           = "es",
    .description    = "Elasticsearch",
    .cb_init        = cb_es_init,
    .cb_pre_run     = NULL,
    .cb_flush       = cb_es_flush,
    .cb_exit        = cb_es_exit,

    /* Plugin flags */
    .flags          = FLB_OUTPUT_NET | FLB_IO_OPT_TLS,
};
