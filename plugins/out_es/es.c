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

#include <msgpack.h>
#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_network.h>
#include <fluent-bit/flb_http_client.h>
#include <fluent-bit/flb_pack.h>

#include "es.h"
#include "es_bulk.h"

struct flb_output_plugin out_es_plugin;

static inline void es_pack_map_content(msgpack_packer *tmp_pck, msgpack_object map)
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
        char *key_ptr;
        size_t key_size;

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
        char *p   = ptr_key;
        char *end = ptr_key + key_size;
        while (p != end) {
            if (*p == '.') *p = '_';
            p++;
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
            es_pack_map_content(tmp_pck, *v);
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
static char *es_format(void *data, size_t bytes, int *out_size,
                       struct flb_out_es_config *ctx)
{
    int ret;
    int map_size;
    int index_len;
    size_t off = 0;
    char *buf;
    msgpack_unpacked result;
    msgpack_object root;
    msgpack_object map;
    msgpack_object time;
    char *json_buf;
    size_t json_size;
    char j_index[ES_BULK_HEADER];
    struct es_bulk *bulk;
    msgpack_sbuffer tmp_sbuf;
    msgpack_packer tmp_pck;

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
    bulk = es_bulk_create();
    if (!bulk) {
        return NULL;
    }

    /* Format the JSON header required by the ES Bulk API */
    index_len = snprintf(j_index,
                         ES_BULK_HEADER,
                         ES_BULK_INDEX_FMT,
                         ctx->index, ctx->type);
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

        time  = root.via.array.ptr[0];
        map   = root.via.array.ptr[1];
        map_size = map.via.map.size;

        /* Create temporal msgpack buffer */
        msgpack_sbuffer_init(&tmp_sbuf);
        msgpack_packer_init(&tmp_pck, &tmp_sbuf, msgpack_sbuffer_write);

        msgpack_pack_map(&tmp_pck, map_size + 1);

        /* Append date k/v */
        msgpack_pack_str(&tmp_pck, 4);
        msgpack_pack_str_body(&tmp_pck, "date", 4);
        msgpack_pack_object(&tmp_pck, time);

        /*
         * The map_content routine iterate over each Key/Value pair found in
         * the map and do some sanitization for the key names.
         *
         * Elasticsearch have a restriction that key names cannot contain
         * a dot; if some dot is found, it's replaced with an underscore.
         */
        es_pack_map_content(&tmp_pck, map);

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
        ret = es_bulk_append(bulk,
                             j_index, index_len,
                             json_buf, json_size);
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
    return buf;
}

int cb_es_init(struct flb_output_instance *ins,
               struct flb_config *config,
               void *data)
{
    int io_type;
    char *tmp;
    struct flb_uri *uri = ins->host.uri;
    struct flb_uri_field *f_index = NULL;
    struct flb_uri_field *f_type = NULL;
    struct flb_out_es_config *ctx = NULL;
    struct flb_upstream *upstream;
    (void) data;

    if (uri) {
        if (uri->count >= 2) {
            f_index = flb_uri_get(uri, 0);
            f_type  = flb_uri_get(uri, 1);
        }
    }

    /* Get network configuration */
    if (!ins->host.name) {
        ins->host.name = flb_strdup("127.0.0.1");
    }

    if (ins->host.port == 0) {
        ins->host.port = 9200;
    }

    /* Allocate plugin context */
    ctx = flb_malloc(sizeof(struct flb_out_es_config));
    if (!ctx) {
        perror("malloc");
        return -1;
    }

    if (ins->use_tls == FLB_TRUE) {
        io_type = FLB_IO_TLS;
    }
    else {
        io_type = FLB_IO_TCP;
    }

    /* Prepare an upstream handler */
    upstream = flb_upstream_create(config,
                                   ins->host.name,
                                   ins->host.port,
                                   io_type,
                                   &ins->tls);
    if (!upstream) {
        flb_free(ctx);
        return -1;
    }


    /* Set the context */
    ctx->u = upstream;
    if (f_index) {
        ctx->index = f_index->value;
    }
    else {
        tmp = flb_output_get_property("index", ins);
        if (!tmp) {
            ctx->index = "fluentbit";
        }
        else {
            ctx->index = tmp;
        }
    }

    if (f_type) {
        ctx->type = f_type->value;
    }
    else {
        tmp = flb_output_get_property("type", ins);
        if (!tmp) {
            ctx->type = "test";
        }
        else {
            ctx->type = tmp;
        }
    }

    flb_debug("[es] host=%s port=%i index=%s type=%s",
              ins->host.name, ins->host.port,
              ctx->index, ctx->type);

    flb_output_set_context(ins, ctx);
    return 0;
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
    struct flb_out_es_config *ctx = out_context;
    struct flb_upstream_conn *u_conn;
    struct flb_http_client *c;
    (void) i_ins;
    (void) tag;
    (void) tag_len;

    /* Convert format */
    pack = es_format(data, bytes, &bytes_out, ctx);
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
    c = flb_http_client(u_conn, FLB_HTTP_POST, "/_bulk",
                        pack, bytes_out, NULL, 0, NULL);
    flb_http_add_header(c, "User-Agent", 10, "Fluent-Bit", 10);
    flb_http_add_header(c, "Content-Type", 12, "application/json", 16);

    ret = flb_http_do(c, &b_sent);
    flb_debug("[out_es] http_do=%i", ret);
    flb_http_client_destroy(c);

    flb_free(pack);

    /* Release the connection */
    flb_upstream_conn_release(u_conn);
    FLB_OUTPUT_RETURN(FLB_OK);
}

int cb_es_exit(void *data, struct flb_config *config)
{
    struct flb_out_es_config *ctx = data;

    flb_upstream_destroy(ctx->u);
    flb_free(ctx);

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
