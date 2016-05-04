/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2016 Treasure Data Inc.
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
#include <cjson/cjson.h>

#include "es.h"
#include "es_bulk.h"

struct flb_output_plugin out_es_plugin;

/*
 * Convert the internal Fluent Bit data representation to the required
 * one by Elasticsearch.
 *
 * 'Sadly' this process involves to convert from Msgpack to JSON.
 */
static char *es_format(void *data, size_t bytes, int *out_size,
                       struct flb_out_es_config *ctx)
{
    int i;
    int ret;
    int n_size;
    int index_len;
    uint32_t psize;
    size_t off = 0;
    time_t atime;
    char *buf;
    char *ptr_key = NULL;
    char *ptr_val = NULL;
    char buf_key[256];
    char buf_val[512];
    msgpack_unpacked result;
    msgpack_object root;
    msgpack_object map;
    char *j_entry;
    char j_index[ES_BULK_HEADER];
    json_t *j_map;
    struct es_bulk *bulk;

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

        /* Create a map entry */
        j_map = json_create_object();

        atime = root.via.array.ptr[0].via.u64;
        map   = root.via.array.ptr[1];

        n_size = map.via.map.size + 1;

        json_add_to_object(j_map, "date", json_create_number(atime));
        for (i = 0; i < n_size - 1; i++) {
            msgpack_object *k = &map.via.map.ptr[i].key;
            msgpack_object *v = &map.via.map.ptr[i].val;

            if (k->type != MSGPACK_OBJECT_BIN && k->type != MSGPACK_OBJECT_STR) {
                continue;
            }

            /* Store key */
            psize = k->via.bin.size;
            if (psize <= (sizeof(buf_key) - 1)) {
                memcpy(buf_key, k->via.bin.ptr, psize);
                buf_key[psize] = '\0';
                ptr_key = buf_key;
            }
            else {
                /* Long JSON map keys have a performance penalty */
                ptr_key = malloc(psize + 1);
                memcpy(ptr_key, k->via.bin.ptr, psize);
                ptr_key[psize] = '\0';
            }

            /*
             * Sanitize key name, Elastic Search 2.x don't allow dots
             * in field names:
             *
             *   https://goo.gl/R5NMTr
             */
            char *p   = ptr_key;
            char *end = ptr_key + psize;
            while (p != end) {
                if (*p == '.') *p = '_';
                p++;
            }

            /* Store value */
            if (v->type == MSGPACK_OBJECT_NIL) {
                json_add_to_object(j_map, ptr_key, json_create_null());
            }
            else if (v->type == MSGPACK_OBJECT_BOOLEAN) {
                json_add_to_object(j_map, ptr_key,
                                   json_create_bool(v->via.boolean));
            }
            else if (v->type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
                json_add_to_object(j_map, ptr_key,
                                   json_create_number(v->via.u64));
            }
            else if (v->type == MSGPACK_OBJECT_NEGATIVE_INTEGER) {
                json_add_to_object(j_map, ptr_key,
                                   json_create_number(v->via.i64));
            }
            else if (v->type == MSGPACK_OBJECT_FLOAT) {
                json_add_to_object(j_map, ptr_key,
                                   json_create_number(v->via.f64));
            }
            else if (v->type == MSGPACK_OBJECT_STR) {
                /* String value */
                psize = v->via.str.size;
                if (psize <= (sizeof(buf_val) - 1)) {
                    memcpy(buf_val, v->via.str.ptr, psize);
                    buf_val[psize] = '\0';
                    ptr_val = buf_val;
                }
                else {
                    ptr_val = malloc(psize + 1);
                    memcpy(ptr_val, k->via.str.ptr, psize);
                    ptr_val[psize] = '\0';
                }
                json_add_to_object(j_map, ptr_key,
                                   json_create_string(ptr_val));
            }
            else if (v->type == MSGPACK_OBJECT_BIN) {
                /* Bin value */
                psize = v->via.bin.size;
                if (psize <= (sizeof(buf_val) - 1)) {
                    memcpy(buf_val, v->via.bin.ptr, psize);
                    buf_val[psize] = '\0';
                    ptr_val = buf_val;
                }
                else {
                    ptr_val = malloc(psize + 1);
                    memcpy(ptr_val, k->via.bin.ptr, psize);
                    ptr_val[psize] = '\0';
                }
                json_add_to_object(j_map, ptr_key,
                                   json_create_string(ptr_val));
            }

            if (ptr_key && ptr_key != buf_key) {
                free(ptr_key);
            }
            ptr_key = NULL;

            if (ptr_val && ptr_val != buf_val) {
                free(ptr_val);
            }
            ptr_val = NULL;
        }

        /*
         * At this point we have our JSON message, but in order to
         * ingest this data into Elasticsearch we need to compose the
         * Bulk API request, sadly it requires to prepend a JSON entry
         * with details about the target 'index' and 'type' for EVERY
         * message.
         */
        j_entry = json_print_unformatted(j_map);
        json_delete(j_map);

        ret = es_bulk_append(bulk,
                             j_index, index_len,
                             j_entry, strlen(j_entry));
        free(j_entry);
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
    free(bulk);

    return buf;
}

int cb_es_init(struct flb_output_instance *ins,
               struct flb_config *config,
               void *data)
{
    int io_type = FLB_IO_TLS;
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

    /* Set default network configuration */
    if (!ins->host.name) {
        ins->host.name = strdup("127.0.0.1");
    }
    if (ins->host.port == 0) {
        ins->host.port = 9200;
    }

    /* Allocate plugin context */
    ctx = malloc(sizeof(struct flb_out_es_config));
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
        free(ctx);
        return -1;
    }


    /* Set the context */
    ctx->u = upstream;
    if (f_index) {
        ctx->index = f_index->value;
    }
    else {
        ctx->index = "fluentbit";
    }

    if (f_type) {
        ctx->type = f_type->value;
    }
    else {
        ctx->type = "test";
    }

    flb_info("[es] host=%s port=%i index=%s type=%s",
             ins->host.name, ins->host.port,
             ctx->index, ctx->type);


    flb_output_set_context(ins, ctx);
    return 0;
}

int cb_es_flush(void *data, size_t bytes,
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

    /* Convert format */
    pack = es_format(data, bytes, &bytes_out, ctx);
    if (!pack) {
        return -1;
    }

    /* Get upstream connection */
    u_conn = flb_upstream_conn_get(ctx->u);
    if (!u_conn) {
        free(pack);
        return -1;
    }

    /* Compose HTTP Client request */
    c = flb_http_client(u_conn, FLB_HTTP_POST, "/_bulk",
                        pack, bytes_out);
    flb_http_add_header(c, "User-Agent", 10, "Fluent-Bit", 10);
    flb_http_add_header(c, "Content-Type", 12, "application/json", 16);

    ret = flb_http_do(c, &b_sent);
    flb_debug("[out_es] http_do=%i", ret);
    flb_http_client_destroy(c);

    free(pack);

    /* Release the connection */
    flb_upstream_conn_release(u_conn);
    return b_sent;
}

int cb_es_exit(void *data, struct flb_config *config)
{
    struct flb_out_es_config *ctx = data;

    flb_upstream_destroy(ctx->u);
    free(ctx);

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
