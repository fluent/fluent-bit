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

#include <stdio.h>
#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_utils.h>
#include <cjson.h>

#include <msgpack.h>

#include "nats.h"

int cb_nats_init(struct flb_output_instance *ins, struct flb_config *config,
                   void *data)
{
    struct flb_io_upstream *upstream;
    struct flb_out_nats_config *ctx;

    /* Set default network configuration */
    if (!ins->host.name) {
        ins->host.name = strdup("127.0.0.1");
    }
    if (ins->host.port == 0) {
        ins->host.port = 4222;
    }

    /* Allocate plugin context */
    ctx = malloc(sizeof(struct flb_out_nats_config));
    if (!ctx) {
        perror("malloc");
        return -1;
    }

    /* Prepare an upstream handler */
    upstream = flb_io_upstream_new(config,
                                   ins->host.name,
                                   ins->host.port,
                                   FLB_IO_TCP,
                                   NULL);
    if (!upstream) {
        free(ctx);
        return -1;
    }
    ctx->u   = upstream;
    ctx->ins = ins;
    flb_output_set_context(ins, ctx);

    return 0;
}

int cb_nats_flush(void *data, size_t bytes,
                  struct flb_input_instance *i_ins,
                  void *out_context,
                  struct flb_config *config)
{
    int i;
    int ret;
    int len;
    int n_size;
    size_t off = 0;
    size_t bytes_sent;
    time_t atime;
    json_t *j_root;
    json_t *j_arr;
    char tmp_key[32];
    char tmp_val[256];
    char *tmp_ext;
    char *json_msg;
    char *request;
    int req_len;
    msgpack_object map;
    msgpack_object root;
    msgpack_object m_key;
    msgpack_object m_val;
    msgpack_packer   mp_pck;
    msgpack_sbuffer  mp_sbuf;
    msgpack_unpacked result;
    struct flb_out_nats_config *ctx = out_context;

    /* Before to flush the content check if we need to start the handshake */
    if (ctx->u->fd <= 0) {
        ret = flb_io_net_write(ctx->u,
                               NATS_CONNECT,
                               sizeof(NATS_CONNECT) - 1,
                               &bytes_sent);
        if (ret == -1) {
            return -1;
        }
    }

    /* Convert MsgPack to JSON */
    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);
    msgpack_unpacked_init(&result);

    j_root = json_create_array();

    while (msgpack_unpack_next(&result, data, bytes, &off)) {
        if (result.data.type != MSGPACK_OBJECT_ARRAY) {
            continue;
        }

        j_arr = json_create_array();

        root = result.data;
        if (root.via.array.size != 2) {
            continue;
        }

        atime  = root.via.array.ptr[0].via.u64;
        map    = root.via.array.ptr[1];
        n_size = map.via.map.size + 1;

        json_add_to_array(j_arr, json_create_number(atime));

        json_t *j_obj = json_create_object();

        json_add_to_object(j_obj, "tag",
                           json_create_string(i_ins->tag));

        for (i = 0; i < n_size - 1; i++) {
            m_key = map.via.map.ptr[i].key;
            m_val = map.via.map.ptr[i].val;

            memcpy(tmp_key, m_key.via.bin.ptr, m_key.via.bin.size);
            tmp_key[m_key.via.bin.size] = '\0';

            if (m_val.type == MSGPACK_OBJECT_NIL) {
                json_add_to_object(j_obj, tmp_key,
                                   json_create_null());
            }
            else if (m_val.type == MSGPACK_OBJECT_BOOLEAN) {
                json_add_to_object(j_obj, tmp_key,
                                   json_create_bool(m_val.via.boolean));
            }
            else if (m_val.type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
                json_add_to_object(j_obj, tmp_key,
                                   json_create_number(m_val.via.u64));
            }
            else if (m_val.type == MSGPACK_OBJECT_NEGATIVE_INTEGER) {
                json_add_to_object(j_obj, tmp_key,
                                   json_create_number(m_val.via.i64));
            }
            else if (m_val.type == MSGPACK_OBJECT_FLOAT) {
                json_add_to_object(j_obj, tmp_key,
                                   json_create_number(m_val.via.f64));
            }
            else if (m_val.type == MSGPACK_OBJECT_STR) {
                if (m_val.via.str.size > sizeof(tmp_val)) {
                    tmp_ext = malloc(m_val.via.str.size);
                }
                else {
                    tmp_ext = tmp_val;
                }
                memcpy(tmp_ext, m_val.via.str.ptr, m_val.via.str.size);
                tmp_ext[m_val.via.str.size] = '\0';

                json_add_to_object(j_obj, tmp_key, json_create_string(tmp_ext));
                if (tmp_ext != tmp_val) {
                    free(tmp_ext);
                }
            }
            else if (m_val.type == MSGPACK_OBJECT_BIN) {
                if (m_val.via.bin.size > sizeof(tmp_val)) {
                    tmp_ext = malloc(m_val.via.bin.size);
                }
                else {
                    tmp_ext = tmp_val;
                }
                memcpy(tmp_ext, m_val.via.bin.ptr, m_val.via.bin.size);
                tmp_ext[m_val.via.bin.size] = '\0';

                json_add_to_object(j_obj, tmp_key, json_create_string(tmp_ext));
                if (tmp_ext != tmp_val) {
                    free(tmp_ext);
                }
            }
        }

        json_add_to_array(j_arr, j_obj);
        json_add_to_array(j_root, j_arr);
    }
    msgpack_unpacked_destroy(&result);

    json_msg = json_print_unformatted(j_root);
    json_delete(j_root);

    /* Compose the NATS Publish request */
    len = strlen(json_msg);
    request = malloc(len + 32);
    req_len = snprintf(request, len + 32,
                       "PUB %s %i\r\n%s\r\n",
                       i_ins->tag, len, json_msg);
    free(json_msg);

    ret = flb_io_net_write(ctx->u, request, req_len, &bytes_sent);
    if (ret == -1) {
        perror("write");
    }
    free(request);

    return bytes_sent;
}

int cb_nats_exit(void *data, struct flb_config *config)
{
    (void) config;
    struct flb_out_nats_config *ctx = data;

    flb_io_upstream_destroy(ctx->u);
    free(ctx);

    return 0;
}

struct flb_output_plugin out_nats_plugin = {
    .name         = "nats",
    .description  = "NATS Server",
    .cb_init      = cb_nats_init,
    .cb_flush     = cb_nats_flush,
    .cb_exit      = cb_nats_exit,
    .flags        = FLB_OUTPUT_NET,
};
