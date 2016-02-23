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
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <errno.h>

#include <msgpack.h>
#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_network.h>
#include <fluent-bit/flb_pack.h>

#include "td.h"
#include "td_http.h"
#include "td_config.h"

struct flb_output_plugin out_td_plugin;

/*
 * Convert the internal Fluent Bit data representation to the required
 * one by Treasure Data cloud service.
 *
 * This function returns a new msgpack buffer and store the bytes length
 * in the out_size variable.
 */
static char *td_format(void *data, size_t bytes, int *out_size)
{
    int i;
    int ret;
    int n_size;
    size_t off = 0;
    time_t atime;
    char *buf;
    struct msgpack_sbuffer mp_sbuf;
    struct msgpack_packer mp_pck;
    msgpack_unpacked result;
    msgpack_object root;
    msgpack_object map;
    msgpack_sbuffer *sbuf;

    /* Initialize contexts for new output */
    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

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
        buf = malloc(bytes);
        if (!buf) {
            return NULL;
        }

        memcpy(buf, data, bytes);
        *out_size = bytes;
        return buf;
    }

    root = result.data;
    if (root.via.array.size == 0) {
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

        atime = root.via.array.ptr[0].via.u64;
        map   = root.via.array.ptr[1];

        n_size = map.via.map.size + 1;
        msgpack_pack_map(&mp_pck, n_size);
        msgpack_pack_bin(&mp_pck, 4);
        msgpack_pack_bin_body(&mp_pck, "time", 4);
        msgpack_pack_int32(&mp_pck, atime);

        for (i = 0; i < n_size - 1; i++) {
            msgpack_pack_object(&mp_pck, map.via.map.ptr[i].key);
            msgpack_pack_object(&mp_pck, map.via.map.ptr[i].val);
        }
    }
    msgpack_unpacked_destroy(&result);

    /* Create new buffer */
    sbuf = &mp_sbuf;
    *out_size = sbuf->size;
    buf = malloc(sbuf->size);
    if (!buf) {
        return NULL;
    }

    /* set a new buffer and re-initialize our MessagePack context */
    memcpy(buf, sbuf->data, sbuf->size);
    msgpack_sbuffer_destroy(&mp_sbuf);

    return buf;
}

int cb_td_init(struct flb_output_instance *ins, struct flb_config *config,
               void *data)
{
    struct flb_out_td_config *ctx;
    struct flb_io_upstream *upstream;
    (void) data;

    if (!config->file) {
        flb_utils_warn_c("[TD] output requires a configuration file");
        return -1;
    }

    ctx = td_config_init(config->file);
    if (!ctx) {
        flb_utils_warn_c("[TD] Error reading configuration file");
        return -1;
    }

    ins->host.name = strdup("api.treasuredata.com");
    ins->host.port = 443;

    upstream = flb_io_upstream_new(config,
                                   ins->host.name,
                                   ins->host.port,
                                   FLB_IO_TLS, (void *) &ins->tls);
    if (!upstream) {
        free(ctx);
        return -1;
    }
    ctx->u = upstream;

    flb_output_set_context(ins, ctx);
    return 0;
}

int cb_td_flush(void *data, size_t bytes, void *out_context,
                struct flb_config *config)
{
    int n;
    int ret;
    int bytes_out;
    char *pack;
    size_t bytes_sent;
    char buf[1024];
    size_t len;
    char *request;
    struct flb_out_td_config *ctx = out_context;

    /* Convert format */
    pack = td_format(data, bytes, &bytes_out);
    if (!pack) {
        return -1;
    }

    request = td_http_request(pack, bytes_out, &len, ctx, config);
    ret = flb_io_net_write(ctx->u, request, len, &bytes_sent);
    if (ret == -1) {
        perror("write");
    }
    free(request);
    free(pack);

    n = flb_io_net_read(ctx->u, buf, sizeof(buf) - 1);
    if (n > 0) {
        buf[n] = '\0';
        flb_debug("[TD] API server response:\n%s", buf);
    }

    return bytes_sent;
}

/* Plugin reference */
struct flb_output_plugin out_td_plugin = {
    .name           = "td",
    .description    = "Treasure Data",
    .cb_init        = cb_td_init,
    .cb_pre_run     = NULL,
    .cb_flush       = cb_td_flush,
    .flags          = FLB_IO_TLS,
};
