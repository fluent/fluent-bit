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
#include <fluent-bit/flb_hash.h>
#include <fluent-bit/flb_http_client.h>

#include "kube_meta.h"

struct kube_meta {
    msgpack_packer *pck;
};

static void cb_results(unsigned char *name, unsigned char *value,
                       size_t vlen, void *data)
{
    int len;
    struct kube_meta *meta = data;

    len = strlen((char *)name);
    msgpack_pack_str(meta->pck, len);
    msgpack_pack_str_body(meta->pck, (char *) name, len);
    msgpack_pack_str(meta->pck, vlen);
    msgpack_pack_str_body(meta->pck, (char *) value, vlen);
}

static inline int tag_to_meta(struct flb_kube *ctx, char *tag, int tag_len,
                              char **out_buf, size_t *out_size)
{
    ssize_t n;
    struct flb_regex_search result;
    struct kube_meta meta;
    msgpack_sbuffer tmp_sbuf;
    msgpack_packer tmp_pck;

    n = flb_regex_do(ctx->regex_tag, (unsigned char *) tag, tag_len, &result);
    if (n <= 0) {
        return -1;
    }

    /* Initialize msgpack buffers */
    msgpack_sbuffer_init(&tmp_sbuf);
    msgpack_packer_init(&tmp_pck, &tmp_sbuf, msgpack_sbuffer_write);
    msgpack_pack_map(&tmp_pck, n);
    meta.pck = &tmp_pck;

    flb_regex_parse(ctx->regex_tag, &result, cb_results, &meta);
    *out_buf = tmp_sbuf.data;
    *out_size = tmp_sbuf.size;

    return 0;
}

/* FIXME: retrieve labels from API Server */
int flb_kube_meta_fetch(struct flb_kube *ctx)
{
    (void) ctx;
    return 0;
}

int flb_kube_meta_get(struct flb_kube *ctx,
                      char *tag, int tag_len,
                      char **out_buf, size_t *out_size)
{
    int id;
    int ret;

    ret = flb_hash_get(ctx->hash_table, tag, tag_len,
                       out_buf, out_size);
    if (ret == -1) {
        /* The entry was not found, create it */
        ret = tag_to_meta(ctx, tag, tag_len, out_buf, out_size);
        if (ret != 0) {
            return -1;
        }

        id = flb_hash_add(ctx->hash_table,
                          tag, tag_len,
                          *out_buf, *out_size);
        if (id >= 0) {
            /*
             * Release the original buffer created on tag_to_meta() as a new
             * copy have been generated into the hash table, then re-set
             * the outgoing buffer and size.
             */
            flb_free(*out_buf);
            flb_hash_get_by_id(ctx->hash_table, id, out_buf, out_size);
            return 0;
        }
    }

    return 0;
}
