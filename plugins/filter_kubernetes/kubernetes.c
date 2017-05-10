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

#include <fluent-bit/flb_filter.h>
#include <fluent-bit/flb_utils.h>

#include "kube_conf.h"
#include "kube_meta.h"
#include "kube_regex.h"

#include <stdio.h>
#include <msgpack.h>

static int cb_kube_init(struct flb_filter_instance *f_ins,
                        struct flb_config *config,
                        void *data)
{
    int ret;
    struct flb_kube *ctx;
    (void) data;

    /* Create configuration context */
    ctx = flb_kube_conf_create(f_ins, config);
    if (!ctx) {
        return -1;
    }

    /* Initialize regex context */
    ret = flb_kube_regex_init(ctx);
    if (ret == -1) {
        flb_kube_conf_destroy(ctx);
        return -1;
    }

    /* Set context */
    flb_filter_set_context(f_ins, ctx);

    /*
     * Get Kubernetes Metadata: we gather this at the beginning
     * as we need this information to process logs in Kubernetes
     * environment, otherwise the service should not start.
     */
    flb_kube_meta_init(ctx, config);

    return 0;
}

static int cb_kube_filter(void *data, size_t bytes,
                          char *tag, int tag_len,
                          void **out_buf, size_t *out_bytes,
                          struct flb_filter_instance *f_ins,
                          void *filter_context,
                          struct flb_config *config)
{
    int i;
    int ret;
    int m_size;
    size_t off = 0;
    char *cache_buf;
    size_t cache_size = 0;
    msgpack_unpacked result;
    msgpack_object time;
    msgpack_object map;
    msgpack_object root;
    msgpack_sbuffer tmp_sbuf;
    msgpack_packer tmp_pck;
    struct flb_kube *ctx = filter_context;
    (void) f_ins;
    (void) config;

    /* Check if we have some cached metadata for the incoming events */
    ret = flb_kube_meta_get(ctx, tag, tag_len, &cache_buf, &cache_size);
    if (ret == -1) {
        return FLB_FILTER_NOTOUCH;
    }

    /* Create temporal msgpack buffer */
    msgpack_sbuffer_init(&tmp_sbuf);
    msgpack_packer_init(&tmp_pck, &tmp_sbuf, msgpack_sbuffer_write);

    /* Iterate each item array and append meta */
    msgpack_unpacked_init(&result);
    while (msgpack_unpack_next(&result, data, bytes, &off)) {
        root = result.data;
        if (root.type != MSGPACK_OBJECT_ARRAY) {
            continue;
        }

        /* get time and map */
        time = root.via.array.ptr[0];
        map  = root.via.array.ptr[1];

        /* Compose the new array */
        msgpack_pack_array(&tmp_pck, 2);
        msgpack_pack_object(&tmp_pck, time);

        m_size = map.via.map.size;
        msgpack_pack_map(&tmp_pck, m_size + 1);
        for (i = 0; i < m_size; i++) {
            msgpack_object k = map.via.map.ptr[i].key;
            msgpack_object v = map.via.map.ptr[i].val;

            msgpack_pack_object(&tmp_pck, k);
            msgpack_pack_object(&tmp_pck, v);
        }

        /* Append Kubernetes metadata */
        msgpack_pack_str(&tmp_pck, 10);
        msgpack_pack_str_body(&tmp_pck, "kubernetes", 10);

        if (cache_size > 0) {
            msgpack_sbuffer_write(&tmp_sbuf, cache_buf, cache_size);
        }
        else {
            msgpack_pack_str(&tmp_pck, 30);
            msgpack_pack_str_body(&tmp_pck, "error connecting to api server", 30);
        }
    }
    msgpack_unpacked_destroy(&result);

    /* link new buffers */
    *out_buf   = tmp_sbuf.data;
    *out_bytes = tmp_sbuf.size;

    return FLB_FILTER_MODIFIED;
}

static int cb_kube_exit(void *data, struct flb_config *config)
{
    struct flb_kube *ctx;

    ctx = data;
    flb_kube_conf_destroy(ctx);

    return 0;
}

struct flb_filter_plugin filter_kubernetes_plugin = {
    .name         = "kubernetes",
    .description  = "Filter to append Kubernetes metadata",
    .cb_init      = cb_kube_init,
    .cb_filter    = cb_kube_filter,
    .cb_exit      = cb_kube_exit,
    .flags        = 0
};
