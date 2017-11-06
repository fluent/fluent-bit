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
#include <fluent-bit/flb_pack.h>

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

static int unescape_string(char *buf, int buf_len, char **unesc_buf)
{
    int i = 0;
    int j = 0;
    char *p;
    char n;

    p = *unesc_buf;
    while (i < buf_len) {
        if (buf[i] == '\\') {
            if (i + 1 < buf_len) {
                n = buf[i + 1];
                if (n != 'a' && n != 'b' &&
                    n != 't' && n != 'n' &&
                    n != 'v' && n != 'f' &&
                    n != 'r') {
                    i++;
                }
            }
            else {
                i++;
            }
        }
        p[j++] = buf[i++];
    }
    p[j] = '\0';
    return j;
}

static int pack_map_content(msgpack_packer *pck, msgpack_sbuffer *sbuf,
                            msgpack_object source_map,
                            char *kube_buf, size_t kube_size,
                            struct flb_kube_meta *meta, struct flb_kube *ctx)
{
    int i;
    int ret;
    int new_size;
    int map_size;
    int size;
    int new_map_size = 0;
    int log_index = -1;
    int log_size = 0;
    int json_size = 0;
    int log_buf_entries = 0;
    size_t off = 0;
    char *tmp;
    char *log_buf = NULL;
    msgpack_unpacked result;
    msgpack_object k;
    msgpack_object v;
    msgpack_object root;

    /* Original map size */
    map_size = source_map.via.map.size;

    /* If merge_json_log is enabled, we need to lookup the 'log' field */
    if (ctx->merge_json_log == FLB_TRUE) {
        for (i = 0; i < map_size; i++) {
            k = source_map.via.map.ptr[i].key;

            /* Validate 'log' field */
            if (k.via.str.size == 3 &&
                strncmp(k.via.str.ptr, "log", 3) == 0) {
                /* do we have a JSON map ? */
                v = source_map.via.map.ptr[i].val;
                if (v.via.str.ptr[0] != '{') {
                    /* not a json map, no merge can be done */
                    break;
                }

                log_index = i;
                break;
            }
        }
    }

    /*
     * If a log_index exists, means that a JSON map is inside a Docker json
     * like a escaped string. Before to pack it we need to convert it to a
     * native JSON structured format.
     */
    if (log_index != -1) {
        v = source_map.via.map.ptr[log_index].val;
        if (v.via.str.size >= ctx->merge_json_buf_size) {
            new_size = v.via.str.size + 1;
            tmp = flb_realloc(ctx->merge_json_buf, new_size);
            if (tmp) {
                ctx->merge_json_buf = tmp;
                ctx->merge_json_buf_size = new_size;
            }
            else {
                flb_errno();
                return -1;
            }
        }

        /* Do not process ending \n if set at the end of the map */
        size = v.via.str.size;
        for (i = size - 1; i > 0; i--) {
            if (v.via.str.ptr[i] == '}') {
                size = i + 1;
                break;
            }
        }
        json_size = unescape_string((char *) v.via.str.ptr,
                                    size, &ctx->merge_json_buf);
        ret = flb_pack_json(ctx->merge_json_buf, json_size,
                            &log_buf, &log_size);
        if (ret != 0) {
            flb_warn("[filter_kube] could not pack merged json");
        }
    }

    /* Determinate the size of the new map */
    new_map_size = map_size;

    /* If a merged json exists, check the number of entries in that new map */
    if (log_buf && log_index != -1) {
        off = 0;
        msgpack_unpacked_init(&result);
        msgpack_unpack_next(&result, log_buf, log_size, &off);
        root = result.data;
        log_buf_entries = root.via.map.size;
        msgpack_unpacked_destroy(&result);
    }

    /* Kubernetes metadata */
    if (kube_buf && kube_size > 0) {
        new_map_size++;
    }

    /* Start packaging the final map */
    if (ctx->merge_json_key != NULL) {
        /* Make room for one new key that will hold the original log entries */
        new_map_size++;
    }
    else {
        new_map_size += log_buf_entries;
    }
    msgpack_pack_map(pck, new_map_size);

    /* Original map */
    for (i = 0; i < map_size; i++) {
        k = source_map.via.map.ptr[i].key;
        v = source_map.via.map.ptr[i].val;

        /*
         * If the original 'log' field was unescaped and converted to
         * msgpack properly, re-pack the new string version to avoid
         * multiple escape sequences in outgoing plugins.
         */
        if (log_buf && log_index == i) {
            msgpack_pack_object(pck, k);
            msgpack_pack_str(pck, json_size);
            msgpack_pack_str_body(pck, ctx->merge_json_buf, json_size);
        }
        else {
            msgpack_pack_object(pck, k);
            msgpack_pack_object(pck, v);
        }
    }

    /* Merged JSON */
    if (log_buf && log_index != -1) {
        if (ctx->merge_json_key && log_buf_entries > 0) {
            msgpack_pack_str(pck, ctx->merge_json_key_len);
            msgpack_pack_str_body(pck, ctx->merge_json_key,
                                  ctx->merge_json_key_len);
            msgpack_pack_map(pck, log_buf_entries);
        }

        off = 0;
        msgpack_unpacked_init(&result);
        msgpack_unpack_next(&result, log_buf, log_size, &off);
        root = result.data;
        for (i = 0; i < log_buf_entries; i++) {
            k = root.via.map.ptr[i].key;
            v = root.via.map.ptr[i].val;
            msgpack_pack_object(pck, k);
            msgpack_pack_object(pck, v);
        }
        msgpack_unpacked_destroy(&result);
        flb_free(log_buf);
    }

    /* Kubernetes */
    if (kube_buf && kube_size > 0) {
        msgpack_pack_str(pck, 10);
        msgpack_pack_str_body(pck, "kubernetes", 10);

        off = 0;
        msgpack_unpacked_init(&result);
        msgpack_unpack_next(&result, kube_buf, kube_size, &off);
        root = result.data;

        /* root points to a map, calc the final size */
        map_size = root.via.map.size;
        map_size += meta->skip;

        /* Pack cached kube buf entries */
        msgpack_pack_map(pck, map_size);
        for (i = 0; i < root.via.map.size; i++) {
            k = root.via.map.ptr[i].key;
            v = root.via.map.ptr[i].val;
            msgpack_pack_object(pck, k);
            msgpack_pack_object(pck, v);
        }
        msgpack_unpacked_destroy(&result);

        /* Pack meta */
        if (meta->container_name != NULL) {
            msgpack_pack_str(pck, 14);
            msgpack_pack_str_body(pck, "container_name", 14);
            msgpack_pack_str(pck, meta->container_name_len);
            msgpack_pack_str_body(pck, meta->container_name,
                                  meta->container_name_len);
        }
        if (meta->docker_id != NULL) {
            msgpack_pack_str(pck, 9);
            msgpack_pack_str_body(pck, "docker_id", 9);
            msgpack_pack_str(pck, meta->docker_id_len);
            msgpack_pack_str_body(pck, meta->docker_id,
                                  meta->docker_id_len);
        }
        if (meta->container_hash != NULL) {
            msgpack_pack_str(pck, 14);
            msgpack_pack_str_body(pck, "container_hash", 14);
            msgpack_pack_str(pck, meta->container_hash_len);
            msgpack_pack_str_body(pck, meta->container_hash,
                                  meta->container_hash_len);
        }
    }

    return 0;
}

static int cb_kube_filter(void *data, size_t bytes,
                          char *tag, int tag_len,
                          void **out_buf, size_t *out_bytes,
                          struct flb_filter_instance *f_ins,
                          void *filter_context,
                          struct flb_config *config)
{
    int ret;
    size_t off = 0;
    char *cache_buf = NULL;
    size_t cache_size = 0;
    msgpack_unpacked result;
    msgpack_object time;
    msgpack_object map;
    msgpack_object root;
    msgpack_sbuffer tmp_sbuf;
    msgpack_packer tmp_pck;
    struct flb_kube *ctx = filter_context;
    struct flb_kube_meta meta = {0};

    (void) f_ins;
    (void) config;

    /* Check if we have some cached metadata for the incoming events */
    ret = flb_kube_meta_get(ctx,
                            tag, tag_len,
                            data, bytes,
                            &cache_buf, &cache_size, &meta);
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

        ret = pack_map_content(&tmp_pck, &tmp_sbuf,
                               map,
                               cache_buf, cache_size,
                               &meta, ctx);
        if (ret != 0) {
            msgpack_sbuffer_destroy(&tmp_sbuf);
            msgpack_unpacked_destroy(&result);
            if (ctx->dummy_meta == FLB_TRUE) {
                flb_free(cache_buf);
            }
            return FLB_FILTER_NOTOUCH;
        }
    }
    msgpack_unpacked_destroy(&result);

    /* Release meta fields */
    flb_kube_meta_release(&meta);

    /* link new buffers */
    *out_buf   = tmp_sbuf.data;
    *out_bytes = tmp_sbuf.size;

    if (ctx->dummy_meta == FLB_TRUE) {
        flb_free(cache_buf);
    }
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
