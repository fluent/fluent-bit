/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
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

#include <fluent-bit/flb_filter.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_parser.h>

#include "kube_conf.h"
#include "kube_meta.h"
#include "kube_regex.h"
#include "kube_property.h"

#include <stdio.h>
#include <msgpack.h>

/* Merge status used by merge_log_handler() */
#define MERGE_UNESCAPED   0 /* merge unescaped string in temporal buffer */
#define MERGE_PARSED      1 /* merge parsed string (log_buf)             */
#define MERGE_BINARY      2 /* merge direct binary object (v)            */

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

static int merge_log_handler(msgpack_object o,
                             struct flb_parser *parser,
                             void **out_buf, size_t *out_size,
                             struct flb_time *log_time,
                             struct flb_kube *ctx)
{
    int i;
    int ret;
    int size;
    int new_size;
    int unesc_len = 0;
    char *tmp;

    /* Reset vars */
    *out_buf = NULL;
    *out_size = 0;
    ctx->unesc_buf_len = 0;

    /* Allocate more space if required */
    if (o.via.str.size >= ctx->unesc_buf_size) {
        new_size = o.via.str.size + 1;
        tmp = flb_realloc(ctx->unesc_buf, new_size);
        if (tmp) {
            ctx->unesc_buf = tmp;
            ctx->unesc_buf_size = new_size;
        }
        else {
            flb_errno();
            return -1;
        }
    }

    /*
     * Check where to cut the string if common ending bytes like \r or \n
     * exists.
     */
    size = o.via.str.size;
    for (i = size - 1; i > 0; i--) {
        if (o.via.str.ptr[i] == '\n') {
            size -= 1;
            i--;
            continue;
        }

        if (o.via.str.ptr[i - 1] == '\\' &&
            (o.via.str.ptr[i] == 'n' || o.via.str.ptr[i] == 'r')) {
            size -= 2;
            i--;
        }
        else {
            break;
        }
    }

    /* Unescape application string */
    unesc_len = unescape_string((char *) o.via.str.ptr,
                                size, &ctx->unesc_buf);
    ctx->unesc_buf_len = unesc_len;

    ret = -1;
    if (parser) {
        ret = flb_parser_do(parser, ctx->unesc_buf, unesc_len,
                            out_buf, out_size, log_time);
        if (ret >= 0) {
            if (flb_time_to_double(log_time) == 0) {
                flb_time_get(log_time);
            }
            return MERGE_PARSED;
        }
    }
    else {
        ret = flb_pack_json(ctx->unesc_buf, unesc_len,
                            (char **) out_buf, out_size);
    }

    if (ret == -1) {
        flb_debug("[filter_kube] could not merge JSON log as requested");
        return MERGE_UNESCAPED;
    }

    return MERGE_PARSED;
}

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

static int pack_map_content(msgpack_packer *pck, msgpack_sbuffer *sbuf,
                            msgpack_object source_map,
                            char *kube_buf, size_t kube_size,
                            struct flb_kube_meta *meta,
                            struct flb_parser *parser,
                            struct flb_kube *ctx)
{
    int i;
    int map_size;
    int merge_status = -1;
    int new_map_size = 0;
    int log_index = -1;
    int log_buf_entries = 0;
    size_t off = 0;
    void *log_buf = NULL;
    size_t log_size = 0;
    msgpack_unpacked result;
    msgpack_object k;
    msgpack_object v;
    msgpack_object root;
    struct flb_time log_time = {0};

    /* Original map size */
    map_size = source_map.via.map.size;

    /* If merge_log is enabled, we need to lookup the 'log' field */
    if (ctx->merge_log == FLB_TRUE) {
        for (i = 0; i < map_size; i++) {
            k = source_map.via.map.ptr[i].key;

            /* Validate 'log' field */
            if (k.via.str.size == 3 &&
                strncmp(k.via.str.ptr, "log", 3) == 0) {
                log_index = i;
                break;
            }
        }
    }

    if (flb_time_to_double(&log_time) == 0) {
        flb_time_get(&log_time);
    }

    /*
     * If a log_index exists, the application log content inside the Docker JSON
     * map is a escaped string. Proceed to reserve a temporal buffer and create
     * an unescaped version.
     */
    if (log_index != -1) {
        v = source_map.via.map.ptr[log_index].val;
        if (v.type == MSGPACK_OBJECT_STR) {
            merge_status = merge_log_handler(v, parser,
                                             &log_buf, &log_size, &log_time,
                                             ctx);
        }
        else if (v.type == MSGPACK_OBJECT_MAP) {
            /* This is the easiest way, no extra processing required */
            merge_status = MERGE_BINARY;
        }
    }
    else {

    }

    /* Determinate the size of the new map */
    new_map_size = map_size;

    /* If a merged json exists, check the number of entries in that new map */
    if (log_index != -1) {
        if (merge_status == MERGE_PARSED) {
            off = 0;
            msgpack_unpacked_init(&result);
            msgpack_unpack_next(&result, log_buf, log_size, &off);
            root = result.data;
            log_buf_entries = root.via.map.size;
            msgpack_unpacked_destroy(&result);
        }
        else if (merge_status == MERGE_BINARY) {
            /* object 'v' represents the original binary log */
            log_buf_entries = v.via.map.size;
        }
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
        if (log_index == i &&
            (merge_status == MERGE_UNESCAPED || merge_status == MERGE_PARSED)) {
            msgpack_pack_object(pck, k);
            msgpack_pack_str(pck, ctx->unesc_buf_len);
            msgpack_pack_str_body(pck, ctx->unesc_buf, ctx->unesc_buf_len);
        }
        else { /* MERGE_BINARY ? */
            msgpack_pack_object(pck, k);
            msgpack_pack_object(pck, v);
        }
    }

    /* Merge Log */
    if (log_index != -1) {
        if (merge_status == MERGE_PARSED) {
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
        else if (merge_status == MERGE_BINARY) {
            msgpack_object bin_map;
            bin_map = source_map.via.map.ptr[log_index].val;
            for (i = 0; i < bin_map.via.map.size; i++) {
                k = bin_map.via.map.ptr[i].key;
                v = bin_map.via.map.ptr[i].val;
                msgpack_pack_object(pck, k);
                msgpack_pack_object(pck, v);
            }
        }
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
    size_t pre = 0;
    size_t off = 0;
    char *cache_buf = NULL;
    size_t cache_size = 0;
    msgpack_unpacked result;
    msgpack_object time;
    msgpack_object map;
    msgpack_object root;
    msgpack_sbuffer tmp_sbuf;
    msgpack_packer tmp_pck;
    struct flb_parser *parser = NULL;
    struct flb_kube *ctx = filter_context;
    struct flb_kube_meta meta = {0};
    struct flb_kube_props props = {0};
    (void) f_ins;
    (void) config;

    if (ctx->use_journal == FLB_FALSE) {
        /* Check if we have some cached metadata for the incoming events */
        ret = flb_kube_meta_get(ctx,
                                tag, tag_len,
                                data, bytes,
                                &cache_buf, &cache_size, &meta, &props);
        if (ret == -1) {
            flb_kube_prop_destroy(&props);
            return FLB_FILTER_NOTOUCH;
        }

        if (props.parser != NULL) {
            parser = flb_parser_get(props.parser, config);
        }

        if (props.exclude == FLB_TRUE) {
            *out_buf   = NULL;
            *out_bytes = 0;
            flb_kube_prop_destroy(&props);
            return FLB_FILTER_MODIFIED;
        }
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

        /*
         * Journal entries can be origined by different Pods, so we are forced
         * to parse and check it metadata.
         *
         * note: when the source is in_tail the situation is different since all
         * records passed to the filter have a unique source log file.
         */
        if (ctx->use_journal == FLB_TRUE) {
            parser = NULL;
            cache_buf = NULL;
            memset(&props, '\0', sizeof(struct flb_kube_props));

            ret = flb_kube_meta_get(ctx,
                                    tag, tag_len,
                                    data + pre, off - pre,
                                    &cache_buf, &cache_size, &meta, &props);
            if (ret == -1) {
                flb_kube_prop_destroy(&props);
                return FLB_FILTER_NOTOUCH;
            }

            if (props.parser != NULL) {
                parser = flb_parser_get(props.parser, config);
            }

            if (props.exclude == FLB_TRUE) {
                /* Skip this record */
                continue;
            }

            pre = off;
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
                               &meta, parser, ctx);
        if (ret != 0) {
            msgpack_sbuffer_destroy(&tmp_sbuf);
            msgpack_unpacked_destroy(&result);
            if (ctx->dummy_meta == FLB_TRUE) {
                flb_free(cache_buf);
            }

            flb_kube_meta_release(&meta);
            flb_kube_prop_destroy(&props);
            return FLB_FILTER_NOTOUCH;
        }

        if (ctx->use_journal == FLB_TRUE) {
            flb_kube_meta_release(&meta);
        }
    }
    msgpack_unpacked_destroy(&result);

    /* Release meta fields */
    if (ctx->use_journal == FLB_FALSE) {
        flb_kube_meta_release(&meta);
    }

    /* link new buffers */
    *out_buf   = tmp_sbuf.data;
    *out_bytes = tmp_sbuf.size;

    if (ctx->dummy_meta == FLB_TRUE) {
        flb_free(cache_buf);
    }

    flb_kube_prop_destroy(&props);
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
