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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_filter_plugin.h>
#include <fluent-bit/flb_filter.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_parser.h>
#include <fluent-bit/flb_unescape.h>

#include "kube_conf.h"
#include "kube_meta.h"
#include "kube_regex.h"
#include "kube_property.h"

#include <stdio.h>
#include <msgpack.h>

/* Merge status used by merge_log_handler() */
#define MERGE_NONE        0 /* merge unescaped string in temporal buffer */
#define MERGE_PARSED      1 /* merge parsed string (log_buf)             */
#define MERGE_MAP         2 /* merge direct binary object (v)            */

static int get_stream(msgpack_object_map map)
{
    int i;
    msgpack_object k;
    msgpack_object v;

    for (i = 0; i < map.size; i++) {
        k = map.ptr[i].key;
        v = map.ptr[i].val;

        if (k.type == MSGPACK_OBJECT_STR &&
            strncmp(k.via.str.ptr, "stream", k.via.str.size) == 0) {
            if (strncmp(v.via.str.ptr, "stdout", v.via.str.size) == 0) {
                return FLB_KUBE_PROP_STREAM_STDOUT;
            }
            else if (strncmp(v.via.str.ptr, "stderr", v.via.str.size) == 0) {
                return FLB_KUBE_PROP_STREAM_STDERR;
            }
            else {
               return FLB_KUBE_PROP_STREAM_UNKNOWN;
            }
        }
    }

    return FLB_KUBE_PROP_NO_STREAM;
}

static int value_trim_size(msgpack_object o)
{
    int i;
    int size = o.via.str.size;

    for (i = size - 1; i > 0; i--) {
        if (o.via.str.ptr[i] == '\n') {
            size -= 1;
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

    return size;
}

static int merge_log_handler(msgpack_object o,
                             struct flb_parser *parser,
                             void **out_buf, size_t *out_size,
                             struct flb_time *log_time,
                             struct flb_kube *ctx)
{
    int ret;
    int new_size;
    int root_type;
    char *tmp;

    /* Reset vars */
    *out_buf = NULL;
    *out_size = 0;

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

    /* Copy the string value and append the required NULL byte */
    ctx->unesc_buf_len = (int) o.via.str.size;
    memcpy(ctx->unesc_buf, o.via.str.ptr, o.via.str.size);
    ctx->unesc_buf[ctx->unesc_buf_len] = '\0';

    ret = -1;

    /* Parser set by Annotation */
    if (parser) {
        ret = flb_parser_do(parser, ctx->unesc_buf, ctx->unesc_buf_len,
                            out_buf, out_size, log_time);
        if (ret >= 0) {
            if (flb_time_to_double(log_time) == 0) {
                flb_time_get(log_time);
            }
            return MERGE_PARSED;
        }
    }
    else if (ctx->merge_parser) { /* Custom parser 'merge_parser' option */
        ret = flb_parser_do(ctx->merge_parser,
                            ctx->unesc_buf, ctx->unesc_buf_len,
                            out_buf, out_size, log_time);
        if (ret >= 0) {
            if (flb_time_to_double(log_time) == 0) {
                flb_time_get(log_time);
            }
            return MERGE_PARSED;
        }
    }
    else { /* Default JSON parser */
        ret = flb_pack_json(ctx->unesc_buf, ctx->unesc_buf_len,
                            (char **) out_buf, out_size, &root_type);
        if (ret == 0 && root_type != FLB_PACK_JSON_OBJECT) {
            flb_plg_debug(ctx->ins, "could not merge JSON, root_type=%i",
                      root_type);
            flb_free(*out_buf);
            return MERGE_NONE;
        }
    }

    if (ret == -1) {
        flb_plg_debug(ctx->ins, "could not merge JSON log as requested");
        return MERGE_NONE;
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
                            const char *kube_buf, size_t kube_size,
                            struct flb_kube_meta *meta,
                            struct flb_time *time_lookup,
                            struct flb_parser *parser,
                            struct flb_kube *ctx)
{
    int i;
    int map_size = 0;
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
    struct flb_time log_time;

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

    /* reset */
    flb_time_zero(&log_time);

    /*
     * If a log_index exists, the application log content inside the
     * Docker JSON map is a escaped string. Proceed to reserve a temporal
     * buffer and create an unescaped version.
     */
    if (log_index != -1) {
        v = source_map.via.map.ptr[log_index].val;
        if (v.type == MSGPACK_OBJECT_MAP) {
            /* This is the easiest way, no extra processing required */
            merge_status = MERGE_MAP;
        }
        else if (v.type == MSGPACK_OBJECT_STR) {
            merge_status = merge_log_handler(v, parser,
                                             &log_buf, &log_size,
                                             &log_time, ctx);
        }
    }

    /* Append record timestamp */
    if (merge_status == MERGE_PARSED) {
        if (flb_time_to_double(&log_time) == 0.0) {
            flb_time_append_to_msgpack(time_lookup, pck, 0);
        }
        else {
            flb_time_append_to_msgpack(&log_time, pck, 0);
        }
    }
    else {
        flb_time_append_to_msgpack(time_lookup, pck, 0);
    }

    /* Determinate the size of the new map */
    new_map_size = map_size;

    /* If a merged status exists, check the number of entries to merge */
    if (log_index != -1) {
        if (merge_status == MERGE_PARSED) {
            off = 0;
            msgpack_unpacked_init(&result);
            msgpack_unpack_next(&result, log_buf, log_size, &off);
            root = result.data;
            if (root.type == MSGPACK_OBJECT_MAP) {
                log_buf_entries = root.via.map.size;
            }
            msgpack_unpacked_destroy(&result);
        }
        else if (merge_status == MERGE_MAP) {
            /* object 'v' represents the original binary log */
            log_buf_entries = v.via.map.size;
        }
    }

    /* Kubernetes metadata */
    if (kube_buf && kube_size > 0) {
        new_map_size++;
    }

    if (log_buf_entries > 0) {
        if (ctx->merge_log_key != NULL) {
            new_map_size++;
        }
        else {
            new_map_size += log_buf_entries;
        }
    }

    if ((merge_status == MERGE_PARSED || merge_status == MERGE_MAP) &&
        ctx->keep_log == FLB_FALSE) {
        new_map_size--;
    }

    /* Pack Map */
    msgpack_pack_map(pck, new_map_size);

    /* Original map */
    for (i = 0; i < map_size; i++) {
        k = source_map.via.map.ptr[i].key;
        v = source_map.via.map.ptr[i].val;

        /*
         * If log_index is set, means a merge log is a requirement but
         * will depend on merge_status. If the parsing failed we cannot
         * merge so we keep the 'log' key/value.
         */
        if (log_index == i) {
            if (ctx->keep_log == FLB_TRUE) {
                msgpack_pack_object(pck, k);
                if (merge_status == MERGE_NONE || merge_status == MERGE_PARSED){
                    msgpack_pack_str(pck, ctx->unesc_buf_len);
                    msgpack_pack_str_body(pck, ctx->unesc_buf,
                                          ctx->unesc_buf_len);
                }
                else {
                    msgpack_pack_object(pck, v);
                }
            }
            else if (merge_status == MERGE_NONE) {
                msgpack_pack_object(pck, k);
                msgpack_pack_object(pck, v);
            }
        }
        else {
            msgpack_pack_object(pck, k);
            msgpack_pack_object(pck, v);
        }
    }

    /* Merge Log */
    if (log_index != -1) {
        if (merge_status == MERGE_PARSED) {
            if (ctx->merge_log_key && log_buf_entries > 0) {
                msgpack_pack_str(pck, flb_sds_len(ctx->merge_log_key));
                msgpack_pack_str_body(pck, ctx->merge_log_key,
                                      flb_sds_len(ctx->merge_log_key));
                msgpack_pack_map(pck, log_buf_entries);
            }

            off = 0;
            msgpack_unpacked_init(&result);
            msgpack_unpack_next(&result, log_buf, log_size, &off);
            root = result.data;

            for (i = 0; i < log_buf_entries; i++) {
                k = root.via.map.ptr[i].key;
                msgpack_pack_object(pck, k);

                v = root.via.map.ptr[i].val;

                /*
                 * If this is the last string value, trim any remaining
                 * break line or return carrier character.
                 */
                if (v.type == MSGPACK_OBJECT_STR &&
                    ctx->merge_log_trim == FLB_TRUE) {
                    int s = value_trim_size(v);
                    msgpack_pack_str(pck, s);
                    msgpack_pack_str_body(pck, v.via.str.ptr, s);
                }
                else {
                    msgpack_pack_object(pck, v);
                }
            }
            msgpack_unpacked_destroy(&result);
            flb_free(log_buf);
        }
        else if (merge_status == MERGE_MAP) {
            msgpack_object map;

            if (ctx->merge_log_key && log_buf_entries > 0) {
                msgpack_pack_str(pck, flb_sds_len(ctx->merge_log_key));
                msgpack_pack_str_body(pck, ctx->merge_log_key,
                                      flb_sds_len(ctx->merge_log_key));
                msgpack_pack_map(pck, log_buf_entries);
            }

            map = source_map.via.map.ptr[log_index].val;
            for (i = 0; i < map.via.map.size; i++) {
                k = map.via.map.ptr[i].key;
                v = map.via.map.ptr[i].val;
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
        msgpack_pack_object(pck, result.data);
        msgpack_unpacked_destroy(&result);
    }

    return 0;
}

static int cb_kube_filter(const void *data, size_t bytes,
                          const char *tag, int tag_len,
                          void **out_buf, size_t *out_bytes,
                          struct flb_filter_instance *f_ins,
                          void *filter_context,
                          struct flb_config *config)
{
    int ret;
    size_t pre = 0;
    size_t off = 0;
    char *dummy_cache_buf = NULL;
    const char *cache_buf = NULL;
    size_t cache_size = 0;
    msgpack_unpacked result;
    msgpack_object map;
    msgpack_object root;
    msgpack_sbuffer tmp_sbuf;
    msgpack_packer tmp_pck;
    msgpack_object *obj;
    struct flb_parser *parser = NULL;
    struct flb_kube *ctx = filter_context;
    struct flb_kube_meta meta = {0};
    struct flb_kube_props props = {0};
    struct flb_time time_lookup;
    (void) f_ins;
    (void) config;

    if (ctx->use_journal == FLB_FALSE || ctx->dummy_meta == FLB_TRUE) {
        if (ctx->dummy_meta == FLB_TRUE) {
            ret = flb_kube_dummy_meta_get(&dummy_cache_buf, &cache_size);
            cache_buf = dummy_cache_buf;
        }
        else {
            /* Check if we have some cached metadata for the incoming events */
            ret = flb_kube_meta_get(ctx,
                                    tag, tag_len,
                                    data, bytes,
                                    &cache_buf, &cache_size, &meta, &props);
        }
        if (ret == -1) {
            return FLB_FILTER_NOTOUCH;
        }
    }

    /* Create temporal msgpack buffer */
    msgpack_sbuffer_init(&tmp_sbuf);
    msgpack_packer_init(&tmp_pck, &tmp_sbuf, msgpack_sbuffer_write);

    /* Iterate each item array and append meta */
    msgpack_unpacked_init(&result);
    while (msgpack_unpack_next(&result, data, bytes, &off) == MSGPACK_UNPACK_SUCCESS) {
        root = result.data;

        if (root.type != MSGPACK_OBJECT_ARRAY ||
            root.via.array.size != 2 ||
            root.via.array.ptr[1].type != MSGPACK_OBJECT_MAP) {
            flb_plg_warn(ctx->ins, "unexpected record format");
            continue;
        }

        /*
         * Journal entries can be origined by different Pods, so we are forced
         * to parse and check it metadata.
         *
         * note: when the source is in_tail the situation is different since all
         * records passed to the filter have a unique source log file.
         */
        if (ctx->use_journal == FLB_TRUE && ctx->dummy_meta == FLB_FALSE) {
            ret = flb_kube_meta_get(ctx,
                                    tag, tag_len,
                                    (char *) data + pre, off - pre,
                                    &cache_buf, &cache_size, &meta, &props);
            if (ret == -1) {
                continue;
            }

            pre = off;
        }

        parser = NULL;

        switch (get_stream(root.via.array.ptr[1].via.map)) {
        case FLB_KUBE_PROP_STREAM_STDOUT:
            {
                if (props.stdout_exclude == FLB_TRUE) {
                    /* Skip this record */
                    if (ctx->use_journal == FLB_TRUE) {
                        flb_kube_meta_release(&meta);
                    }
                    continue;
                }
                if (props.stdout_parser != NULL) {
                    parser = flb_parser_get(props.stdout_parser, config);
                }
            }
            break;
        case FLB_KUBE_PROP_STREAM_STDERR:
            {
                if (props.stderr_exclude == FLB_TRUE) {
                    continue;
                }
                if (props.stderr_parser != NULL) {
                    parser = flb_parser_get(props.stderr_parser, config);
                }
            }
            break;
        default:
            {
                if (props.stdout_exclude == props.stderr_exclude &&
                    props.stderr_exclude == FLB_TRUE) {
                    continue;
                }
                if (props.stdout_parser == props.stderr_parser &&
                    props.stderr_parser != NULL) {
                    parser = flb_parser_get(props.stdout_parser, config);
                }
            }
            break;
        }

        /*
         * Temporal time lookup in case a parser comes up with a new
         * timestamp for the record.
         */
        flb_time_pop_from_msgpack(&time_lookup, &result, &obj);

        /* get records map */
        map  = root.via.array.ptr[1];

        /* Compose the new array (0=timestamp, 1=record) */
        msgpack_pack_array(&tmp_pck, 2);


        ret = pack_map_content(&tmp_pck, &tmp_sbuf,
                               map,
                               cache_buf, cache_size,
                               &meta, &time_lookup, parser, ctx);
        if (ret == -1) {
            msgpack_sbuffer_destroy(&tmp_sbuf);
            msgpack_unpacked_destroy(&result);
            if (ctx->dummy_meta == FLB_TRUE) {
                flb_free(dummy_cache_buf);
            }

            flb_kube_meta_release(&meta);
            flb_kube_prop_destroy(&props);
            return FLB_FILTER_NOTOUCH;
        }

        if (ctx->use_journal == FLB_TRUE) {
            flb_kube_meta_release(&meta);
            flb_kube_prop_destroy(&props);
        }
    }
    msgpack_unpacked_destroy(&result);

    /* Release meta fields */
    if (ctx->use_journal == FLB_FALSE) {
        flb_kube_meta_release(&meta);
        flb_kube_prop_destroy(&props);
    }

    /* link new buffers */
    *out_buf   = tmp_sbuf.data;
    *out_bytes = tmp_sbuf.size;

    if (ctx->dummy_meta == FLB_TRUE) {
        flb_free(dummy_cache_buf);
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

/* Configuration properties map */
static struct flb_config_map config_map[] = {

    /* Buffer size for HTTP Client when reading responses from API Server */
    {
     FLB_CONFIG_MAP_SIZE, "buffer_size", "32K",
     0, FLB_TRUE, offsetof(struct flb_kube, buffer_size),
     "buffer size to receive response from API server",
    },

    /* TLS: set debug 'level' */
    {
     FLB_CONFIG_MAP_INT, "tls.debug", "0",
     0, FLB_TRUE, offsetof(struct flb_kube, tls_debug),
     "set TLS debug level: 0 (no debug), 1 (error), "
     "2 (state change), 3 (info) and 4 (verbose)"
    },

    /* TLS: enable verification */
    {
     FLB_CONFIG_MAP_BOOL, "tls.verify", "true",
     0, FLB_TRUE, offsetof(struct flb_kube, tls_verify),
     "enable or disable verification of TLS peer certificate"
    },

    /* TLS: set tls.vhost feature */
    {
     FLB_CONFIG_MAP_STR, "tls.vhost", NULL,
     0, FLB_TRUE, offsetof(struct flb_kube, tls_vhost),
     "set optional TLS virtual host"
    },

    /* Merge structured record as independent keys */
    {
     FLB_CONFIG_MAP_BOOL, "merge_log", "false",
     0, FLB_TRUE, offsetof(struct flb_kube, merge_log),
     "merge 'log' key content as individual keys"
    },

    /* Optional parser for 'log' key content */
    {
     FLB_CONFIG_MAP_STR, "merge_parser", NULL,
     0, FLB_FALSE, 0,
     "specify a 'parser' name to parse the 'log' key content"
    },

    /* New key name to merge the structured content of 'log' */
    {
     FLB_CONFIG_MAP_STR, "merge_log_key", NULL,
     0, FLB_TRUE, offsetof(struct flb_kube, merge_log_key),
     "set the 'key' name where the content of 'key' will be placed. Only "
     "used if the option 'merge_log' is enabled"
    },

    /* On merge, trim field values (remove possible ending \n or \r) */
    {
     FLB_CONFIG_MAP_BOOL, "merge_log_trim", "true",
     0, FLB_TRUE, offsetof(struct flb_kube, merge_log_trim),
     "remove ending '\\n' or '\\r' characters from the log content"
    },

    /* Keep original log key after successful merging/parsing */
    {
     FLB_CONFIG_MAP_BOOL, "keep_log", "true",
     0, FLB_TRUE, offsetof(struct flb_kube, keep_log),
     "keep original log content if it was successfully parsed and merged"
    },

    /* Full Kubernetes API server URL */
    {
     FLB_CONFIG_MAP_STR, "kube_url", "https://kubernetes.default.svc",
     0, FLB_FALSE, 0,
     "Kubernetes API server URL"
    },

    /*
     * If set, meta-data load will be attempted from files in this dir,
     * falling back to API if not existing.
     */
    {
     FLB_CONFIG_MAP_STR, "kube_meta_preload_cache_dir", NULL,
     0, FLB_TRUE, offsetof(struct flb_kube, meta_preload_cache_dir),
     "set directory with metadata files"
    },

    /* Kubernetes TLS: CA file */
    {
     FLB_CONFIG_MAP_STR, "kube_ca_file", FLB_KUBE_CA,
     0, FLB_TRUE, offsetof(struct flb_kube, tls_ca_file),
     "Kubernetes TLS CA file"
    },

    /* Kubernetes TLS: CA certs path */
    {
     FLB_CONFIG_MAP_STR, "kube_ca_path", NULL,
     0, FLB_TRUE, offsetof(struct flb_kube, tls_ca_path),
     "Kubernetes TLS ca path"
    },

    /* Kubernetes Tag prefix */
    {
     FLB_CONFIG_MAP_STR, "kube_tag_prefix", FLB_KUBE_TAG_PREFIX,
     0, FLB_TRUE, offsetof(struct flb_kube, kube_tag_prefix),
     "prefix used in tag by the input plugin"
    },

    /* Kubernetes Token file */
    {
     FLB_CONFIG_MAP_STR, "kube_token_file", FLB_KUBE_TOKEN,
     0, FLB_TRUE, offsetof(struct flb_kube, token_file),
     "Kubernetes authorization token file"
    },

    /* Include Kubernetes Labels in the final record ? */
    {
     FLB_CONFIG_MAP_BOOL, "labels", "true",
     0, FLB_TRUE, offsetof(struct flb_kube, labels),
     "include Kubernetes labels on every record"
    },

    /* Include Kubernetes Annotations in the final record ? */
    {
     FLB_CONFIG_MAP_BOOL, "annotations", "true",
     0, FLB_TRUE, offsetof(struct flb_kube, annotations),
     "include Kubernetes annotations on every record"
    },

    /*
     * The Application may 'propose' special configuration keys
     * to the logging agent (Fluent Bit) through the annotations
     * set in the Pod definition, e.g:
     *
     *  "annotations": {
     *      "logging": {"parser": "apache"}
     *  }
     *
     * As of now, Fluent Bit/filter_kubernetes supports the following
     * options under the 'logging' map value:
     *
     * - k8s-logging.parser:  propose Fluent Bit to parse the content
     *                        using the  pre-defined parser in the
     *                        value (e.g: apache).
     * - k8s-logging.exclude: Fluent Bit allows Pods to exclude themselves
     *
     * By default all options are disabled, so each option needs to
     * be enabled manually.
     */
    {
     FLB_CONFIG_MAP_BOOL, "k8s-logging.parser", "false",
     0, FLB_TRUE, offsetof(struct flb_kube, k8s_logging_parser),
     "allow Pods to suggest a parser"
    },
    {
     FLB_CONFIG_MAP_BOOL, "k8s-logging.exclude", "false",
     0, FLB_TRUE, offsetof(struct flb_kube, k8s_logging_exclude),
     "allow Pods to exclude themselves from the logging pipeline"
    },

    /* Use Systemd Journal mode ? */
    {
     FLB_CONFIG_MAP_BOOL, "use_journal", "false",
     0, FLB_TRUE, offsetof(struct flb_kube, use_journal),
     "use Journald (Systemd) mode"
    },

    /* Custom Tag Regex */
    {
     FLB_CONFIG_MAP_STR, "regex_parser", NULL,
     0, FLB_FALSE, 0,
     "optional regex parser to extract metadata from container name or container log file name"
    },

    /* Generate dummy metadata (only for test/dev purposes) */
    {
     FLB_CONFIG_MAP_BOOL, "dummy_meta", "false",
     0, FLB_TRUE, offsetof(struct flb_kube, dummy_meta),
     "use 'dummy' metadata, do not talk to API server"
    },

    /*
     * Poll DNS status to mitigate unreliable network issues.
     * See fluent/fluent-bit/2144.
     */
    {
     FLB_CONFIG_MAP_INT, "dns_retries", "6",
     0, FLB_TRUE, offsetof(struct flb_kube, dns_retries),
     "dns lookup retries N times until the network start working"
    },

    {
     FLB_CONFIG_MAP_TIME, "dns_wait_time", "30",
     0, FLB_TRUE, offsetof(struct flb_kube, dns_wait_time),
     "dns interval between network status checks"
    },

    /* EOF */
    {0}
};

struct flb_filter_plugin filter_kubernetes_plugin = {
    .name         = "kubernetes",
    .description  = "Filter to append Kubernetes metadata",
    .cb_init      = cb_kube_init,
    .cb_filter    = cb_kube_filter,
    .cb_exit      = cb_kube_exit,
    .config_map   = config_map,
    .flags        = 0
};
