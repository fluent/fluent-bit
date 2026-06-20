/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2026 The Fluent Bit Authors
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
#include <fluent-bit/flb_log_event_decoder.h>
#include <fluent-bit/flb_log_event_encoder.h>

#include "kube_conf.h"
#include "kube_meta.h"
#include "kube_regex.h"
#include "kube_property.h"
#include "kubernetes_aws.h"

#include <stdio.h>
#include <msgpack.h>
#include <sys/stat.h>

/* Merge status used by merge_log_handler() */
#define MERGE_NONE        0 /* merge unescaped string in temporary buffer */
#define MERGE_PARSED      1 /* merge parsed string (log_buf)             */
#define MERGE_MAP         2 /* merge direct binary object (v)            */

struct task_args {
    struct flb_kube *ctx;
    char *api_server_url;
};

pthread_mutex_t metadata_mutex;
pthread_t background_thread;
struct task_args *task_args = {0};
struct mk_event_loop *evl;

void *update_pod_service_map(void *arg)
{
    flb_engine_evl_init();
    evl = mk_event_loop_create(256);
    if (evl == NULL) {
        flb_plg_error(task_args->ctx->ins,
                      "Failed to create event loop for pod service map");
        return NULL;
    }
    flb_engine_evl_set(evl);
    while (1) {
        fetch_pod_service_map(task_args->ctx,task_args->api_server_url,&metadata_mutex);
        flb_plg_debug(task_args->ctx->ins, "Updating pod to service map after %d seconds", task_args->ctx->aws_pod_service_map_refresh_interval);
        sleep(task_args->ctx->aws_pod_service_map_refresh_interval);
    }
}

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
    int records = 0;
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
            if (flb_time_to_nanosec(log_time) == 0L) {
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
            if (flb_time_to_nanosec(log_time) == 0L) {
                flb_time_get(log_time);
            }
            return MERGE_PARSED;
        }
    }
    else { /* Default JSON parser */
        ret = flb_pack_json_recs(ctx->unesc_buf, ctx->unesc_buf_len,
                                 (char **) out_buf, out_size, &root_type,
                                 &records, NULL);
        if (ret == 0 && root_type != FLB_PACK_JSON_OBJECT) {
            flb_plg_debug(ctx->ins, "could not merge JSON, root_type=%i",
                      root_type);
            flb_free(*out_buf);
            return MERGE_NONE;
        }

        if (ret == 0 && records != 1) {
            flb_plg_debug(ctx->ins,
                          "could not merge JSON, invalid number of records: %i",
                          records);
            flb_free(*out_buf);
            return MERGE_NONE;
        }
    }

    if (ret == -1) {
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

/*
 * Init separate thread for calling pod to
 * service map
 */
    pthread_mutex_init(&metadata_mutex, NULL);

    if (ctx->aws_use_pod_association) {
        task_args = flb_malloc(sizeof(struct task_args));
        if (!task_args) {
            flb_errno();
            return -1;
        }
        task_args->ctx = ctx;
        task_args->api_server_url = ctx->aws_pod_association_endpoint;
        if (pthread_create(&background_thread, NULL, update_pod_service_map, NULL) != 0) {
            flb_error("Failed to create background thread");
            background_thread = 0;
            flb_free(task_args);
        }
    }

    return 0;
}

static int pack_map_content(struct flb_log_event_encoder *log_encoder,
                            msgpack_object source_map,
                            const char *kube_buf, size_t kube_size,
                            const char *namespace_kube_buf,
                            size_t namespace_kube_size,
                            struct flb_time *time_lookup,
                            struct flb_parser *parser,
                            struct flb_kube *ctx)
{
    int append_original_objects;
    int scope_opened;
    int ret;
    int i;
    int map_size = 0;
    int merge_status = -1;
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
     * Docker JSON map is a escaped string. Proceed to reserve a temporary
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
        if (flb_time_to_nanosec(&log_time) == 0L) {
            ret = flb_log_event_encoder_set_timestamp(
                    log_encoder, time_lookup);
        }
        else {
            ret = flb_log_event_encoder_set_timestamp(
                    log_encoder, &log_time);
        }
    }
    else {
        ret = flb_log_event_encoder_set_timestamp(
                log_encoder, time_lookup);
    }

    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        return -1;
    }

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

    if ((merge_status == MERGE_PARSED || merge_status == MERGE_MAP) &&
        ctx->keep_log == FLB_FALSE) {
    }

    /* Original map */
    for (i = 0;
         i < map_size &&
         ret == FLB_EVENT_ENCODER_SUCCESS;
         i++) {
        k = source_map.via.map.ptr[i].key;
        v = source_map.via.map.ptr[i].val;

        /*
         * If log_index is set, means a merge log is a requirement but
         * will depend on merge_status. If the parsing failed we cannot
         * merge so we keep the 'log' key/value.
         */
        append_original_objects = FLB_FALSE;

        if (log_index == i) {
            if (ctx->keep_log == FLB_TRUE) {
                if (merge_status == MERGE_NONE || merge_status == MERGE_PARSED){
                    ret = flb_log_event_encoder_append_body_values(
                            log_encoder,
                            FLB_LOG_EVENT_MSGPACK_OBJECT_VALUE(&k),
                            FLB_LOG_EVENT_STRING_VALUE(ctx->unesc_buf,
                                                       ctx->unesc_buf_len));
                }
                else {
                    append_original_objects = FLB_TRUE;
                }
            }
            else if (merge_status == MERGE_NONE) {
                append_original_objects = FLB_TRUE;
            }
        }
        else {
            append_original_objects = FLB_TRUE;
        }

        if (append_original_objects) {
            ret = flb_log_event_encoder_append_body_values(
                    log_encoder,
                    FLB_LOG_EVENT_MSGPACK_OBJECT_VALUE(&k),
                    FLB_LOG_EVENT_MSGPACK_OBJECT_VALUE(&v));
        }
    }

    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        return -2;
    }

    scope_opened = FLB_FALSE;
    /* Merge Log */
    if (log_index != -1) {
        if (merge_status == MERGE_PARSED) {
            if (ctx->merge_log_key && log_buf_entries > 0) {
                ret = flb_log_event_encoder_append_body_string(
                        log_encoder,
                        ctx->merge_log_key,
                        flb_sds_len(ctx->merge_log_key));

                if (ret == FLB_EVENT_ENCODER_SUCCESS) {
                    ret = flb_log_event_encoder_body_begin_map(log_encoder);
                }

                if (ret != FLB_EVENT_ENCODER_SUCCESS) {
                    return -3;
                }

                scope_opened = FLB_TRUE;
            }

            off = 0;
            msgpack_unpacked_init(&result);
            msgpack_unpack_next(&result, log_buf, log_size, &off);
            root = result.data;

            for (i = 0;
                 i < log_buf_entries &&
                 ret == FLB_EVENT_ENCODER_SUCCESS;
                 i++) {
                k = root.via.map.ptr[i].key;

                ret = flb_log_event_encoder_append_body_msgpack_object(
                        log_encoder, &k);

                if (ret != FLB_EVENT_ENCODER_SUCCESS) {
                    return -4;
                }

                v = root.via.map.ptr[i].val;

                /*
                 * If this is the last string value, trim any remaining
                 * break line or return carrier character.
                 */
                if (v.type == MSGPACK_OBJECT_STR &&
                    ctx->merge_log_trim == FLB_TRUE) {
                    ret = flb_log_event_encoder_append_body_string(
                            log_encoder,
                            (char *) v.via.str.ptr,
                            value_trim_size(v));
                }
                else {
                    ret = flb_log_event_encoder_append_body_msgpack_object(
                            log_encoder, &v);
                }
            }

            msgpack_unpacked_destroy(&result);

            flb_free(log_buf);

            if (scope_opened && ret == FLB_EVENT_ENCODER_SUCCESS) {
                ret = flb_log_event_encoder_body_commit_map(log_encoder);
            }

            if (ret != FLB_EVENT_ENCODER_SUCCESS) {
                return -5;
            }
        }
        else if (merge_status == MERGE_MAP) {
            msgpack_object map;

            if (ctx->merge_log_key && log_buf_entries > 0) {
                ret = flb_log_event_encoder_append_body_string(
                        log_encoder,
                        ctx->merge_log_key,
                        flb_sds_len(ctx->merge_log_key));

                if (ret == FLB_EVENT_ENCODER_SUCCESS) {
                    ret = flb_log_event_encoder_body_begin_map(log_encoder);
                }

                if (ret != FLB_EVENT_ENCODER_SUCCESS) {
                    return -6;
                }

                scope_opened = FLB_TRUE;
            }

            map = source_map.via.map.ptr[log_index].val;
            for (i = 0;
                 i < map.via.map.size &&
                 ret == FLB_EVENT_ENCODER_SUCCESS;
                 i++) {
                k = map.via.map.ptr[i].key;
                v = map.via.map.ptr[i].val;

                ret = flb_log_event_encoder_append_body_values(
                        log_encoder,
                        FLB_LOG_EVENT_MSGPACK_OBJECT_VALUE(&k),
                        FLB_LOG_EVENT_MSGPACK_OBJECT_VALUE(&v));
            }

            if (scope_opened && ret == FLB_EVENT_ENCODER_SUCCESS) {
                ret = flb_log_event_encoder_body_commit_map(log_encoder);
            }

            if (ret != FLB_EVENT_ENCODER_SUCCESS) {
                return -7;
            }
        }
    }

    /* Kubernetes */
    if (kube_buf && kube_size > 0) {
        ret = flb_log_event_encoder_append_body_cstring(
                log_encoder,
                "kubernetes");

        off = 0;
        msgpack_unpacked_init(&result);
        msgpack_unpack_next(&result, kube_buf, kube_size, &off);

        if (kube_size != off) {
            /* This buffer should contain a single map and we shouldn't
             * have to unpack it in order to ensure that we are appending
             * a single map but considering that the current code only
             * appends the first entry without taking any actions I think
             * we should warn the user if there is more than one entry in
             * it so in the future we can remove the unpack code and just
             * use flb_log_event_encoder_append_body_raw_msgpack with
             * kube_size.
             */
        }

        if (ret == FLB_EVENT_ENCODER_SUCCESS) {
            ret = flb_log_event_encoder_append_body_raw_msgpack(log_encoder,
                    (char *) kube_buf, off);
        }

        msgpack_unpacked_destroy(&result);
    }

    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        return -8;
    }

    /* Kubernetes Namespace */
    if (namespace_kube_buf && namespace_kube_size > 0) {
        ret = flb_log_event_encoder_append_body_cstring(
                log_encoder,
                "kubernetes_namespace");

        off = 0;
        msgpack_unpacked_init(&result);
        msgpack_unpack_next(&result, namespace_kube_buf,
                            namespace_kube_size, &off);

        if (ret == FLB_EVENT_ENCODER_SUCCESS) {
            ret = flb_log_event_encoder_append_body_raw_msgpack(log_encoder,
                    (char *) namespace_kube_buf, off);
        }

        msgpack_unpacked_destroy(&result);
    }

    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        return -8;
    }

    return 0;
}

static int cb_kube_filter(const void *data, size_t bytes,
                          const char *tag, int tag_len,
                          void **out_buf, size_t *out_bytes,
                          struct flb_filter_instance *f_ins,
                          struct flb_input_instance *i_ins,
                          void *filter_context,
                          struct flb_config *config)
{
    int ret;
    size_t pre = 0;
    size_t off = 0;
    char *dummy_cache_buf = NULL;
    const char *cache_buf = NULL;
    size_t cache_size = 0;
    const char *namespace_cache_buf = NULL;
    size_t namespace_cache_size = 0;
    msgpack_object map;
    struct flb_parser *parser = NULL;
    struct flb_kube *ctx = filter_context;
    struct flb_kube_meta meta = {0};
    struct flb_kube_props props = {0};
    struct flb_kube_meta namespace_meta = {0};
    struct flb_log_event_encoder log_encoder;
    struct flb_log_event_decoder log_decoder;
    struct flb_log_event log_event;

    (void) f_ins;
    (void) i_ins;
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
                                    &cache_buf, &cache_size,
                                    &namespace_cache_buf, &namespace_cache_size,
                                    &meta, &props,
                                    &namespace_meta);
        }
        if (ret == -1) {
            return FLB_FILTER_NOTOUCH;
        }
    }

    ret = flb_log_event_decoder_init(&log_decoder, (char *) data, bytes);

    if (ret != FLB_EVENT_DECODER_SUCCESS) {
        flb_plg_error(ctx->ins,
                      "Log event decoder initialization error : %d", ret);

        flb_kube_meta_release(&meta);
        flb_kube_prop_destroy(&props);
        flb_kube_meta_release(&namespace_meta);

        return FLB_FILTER_NOTOUCH;
    }

    ret = flb_log_event_encoder_init(&log_encoder,
                                     FLB_LOG_EVENT_FORMAT_DEFAULT);

    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        flb_plg_error(ctx->ins,
                      "Log event encoder initialization error : %d", ret);

        flb_log_event_decoder_destroy(&log_decoder);
        flb_kube_meta_release(&meta);
        flb_kube_prop_destroy(&props);
        flb_kube_meta_release(&namespace_meta);

        return FLB_FILTER_NOTOUCH;
    }

    while ((ret = flb_log_event_decoder_next(
                    &log_decoder,
                    &log_event)) == FLB_EVENT_DECODER_SUCCESS) {
        off = log_decoder.offset;
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
                                    &cache_buf, &cache_size,
                                    &namespace_cache_buf, &namespace_cache_size,
                                    &meta, &props,
                                    &namespace_meta);
            if (ret == -1) {
                continue;
            }

            pre = off;
        }

        parser = NULL;

        switch (get_stream(log_event.body->via.map)) {
        case FLB_KUBE_PROP_STREAM_STDOUT:
            {
                if (props.stdout_exclude == FLB_TRUE) {
                    /* Skip this record */
                    if (ctx->use_journal == FLB_TRUE) {
                        flb_kube_meta_release(&meta);
                        flb_kube_prop_destroy(&props);
                        flb_kube_meta_release(&namespace_meta);
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
                    /* Skip this record */
                    if (ctx->use_journal == FLB_TRUE) {
                        flb_kube_meta_release(&meta);
                        flb_kube_prop_destroy(&props);
                        flb_kube_meta_release(&namespace_meta);
                    }
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

        /* get records map */
        map  = *log_event.body;

        ret = flb_log_event_encoder_begin_record(&log_encoder);

        if (ret != FLB_EVENT_ENCODER_SUCCESS) {
            break;
        }

        ret = pack_map_content(&log_encoder,
                               map,
                               cache_buf, cache_size,
                               namespace_cache_buf, namespace_cache_size,
                               &log_event.timestamp, parser, ctx);
        if (ret != 0) {
            flb_log_event_decoder_destroy(&log_decoder);
            flb_log_event_encoder_destroy(&log_encoder);

            if (ctx->dummy_meta == FLB_TRUE) {
                flb_free(dummy_cache_buf);
            }

            flb_kube_meta_release(&meta);
            flb_kube_prop_destroy(&props);
            flb_kube_meta_release(&namespace_meta);

            return FLB_FILTER_NOTOUCH;
        }

        ret = flb_log_event_encoder_commit_record(&log_encoder);

        if (ret != FLB_EVENT_ENCODER_SUCCESS) {
            flb_log_event_encoder_rollback_record(&log_encoder);

            break;
        }

        if (ctx->use_journal == FLB_TRUE) {
            flb_kube_meta_release(&meta);
            flb_kube_prop_destroy(&props);
            flb_kube_meta_release(&namespace_meta);
        }
    }

    /* Release meta fields */
    if (ctx->use_journal == FLB_FALSE) {
        flb_kube_meta_release(&meta);
        flb_kube_prop_destroy(&props);
        flb_kube_meta_release(&namespace_meta);
    }

    if (ctx->dummy_meta == FLB_TRUE) {
        flb_free(dummy_cache_buf);
    }

    *out_buf   = log_encoder.output_buffer;
    *out_bytes = log_encoder.output_length;

    flb_log_event_encoder_claim_internal_buffer_ownership(&log_encoder);

    flb_log_event_decoder_destroy(&log_decoder);
    flb_log_event_encoder_destroy(&log_encoder);

    return FLB_FILTER_MODIFIED;
}

static int cb_kube_exit(void *data, struct flb_config *config)
{
    struct flb_kube *ctx;

    ctx = data;
    
    flb_kube_conf_destroy(ctx);
    if (background_thread) {
        pthread_cancel(background_thread);
        pthread_join(background_thread, NULL);
    }
    pthread_mutex_destroy(&metadata_mutex);

    if (task_args) {
        flb_free(task_args);
    }
    if (evl) {
        mk_event_loop_destroy(evl);
    }
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

    /* TLS: set tls.hostame_verification feature */
    {
     FLB_CONFIG_MAP_BOOL, "tls.verify_hostname", "off",
     0, FLB_TRUE, offsetof(struct flb_kube, tls_verify_hostname),
     "enable or disable to verify hostname"
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

    /* Kubernetes Token command */
    {
     FLB_CONFIG_MAP_STR, "kube_token_command", NULL,
     0, FLB_FALSE, 0,
     "command to get Kubernetes authorization token"
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

    /* Include Kubernetes OwnerReferences in the final record ? */
    {
     FLB_CONFIG_MAP_BOOL, "owner_references", "false",
     0, FLB_TRUE, offsetof(struct flb_kube, owner_references),
     "include Kubernetes owner references on every record"
    },

    /* Include Kubernetes Namespace Labels in the final record ? */
    {
     FLB_CONFIG_MAP_BOOL, "namespace_labels", "false",
     0, FLB_TRUE, offsetof(struct flb_kube, namespace_labels),
     "include Kubernetes namespace labels on every record"
    },
    /* Include Kubernetes Namespace Annotations in the final record ? */
    {
     FLB_CONFIG_MAP_BOOL, "namespace_annotations", "false",
     0, FLB_TRUE, offsetof(struct flb_kube, namespace_annotations),
     "include Kubernetes namespace annotations on every record"
    },
    /* Ignore pod metadata entirely, useful for fetching only namespace meta */
    {
     FLB_CONFIG_MAP_BOOL, "namespace_metadata_only", "false",
     0, FLB_TRUE, offsetof(struct flb_kube, namespace_metadata_only),
     "ignore pod metadata entirely and only fetch namespace metadata"
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
    /* Fetch K8s meta when docker_id has changed */
    {
     FLB_CONFIG_MAP_BOOL, "cache_use_docker_id", "false",
     0, FLB_TRUE, offsetof(struct flb_kube, cache_use_docker_id),
     "fetch K8s meta when docker_id is changed"
    },

    {
     FLB_CONFIG_MAP_BOOL, "use_tag_for_meta", "false",
     0, FLB_TRUE, offsetof(struct flb_kube, use_tag_for_meta),
     "use tag associated to retrieve metadata instead of kube-server"
    },

    /*
     * Enable the feature for using kubelet to get pods information
     */
    {
     FLB_CONFIG_MAP_BOOL, "use_kubelet", "false",
     0, FLB_TRUE, offsetof(struct flb_kube, use_kubelet),
     "use kubelet to get metadata instead of kube-server"
    },
    /*
     * The kubelet host for /pods endpoint, default is 127.0.0.1
     * Will only check when "use_kubelet" config is set to true
     */
    {
     FLB_CONFIG_MAP_STR, "kubelet_host", "127.0.0.1",
     0, FLB_TRUE, offsetof(struct flb_kube, kubelet_host),
     "kubelet host to connect with when using kubelet"
    },
    /*
     * The kubelet port for /pods endpoint, default is 10250
     * Will only check when "use_kubelet" config is set to true
     */
    {
     FLB_CONFIG_MAP_INT, "kubelet_port", "10250",
     0, FLB_TRUE, offsetof(struct flb_kube, kubelet_port),
     "kubelet port to connect with when using kubelet"
    },
    {
     FLB_CONFIG_MAP_TIME, "kube_token_ttl", "10m",
     0, FLB_TRUE, offsetof(struct flb_kube, kube_token_ttl),
     "kubernetes token ttl, until it is reread from the token file. Default: 10m"
    },
    /*
     * Set TTL for K8s cached metadata 
     */
    {
     FLB_CONFIG_MAP_TIME, "kube_meta_cache_ttl", "0",
     0, FLB_TRUE, offsetof(struct flb_kube, kube_meta_cache_ttl),
     "configurable TTL for K8s cached metadata. " 
     "By default, it is set to 0 which means TTL for cache entries is disabled and " 
     "cache entries are evicted at random when capacity is reached. " 
     "In order to enable this option, you should set the number to a time interval. " 
     "For example, set this value to 60 or 60s and cache entries " 
     "which have been created more than 60s will be evicted"
    },
    {
     FLB_CONFIG_MAP_TIME, "kube_meta_namespace_cache_ttl", "15m",
     0, FLB_TRUE, offsetof(struct flb_kube, kube_meta_namespace_cache_ttl),
     "configurable TTL for K8s cached namespace metadata. "
     "By default, it is set to 15m and cached entries will be evicted after 15m."
     "Setting this to 0 will disable the cache TTL and "
     "will evict entries once the cache reaches capacity."
    },

    /*
     * Enable pod to service name association logics
     * This can be configured with endpoint that returns a response with the corresponding
     * podname in relation to the service name. For example, if there is a pod named "petclinic-12345"
     * then in order to associate a service name to pod "petclinic-12345", the JSON response to the endpoint
     * must follow the below patterns
     * {
     *   "petclinic-12345": {
     *      "ServiceName":"petclinic",
     *      "Environment":"default"
     *   }
     * }
     */
    {
     FLB_CONFIG_MAP_BOOL, "aws_use_pod_association", "false",
     0, FLB_TRUE, offsetof(struct flb_kube, aws_use_pod_association),
     "use custom endpoint to get pod to service name mapping"
    },
    {
     FLB_CONFIG_MAP_BOOL, "use_pod_association", "false",
     0, FLB_TRUE, offsetof(struct flb_kube, aws_use_pod_association),
     "use custom endpoint to get pod to service name mapping. "
     "this config option is kept for backward compatibility for "
     "AWS Observability users and will be deprecated in favor of "
     "aws_use_pod_association."
    },
    /*
     * The host used for pod to service name association , default is 127.0.0.1
     * Will only check when "use_pod_association" config is set to true
     */
    {
     FLB_CONFIG_MAP_STR, "aws_pod_association_host", "cloudwatch-agent.amazon-cloudwatch",
     0, FLB_TRUE, offsetof(struct flb_kube, aws_pod_association_host),
     "host to connect with when performing pod to service name association"
    },
    /*
     * The endpoint used for pod to service name association, default is /kubernetes/pod-to-service-env-map
     * Will only check when "use_pod_association" config is set to true
     */
    {
     FLB_CONFIG_MAP_STR, "aws_pod_association_endpoint", "/kubernetes/pod-to-service-env-map",
     0, FLB_TRUE, offsetof(struct flb_kube, aws_pod_association_endpoint),
     "endpoint to connect with when performing pod to service name association"
    },
    /*
     * The port for pod to service name association endpoint, default is 4311
     * Will only check when "use_pod_association" config is set to true
     */
    {
     FLB_CONFIG_MAP_INT, "aws_pod_association_port", "4311",
     0, FLB_TRUE, offsetof(struct flb_kube, aws_pod_association_port),
     "port to connect with when performing pod to service name association"
    },
    {
     FLB_CONFIG_MAP_INT, "aws_pod_service_map_ttl", "0",
     0, FLB_TRUE, offsetof(struct flb_kube, aws_pod_service_map_ttl),
     "configurable TTL for pod to service map storage. "
     "By default, it is set to 0 which means TTL for cache entries is disabled and "
     "cache entries are evicted at random when capacity is reached. "
     "In order to enable this option, you should set the number to a time interval. "
     "For example, set this value to 60 or 60s and cache entries "
     "which have been created more than 60s will be evicted"
    },
    {
     FLB_CONFIG_MAP_INT, "aws_pod_service_map_refresh_interval", "60",
     0, FLB_TRUE, offsetof(struct flb_kube, aws_pod_service_map_refresh_interval),
     "Refresh interval for the pod to service map storage."
     "By default, it is set to refresh every 60 seconds"
    },
    {
     FLB_CONFIG_MAP_STR, "aws_pod_service_preload_cache_dir", NULL,
     0, FLB_TRUE, offsetof(struct flb_kube, aws_pod_service_preload_cache_path),
     "set directory with pod to service map files"
    },
    {
     FLB_CONFIG_MAP_STR, "aws_pod_association_host_server_ca_file", "/etc/amazon-cloudwatch-observability-agent-server-cert/tls-ca.crt",
     0, FLB_TRUE, offsetof(struct flb_kube, aws_pod_association_host_server_ca_file),
     "TLS CA certificate path for communication with agent server"
    },
    {
     FLB_CONFIG_MAP_STR, "aws_pod_association_host_client_cert_file", "/etc/amazon-cloudwatch-observability-agent-client-cert/client.crt",
     0, FLB_TRUE, offsetof(struct flb_kube, aws_pod_association_host_client_cert_file),
     "Client Certificate path for enabling mTLS on calls to agent server"
    },
    {
     FLB_CONFIG_MAP_STR, "aws_pod_association_host_client_key_file", "/etc/amazon-cloudwatch-observability-agent-client-cert/client.key",
     0, FLB_TRUE, offsetof(struct flb_kube, aws_pod_association_host_client_key_file),
     "Client Certificate Key path for enabling mTLS on calls to agent server"
    },
    {
     FLB_CONFIG_MAP_INT, "aws_pod_association_host_tls_debug", "0",
     0, FLB_TRUE, offsetof(struct flb_kube, aws_pod_association_host_tls_debug),
     "set TLS debug level: 0 (no debug), 1 (error), "
     "2 (state change), 3 (info) and 4 (verbose)"
    },
    {
     FLB_CONFIG_MAP_BOOL, "aws_pod_association_host_tls_verify", "true",
     0, FLB_TRUE, offsetof(struct flb_kube, aws_pod_association_host_tls_verify),
     "enable or disable verification of TLS peer certificate"
    },
    {
     FLB_CONFIG_MAP_STR, "set_platform", NULL,
     0, FLB_TRUE, offsetof(struct flb_kube, set_platform),
     "Set the platform that kubernetes is in. Possible values are k8s and eks"
     "This should only be used for testing purpose"
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
