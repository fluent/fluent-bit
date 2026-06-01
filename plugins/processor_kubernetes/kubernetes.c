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
#include <fluent-bit/flb_processor_plugin.h>
#include <fluent-bit/flb_filter.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_parser.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_str.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_hash_table.h>
#include <fluent-bit/flb_upstream.h>
#include <fluent-bit/flb_log_event_encoder.h>
#include <fluent-bit/flb_conditionals.h>
#include <fluent-bit/flb_engine.h>
#include <fluent-bit/tls/flb_tls.h>

#include <cfl/cfl.h>
#include <cfl/cfl_container.h>

#include <msgpack.h>
#include <pthread.h>
#include <stddef.h>
#include <unistd.h>

#include "../filter_kubernetes/kube_conf.h"
#include "../filter_kubernetes/kube_meta.h"
#include "../filter_kubernetes/kube_regex.h"
#include "../filter_kubernetes/kube_property.h"
#include "../filter_kubernetes/kubernetes_aws.h"

/* Merge status used by merge_log_handler() */
#define MERGE_ERROR     -1
#define MERGE_NONE       0
#define MERGE_PARSED     1
#define MERGE_MAP        2

struct processor_kube_ctx {
    struct flb_kube kube;
    struct flb_filter_plugin filter_plugin;
    struct flb_filter_instance filter_instance;
    pthread_mutex_t metadata_mutex;
    pthread_t background_thread;
    struct mk_event_loop *evl;
    int metadata_mutex_initialized;
};

static int encode_empty_msgpack_map(char **out_buf, size_t *out_size)
{
    msgpack_sbuffer mp_sbuf;
    msgpack_packer mp_pck;

    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    msgpack_pack_map(&mp_pck, 0);

    *out_buf = mp_sbuf.data;
    *out_size = mp_sbuf.size;

    return 0;
}

static struct cfl_kvpair *kvlist_find_pair(struct cfl_kvlist *kvlist,
                                           const char *key, size_t key_len)
{
    struct cfl_list *head;
    struct cfl_kvpair *pair;

    if (kvlist == NULL || key == NULL) {
        return NULL;
    }

    cfl_list_foreach(head, &kvlist->list) {
        pair = cfl_list_entry(head, struct cfl_kvpair, _head);
        if (cfl_sds_len(pair->key) != key_len) {
            continue;
        }

        if (strncmp(pair->key, key, key_len) == 0) {
            return pair;
        }
    }

    return NULL;
}

static int kvpair_set_value(struct cfl_kvlist *owner, struct cfl_kvpair *pair,
                            struct cfl_variant *value)
{
    if (owner == NULL || pair == NULL || value == NULL) {
        return -1;
    }

    if (cfl_container_move_variant_to_kvlist(owner, value) != 0) {
        return -1;
    }

    if (pair->val != NULL) {
        cfl_variant_destroy(pair->val);
    }

    pair->val = value;

    return 0;
}

static int value_trim_size(struct cfl_variant *var)
{
    int i;
    int size;
    char *buf;

    if (var->type != CFL_VARIANT_STRING) {
        return 0;
    }

    size = cfl_variant_size_get(var);
    buf = var->data.as_string;

    for (i = size - 1; i > 0; i--) {
        if (buf[i] == '\n') {
            size -= 1;
            continue;
        }

        if (buf[i - 1] == '\\' &&
            (buf[i] == 'n' || buf[i] == 'r')) {
            size -= 2;
            i--;
        }
        else {
            break;
        }
    }

    return size;
}

static struct cfl_variant *copy_variant(struct cfl_variant *val);

static struct cfl_object *copy_object(struct cfl_object *src)
{
    int ret;
    struct cfl_object *copy;
    struct cfl_variant *var;

    if (src == NULL || src->variant == NULL) {
        return NULL;
    }

    var = copy_variant(src->variant);
    if (var == NULL) {
        return NULL;
    }

    copy = cfl_object_create();
    if (copy == NULL) {
        cfl_variant_destroy(var);
        return NULL;
    }

    ret = cfl_object_set(copy, CFL_OBJECT_VARIANT, var);
    if (ret != 0) {
        cfl_variant_destroy(var);
        cfl_object_destroy(copy);
        return NULL;
    }

    return copy;
}

static struct cfl_array *copy_array(struct cfl_array *array)
{
    int i;
    struct cfl_array *copy;
    struct cfl_variant *v;

    copy = cfl_array_create(array->entry_count);
    if (!copy) {
        return NULL;
    }

    for (i = 0; i < array->entry_count; i++) {
        v = copy_variant(array->entries[i]);
        if (!v) {
            cfl_array_destroy(copy);
            return NULL;
        }

        if (cfl_array_append(copy, v) != 0) {
            cfl_variant_destroy(v);
            cfl_array_destroy(copy);
            return NULL;
        }
    }

    return copy;
}

static struct cfl_kvlist *copy_kvlist(struct cfl_kvlist *kv)
{
    struct cfl_kvlist *kvlist;
    struct cfl_kvpair *pair;
    struct cfl_variant *v;
    struct cfl_list *head;

    kvlist = cfl_kvlist_create();
    if (!kvlist) {
        return NULL;
    }

    cfl_list_foreach(head, &kv->list) {
        pair = cfl_list_entry(head, struct cfl_kvpair, _head);
        v = copy_variant(pair->val);
        if (!v) {
            cfl_kvlist_destroy(kvlist);
            return NULL;
        }

        if (cfl_kvlist_insert_s(kvlist, pair->key, cfl_sds_len(pair->key), v) != 0) {
            cfl_variant_destroy(v);
            cfl_kvlist_destroy(kvlist);
            return NULL;
        }
    }

    return kvlist;
}

static struct cfl_variant *copy_variant(struct cfl_variant *val)
{
    struct cfl_kvlist *kvlist;
    struct cfl_array *array;
    struct cfl_variant *var = NULL;

    switch (val->type) {
    case CFL_VARIANT_STRING:
        var = cfl_variant_create_from_string_s(val->data.as_string,
                                               cfl_variant_size_get(val),
                                               CFL_FALSE);
        break;
    case CFL_VARIANT_BYTES:
        var = cfl_variant_create_from_bytes(val->data.as_bytes,
                                            cfl_variant_size_get(val),
                                            CFL_FALSE);
        break;
    case CFL_VARIANT_BOOL:
        var = cfl_variant_create_from_bool(val->data.as_bool);
        break;
    case CFL_VARIANT_INT:
        var = cfl_variant_create_from_int64(val->data.as_int64);
        break;
    case CFL_VARIANT_UINT:
        var = cfl_variant_create_from_uint64(val->data.as_uint64);
        break;
    case CFL_VARIANT_DOUBLE:
        var = cfl_variant_create_from_double(val->data.as_double);
        break;
    case CFL_VARIANT_NULL:
        var = cfl_variant_create_from_null();
        break;
    case CFL_VARIANT_ARRAY:
        array = copy_array(val->data.as_array);
        if (!array) {
            return NULL;
        }
        var = cfl_variant_create_from_array(array);
        if (!var) {
            cfl_array_destroy(array);
        }
        break;
    case CFL_VARIANT_KVLIST:
        kvlist = copy_kvlist(val->data.as_kvlist);
        if (!kvlist) {
            return NULL;
        }
        var = cfl_variant_create_from_kvlist(kvlist);
        if (!var) {
            cfl_kvlist_destroy(kvlist);
        }
        break;
    default:
        break;
    }

    return var;
}

static struct cfl_object *msgpack_buffer_to_cfl_object(const char *buf, size_t size)
{
    size_t off = 0;
    msgpack_unpacked result;
    struct cfl_object *obj;
    struct cfl_object *copy;

    if (buf == NULL || size == 0) {
        return NULL;
    }

    msgpack_unpacked_init(&result);
    if (msgpack_unpack_next(&result, buf, size, &off) != MSGPACK_UNPACK_SUCCESS) {
        msgpack_unpacked_destroy(&result);
        return NULL;
    }

    obj = flb_mp_object_to_cfl(&result.data);
    copy = copy_object(obj);

    if (obj != NULL) {
        cfl_object_destroy(obj);
    }
    msgpack_unpacked_destroy(&result);

    return copy;
}

static int insert_object_as_kv(struct cfl_kvlist *target,
                               const char *key, size_t key_len,
                               struct cfl_object *obj)
{
    int ret;
    struct cfl_variant *var;

    if (target == NULL || key == NULL || obj == NULL || obj->variant == NULL) {
        return -1;
    }

    var = obj->variant;
    obj->variant = NULL;
    obj->type = CFL_OBJECT_NONE;
    cfl_container_release_variant(var);

    ret = cfl_kvlist_insert_s(target, (char *) key, key_len, var);
    if (ret != 0) {
        cfl_variant_destroy(var);
        return -1;
    }

    return 0;
}

static int append_msgpack_map(struct cfl_kvlist *body,
                              const char *key, size_t key_len,
                              const char *buf, size_t size)
{
    int ret;
    struct cfl_object *obj;

    if (buf == NULL || size == 0) {
        return 0;
    }

    obj = msgpack_buffer_to_cfl_object(buf, size);
    if (obj == NULL) {
        return -1;
    }

    ret = insert_object_as_kv(body, key, key_len, obj);
    cfl_object_destroy(obj);

    return ret;
}

static int get_stream(struct cfl_kvlist *body)
{
    struct cfl_kvpair *pair;
    struct cfl_variant *val;
    size_t len;
    char *buf;

    pair = kvlist_find_pair(body, "stream", 6);
    if (pair == NULL) {
        return FLB_KUBE_PROP_NO_STREAM;
    }

    val = pair->val;
    if (val == NULL || val->type != CFL_VARIANT_STRING) {
        return FLB_KUBE_PROP_STREAM_UNKNOWN;
    }

    buf = val->data.as_string;
    len = cfl_variant_size_get(val);

    if (len == 6 && strncmp(buf, "stdout", 6) == 0) {
        return FLB_KUBE_PROP_STREAM_STDOUT;
    }
    else if (len == 6 && strncmp(buf, "stderr", 6) == 0) {
        return FLB_KUBE_PROP_STREAM_STDERR;
    }

    return FLB_KUBE_PROP_STREAM_UNKNOWN;
}

static int append_copied_map_entries(struct cfl_kvlist *target,
                                     struct cfl_kvlist *source,
                                     int trim_strings)
{
    int ret;
    int trim_size;
    struct cfl_list *head;
    struct cfl_kvpair *pair;
    struct cfl_variant *val;
    struct cfl_variant *tmp;

    cfl_list_foreach(head, &source->list) {
        pair = cfl_list_entry(head, struct cfl_kvpair, _head);
        val = copy_variant(pair->val);
        if (val == NULL) {
            return -1;
        }

        if (trim_strings == FLB_TRUE && val->type == CFL_VARIANT_STRING) {
            trim_size = value_trim_size(val);
            tmp = cfl_variant_create_from_string_s(val->data.as_string,
                                                   trim_size, CFL_FALSE);
            cfl_variant_destroy(val);
            val = tmp;
            if (val == NULL) {
                return -1;
            }
        }

        ret = cfl_kvlist_insert_s(target, pair->key, cfl_sds_len(pair->key), val);
        if (ret != 0) {
            cfl_variant_destroy(val);
            return -1;
        }
    }

    return 0;
}

static int append_moved_map_entries(struct cfl_kvlist *target,
                                    struct cfl_kvlist *source,
                                    int trim_strings)
{
    int ret;
    int trim_size;
    struct cfl_list *head;
    struct cfl_list *tmp_head;
    struct cfl_kvpair *pair;
    struct cfl_variant *val;
    struct cfl_variant *tmp;

    cfl_list_foreach_safe(head, tmp_head, &source->list) {
        pair = cfl_list_entry(head, struct cfl_kvpair, _head);
        val = cfl_kvpair_take_value(pair);
        if (val == NULL) {
            return -1;
        }

        if (trim_strings == FLB_TRUE && val->type == CFL_VARIANT_STRING) {
            trim_size = value_trim_size(val);
            tmp = cfl_variant_create_from_string_s(val->data.as_string,
                                                   trim_size, CFL_FALSE);
            cfl_variant_destroy(val);
            val = tmp;
            if (val == NULL) {
                return -1;
            }
        }

        ret = cfl_kvlist_insert_s(target, pair->key, cfl_sds_len(pair->key), val);
        if (ret != 0) {
            cfl_variant_destroy(val);
            return -1;
        }

        cfl_kvpair_destroy(pair);
    }

    return 0;
}

static int merge_log_handler(struct cfl_variant *log_value,
                             struct flb_parser *parser,
                             struct cfl_object **out_obj,
                             struct flb_time *log_time,
                             struct flb_kube *ctx)
{
    int ret;
    int root_type;
    int records = 0;
    int new_size;
    char *tmp;
    char *log_buf = NULL;
    size_t log_size = 0;

    *out_obj = NULL;

    if (log_value->type != CFL_VARIANT_STRING) {
        return MERGE_NONE;
    }

    if (cfl_variant_size_get(log_value) >= ctx->unesc_buf_size) {
        new_size = cfl_variant_size_get(log_value) + 1;
        tmp = flb_realloc(ctx->unesc_buf, new_size);
        if (!tmp) {
            flb_errno();
            return MERGE_ERROR;
        }
        ctx->unesc_buf = tmp;
        ctx->unesc_buf_size = new_size;
    }

    ctx->unesc_buf_len = cfl_variant_size_get(log_value);
    memcpy(ctx->unesc_buf, log_value->data.as_string, ctx->unesc_buf_len);
    ctx->unesc_buf[ctx->unesc_buf_len] = '\0';

    ret = -1;

    if (parser != NULL) {
        ret = flb_parser_do(parser, ctx->unesc_buf, ctx->unesc_buf_len,
                            (void *) &log_buf, &log_size, log_time);
        if (ret >= 0) {
            if (flb_time_to_nanosec(log_time) == 0L) {
                flb_time_get(log_time);
            }
            *out_obj = msgpack_buffer_to_cfl_object(log_buf, log_size);
            flb_free(log_buf);
            return *out_obj == NULL ? MERGE_ERROR : MERGE_PARSED;
        }
    }
    else if (ctx->merge_parser != NULL) {
        ret = flb_parser_do(ctx->merge_parser,
                            ctx->unesc_buf, ctx->unesc_buf_len,
                            (void *) &log_buf, &log_size, log_time);
        if (ret >= 0) {
            if (flb_time_to_nanosec(log_time) == 0L) {
                flb_time_get(log_time);
            }
            *out_obj = msgpack_buffer_to_cfl_object(log_buf, log_size);
            flb_free(log_buf);
            return *out_obj == NULL ? MERGE_ERROR : MERGE_PARSED;
        }
    }
    else {
        ret = flb_pack_json_recs(ctx->unesc_buf, ctx->unesc_buf_len,
                                 &log_buf, &log_size, &root_type,
                                 &records, NULL);
        if (ret == 0 && root_type != FLB_PACK_JSON_OBJECT) {
            flb_debug("[processor:kubernetes] could not merge JSON, root_type=%i",
                      root_type);
            flb_free(log_buf);
            return MERGE_NONE;
        }

        if (ret == 0 && records != 1) {
            flb_debug("[processor:kubernetes] could not merge JSON, "
                      "invalid number of records: %i", records);
            flb_free(log_buf);
            return MERGE_NONE;
        }
    }

    if (ret == -1) {
        return MERGE_NONE;
    }

    *out_obj = msgpack_buffer_to_cfl_object(log_buf, log_size);
    flb_free(log_buf);

    return *out_obj == NULL ? MERGE_ERROR : MERGE_PARSED;
}

static int append_merged_entries(struct cfl_kvlist *body,
                                 struct cfl_variant *log_value,
                                 struct cfl_object *parsed_obj,
                                 int merge_status,
                                 struct flb_kube *ctx)
{
    int ret;
    int entry_count;
    struct cfl_kvlist *source;
    struct cfl_kvlist *target;
    struct cfl_kvlist *nested = NULL;

    if (merge_status == MERGE_NONE) {
        return 0;
    }

    if (merge_status == MERGE_PARSED) {
        if (parsed_obj == NULL || parsed_obj->variant == NULL ||
            parsed_obj->variant->type != CFL_VARIANT_KVLIST) {
            return -1;
        }
        source = parsed_obj->variant->data.as_kvlist;
        entry_count = cfl_kvlist_count(source);
    }
    else if (merge_status == MERGE_MAP) {
        if (log_value == NULL || log_value->type != CFL_VARIANT_KVLIST) {
            return -1;
        }
        source = log_value->data.as_kvlist;
        entry_count = cfl_kvlist_count(source);
    }
    else {
        return -1;
    }

    if (entry_count == 0) {
        return 0;
    }

    target = body;
    if (ctx->merge_log_key != NULL) {
        nested = cfl_kvlist_create();
        if (nested == NULL) {
            return -1;
        }
        target = nested;
    }

    if (merge_status == MERGE_PARSED) {
        ret = append_moved_map_entries(target, source, ctx->merge_log_trim);
    }
    else {
        ret = append_copied_map_entries(target, source, FLB_FALSE);
    }

    if (ret != 0) {
        if (nested != NULL) {
            cfl_kvlist_destroy(nested);
        }
        return -1;
    }

    if (nested != NULL) {
        ret = cfl_kvlist_insert_kvlist_s(body,
                                         ctx->merge_log_key,
                                         flb_sds_len(ctx->merge_log_key),
                                         nested);
        if (ret != 0) {
            cfl_kvlist_destroy(nested);
            return -1;
        }
    }

    return 0;
}

static int merge_log(struct cfl_kvlist *body,
                     struct flb_parser *parser,
                     struct flb_time *time_lookup,
                     struct flb_kube *ctx)
{
    int ret;
    int merge_status = MERGE_NONE;
    struct cfl_kvpair *log_pair;
    struct cfl_variant *log_value;
    struct cfl_variant *new_value;
    struct cfl_object *parsed_obj = NULL;
    struct flb_time log_time;

    if (ctx->merge_log != FLB_TRUE) {
        return 0;
    }

    log_pair = kvlist_find_pair(body, "log", 3);
    if (log_pair == NULL || log_pair->val == NULL) {
        return 0;
    }

    log_value = log_pair->val;
    flb_time_zero(&log_time);

    if (log_value->type == CFL_VARIANT_KVLIST) {
        merge_status = MERGE_MAP;
    }
    else if (log_value->type == CFL_VARIANT_STRING) {
        merge_status = merge_log_handler(log_value, parser,
                                         &parsed_obj, &log_time, ctx);
    }

    if (merge_status == MERGE_ERROR) {
        return -1;
    }

    if (merge_status == MERGE_PARSED &&
        flb_time_to_nanosec(&log_time) != 0L) {
        flb_time_copy(time_lookup, &log_time);
    }

    ret = append_merged_entries(body, log_value, parsed_obj, merge_status, ctx);
    if (parsed_obj != NULL) {
        cfl_object_destroy(parsed_obj);
    }

    if (ret != 0) {
        return -1;
    }

    if (ctx->keep_log == FLB_FALSE &&
        (merge_status == MERGE_PARSED || merge_status == MERGE_MAP)) {
        cfl_kvpair_destroy(log_pair);
    }
    else if (ctx->keep_log == FLB_TRUE &&
             (merge_status == MERGE_NONE || merge_status == MERGE_PARSED) &&
             log_value->type == CFL_VARIANT_STRING) {
        new_value = cfl_variant_create_from_string_s(ctx->unesc_buf,
                                                     ctx->unesc_buf_len,
                                                     CFL_FALSE);
        if (new_value == NULL) {
            return -1;
        }

        ret = kvpair_set_value(body, log_pair, new_value);
        if (ret != 0) {
            cfl_variant_destroy(new_value);
            return -1;
        }
    }

    return 0;
}

static int select_parser(struct flb_config *config,
                         struct flb_kube_props *props,
                         struct cfl_kvlist *body,
                         struct flb_parser **parser)
{
    *parser = NULL;

    switch (get_stream(body)) {
    case FLB_KUBE_PROP_STREAM_STDOUT:
        if (props->stdout_exclude == FLB_TRUE) {
            return FLB_FALSE;
        }
        if (props->stdout_parser != NULL) {
            *parser = flb_parser_get(props->stdout_parser, config);
        }
        break;
    case FLB_KUBE_PROP_STREAM_STDERR:
        if (props->stderr_exclude == FLB_TRUE) {
            return FLB_FALSE;
        }
        if (props->stderr_parser != NULL) {
            *parser = flb_parser_get(props->stderr_parser, config);
        }
        break;
    default:
        if (props->stdout_exclude == props->stderr_exclude &&
            props->stderr_exclude == FLB_TRUE) {
            return FLB_FALSE;
        }
        if (props->stdout_parser == props->stderr_parser &&
            props->stderr_parser != NULL) {
            *parser = flb_parser_get(props->stdout_parser, config);
        }
        break;
    }

    return FLB_TRUE;
}

static int encode_record_for_journal_lookup(struct flb_mp_chunk_record *record,
                                            char **out_buf, size_t *out_size)
{
    int ret;
    char *body_buf = NULL;
    char *meta_buf = NULL;
    size_t body_size = 0;
    size_t meta_size = 0;
    struct flb_log_event_encoder log_encoder;

    ret = flb_mp_cfl_to_msgpack(record->cobj_record, &body_buf, &body_size);
    if (ret != 0) {
        return -1;
    }

    ret = encode_empty_msgpack_map(&meta_buf, &meta_size);
    if (ret != 0) {
        flb_free(body_buf);
        return -1;
    }

    ret = flb_log_event_encoder_init(&log_encoder,
                                     FLB_LOG_EVENT_FORMAT_DEFAULT);
    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        flb_free(meta_buf);
        flb_free(body_buf);
        return -1;
    }

    ret = flb_log_event_encoder_begin_record(&log_encoder);
    if (ret == FLB_EVENT_ENCODER_SUCCESS) {
        ret = flb_log_event_encoder_set_timestamp(&log_encoder,
                                                  &record->event.timestamp);
    }
    if (ret == FLB_EVENT_ENCODER_SUCCESS) {
        ret = flb_log_event_encoder_set_metadata_from_raw_msgpack(&log_encoder,
                                                                  meta_buf,
                                                                  meta_size);
    }
    if (ret == FLB_EVENT_ENCODER_SUCCESS) {
        ret = flb_log_event_encoder_set_body_from_raw_msgpack(&log_encoder,
                                                              body_buf,
                                                              body_size);
    }
    if (ret == FLB_EVENT_ENCODER_SUCCESS) {
        ret = flb_log_event_encoder_commit_record(&log_encoder);
    }

    flb_free(meta_buf);
    flb_free(body_buf);

    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        flb_log_event_encoder_destroy(&log_encoder);
        return -1;
    }

    *out_buf = log_encoder.output_buffer;
    *out_size = log_encoder.output_length;

    flb_log_event_encoder_claim_internal_buffer_ownership(&log_encoder);
    flb_log_event_encoder_destroy(&log_encoder);

    return 0;
}

static int process_record(struct processor_kube_ctx *pctx,
                          struct flb_mp_chunk_cobj *chunk_cobj,
                          struct flb_mp_chunk_record *record,
                          const char *tag, int tag_len,
                          const char *chunk_cache_buf,
                          size_t chunk_cache_size,
                          const char *chunk_namespace_cache_buf,
                          size_t chunk_namespace_cache_size,
                          struct flb_kube_props *chunk_props)
{
    int ret;
    int record_type;
    char *journal_buf = NULL;
    size_t journal_size = 0;
    const char *cache_buf = chunk_cache_buf;
    size_t cache_size = chunk_cache_size;
    const char *namespace_cache_buf = chunk_namespace_cache_buf;
    size_t namespace_cache_size = chunk_namespace_cache_size;
    struct flb_parser *parser = NULL;
    struct flb_kube *ctx = &pctx->kube;
    struct flb_kube_meta meta = {0};
    struct flb_kube_props props = {0};
    struct flb_kube_meta namespace_meta = {0};
    struct cfl_kvlist *body;

    ret = flb_log_event_decoder_get_record_type(&record->event, &record_type);
    if (ret != FLB_EVENT_DECODER_SUCCESS) {
        flb_error("[processor:kubernetes] record has invalid event type");
        return 0;
    }

    if (record_type != FLB_LOG_EVENT_NORMAL) {
        return 0;
    }

    if (record->cobj_record == NULL ||
        record->cobj_record->variant == NULL ||
        record->cobj_record->variant->type != CFL_VARIANT_KVLIST) {
        return 0;
    }

    if (chunk_cobj->condition != NULL &&
        flb_condition_evaluate(chunk_cobj->condition, record) == FLB_FALSE) {
        return 0;
    }

    body = record->cobj_record->variant->data.as_kvlist;
    if (ctx->use_journal == FLB_TRUE && ctx->dummy_meta == FLB_FALSE) {
        ret = encode_record_for_journal_lookup(record, &journal_buf, &journal_size);
        if (ret != 0) {
            return -1;
        }

        ret = flb_kube_meta_get(ctx,
                                tag, tag_len,
                                journal_buf, journal_size,
                                &cache_buf, &cache_size,
                                &namespace_cache_buf, &namespace_cache_size,
                                &meta, &props,
                                &namespace_meta);
        flb_free(journal_buf);
        if (ret == -1) {
            return 0;
        }
    }
    else {
        props = *chunk_props;
    }

    ret = select_parser(ctx->config, &props, body, &parser);
    if (ret == FLB_FALSE) {
        flb_mp_chunk_cobj_record_destroy(chunk_cobj, record);

        if (ctx->use_journal == FLB_TRUE && ctx->dummy_meta == FLB_FALSE) {
            flb_kube_meta_release(&meta);
            flb_kube_prop_destroy(&props);
            flb_kube_meta_release(&namespace_meta);
        }

        return 0;
    }

    ret = merge_log(body, parser, &record->event.timestamp, ctx);
    if (ret != 0) {
        if (ctx->use_journal == FLB_TRUE && ctx->dummy_meta == FLB_FALSE) {
            flb_kube_meta_release(&meta);
            flb_kube_prop_destroy(&props);
            flb_kube_meta_release(&namespace_meta);
        }
        return -1;
    }

    ret = append_msgpack_map(body, "kubernetes", 10, cache_buf, cache_size);
    if (ret == 0) {
        ret = append_msgpack_map(body, "kubernetes_namespace", 20,
                                 namespace_cache_buf, namespace_cache_size);
    }

    if (ctx->use_journal == FLB_TRUE && ctx->dummy_meta == FLB_FALSE) {
        flb_kube_meta_release(&meta);
        flb_kube_prop_destroy(&props);
        flb_kube_meta_release(&namespace_meta);
    }

    return ret;
}

static int materialize_records(struct flb_mp_chunk_cobj *chunk_cobj)
{
    int ret;
    struct flb_mp_chunk_record *record;

    while ((ret = flb_mp_chunk_cobj_record_next(chunk_cobj, &record)) ==
           FLB_MP_CHUNK_RECORD_OK) {
    }

    chunk_cobj->record_pos = NULL;

    return ret == FLB_MP_CHUNK_RECORD_EOF ? 0 : -1;
}

static int cb_process_logs(struct flb_processor_instance *ins,
                           void *chunk_data,
                           const char *tag,
                           int tag_len)
{
    int ret;
    char *dummy_cache_buf = NULL;
    const char *cache_buf = NULL;
    size_t cache_size = 0;
    const char *namespace_cache_buf = NULL;
    size_t namespace_cache_size = 0;
    struct cfl_list *head;
    struct cfl_list *tmp;
    struct flb_mp_chunk_record *record;
    struct flb_mp_chunk_cobj *chunk_cobj;
    struct processor_kube_ctx *pctx;
    struct flb_kube *ctx;
    struct flb_kube_meta meta = {0};
    struct flb_kube_props props = {0};
    struct flb_kube_meta namespace_meta = {0};

    pctx = ins->context;
    if (pctx == NULL) {
        return FLB_PROCESSOR_FAILURE;
    }

    ctx = &pctx->kube;
    chunk_cobj = (struct flb_mp_chunk_cobj *) chunk_data;

    if (ctx->use_journal == FLB_FALSE || ctx->dummy_meta == FLB_TRUE) {
        if (ctx->dummy_meta == FLB_TRUE) {
            ret = flb_kube_dummy_meta_get(&dummy_cache_buf, &cache_size);
            if (ret == 0) {
                cache_buf = dummy_cache_buf;
            }
        }
        else {
            ret = flb_kube_meta_get(ctx,
                                    tag, tag_len,
                                    NULL, 0,
                                    &cache_buf, &cache_size,
                                    &namespace_cache_buf, &namespace_cache_size,
                                    &meta, &props,
                                    &namespace_meta);
        }

        if (ret == -1) {
            return FLB_PROCESSOR_SUCCESS;
        }
    }

    ret = materialize_records(chunk_cobj);
    if (ret != 0) {
        if (dummy_cache_buf != NULL) {
            flb_free(dummy_cache_buf);
        }
        flb_kube_meta_release(&meta);
        flb_kube_prop_destroy(&props);
        flb_kube_meta_release(&namespace_meta);
        return FLB_PROCESSOR_FAILURE;
    }

    cfl_list_foreach_safe(head, tmp, &chunk_cobj->records) {
        record = cfl_list_entry(head, struct flb_mp_chunk_record, _head);
        ret = process_record(pctx, chunk_cobj, record,
                             tag, tag_len,
                             cache_buf, cache_size,
                             namespace_cache_buf, namespace_cache_size,
                             &props);
        if (ret != 0) {
            if (dummy_cache_buf != NULL) {
                flb_free(dummy_cache_buf);
            }
            flb_kube_meta_release(&meta);
            flb_kube_prop_destroy(&props);
            flb_kube_meta_release(&namespace_meta);
            return FLB_PROCESSOR_FAILURE;
        }
    }

    if (dummy_cache_buf != NULL) {
        flb_free(dummy_cache_buf);
    }

    flb_kube_meta_release(&meta);
    flb_kube_prop_destroy(&props);
    flb_kube_meta_release(&namespace_meta);

    return FLB_PROCESSOR_SUCCESS;
}

static void *update_pod_service_map(void *arg)
{
    struct processor_kube_ctx *pctx;
    struct flb_kube *ctx;

    pctx = arg;
    ctx = &pctx->kube;

    flb_engine_evl_init();
    pctx->evl = mk_event_loop_create(256);
    if (pctx->evl == NULL) {
        flb_error("[processor:kubernetes] "
                  "Failed to create event loop for pod service map");
        return NULL;
    }

    flb_engine_evl_set(pctx->evl);

    while (1) {
        fetch_pod_service_map(ctx,
                              ctx->aws_pod_association_endpoint,
                              &pctx->metadata_mutex);
        flb_debug("[processor:kubernetes] "
                  "Updating pod to service map after %d seconds",
                  ctx->aws_pod_service_map_refresh_interval);
        sleep(ctx->aws_pod_service_map_refresh_interval);
    }

    return NULL;
}

static void processor_kube_conf_destroy(struct processor_kube_ctx *pctx)
{
    struct flb_kube *ctx;

    if (pctx == NULL) {
        return;
    }

    ctx = &pctx->kube;

    if (pctx->background_thread) {
        pthread_cancel(pctx->background_thread);
        pthread_join(pctx->background_thread, NULL);
    }

    if (pctx->metadata_mutex_initialized == FLB_TRUE) {
        pthread_mutex_destroy(&pctx->metadata_mutex);
    }

    if (pctx->evl != NULL) {
        mk_event_loop_destroy(pctx->evl);
    }

    flb_kube_meta_cache_destroy(ctx->hash_table);
    flb_kube_meta_cache_destroy(ctx->namespace_hash_table);

    if (ctx->aws_pod_service_hash_table) {
        flb_hash_table_destroy(ctx->aws_pod_service_hash_table);
    }

    if (ctx->merge_log == FLB_TRUE) {
        flb_free(ctx->unesc_buf);
    }

    if (ctx->parser == NULL && ctx->regex) {
        flb_regex_destroy(ctx->regex);
    }
    if (ctx->deploymentRegex) {
        flb_regex_destroy(ctx->deploymentRegex);
    }

    flb_free(ctx->api_host);
    flb_free(ctx->token);
    flb_free(ctx->namespace);
    flb_free(ctx->podname);
    flb_free(ctx->auth);

    if (ctx->kubelet_upstream) {
        flb_upstream_destroy(ctx->kubelet_upstream);
    }
    if (ctx->kube_api_upstream) {
        flb_upstream_destroy(ctx->kube_api_upstream);
    }
    if (ctx->aws_pod_association_upstream) {
        flb_upstream_destroy(ctx->aws_pod_association_upstream);
    }

    if (ctx->kube_client) {
        flb_kube_client_destroy(ctx->kube_client);
    }

    if (ctx->platform) {
        flb_free(ctx->platform);
    }

    if (ctx->aws_pod_association_tls) {
        flb_tls_destroy(ctx->aws_pod_association_tls);
    }

#ifdef FLB_HAVE_TLS
    if (ctx->tls) {
        flb_tls_destroy(ctx->tls);
    }
    if (ctx->kubelet_tls) {
        flb_tls_destroy(ctx->kubelet_tls);
    }
#endif

    flb_free(pctx);
}

static int processor_kube_conf_init(struct processor_kube_ctx *pctx,
                                    struct flb_processor_instance *ins,
                                    struct flb_config *config)
{
    int ret;
    int off;
    const char *url;
    const char *tmp;
    const char *p;
    const char *cmd;
    struct flb_kube *ctx;

    ctx = &pctx->kube;
    ctx->config = config;
    ctx->ins = &pctx->filter_instance;

    pctx->filter_plugin.name = "kubernetes";
    pctx->filter_instance.event_type = FLB_FILTER_LOGS;
    pctx->filter_instance.id = ins->id;
    pctx->filter_instance.log_level = ins->log_level;
    pctx->filter_instance.p = &pctx->filter_plugin;
    pctx->filter_instance.config = config;
    snprintf(pctx->filter_instance.name, sizeof(pctx->filter_instance.name) - 1,
             "%s", flb_processor_instance_get_name(ins));

    ret = flb_processor_instance_config_map_set(ins, ctx);
    if (ret == -1) {
        return -1;
    }

    cmd = flb_processor_instance_get_property("kube_token_command", ins);
    if (cmd != NULL) {
        ctx->kube_token_command = cmd;
    }
    else {
        ctx->kube_token_command = NULL;
    }
    ctx->kube_token_create = 0;

    tmp = flb_processor_instance_get_property("merge_parser", ins);
    if (tmp != NULL) {
        ctx->merge_parser = flb_parser_get(tmp, config);
        if (ctx->merge_parser == NULL) {
            flb_error("[processor:kubernetes] parser '%s' is not registered",
                      tmp);
        }
    }
    else {
        ctx->merge_parser = NULL;
    }

    url = flb_processor_instance_get_property("kube_url", ins);
    if (ctx->use_tag_for_meta) {
        ctx->api_https = FLB_FALSE;
    }
    else if (url == NULL) {
        ctx->api_host = flb_strdup(FLB_API_HOST);
        ctx->api_port = FLB_API_PORT;
        ctx->api_https = FLB_API_TLS;
    }
    else {
        tmp = url;
        if (strncmp(tmp, "http://", 7) == 0) {
            off = 7;
            ctx->api_https = FLB_FALSE;
        }
        else if (strncmp(tmp, "https://", 8) == 0) {
            off = 8;
            ctx->api_https = FLB_TRUE;
        }
        else {
            return -1;
        }

        p = url + off;
        tmp = strchr(p, ':');
        if (tmp != NULL) {
            ctx->api_host = flb_strndup(p, tmp - p);
            tmp++;
            ctx->api_port = atoi(tmp);
        }
        else {
            ctx->api_host = flb_strdup(p);
            ctx->api_port = FLB_API_PORT;
        }
    }

    if (ctx->api_host == NULL) {
        return -1;
    }

    ctx->hash_table = flb_kube_meta_cache_create(ctx->kube_meta_cache_ttl,
                                                 FLB_HASH_TABLE_SIZE);
    ctx->namespace_hash_table =
        flb_kube_meta_cache_create(ctx->kube_meta_namespace_cache_ttl,
                                   FLB_HASH_TABLE_SIZE);

    if (ctx->hash_table == NULL || ctx->namespace_hash_table == NULL) {
        return -1;
    }

    if (ctx->merge_log == FLB_TRUE) {
        ctx->unesc_buf = flb_malloc(FLB_MERGE_BUF_SIZE);
        if (ctx->unesc_buf == NULL) {
            flb_errno();
            return -1;
        }
        ctx->unesc_buf_size = FLB_MERGE_BUF_SIZE;
    }

    tmp = flb_processor_instance_get_property("regex_parser", ins);
    if (tmp != NULL) {
        ctx->parser = flb_parser_get(tmp, config);
        if (ctx->parser == NULL) {
            flb_error("[processor:kubernetes] invalid parser '%s'", tmp);
            return -1;
        }

        if (ctx->parser->type != FLB_PARSER_REGEX) {
            flb_error("[processor:kubernetes] invalid parser type '%s'", tmp);
            return -1;
        }
        else {
            ctx->regex = ctx->parser->regex;
        }
    }

    if (!ctx->use_tag_for_meta) {
        flb_info("[processor:kubernetes] https=%i host=%s port=%i",
                 ctx->api_https, ctx->api_host, ctx->api_port);
    }

    ctx->aws_pod_service_hash_table = flb_hash_table_create_with_ttl(
                                            ctx->aws_pod_service_map_ttl,
                                            FLB_HASH_TABLE_EVICT_OLDER,
                                            FLB_HASH_TABLE_SIZE,
                                            FLB_HASH_TABLE_SIZE);
    if (ctx->aws_pod_service_hash_table == NULL) {
        return -1;
    }

    return 0;
}

static int cb_init(struct flb_processor_instance *ins,
                   void *source_plugin_instance,
                   int source_plugin_type,
                   struct flb_config *config)
{
    int ret;
    struct processor_kube_ctx *pctx;
    struct flb_kube *ctx;

    (void) source_plugin_instance;
    (void) source_plugin_type;

    pctx = flb_calloc(1, sizeof(struct processor_kube_ctx));
    if (pctx == NULL) {
        flb_errno();
        return FLB_PROCESSOR_FAILURE;
    }

    ret = processor_kube_conf_init(pctx, ins, config);
    if (ret != 0) {
        processor_kube_conf_destroy(pctx);
        return FLB_PROCESSOR_FAILURE;
    }

    ctx = &pctx->kube;

    ret = flb_kube_regex_init(ctx);
    if (ret == -1) {
        processor_kube_conf_destroy(pctx);
        return FLB_PROCESSOR_FAILURE;
    }

    ret = flb_kube_meta_init(ctx, config);
    if (ret == -1) {
        processor_kube_conf_destroy(pctx);
        return FLB_PROCESSOR_FAILURE;
    }

    ret = pthread_mutex_init(&pctx->metadata_mutex, NULL);
    if (ret != 0) {
        processor_kube_conf_destroy(pctx);
        return FLB_PROCESSOR_FAILURE;
    }
    pctx->metadata_mutex_initialized = FLB_TRUE;

    if (ctx->aws_use_pod_association) {
        ret = pthread_create(&pctx->background_thread,
                             NULL,
                             update_pod_service_map,
                             pctx);
        if (ret != 0) {
            flb_error("[processor:kubernetes] Failed to create background thread");
            processor_kube_conf_destroy(pctx);
            return FLB_PROCESSOR_FAILURE;
        }
    }

    flb_processor_instance_set_context(ins, pctx);

    return FLB_PROCESSOR_SUCCESS;
}

static int cb_exit(struct flb_processor_instance *ins, void *data)
{
    (void) ins;

    processor_kube_conf_destroy(data);

    return FLB_PROCESSOR_SUCCESS;
}

/* Configuration properties map */
static struct flb_config_map config_map[] = {
    {
     FLB_CONFIG_MAP_SIZE, "buffer_size", "32K",
     0, FLB_TRUE, offsetof(struct flb_kube, buffer_size),
     "buffer size to receive response from API server",
    },
    {
     FLB_CONFIG_MAP_INT, "tls.debug", "0",
     0, FLB_TRUE, offsetof(struct flb_kube, tls_debug),
     "set TLS debug level: 0 (no debug), 1 (error), "
     "2 (state change), 3 (info) and 4 (verbose)"
    },
    {
     FLB_CONFIG_MAP_BOOL, "tls.verify", "true",
     0, FLB_TRUE, offsetof(struct flb_kube, tls_verify),
     "enable or disable verification of TLS peer certificate"
    },
    {
     FLB_CONFIG_MAP_STR, "tls.vhost", NULL,
     0, FLB_TRUE, offsetof(struct flb_kube, tls_vhost),
     "set optional TLS virtual host"
    },
    {
     FLB_CONFIG_MAP_BOOL, "tls.verify_hostname", "off",
     0, FLB_TRUE, offsetof(struct flb_kube, tls_verify_hostname),
     "enable or disable to verify hostname"
    },
    {
     FLB_CONFIG_MAP_BOOL, "merge_log", "false",
     0, FLB_TRUE, offsetof(struct flb_kube, merge_log),
     "merge 'log' key content as individual keys"
    },
    {
     FLB_CONFIG_MAP_STR, "merge_parser", NULL,
     0, FLB_FALSE, 0,
     "specify a 'parser' name to parse the 'log' key content"
    },
    {
     FLB_CONFIG_MAP_STR, "merge_log_key", NULL,
     0, FLB_TRUE, offsetof(struct flb_kube, merge_log_key),
     "set the 'key' name where the content of 'key' will be placed"
    },
    {
     FLB_CONFIG_MAP_BOOL, "merge_log_trim", "true",
     0, FLB_TRUE, offsetof(struct flb_kube, merge_log_trim),
     "remove ending '\\n' or '\\r' characters from the log content"
    },
    {
     FLB_CONFIG_MAP_BOOL, "keep_log", "true",
     0, FLB_TRUE, offsetof(struct flb_kube, keep_log),
     "keep original log content if it was successfully parsed and merged"
    },
    {
     FLB_CONFIG_MAP_STR, "kube_url", "https://kubernetes.default.svc",
     0, FLB_FALSE, 0,
     "Kubernetes API server URL"
    },
    {
     FLB_CONFIG_MAP_STR, "kube_meta_preload_cache_dir", NULL,
     0, FLB_TRUE, offsetof(struct flb_kube, meta_preload_cache_dir),
     "set directory with metadata files"
    },
    {
     FLB_CONFIG_MAP_STR, "kube_ca_file", FLB_KUBE_CA,
     0, FLB_TRUE, offsetof(struct flb_kube, tls_ca_file),
     "Kubernetes TLS CA file"
    },
    {
     FLB_CONFIG_MAP_STR, "kube_ca_path", NULL,
     0, FLB_TRUE, offsetof(struct flb_kube, tls_ca_path),
     "Kubernetes TLS ca path"
    },
    {
     FLB_CONFIG_MAP_STR, "kube_tag_prefix", FLB_KUBE_TAG_PREFIX,
     0, FLB_TRUE, offsetof(struct flb_kube, kube_tag_prefix),
     "prefix used in tag by the input plugin"
    },
    {
     FLB_CONFIG_MAP_STR, "kube_token_file", FLB_KUBE_TOKEN,
     0, FLB_TRUE, offsetof(struct flb_kube, token_file),
     "Kubernetes authorization token file"
    },
    {
     FLB_CONFIG_MAP_STR, "kube_token_command", NULL,
     0, FLB_FALSE, 0,
     "command to get Kubernetes authorization token"
    },
    {
     FLB_CONFIG_MAP_BOOL, "labels", "true",
     0, FLB_TRUE, offsetof(struct flb_kube, labels),
     "include Kubernetes labels on every record"
    },
    {
     FLB_CONFIG_MAP_BOOL, "annotations", "true",
     0, FLB_TRUE, offsetof(struct flb_kube, annotations),
     "include Kubernetes annotations on every record"
    },
    {
     FLB_CONFIG_MAP_BOOL, "owner_references", "false",
     0, FLB_TRUE, offsetof(struct flb_kube, owner_references),
     "include Kubernetes owner references on every record"
    },
    {
     FLB_CONFIG_MAP_BOOL, "namespace_labels", "false",
     0, FLB_TRUE, offsetof(struct flb_kube, namespace_labels),
     "include Kubernetes namespace labels on every record"
    },
    {
     FLB_CONFIG_MAP_BOOL, "namespace_annotations", "false",
     0, FLB_TRUE, offsetof(struct flb_kube, namespace_annotations),
     "include Kubernetes namespace annotations on every record"
    },
    {
     FLB_CONFIG_MAP_BOOL, "namespace_metadata_only", "false",
     0, FLB_TRUE, offsetof(struct flb_kube, namespace_metadata_only),
     "ignore pod metadata entirely and only fetch namespace metadata"
    },
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
    {
     FLB_CONFIG_MAP_BOOL, "use_journal", "false",
     0, FLB_TRUE, offsetof(struct flb_kube, use_journal),
     "use Journald (Systemd) mode"
    },
    {
     FLB_CONFIG_MAP_STR, "regex_parser", NULL,
     0, FLB_FALSE, 0,
     "optional regex parser to extract metadata"
    },
    {
     FLB_CONFIG_MAP_BOOL, "dummy_meta", "false",
     0, FLB_TRUE, offsetof(struct flb_kube, dummy_meta),
     "use 'dummy' metadata, do not talk to API server"
    },
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
    {
     FLB_CONFIG_MAP_BOOL, "use_kubelet", "false",
     0, FLB_TRUE, offsetof(struct flb_kube, use_kubelet),
     "use kubelet to get metadata instead of kube-server"
    },
    {
     FLB_CONFIG_MAP_STR, "kubelet_host", "127.0.0.1",
     0, FLB_TRUE, offsetof(struct flb_kube, kubelet_host),
     "kubelet host to connect with when using kubelet"
    },
    {
     FLB_CONFIG_MAP_INT, "kubelet_port", "10250",
     0, FLB_TRUE, offsetof(struct flb_kube, kubelet_port),
     "kubelet port to connect with when using kubelet"
    },
    {
     FLB_CONFIG_MAP_TIME, "kube_token_ttl", "10m",
     0, FLB_TRUE, offsetof(struct flb_kube, kube_token_ttl),
     "kubernetes token ttl"
    },
    {
     FLB_CONFIG_MAP_TIME, "kube_meta_cache_ttl", "0",
     0, FLB_TRUE, offsetof(struct flb_kube, kube_meta_cache_ttl),
     "configurable TTL for K8s cached metadata"
    },
    {
     FLB_CONFIG_MAP_TIME, "kube_meta_namespace_cache_ttl", "15m",
     0, FLB_TRUE, offsetof(struct flb_kube, kube_meta_namespace_cache_ttl),
     "configurable TTL for K8s cached namespace metadata"
    },
    {
     FLB_CONFIG_MAP_BOOL, "aws_use_pod_association", "false",
     0, FLB_TRUE, offsetof(struct flb_kube, aws_use_pod_association),
     "use custom endpoint to get pod to service name mapping"
    },
    {
     FLB_CONFIG_MAP_BOOL, "use_pod_association", "false",
     0, FLB_TRUE, offsetof(struct flb_kube, aws_use_pod_association),
     "use custom endpoint to get pod to service name mapping"
    },
    {
     FLB_CONFIG_MAP_STR, "aws_pod_association_host",
     "cloudwatch-agent.amazon-cloudwatch",
     0, FLB_TRUE, offsetof(struct flb_kube, aws_pod_association_host),
     "host to connect with when performing pod to service association"
    },
    {
     FLB_CONFIG_MAP_STR, "aws_pod_association_endpoint",
     "/kubernetes/pod-to-service-env-map",
     0, FLB_TRUE, offsetof(struct flb_kube, aws_pod_association_endpoint),
     "endpoint for pod to service association"
    },
    {
     FLB_CONFIG_MAP_INT, "aws_pod_association_port", "4311",
     0, FLB_TRUE, offsetof(struct flb_kube, aws_pod_association_port),
     "port for pod to service association endpoint"
    },
    {
     FLB_CONFIG_MAP_INT, "aws_pod_service_map_ttl", "0",
     0, FLB_TRUE, offsetof(struct flb_kube, aws_pod_service_map_ttl),
     "configurable TTL for pod to service map storage"
    },
    {
     FLB_CONFIG_MAP_INT, "aws_pod_service_map_refresh_interval", "60",
     0, FLB_TRUE, offsetof(struct flb_kube, aws_pod_service_map_refresh_interval),
     "refresh interval for the pod to service map storage"
    },
    {
     FLB_CONFIG_MAP_STR, "aws_pod_service_preload_cache_dir", NULL,
     0, FLB_TRUE, offsetof(struct flb_kube, aws_pod_service_preload_cache_path),
     "set directory with pod to service map files"
    },
    {
     FLB_CONFIG_MAP_STR, "aws_pod_association_host_server_ca_file",
     "/etc/amazon-cloudwatch-observability-agent-server-cert/tls-ca.crt",
     0, FLB_TRUE, offsetof(struct flb_kube, aws_pod_association_host_server_ca_file),
     "TLS CA certificate path for communication with agent server"
    },
    {
     FLB_CONFIG_MAP_STR, "aws_pod_association_host_client_cert_file",
     "/etc/amazon-cloudwatch-observability-agent-client-cert/client.crt",
     0, FLB_TRUE, offsetof(struct flb_kube, aws_pod_association_host_client_cert_file),
     "Client Certificate path for mTLS calls to agent server"
    },
    {
     FLB_CONFIG_MAP_STR, "aws_pod_association_host_client_key_file",
     "/etc/amazon-cloudwatch-observability-agent-client-cert/client.key",
     0, FLB_TRUE, offsetof(struct flb_kube, aws_pod_association_host_client_key_file),
     "Client Certificate Key path for mTLS calls to agent server"
    },
    {
     FLB_CONFIG_MAP_INT, "aws_pod_association_host_tls_debug", "0",
     0, FLB_TRUE, offsetof(struct flb_kube, aws_pod_association_host_tls_debug),
     "set TLS debug level"
    },
    {
     FLB_CONFIG_MAP_BOOL, "aws_pod_association_host_tls_verify", "true",
     0, FLB_TRUE, offsetof(struct flb_kube, aws_pod_association_host_tls_verify),
     "enable or disable verification of TLS peer certificate"
    },
    {
     FLB_CONFIG_MAP_STR, "set_platform", NULL,
     0, FLB_TRUE, offsetof(struct flb_kube, set_platform),
     "Set the platform that kubernetes is in"
    },
    {0}
};

struct flb_processor_plugin processor_kubernetes_plugin = {
    .name            = "kubernetes",
    .description     = "Processor to append Kubernetes metadata",
    .cb_init         = cb_init,
    .cb_process_logs = cb_process_logs,
    .cb_exit         = cb_exit,
    .config_map      = config_map,
    .flags           = 0
};
