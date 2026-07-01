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

#include <stdio.h>
#include <sys/types.h>

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_kv.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_str.h>
#include <fluent-bit/flb_filter.h>
#include <fluent-bit/flb_hash_table.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_filter_plugin.h>
#include <fluent-bit/flb_log_event_decoder.h>
#include <fluent-bit/flb_log_event_encoder.h>
#include <msgpack.h>

#include "geoip2.h"

static int configure(struct geoip2_ctx *ctx,
                     struct flb_filter_instance *f_ins)
{
    struct flb_kv *kv = NULL;
    struct mk_list *head = NULL;
    struct mk_list *split;
    int status;
    struct geoip2_record *record;
    struct flb_split_entry *sentry;
    struct flb_config_map_val *record_key;
    int ret;

    ctx->mmdb = flb_malloc(sizeof(MMDB_s));
    ctx->lookup_keys_num = 0;
    ctx->records_num = 0;

    ret = flb_filter_config_map_set(f_ins, (void *)ctx);
    if (ret == -1) {
        flb_plg_error(f_ins, "unable to load configuration");
        flb_free(ctx->mmdb);
        return -1;
    }

    if (ctx->database) {
        status = MMDB_open(ctx->database, MMDB_MODE_MMAP, ctx->mmdb);
        if (status != MMDB_SUCCESS) {
            flb_plg_error(f_ins, "Cannot open geoip2 database: %s: %s",
                          ctx->database, MMDB_strerror(status));
            flb_free(ctx->mmdb);
            return -1;
        }
    } else {
        flb_plg_error(f_ins, "no geoip2 database has been loaded");
        flb_free(ctx->mmdb);
        return -1;
    }
    
    mk_list_foreach(head, ctx->lookup_keys) {
        ctx->lookup_keys_num++;
    }
    
    flb_config_map_foreach(head, record_key, ctx->record_keys) {
        record = flb_malloc(sizeof(struct geoip2_record));
        if (!record) {
            flb_errno();
            continue;
        }
        split = flb_utils_split(record_key->val.str, ' ', 2);
        if (mk_list_size(split) != 3) {
            flb_plg_error(f_ins, "invalid record parameter: '%s'", kv->val);
            flb_plg_error(f_ins, "expects 'KEY LOOKUP_KEY VALUE'");
            flb_free(record);
            flb_utils_split_free(split);
            continue;
        }

        /* Get first value (field) */
        sentry = mk_list_entry_first(split, struct flb_split_entry, _head);
        record->key = flb_strndup(sentry->value, sentry->len);
        record->key_len = sentry->len;

        sentry = mk_list_entry_next(&sentry->_head, struct flb_split_entry,
                                    _head, split);
        record->lookup_key = flb_strndup(sentry->value, sentry->len);
        record->lookup_key_len = sentry->len;

        sentry = mk_list_entry_last(split, struct flb_split_entry, _head);
        record->val = flb_strndup(sentry->value, sentry->len);
        record->val_len = sentry->len;

        flb_utils_split_free(split);
        mk_list_add(&record->_head, &ctx->records);
        ctx->records_num++;
    }

    if (ctx->lookup_keys_num <= 0) {
        flb_plg_error(f_ins, "at least one lookup_key is required");
        return -1;
    }
    if (ctx->records_num <= 0) {
        flb_plg_error(f_ins, "at least one record is required");
        return -1;
    }
    return 0;
}

static int delete_list(struct geoip2_ctx *ctx)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct geoip2_record *record;

    mk_list_foreach_safe(head, tmp, &ctx->records) {
        record = mk_list_entry(head, struct geoip2_record, _head);
        flb_free(record->lookup_key);
        flb_free(record->key);
        flb_free(record->val);
        mk_list_del(&record->_head);
        flb_free(record);
    }
    return 0;
}

static struct flb_hash_table *prepare_lookup_keys(msgpack_object *map,
                                                 struct geoip2_ctx *ctx)
{
    msgpack_object_kv *kv;
    msgpack_object *key;
    msgpack_object *val;
    struct mk_list *head;
    struct flb_config_map_val *lookup_key;
    struct flb_hash_table *ht;

    ht = flb_hash_table_create(FLB_HASH_TABLE_EVICT_NONE, ctx->lookup_keys_num, -1);
    if (!ht) {
        return NULL;
    }

    kv = map->via.map.ptr;
    for (int i = 0; i < map->via.map.size; i++) {
        key = &(kv + i)->key;
        val = &(kv + i)->val;
        if (key->type != MSGPACK_OBJECT_STR) {
            continue;
        }
        if (val->type != MSGPACK_OBJECT_STR) {
            continue;
        }
        
        flb_config_map_foreach(head, lookup_key, ctx->lookup_keys) {
            if (strncasecmp(key->via.str.ptr, lookup_key->val.str, 
                flb_sds_len(lookup_key->val.str)) == 0) {
                flb_hash_table_add(ht, lookup_key->val.str, flb_sds_len(lookup_key->val.str),
                                   (void *) val->via.str.ptr, val->via.str.size);
            }
        }
    }

    return ht;
}

static MMDB_lookup_result_s mmdb_lookup(struct geoip2_ctx *ctx, const char *ip)
{
    int gai_error;
    int mmdb_error;
    MMDB_lookup_result_s result;

    result = MMDB_lookup_string(ctx->mmdb, ip, &gai_error, &mmdb_error);
    if (gai_error != 0) {
        flb_plg_error(ctx->ins, "getaddrinfo failed: %s", gai_strerror(gai_error));
    }
    if (mmdb_error != MMDB_SUCCESS) {
        flb_plg_error(ctx->ins, "lookup failed : %s", MMDB_strerror(mmdb_error));
    }

    return result;
}

static void add_geoip_fields(msgpack_object *map,
                             struct flb_hash_table *lookup_keys,
                             struct geoip2_ctx *ctx,
                             struct flb_log_event_encoder *encoder)
{
    int ret;
    struct mk_list *head;
    struct mk_list *tmp;
    struct geoip2_record *record;
    const char *ip;
    size_t ip_size;
    MMDB_lookup_result_s result;
    MMDB_entry_s entry;
    MMDB_entry_data_s entry_data;
    char **path;
    int status;
    char *pos;
    char key[64];
    struct mk_list *split;
    int split_size;
    struct mk_list *path_head;
    struct mk_list *path_tmp;
    struct flb_split_entry *sentry;
    int i = 0;

    mk_list_foreach_safe(head, tmp, &ctx->records) {
        record = mk_list_entry(head, struct geoip2_record, _head);

        flb_log_event_encoder_append_body_string(
            encoder, record->key, record->key_len);

        ret = flb_hash_table_get(lookup_keys, record->lookup_key, record->lookup_key_len,
                                 (void *) &ip, &ip_size);
        if (ret == -1) {
            flb_log_event_encoder_append_body_null(encoder);
            continue;
        }

        result = mmdb_lookup(ctx, ip);
        if (!result.found_entry) {
            flb_log_event_encoder_append_body_null(encoder);
            continue;
        }
        entry = result.entry;
        pos = strstr(record->val, "}");
        memset(key, '\0', sizeof(key));
        strncpy(key, record->val + 2, pos - (record->val + 2));
        split = flb_utils_split(key, '.', 8);
        split_size = mk_list_size(split);
        path = flb_malloc(sizeof(char *) * (split_size + 1));
        i = 0;
        mk_list_foreach_safe(path_head, path_tmp, split) {
            sentry = mk_list_entry(path_head, struct flb_split_entry, _head);
            path[i] = flb_strndup(sentry->value, sentry->len);
            i++;
        }
        path[split_size] = NULL;
        status = MMDB_aget_value(&entry, &entry_data, (const char *const *const)path);
        flb_utils_split_free(split);
        for (int j = 0; j < split_size; j++) {
            flb_free(path[j]);
        }
        flb_free(path);
        if (status != MMDB_SUCCESS) {
            flb_plg_warn(ctx->ins, "cannot get value: %s", MMDB_strerror(status));
            flb_log_event_encoder_append_body_null(encoder);
            continue;
        }
        if (!entry_data.has_data) {
            flb_plg_warn(ctx->ins, "found entry does not have data");
            flb_log_event_encoder_append_body_null(encoder);
            continue;
        }
        if (entry_data.type == MMDB_DATA_TYPE_MAP ||
            entry_data.type == MMDB_DATA_TYPE_ARRAY) {
            flb_plg_warn(ctx->ins, "Not supported MAP and ARRAY");
            flb_log_event_encoder_append_body_null(encoder);
            continue;
        }

        switch (entry_data.type) {
        case MMDB_DATA_TYPE_EXTENDED:
            /* TODO: not implemented */
            flb_log_event_encoder_append_body_null(encoder);
            break;
        case MMDB_DATA_TYPE_POINTER:
            /* TODO: not implemented */
            flb_log_event_encoder_append_body_null(encoder);
            break;
        case MMDB_DATA_TYPE_UTF8_STRING:
            flb_log_event_encoder_append_body_string(
                encoder,
                (char *) entry_data.utf8_string,
                entry_data.data_size);
            break;
        case MMDB_DATA_TYPE_DOUBLE:
            flb_log_event_encoder_append_body_double(
                encoder, entry_data.double_value);
            break;
        case MMDB_DATA_TYPE_BYTES:
            flb_log_event_encoder_append_body_string(
                encoder,
                (char *) entry_data.bytes,
                entry_data.data_size);
            break;
        case MMDB_DATA_TYPE_UINT16:
            flb_log_event_encoder_append_body_uint16(
                encoder, entry_data.uint16);
            break;
        case MMDB_DATA_TYPE_UINT32:
            flb_log_event_encoder_append_body_uint32(
                encoder, entry_data.uint32);
            break;
        case MMDB_DATA_TYPE_MAP:
            /* TODO: not implemented */
            flb_log_event_encoder_append_body_null(encoder);
            break;
        case MMDB_DATA_TYPE_INT32:
            flb_log_event_encoder_append_body_int32(
                encoder, entry_data.int32);
            break;
        case MMDB_DATA_TYPE_UINT64:
            flb_log_event_encoder_append_body_uint64(
                encoder, entry_data.uint64);
            break;
        case MMDB_DATA_TYPE_UINT128:
#if !(MMDB_UINT128_IS_BYTE_ARRAY)
            /* entry_data.uint128; */
            flb_warn("Not supported uint128");
#else
            flb_warn("Not implemented when MMDB_UINT128_IS_BYTE_ARRAY");
#endif
            flb_log_event_encoder_append_body_null(encoder);
            break;
        case MMDB_DATA_TYPE_ARRAY:
            /* TODO: not implemented */
            flb_log_event_encoder_append_body_null(encoder);
            break;
        case MMDB_DATA_TYPE_CONTAINER:
            /* TODO: not implemented */
            flb_log_event_encoder_append_body_null(encoder);
            break;
        case MMDB_DATA_TYPE_END_MARKER:
            break;
        case MMDB_DATA_TYPE_BOOLEAN:
            flb_log_event_encoder_append_body_boolean(
                encoder, (int) entry_data.boolean);
            break;
        case MMDB_DATA_TYPE_FLOAT:
            flb_log_event_encoder_append_body_double(
                encoder, entry_data.float_value);
            break;
        default:
            flb_error("Unknown type: %d", entry_data.type);
            break;
        }
    }
}

static int cb_geoip2_init(struct flb_filter_instance *f_ins,
                          struct flb_config *config,
                          void *data)
{
    struct geoip2_ctx *ctx = NULL;
    /* Create context */
    ctx = flb_calloc(1, sizeof(struct geoip2_ctx));
    if (!ctx) {
        flb_errno();
        return -1;
    }
    mk_list_init(&ctx->records);


    if (configure(ctx, f_ins) < 0) {
        delete_list(ctx);
        return -1;
    }

    ctx->ins = f_ins;
    flb_filter_set_context(f_ins, ctx);

    return 0;
}

static int cb_geoip2_filter(const void *data, size_t bytes,
                            const char *tag, int tag_len,
                            void **out_buf, size_t *out_size,
                            struct flb_filter_instance *f_ins,
                            struct flb_input_instance *i_ins,
                            void *context,
                            struct flb_config *config)
{
    struct geoip2_ctx *ctx = context;
    msgpack_object_kv *kv;
    struct flb_hash_table *lookup_keys_hash;
    struct flb_log_event_encoder log_encoder;
    struct flb_log_event_decoder log_decoder;
    struct flb_log_event log_event;
    int ret;
    int i;

    (void) i_ins;

    ret = flb_log_event_decoder_init(&log_decoder, (char *) data, bytes);

    if (ret != FLB_EVENT_DECODER_SUCCESS) {
        flb_plg_error(ctx->ins,
                      "Log event decoder initialization error : %d", ret);

        return FLB_FILTER_NOTOUCH;
    }

    ret = flb_log_event_encoder_init(&log_encoder,
                                     FLB_LOG_EVENT_FORMAT_DEFAULT);

    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        flb_plg_error(ctx->ins,
                      "Log event encoder initialization error : %d", ret);

        flb_log_event_decoder_destroy(&log_decoder);

        return FLB_FILTER_NOTOUCH;
    }

    while ((ret = flb_log_event_decoder_next(
                    &log_decoder,
                    &log_event)) == FLB_EVENT_DECODER_SUCCESS) {

        ret = flb_log_event_encoder_begin_record(&log_encoder);

        if (ret == FLB_EVENT_ENCODER_SUCCESS) {
            ret = flb_log_event_encoder_set_timestamp(
                    &log_encoder, &log_event.timestamp);
        }

        kv = log_event.body->via.map.ptr;
        for (i = 0;
             i < log_event.body->via.map.size &&
             ret == FLB_EVENT_ENCODER_SUCCESS ;
             i++) {
            ret = flb_log_event_encoder_append_body_values(
                    &log_encoder,
                    FLB_LOG_EVENT_MSGPACK_OBJECT_VALUE(&kv[i].key),
                    FLB_LOG_EVENT_MSGPACK_OBJECT_VALUE(&kv[i].val));
        }

        lookup_keys_hash = prepare_lookup_keys(log_event.body, ctx);
        add_geoip_fields(log_event.body, lookup_keys_hash, ctx, &log_encoder);
        flb_hash_table_destroy(lookup_keys_hash);

        if (ret == FLB_EVENT_ENCODER_SUCCESS) {
            ret = flb_log_event_encoder_commit_record(&log_encoder);
        }
    }

    if (ret == FLB_EVENT_DECODER_ERROR_INSUFFICIENT_DATA &&
        log_decoder.offset == bytes) {
        ret = FLB_EVENT_ENCODER_SUCCESS;
    }

    if (ret == FLB_EVENT_ENCODER_SUCCESS) {
        *out_buf  = log_encoder.output_buffer;
        *out_size = log_encoder.output_length;

        ret = FLB_FILTER_MODIFIED;

        flb_log_event_encoder_claim_internal_buffer_ownership(&log_encoder);
    }
    else {
        flb_plg_error(ctx->ins,
                      "Log event encoder error : %d", ret);

        ret = FLB_FILTER_NOTOUCH;
    }

    flb_log_event_decoder_destroy(&log_decoder);
    flb_log_event_encoder_destroy(&log_encoder);

    return ret;
}

static int cb_geoip2_exit(void *data, struct flb_config *config)
{
    struct geoip2_ctx *ctx = data;

    if (ctx != NULL) {
        delete_list(ctx);
        MMDB_close(ctx->mmdb);
        flb_free(ctx->mmdb);
        flb_free(ctx);
    }

    return 0;
}

static struct flb_config_map config_map[] = {
    {
     FLB_CONFIG_MAP_STR, "database", (char *)NULL,
     0, FLB_TRUE, offsetof(struct geoip2_ctx, database),
     "Set the geoip2 database path"
    },
    {
     FLB_CONFIG_MAP_STR, "lookup_key", NULL,
     FLB_CONFIG_MAP_MULT, FLB_TRUE, offsetof(struct geoip2_ctx, lookup_keys),
     "Add a lookup_key"
    },
    {
     FLB_CONFIG_MAP_STR, "record", NULL,
     FLB_CONFIG_MAP_MULT, FLB_TRUE, offsetof(struct geoip2_ctx, record_keys),
     "Add a record to the output base on geoip2"
    },
    /* EOF */
    {0}
};

struct flb_filter_plugin filter_geoip2_plugin = {
    .name        = "geoip2",
    .description = "add geoip information to records",
    .cb_init     = cb_geoip2_init,
    .cb_filter   = cb_geoip2_filter,
    .cb_exit     = cb_geoip2_exit,
    .config_map  = config_map,
    .flags       = 0,
};
