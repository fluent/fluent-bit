/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
#include <stdio.h>
#include <sys/types.h>

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_kv.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_str.h>
#include <fluent-bit/flb_filter.h>
#include <fluent-bit/flb_hash.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_pack.h>
#include <msgpack.h>

#include "geoip2.h"

#define PLUGIN_NAME "filter_geoip2"

static int configure(struct geoip2_ctx *ctx,
                     struct flb_filter_instance *f_ins)
{
    struct flb_kv *kv = NULL;
    struct mk_list *head = NULL;
    struct mk_list *split;
    int status;
    struct geoip2_lookup_key *key;
    struct geoip2_record *record;
    struct flb_split_entry *sentry;

    ctx->mmdb = flb_malloc(sizeof(MMDB_s));
    ctx->lookup_keys_num = 0;
    ctx->records_num = 0;

    /* Iterate all filter properties */
    mk_list_foreach(head, &f_ins->properties) {
        kv = mk_list_entry(head, struct flb_kv, _head);

        if (strcasecmp(kv->key, "database") == 0) {
            status = MMDB_open(kv->val, MMDB_MODE_MMAP, ctx->mmdb);
            if (status != MMDB_SUCCESS) {
                flb_error("[%s] Cannot open geoip2 database: %s: %s",
                          PLUGIN_NAME, kv->val, MMDB_strerror(status));
                flb_free(ctx->mmdb);
                return -1;
            }
        }
        else if (strcasecmp(kv->key, "lookup_key") == 0) {
            key = flb_malloc(sizeof(struct geoip2_lookup_key));
            if (!key) {
                flb_errno();
                continue;
            }
            key->key = flb_strndup(kv->val, flb_sds_len(kv->val));
            key->key_len = flb_sds_len(kv->val);
            mk_list_add(&key->_head, &ctx->lookup_keys);
            ctx->lookup_keys_num++;
        }
        else if (strcasecmp(kv->key, "record") == 0) {
            record = flb_malloc(sizeof(struct geoip2_record));
            if (!record) {
                flb_errno();
                continue;
            }
            split = flb_utils_split(kv->val, ' ', 2);
            if (mk_list_size(split) != 3) {
                flb_error("[%s] invalid record parameters, expects 'KEY LOOKUP_KEY VALUE'",
                          PLUGIN_NAME);
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
    }

    if (ctx->lookup_keys_num <= 0) {
        flb_error("lookup_key is required at least one.");
        return -1;
    }
    if (ctx->records_num <= 0) {
        flb_error("record is required at least one.");
        return -1;
    }
    return 0;
}

static int delete_list(struct geoip2_ctx *ctx)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct geoip2_lookup_key *key;
    struct geoip2_record *record;

    mk_list_foreach_safe(head, tmp, &ctx->lookup_keys) {
        key = mk_list_entry(head, struct geoip2_lookup_key, _head);
        flb_free(key->key);
        mk_list_del(&key->_head);
        flb_free(key);
    }
    mk_list_foreach_safe(head, tmp, &ctx->records) {
        record = mk_list_entry(head, struct geoip2_record, _head);
        flb_free(record->key);
        flb_free(record->val);
        mk_list_del(&record->_head);
        flb_free(record);
    }
    return 0;
}

static struct flb_hash *prepare_lookup_keys(msgpack_object *map,
                                            struct geoip2_ctx *ctx)
{
    msgpack_object_kv *kv;
    msgpack_object *key;
    msgpack_object *val;
    struct mk_list *head;
    struct mk_list *tmp;
    struct geoip2_lookup_key *lookup_key;
    struct flb_hash *ht = flb_hash_create(FLB_HASH_EVICT_NONE, ctx->lookup_keys_num, -1);

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
        mk_list_foreach_safe(head, tmp, &ctx->lookup_keys) {
            lookup_key = mk_list_entry(head, struct geoip2_lookup_key, _head);
            if (strncasecmp(key->via.str.ptr, lookup_key->key, lookup_key->key_len) == 0) {
                flb_hash_add(ht, lookup_key->key, lookup_key->key_len, val->via.str.ptr, val->via.str.size);
            }
        }
    }

    return ht;
}

static MMDB_lookup_result_s mmdb_lookup(MMDB_s *mmdb, const char *ip)
{
    int gai_error;
    int mmdb_error;
    MMDB_lookup_result_s result;

    result = MMDB_lookup_string(mmdb, ip, &gai_error, &mmdb_error);
    if (gai_error != 0) {
        flb_error("[%s] getaddrinfo failed: %s",
                  PLUGIN_NAME, gai_strerror(gai_error));
    }
    if (mmdb_error != MMDB_SUCCESS) {
        flb_error("[%s] lookup failed: %s",
                  PLUGIN_NAME, MMDB_strerror(mmdb_error));
    }

    return result;
}

static void add_geoip_fields(msgpack_object *map,
                             struct flb_hash *lookup_keys,
                             struct geoip2_ctx *ctx,
                             msgpack_packer *packer)
{
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
    int added = 0;

    mk_list_foreach_safe(head, tmp, &ctx->records) {
        record = mk_list_entry(head, struct geoip2_record, _head);

        msgpack_pack_str(packer, record->key_len);
        msgpack_pack_str_body(packer, record->key, record->key_len);

        flb_hash_get(lookup_keys, record->lookup_key, record->lookup_key_len, &ip, &ip_size);
        result = mmdb_lookup(ctx->mmdb, ip);
        if (!result.found_entry) {
            msgpack_pack_nil(packer);
            continue;
        }
        entry = result.entry;
        pos = strstr(record->val, "}");
        memset(key, '\0', sizeof(key));
        strncpy(key, record->val + 2, pos - (record->val + 2));
        split = flb_utils_split(key, '.', 2);
        split_size = mk_list_size(split);
        path = flb_malloc(sizeof(char *) * (split_size + 1));
        mk_list_foreach_safe(path_head, path_tmp, split) {
            sentry = mk_list_entry(path_head, struct flb_split_entry, _head);
            path[i] = flb_strndup(sentry->value, sentry->len);
            i++;
        }
        path[split_size] = NULL;
        status = MMDB_aget_value(&entry, &entry_data, (const char *const *const)path);
        for (int j = 0; j < split_size; j++) {
            flb_free(path[j]);
        }
        flb_free(path);
        if (status != MMDB_SUCCESS) {
            flb_warn("[%s] %s:%d %s",
                     PLUGIN_NAME, __FUNCTION__, __LINE__,
                     MMDB_strerror(status));
            msgpack_pack_nil(packer);
            continue;
        }
        if (!entry_data.has_data) {
            flb_warn("[%s] %s:%d found entry does not have data",
                     PLUGIN_NAME, __FUNCTION__, __LINE__);
            msgpack_pack_nil(packer);
            continue;
        }
        if (entry_data.type == MMDB_DATA_TYPE_MAP ||
            entry_data.type == MMDB_DATA_TYPE_ARRAY) {
            flb_warn("[%s] %s:%d Not supported MAP and ARRAY",
                     PLUGIN_NAME, __FUNCTION__, __LINE__);
            msgpack_pack_nil(packer);
            continue;
        }

        switch (entry_data.type) {
        case MMDB_DATA_TYPE_EXTENDED:
            /* TODO: not implemented */
            msgpack_pack_nil(packer);
            break;
        case MMDB_DATA_TYPE_POINTER:
            /* TODO: not implemented */
            msgpack_pack_nil(packer);
            break;
        case MMDB_DATA_TYPE_UTF8_STRING:
            msgpack_pack_str(packer, entry_data.data_size);
            msgpack_pack_str_body(packer,
                                  entry_data.utf8_string,
                                  entry_data.data_size);
            break;
        case MMDB_DATA_TYPE_DOUBLE:
            msgpack_pack_double(packer, entry_data.double_value);
            break;
        case MMDB_DATA_TYPE_BYTES:
            msgpack_pack_str(packer, entry_data.data_size);
            msgpack_pack_str_body(packer,
                                  entry_data.bytes,
                                  entry_data.data_size);
            break;
        case MMDB_DATA_TYPE_UINT16:
            msgpack_pack_uint16(packer, entry_data.uint16);
            break;
        case MMDB_DATA_TYPE_UINT32:
            msgpack_pack_uint32(packer, entry_data.uint32);
            break;
        case MMDB_DATA_TYPE_MAP:
            /* TODO: not implemented */
            msgpack_pack_nil(packer);
            break;
        case MMDB_DATA_TYPE_INT32:
            msgpack_pack_int32(packer, entry_data.int32);
            break;
        case MMDB_DATA_TYPE_UINT64:
            msgpack_pack_uint64(packer, entry_data.uint64);
            break;
        case MMDB_DATA_TYPE_UINT128:
#if !(MMDB_UINT128_IS_BYTE_ARRAY)
            /* entry_data.uint128; */
            flb_warn("Not supported uint128");
#else
            flb_warn("Not implemented when MMDB_UINT128_IS_BYTE_ARRAY");
#endif
            msgpack_pack_nil(packer);
            break;
        case MMDB_DATA_TYPE_ARRAY:
            /* TODO: not implemented */
            msgpack_pack_nil(packer);
            break;
        case MMDB_DATA_TYPE_CONTAINER:
            /* TODO: not implemented */
            msgpack_pack_nil(packer);
            break;
        case MMDB_DATA_TYPE_END_MARKER:
            break;
        case MMDB_DATA_TYPE_BOOLEAN:
            entry_data.boolean ? msgpack_pack_true(packer) : msgpack_pack_false(packer);
            break;
        case MMDB_DATA_TYPE_FLOAT:
            msgpack_pack_float(packer, entry_data.float_value);
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
    ctx = flb_malloc(sizeof(struct geoip2_ctx));
    if (!ctx) {
        flb_errno();
        return -1;
    }
    mk_list_init(&ctx->lookup_keys);
    mk_list_init(&ctx->records);

    if (configure(ctx, f_ins) < 0) {
        delete_list(ctx);
        return -1;
    }

    flb_filter_set_context(f_ins, ctx);

    return 0;
}

static int cb_geoip2_filter(const void *data, size_t bytes,
                            const char *tag, int tag_len,
                            void **out_buf, size_t *out_size,
                            struct flb_filter_instance *f_ins,
                            void *context,
                            struct flb_config *config)
{
    struct geoip2_ctx *ctx = context;
    size_t off = 0;
    int map_num = 0;
    struct flb_time tm;
    msgpack_sbuffer sbuffer;
    msgpack_packer packer;
    msgpack_unpacked unpacked;
    msgpack_object *obj;
    msgpack_object_kv *kv;
    struct flb_hash *lookup_keys_hash;
    int added = 0;

    /* Create temporal msgpack buffer */
    msgpack_sbuffer_init(&sbuffer);
    msgpack_packer_init(&packer, &sbuffer, msgpack_sbuffer_write);

    /* Iterate each item to know map number */
    msgpack_unpacked_init(&unpacked);
    while (msgpack_unpack_next(&unpacked, data, bytes, &off) == MSGPACK_UNPACK_SUCCESS) {
        if (unpacked.data.type != MSGPACK_OBJECT_ARRAY) {
            continue;
        }

        flb_time_pop_from_msgpack(&tm, &unpacked, &obj);

        if (obj->type == MSGPACK_OBJECT_MAP) {
            map_num = obj->via.map.size;
        }
        else {
            continue;
        }

        msgpack_pack_array(&packer, 2);
        flb_time_append_to_msgpack(&tm, &packer, 0);

        msgpack_pack_map(&packer, map_num + ctx->records_num);
        kv = obj->via.map.ptr;
        for (int i = 0; i < map_num; i++) {
            msgpack_pack_object(&packer, (kv + i)->key);
            msgpack_pack_object(&packer, (kv + i)->val);
        }

        lookup_keys_hash = prepare_lookup_keys(obj, ctx);
        add_geoip_fields(obj, lookup_keys_hash, ctx, &packer);
    }
    msgpack_unpacked_destroy(&unpacked);

    /* link new buffers */
    *out_buf = sbuffer.data;
    *out_size = sbuffer.size;
    return FLB_FILTER_MODIFIED;
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

struct flb_filter_plugin filter_geoip2_plugin = {
    .name = "geoip2",
    .description = "add geoip information to records",
    .cb_init = cb_geoip2_init,
    .cb_filter = cb_geoip2_filter,
    .cb_exit = cb_geoip2_exit,
    .flags = 0,
};
