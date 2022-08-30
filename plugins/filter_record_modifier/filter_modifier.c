/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2022 The Fluent Bit Authors
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
#include <fluent-bit/flb_filter.h>
#include <fluent-bit/flb_filter_plugin.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_str.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_kv.h>
#include <fluent-bit/flb_time.h>

#include <msgpack.h>
#include "filter_modifier.h"

#define PLUGIN_NAME "filter_record_modifier"

static int config_allowlist_key(struct record_modifier_ctx *ctx,
                                struct mk_list *list)
{
    struct modifier_key    *mod_key = NULL;
    struct mk_list *head = NULL;
    struct flb_config_map_val *mv = NULL;

    if (ctx == NULL || list == NULL) {
        return -1;
    }

    flb_config_map_foreach(head, mv, ctx->allowlist_keys_map) {
        mod_key = flb_malloc(sizeof(struct modifier_key));
        if (!mod_key) {
            flb_errno();
            continue;
        }
        mod_key->key     = mv->val.str;
        mod_key->key_len = flb_sds_len(mv->val.str);
        if (mod_key->key[mod_key->key_len - 1] == '*') {
            mod_key->dynamic_key = FLB_TRUE;
            mod_key->key_len--;
        }
        else {
            mod_key->dynamic_key = FLB_FALSE;
        }
        mk_list_add(&mod_key->_head, &ctx->allowlist_keys);
        ctx->allowlist_keys_num++;
    }
    return 0;
}

static int configure(struct record_modifier_ctx *ctx,
                         struct flb_filter_instance *f_ins)
{
    struct mk_list *head = NULL;
    struct modifier_key    *mod_key;
    struct modifier_record *mod_record;
    struct flb_config_map_val *mv;
    struct flb_slist_entry *sentry = NULL;

    ctx->records_num = 0;
    ctx->remove_keys_num = 0;
    ctx->allowlist_keys_num = 0;

    if (flb_filter_config_map_set(f_ins, ctx) < 0) {
        flb_errno();
        flb_plg_error(f_ins, "configuration error");
        return -1;
    }

    /* Check 'Record' properties */
    flb_config_map_foreach(head, mv, ctx->records_map) {
        mod_record = flb_malloc(sizeof(struct modifier_record));
        if (!mod_record) {
            flb_errno();
            continue;
        }

        if (mk_list_size(mv->val.list) != 2) {
            flb_plg_error(ctx->ins, "invalid record parameters, "
                          "expects 'KEY VALUE'");
            flb_free(mod_record);
            continue;
        }
        /* Get first value (field) */
        sentry = mk_list_entry_first(mv->val.list, struct flb_slist_entry, _head);
        mod_record->key_len = flb_sds_len(sentry->str);
        mod_record->key = flb_strndup(sentry->str, mod_record->key_len);
        if (mod_record->key == NULL) {
            flb_errno();
            flb_free(mod_record);
            continue;
        }

        sentry = mk_list_entry_last(mv->val.list, struct flb_slist_entry, _head);
        mod_record->val_len = flb_sds_len(sentry->str);
        mod_record->val = flb_strndup(sentry->str, mod_record->val_len);
        if (mod_record->val == NULL) {
            flb_errno();
            flb_free(mod_record->key);
            flb_free(mod_record);
            continue;
        }

        mk_list_add(&mod_record->_head, &ctx->records);
        ctx->records_num++;
    }
    /* Check "Remove_Key" properties */
    flb_config_map_foreach(head, mv, ctx->remove_keys_map) {
        mod_key = flb_malloc(sizeof(struct modifier_key));
        if (!mod_key) {
            flb_errno();
            continue;
        }
        mod_key->key     = mv->val.str;
        mod_key->key_len = flb_sds_len(mv->val.str);
        if (mod_key->key[mod_key->key_len - 1] == '*') {
            mod_key->dynamic_key = FLB_TRUE;
            mod_key->key_len--;
        }
        else {
            mod_key->dynamic_key = FLB_FALSE;
        }
        mk_list_add(&mod_key->_head, &ctx->remove_keys);
        ctx->remove_keys_num++;
    }

    /* Check "Allowlist_key" and "Whitelist_key" properties */
    config_allowlist_key(ctx, ctx->allowlist_keys_map);
    config_allowlist_key(ctx, ctx->whitelist_keys_map);

    if (ctx->remove_keys_num > 0 && ctx->allowlist_keys_num > 0) {
        flb_plg_error(ctx->ins, "remove_keys and allowlist_keys are exclusive "
                      "with each other.");
        return -1;
    }
    return 0;
}

static int delete_list(struct record_modifier_ctx *ctx)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct modifier_key *key;
    struct modifier_record *record;

    mk_list_foreach_safe(head, tmp, &ctx->remove_keys) {
        key = mk_list_entry(head, struct modifier_key,  _head);
        mk_list_del(&key->_head);
        flb_free(key);
    }
    mk_list_foreach_safe(head, tmp, &ctx->allowlist_keys) {
        key = mk_list_entry(head, struct modifier_key,  _head);
        mk_list_del(&key->_head);
        flb_free(key);
    }
    mk_list_foreach_safe(head, tmp, &ctx->records) {
        record = mk_list_entry(head, struct modifier_record,  _head);
        flb_free(record->key);
        flb_free(record->val);
        mk_list_del(&record->_head);
        flb_free(record);
    }
    return 0;
}


static int cb_modifier_init(struct flb_filter_instance *f_ins,
                                struct flb_config *config,
                                void *data)
{
    struct record_modifier_ctx *ctx = NULL;

    /* Create context */
    ctx = flb_malloc(sizeof(struct record_modifier_ctx));
    if (!ctx) {
        flb_errno();
        return -1;
    }
    mk_list_init(&ctx->records);
    mk_list_init(&ctx->remove_keys);
    mk_list_init(&ctx->allowlist_keys);
    ctx->ins = f_ins;

    if ( configure(ctx, f_ins) < 0 ){
        delete_list(ctx);
        flb_free(ctx);
        return -1;
    }

    flb_filter_set_context(f_ins, ctx);

    return 0;
}

static int make_bool_map(struct record_modifier_ctx *ctx, msgpack_object *map,
                             bool_map_t *bool_map, int map_num)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct mk_list *check = NULL;
    msgpack_object_kv *kv;
    struct modifier_key *mod_key;

    char result;
    char is_to_delete;
    msgpack_object *key;
    int ret = map_num;
    int i;

    for (i=0; i<map_num; i++) {
        bool_map[i] = TO_BE_REMAINED;
    }
    bool_map[map_num] = TAIL_OF_ARRAY;/* tail of map */

    if (ctx->remove_keys_num > 0) {
        check = &(ctx->remove_keys);
        is_to_delete = FLB_TRUE;
    }
    else if(ctx->allowlist_keys_num > 0) {
        check = &(ctx->allowlist_keys);
        is_to_delete = FLB_FALSE;
    }

    if (check != NULL){
        kv = map->via.map.ptr;
        for(i=0; i<map_num; i++){
            key = &(kv+i)->key;
            result = FLB_FALSE;

            mk_list_foreach_safe(head, tmp, check) {
                mod_key = mk_list_entry(head, struct modifier_key,  _head);
                if (key->via.bin.size != mod_key->key_len &&
                    key->via.str.size != mod_key->key_len &&
                    mod_key->dynamic_key == FLB_FALSE) {
                    continue;
                }
                if (key->via.bin.size < mod_key->key_len &&
                    key->via.str.size < mod_key->key_len &&
                    mod_key->dynamic_key == FLB_TRUE) {
                    continue;
                }
                if ((key->type == MSGPACK_OBJECT_BIN &&
                     !strncasecmp(key->via.bin.ptr, mod_key->key,
                                  mod_key->key_len)) ||
                    (key->type == MSGPACK_OBJECT_STR &&
                     !strncasecmp(key->via.str.ptr, mod_key->key,
                                  mod_key->key_len))
                    ) {
                    result = FLB_TRUE;
                    break;
                }
            }
            if (result == is_to_delete) {
                bool_map[i] = TO_BE_REMOVED;
                ret--;
            }
        }
    }

    return ret;
}

#define BOOL_MAP_LIMIT 65535
static int cb_modifier_filter(const void *data, size_t bytes,
                              const char *tag, int tag_len,
                              void **out_buf, size_t *out_size,
                              struct flb_filter_instance *f_ins,
                              struct flb_input_instance *i_ins,
                              void *context,
                              struct flb_config *config)
{
    struct record_modifier_ctx *ctx = context;
    char is_modified = FLB_FALSE;
    size_t off = 0;
    int i;
    int removed_map_num  = 0;
    int map_num          = 0;
    bool_map_t *bool_map = NULL;
    (void) f_ins;
    (void) i_ins;
    (void) config;
    struct flb_time tm;
    struct modifier_record *mod_rec;
    msgpack_sbuffer tmp_sbuf;
    msgpack_packer tmp_pck;
    msgpack_unpacked result;
    msgpack_object  *obj;
    msgpack_object_kv *kv;
    struct mk_list *tmp;
    struct mk_list *head;

    /* Create temporary msgpack buffer */
    msgpack_sbuffer_init(&tmp_sbuf);
    msgpack_packer_init(&tmp_pck, &tmp_sbuf, msgpack_sbuffer_write);

    /* Iterate each item to know map number */
    msgpack_unpacked_init(&result);
    while (msgpack_unpack_next(&result, data, bytes, &off) == MSGPACK_UNPACK_SUCCESS) {
        map_num = 0;
        removed_map_num = 0;
        if (bool_map != NULL) {
            flb_free(bool_map);
            bool_map = NULL;
        }

        if (result.data.type != MSGPACK_OBJECT_ARRAY) {
            continue;
        }

        flb_time_pop_from_msgpack(&tm, &result, &obj);

        /* grep keys */
        if (obj->type == MSGPACK_OBJECT_MAP) {
            map_num = obj->via.map.size;
            if (map_num > BOOL_MAP_LIMIT) {
                flb_plg_error(ctx->ins, "The number of elements exceeds limit %d",
                              BOOL_MAP_LIMIT);
                return -1;
            }
            /* allocate map_num + guard byte */
            bool_map = flb_calloc(map_num+1, sizeof(bool_map_t));
            if (bool_map == NULL) {
                flb_errno();
                return -1;
            }
            removed_map_num = make_bool_map(ctx, obj,
                                            bool_map, obj->via.map.size);
        }
        else {
            continue;
        }

        if (removed_map_num != map_num) {
            is_modified = FLB_TRUE;
        }

        removed_map_num += ctx->records_num;
        if (removed_map_num <= 0) {
            continue;
        }

        msgpack_pack_array(&tmp_pck, 2);
        flb_time_append_to_msgpack(&tm, &tmp_pck, 0);

        msgpack_pack_map(&tmp_pck, removed_map_num);
        kv = obj->via.map.ptr;
        for(i=0; bool_map[i] != TAIL_OF_ARRAY; i++) {
            if (bool_map[i] == TO_BE_REMAINED) {
                msgpack_pack_object(&tmp_pck, (kv+i)->key);
                msgpack_pack_object(&tmp_pck, (kv+i)->val);
            }
        }
        flb_free(bool_map);
        bool_map = NULL;

        /* append record */
        if (ctx->records_num > 0) {
            is_modified = FLB_TRUE;
            mk_list_foreach_safe(head, tmp, &ctx->records) {
                mod_rec = mk_list_entry(head, struct modifier_record,  _head);
                msgpack_pack_str(&tmp_pck, mod_rec->key_len);
                msgpack_pack_str_body(&tmp_pck,
                                      mod_rec->key, mod_rec->key_len);
                msgpack_pack_str(&tmp_pck, mod_rec->val_len);
                msgpack_pack_str_body(&tmp_pck,
                                      mod_rec->val, mod_rec->val_len);
            }
        }
    }
    msgpack_unpacked_destroy(&result);
    if (bool_map != NULL) {
        flb_free(bool_map);
    }

    if (is_modified != FLB_TRUE) {
        /* Destroy the buffer to avoid more overhead */
        msgpack_sbuffer_destroy(&tmp_sbuf);
        return FLB_FILTER_NOTOUCH;
    }

    /* link new buffers */
    *out_buf  = tmp_sbuf.data;
    *out_size = tmp_sbuf.size;
    return FLB_FILTER_MODIFIED;
}

static int cb_modifier_exit(void *data, struct flb_config *config)
{
    struct record_modifier_ctx *ctx = data;

    if (ctx != NULL) {
        delete_list(ctx);
        flb_free(ctx);
    }
    return 0;
}

static struct flb_config_map config_map[] = {
    {
     FLB_CONFIG_MAP_SLIST_2, "record", NULL,
     FLB_CONFIG_MAP_MULT, FLB_TRUE, offsetof(struct record_modifier_ctx, records_map),
     "Append fields. This parameter needs key and value pair."
    },

    {
     FLB_CONFIG_MAP_STR, "remove_key", NULL,
     FLB_CONFIG_MAP_MULT, FLB_TRUE, offsetof(struct record_modifier_ctx, remove_keys_map),
     "If the key is matched, that field is removed."
    },
    {
     FLB_CONFIG_MAP_STR, "allowlist_key", NULL,
     FLB_CONFIG_MAP_MULT, FLB_TRUE, offsetof(struct record_modifier_ctx, allowlist_keys_map),
     "If the key is not matched, that field is removed."
    },
    {
     FLB_CONFIG_MAP_STR, "whitelist_key", NULL,
     FLB_CONFIG_MAP_MULT, FLB_TRUE, offsetof(struct record_modifier_ctx, whitelist_keys_map),
     "(Alias of allowlist_key)"
    },

    {0}
};

struct flb_filter_plugin filter_record_modifier_plugin = {
    .name         = "record_modifier",
    .description  = "modify record",
    .cb_init      = cb_modifier_init,
    .cb_filter    = cb_modifier_filter,
    .cb_exit      = cb_modifier_exit,
    .config_map   = config_map,
    .flags        = 0
};
