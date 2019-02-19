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
#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_filter.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_str.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_time.h>

#include <msgpack.h>
#include "filter_modifier.h"

#define PLUGIN_NAME "filter_record_modifier"

static int configure(struct record_modifier_ctx *ctx,
                         struct flb_filter_instance *f_ins)
{
    struct mk_list *head = NULL;
    struct mk_list *split;
    struct flb_config_prop *prop = NULL;
    struct modifier_key    *mod_key;
    struct modifier_record *mod_record;
    struct flb_split_entry *sentry;

    ctx->records_num = 0;
    ctx->remove_keys_num = 0;
    ctx->whitelist_keys_num = 0;

    /* Iterate all filter properties */
    mk_list_foreach(head, &f_ins->properties) {
        prop = mk_list_entry(head, struct flb_config_prop, _head);

        if (!strcasecmp(prop->key, "remove_key")) {
            mod_key = flb_malloc(sizeof(struct modifier_key));
            if (!mod_key) {
                flb_errno();
                continue;
            }
            mod_key->key     = prop->val;
            mod_key->key_len = strlen(prop->val);
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
        else if (!strcasecmp(prop->key, "whitelist_key")) {
            mod_key = flb_malloc(sizeof(struct modifier_key));
            if (!mod_key) {
                flb_errno();
                continue;
            }
            mod_key->key     = prop->val;
            mod_key->key_len = strlen(prop->val);
            if (mod_key->key[mod_key->key_len - 1] == '*') {
                mod_key->dynamic_key = FLB_TRUE;
                mod_key->key_len--;
            }
            else {
                mod_key->dynamic_key = FLB_FALSE;
            }
            mk_list_add(&mod_key->_head, &ctx->whitelist_keys);
            ctx->whitelist_keys_num++;
        }
        else if (!strcasecmp(prop->key, "record")) {
            mod_record = flb_malloc(sizeof(struct modifier_record));
            if (!mod_record) {
                flb_errno();
                continue;
            }
            split = flb_utils_split(prop->val, ' ', 1);
            if (mk_list_size(split) != 2) {
                flb_error("[%s] invalid record parameters, expects 'KEY VALUE'",
                          PLUGIN_NAME);
                flb_free(mod_record);
                flb_utils_split_free(split);
                continue;
            }
            /* Get first value (field) */
            sentry = mk_list_entry_first(split, struct flb_split_entry, _head);
            mod_record->key = flb_strndup(sentry->value, sentry->len);
            mod_record->key_len = sentry->len;

            sentry = mk_list_entry_last(split, struct flb_split_entry, _head);
            mod_record->val = flb_strndup(sentry->value, sentry->len);
            mod_record->val_len = sentry->len;

            flb_utils_split_free(split);
            mk_list_add(&mod_record->_head, &ctx->records);
            ctx->records_num++;
        }
    }

    if (ctx->remove_keys_num > 0 && ctx->whitelist_keys_num > 0) {
        flb_error("remove_keys and whitelist_keys are exclusive with each other.");
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
    mk_list_foreach_safe(head, tmp, &ctx->whitelist_keys) {
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
    mk_list_init(&ctx->whitelist_keys);

    if ( configure(ctx, f_ins) < 0 ){
        delete_list(ctx);
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
    else if(ctx->whitelist_keys_num > 0) {
        check = &(ctx->whitelist_keys);
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

static int cb_modifier_filter(void *data, size_t bytes,
                                  char *tag, int tag_len,
                                  void **out_buf, size_t *out_size,
                                  struct flb_filter_instance *f_ins,
                                  void *context,
                                  struct flb_config *config)
{
    struct record_modifier_ctx *ctx = context;
    char is_modified = FLB_FALSE;
    size_t off = 0;
    int i;
    int removed_map_num  = 0;
    int map_num          = 0;
    bool_map_t bool_map[128];
    (void) f_ins;
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

    /* Create temporal msgpack buffer */
    msgpack_sbuffer_init(&tmp_sbuf);
    msgpack_packer_init(&tmp_pck, &tmp_sbuf, msgpack_sbuffer_write);

    /* Iterate each item to know map number */
    msgpack_unpacked_init(&result);
    while (msgpack_unpack_next(&result, data, bytes, &off) == MSGPACK_UNPACK_SUCCESS) {
        map_num = 0;
        removed_map_num = 0;
        if (result.data.type != MSGPACK_OBJECT_ARRAY) {
            continue;
        }

        flb_time_pop_from_msgpack(&tm, &result, &obj);

        /* grep keys */
        if (obj->type == MSGPACK_OBJECT_MAP) {
            map_num = obj->via.map.size;
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

struct flb_filter_plugin filter_record_modifier_plugin = {
    .name         = "record_modifier",
    .description  = "modify record",
    .cb_init      = cb_modifier_init,
    .cb_filter    = cb_modifier_filter,
    .cb_exit      = cb_modifier_exit,
    .flags        = 0
};
