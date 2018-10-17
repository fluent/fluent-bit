/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2018 SpareBank 1 Banksamarbeidet DA
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
#include <stdbool.h>

#include <fluent-bit/flb_filter.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_hash.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_str.h>

#include <msgpack.h>

#include "join_partial.h"

static struct filter_join_partial_ctx* join_partial_conf_create(struct flb_filter_instance *filter_inst,
                                                                struct flb_config *config)
{
    struct filter_join_partial_ctx* ctx = flb_calloc(1, sizeof(struct filter_join_partial_ctx));
    if (!ctx) {
        flb_errno();
        return NULL;
    }

    char *tmp = flb_filter_get_property("log_key", filter_inst);
    if (tmp) {
        ctx->log_key = flb_strdup(tmp);
        ctx->log_key_len = strlen(tmp);
    } else {
        flb_error("[filter_join_partial] no log_key set");
        flb_free(ctx);
        return NULL;
    }

    ctx->hash_table = flb_hash_create(FLB_HASH_EVICT_NONE,
                                      FLB_HASH_TABLE_SIZE,
                                      FLB_HASH_TABLE_SIZE);
    if (!ctx->hash_table) {
        flb_error("[filter_join_partial] could not create hash table");
        flb_free(ctx->log_key);
        flb_free(ctx);
        return NULL;
    }

    flb_info("[filter_join_partial] initialized with log_key %s", tmp);

    return ctx;
}

static int cb_join_partial_init(struct flb_filter_instance *f_ins,
                                struct flb_config *config,
                                void *data)
{
    (void) data;

    // create configuration context
    struct filter_join_partial_ctx *ctx = join_partial_conf_create(f_ins, config);
    if (!ctx) {
        return -1;
    }

    // set context
    flb_filter_set_context(f_ins, ctx);

    return 0;
}

static bool kv_key_matches(msgpack_object_kv *kv, char *str, int str_len)
{
    msgpack_object* obj = &kv->key;
    char *key;
    int key_len;

    if (obj->type == MSGPACK_OBJECT_BIN) {
        key = (char *) obj->via.bin.ptr;
        key_len = obj->via.bin.size;
    }
    else if (obj->type == MSGPACK_OBJECT_STR) {
        key = (char *) obj->via.str.ptr;
        key_len = obj->via.str.size;
    }
    else {
        return false;
    }

    return ((str_len == key_len) && (strncmp(str, key, key_len) == 0));
}

static msgpack_object* get_value_by_key(msgpack_object* map, char *key, int key_len)
{
    int i;
    msgpack_object_kv *kv;

    for (i = 0; i < map->via.map.size; i++) {
        kv = &map->via.map.ptr[i];
        if (kv_key_matches(kv, key, key_len)) {
            return &kv->val;
        }
    }

    return NULL;
}

static bool is_initial_partial_content(char* val, size_t slen, int format)
{
    // docker log partial value ends without '\n'

    if (format == FORMAT_DOCKER) {
        return slen > 1 && val[slen-2] != '\\' && val[slen-1] != 'n';
    } else {
        return false;
    }
}

static bool is_last_partial_content(char* val, size_t slen, int format)
{
    // docker log value ends with '\n'

   if (format == FORMAT_DOCKER) {
       return slen > 1 && val[slen-2] == '\\' && val[slen-1] == 'n';
   } else {
       return false;
   }
}

static bool partial_in_progress_for_tag(char* tag, int tag_len, struct filter_join_partial_ctx* ctx,
                                        char **partial_log_buf, size_t *partial_log_size)
{
    // Check if we have some data associated with the tag
    int ret = flb_hash_get(ctx->hash_table, tag, tag_len, partial_log_buf, partial_log_size);

    if (ret == -1) {
        return false;
    } else {
        return true;
    }
}

// packs all kv from map except for replace_key that is replaced by val_part_one and val_part_two
static void merge_objects_by_key(msgpack_packer* packer, msgpack_object* map,
                                 char* replace_key, int replace_key_len,
                                 char* val_part_one, int val_part_one_len,
                                 char* val_part_two, int val_part_two_len)
{
    int i;
    msgpack_pack_map(packer, map->via.map.size);

    for (i = 0; i < map->via.map.size; i++) {

        msgpack_object* key = &map->via.map.ptr[i].key;

        if(key->type == MSGPACK_OBJECT_STR &&
           key->via.str.size == replace_key_len &&
           strncmp(key->via.str.ptr, replace_key, replace_key_len) == 0)
        {
            msgpack_pack_object(packer, map->via.map.ptr[i].key);
            msgpack_pack_str(packer, val_part_one_len + val_part_two_len);
            msgpack_pack_str_body(packer, val_part_one, val_part_one_len);
            msgpack_pack_str_body(packer, val_part_two, val_part_two_len);
        } else {
            msgpack_pack_object(packer, map->via.map.ptr[i].key);
            msgpack_pack_object(packer, map->via.map.ptr[i].val);
        }
    }
}

static int cb_join_partial_filter(void *data, size_t bytes,
                            char *tag, int tag_len,
                            void **out_buf, size_t *out_bytes,
                            struct flb_filter_instance *f_ins,
                            void* context, struct flb_config *config)
{
    int result_code = FLB_FILTER_NOTOUCH;
    msgpack_unpacked result;
    msgpack_object map;
    size_t off = 0;
    (void) out_buf;
    (void) out_bytes;
    (void) f_ins;
    (void) config;
    msgpack_sbuffer tmp_sbuf;
    msgpack_packer tmp_pck;

    struct filter_join_partial_ctx* ctx = context;

    // Create temporal msgpack buffer
    msgpack_sbuffer_init(&tmp_sbuf);
    msgpack_packer_init(&tmp_pck, &tmp_sbuf, msgpack_sbuffer_write);

    // Iterate each item array
    msgpack_unpacked_init(&result);
    while(msgpack_unpack_next(&result, data, bytes, &off)) {
        if (result.data.type != MSGPACK_OBJECT_ARRAY) {
            continue;
        }

        // get map
        map = result.data.via.array.ptr[1];

        // get log content
        msgpack_object* log_value = get_value_by_key(&map, ctx->log_key, ctx->log_key_len);
        if (log_value == NULL) {
            continue;
        }

        char *log_content;
        int log_content_len;
        if (log_value->type == MSGPACK_OBJECT_STR) {
            log_content = (char *) log_value->via.str.ptr;
            log_content_len = log_value->via.str.size;
        } else {
            // If the key is not something we can match on then we leave it alone
            continue;
        }

        // content from hash_map
        char *partial_log_buf;
        size_t partial_log_size;

        // writes to the buffers above
        if (partial_in_progress_for_tag(tag, tag_len, ctx, &partial_log_buf, &partial_log_size)) {

            // unpack object from hash_map
            msgpack_unpacked existing_partial;
            msgpack_unpacked_init(&existing_partial);
            size_t unpack_off = 0;

            // do unpacking
            msgpack_unpack_next(&existing_partial, partial_log_buf, partial_log_size, &unpack_off);

            // existing objects
            msgpack_object existing_partial_ts  = existing_partial.data.via.array.ptr[0];
            msgpack_object existing_partial_map = existing_partial.data.via.array.ptr[1];

            msgpack_object* existing_log_value = get_value_by_key(&existing_partial_map,
                                                                  ctx->log_key, ctx->log_key_len);
            if (existing_log_value == NULL) {
                flb_error("[filter_join_partial] get_value_by_key returned NULL, invalid state - this should not happen");
            }

            char* existing_log_content;
            int existing_log_content_len;

            if (existing_log_value->type == MSGPACK_OBJECT_STR) {
                existing_log_content = (char *) existing_log_value->via.str.ptr;
                existing_log_content_len = existing_log_value->via.str.size;
            } else {
                flb_error("[filter_join_partial] value in hash_table was in unexpected format - this should not happen");
            }

            if (is_last_partial_content(log_content, log_content_len, FORMAT_DOCKER)) {

                msgpack_pack_array(&tmp_pck, 2);
                msgpack_pack_object(&tmp_pck, existing_partial_ts);

                merge_objects_by_key(&tmp_pck, &existing_partial_map,
                                     ctx->log_key, ctx->log_key_len,
                                     existing_log_content, existing_log_content_len,
                                     log_content, log_content_len);

                flb_hash_del(ctx->hash_table, tag);

                result_code = FLB_FILTER_MODIFIED;

            } else {

                msgpack_sbuffer new_partial_sbuf;
                msgpack_packer new_partial_packer;

                msgpack_sbuffer_init(&new_partial_sbuf);
                msgpack_packer_init(&new_partial_packer, &new_partial_sbuf, msgpack_sbuffer_write);

                msgpack_pack_array(&new_partial_packer, 2);
                msgpack_pack_object(&new_partial_packer, existing_partial_ts);

                merge_objects_by_key(&new_partial_packer, &existing_partial_map,
                                     ctx->log_key, ctx->log_key_len,
                                     existing_log_content, existing_log_content_len,
                                     log_content, log_content_len);

                int ret = flb_hash_del(ctx->hash_table, tag);
                if (ret == -1) {
                    flb_error("[filter_join_partial] can not delete tag from hash table");
                }

                ret = flb_hash_add(ctx->hash_table, tag, tag_len, new_partial_sbuf.data, new_partial_sbuf.size);
                if (ret == -1) {
                    flb_error("[filter_join_partial] can not add tag to hash table");
                }

                // Release the original buffer as a new
                // copy have been generated into the hash table
                msgpack_sbuffer_destroy(&new_partial_sbuf);

                msgpack_unpacked_destroy(&existing_partial);

                result_code = FLB_FILTER_MODIFIED;
            }

            // clean up allocated resources
            msgpack_unpacked_destroy(&existing_partial);

        } else {

            if (is_initial_partial_content(log_content, log_content_len, FORMAT_DOCKER)) {

                msgpack_sbuffer partial_sbuf;
                msgpack_packer partial_packer;

                msgpack_sbuffer_init(&partial_sbuf);
                msgpack_packer_init(&partial_packer, &partial_sbuf, msgpack_sbuffer_write);

                msgpack_pack_object(&partial_packer, result.data);

                int ret = flb_hash_add(ctx->hash_table, tag, tag_len, partial_sbuf.data, partial_sbuf.size);
                if (ret == -1) {
                    flb_error("[filter_join_partial] cannot add tag to hash table");
                }

                // Release the original buffer as a new
                // copy have been generated into the hash table
                msgpack_sbuffer_destroy(&partial_sbuf);

                result_code = FLB_FILTER_MODIFIED;
            } else {
                msgpack_pack_object(&tmp_pck, result.data);
            }
        }
    }
    msgpack_unpacked_destroy(&result);

    if (result_code == FLB_FILTER_MODIFIED) {

        // link new buffers
        *out_buf   = tmp_sbuf.data;
        *out_bytes = tmp_sbuf.size;

        return result_code;

    } else {

        // destroy the tmp buffer
        msgpack_sbuffer_destroy(&tmp_sbuf);

        return result_code;
    }
}

static int cb_join_partial_exit(void *data, struct flb_config *config)
{
    struct filter_join_partial_ctx *ctx = data;

    if (ctx->hash_table) {
        flb_hash_destroy(ctx->hash_table);
    }

    flb_free(ctx);
    return 0;
}

struct flb_filter_plugin filter_join_partial_plugin = {
    .name         = "join_partial",
    .description  = "Filter that join partial log events",
    .cb_init      = cb_join_partial_init,
    .cb_filter    = cb_join_partial_filter,
    .cb_exit      = cb_join_partial_exit,
    .flags        = 0
};