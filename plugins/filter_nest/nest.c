/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019      The Fluent Bit Authors
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

#include <stdio.h>
#include <sys/types.h>

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_str.h>
#include <fluent-bit/flb_filter.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_pack.h>
#include <msgpack.h>

#include "nest.h"

static void teardown(struct filter_nest_ctx *ctx)
{
    struct mk_list *tmp;
    struct mk_list *head;

    struct filter_nest_wildcard *wildcard;

    flb_free(ctx->prefix);
    flb_free(ctx->key);

    mk_list_foreach_safe(head, tmp, &ctx->wildcards) {
        wildcard = mk_list_entry(head, struct filter_nest_wildcard, _head);
        flb_free(wildcard->key);
        mk_list_del(&wildcard->_head);
        flb_free(wildcard);
    }

}

static int configure(struct filter_nest_ctx *ctx,
                     struct flb_filter_instance *f_ins,
                     struct flb_config *config)
{

    struct mk_list *head;
    struct flb_config_prop *prop;
    struct filter_nest_wildcard *wildcard;

    char *operation_nest = "nest";
    char *operation_lift = "lift";

    ctx->key = NULL;
    ctx->key_len = 0;
    ctx->prefix = NULL;
    ctx->prefix_len = 0;
    ctx->remove_prefix = false;
    ctx->add_prefix = false;

    mk_list_foreach(head, &f_ins->properties) {
        prop = mk_list_entry(head, struct flb_config_prop, _head);

        if (strcasecmp(prop->key, "operation") == 0) {
            if (strncmp(prop->val, operation_nest, 4) == 0) {
                ctx->operation = NEST;
            }
            else if (strncmp(prop->val, operation_lift, 4) == 0) {
                ctx->operation = LIFT;
            }
            else {
                flb_error
                    ("[filter_nest] Key \"operation\" has invalid value '%s'. Expected 'nest' or 'lift'\n", prop->val);
                return -1;
            }
        }
        else if (strcasecmp(prop->key, "wildcard") == 0) {
            wildcard = flb_malloc(sizeof(struct filter_nest_wildcard));
            if (!wildcard) {
                flb_error
                    ("[filter_nest] Unable to allocate memory for wildcard");
                flb_free(wildcard);
                return -1;
            }

            wildcard->key = flb_strndup(prop->val, strlen(prop->val));
            wildcard->key_len = strlen(prop->val);

            if (wildcard->key[wildcard->key_len - 1] == '*') {
                wildcard->key_is_dynamic = true;
                wildcard->key_len--;
            }
            else {
                wildcard->key_is_dynamic = false;
            }

            mk_list_add(&wildcard->_head, &ctx->wildcards);
            ctx->wildcards_cnt++;

        }
        else if (strcasecmp(prop->key, "nest_under") == 0) {
            ctx->key = flb_strdup(prop->val);
            ctx->key_len = strlen(prop->val);
        }
        else if (strcasecmp(prop->key, "nested_under") == 0) {
            ctx->key = flb_strdup(prop->val);
            ctx->key_len = strlen(prop->val);
        }
        else if (strcasecmp(prop->key, "prefix_with") == 0) {
            ctx->prefix = flb_strdup(prop->val);
            ctx->prefix_len = strlen(prop->val);
            ctx->add_prefix = true;
        }
        else if (strcasecmp(prop->key, "add_prefix") == 0) {
            ctx->prefix = flb_strdup(prop->val);
            ctx->prefix_len = strlen(prop->val);
            ctx->add_prefix = true;
        }
        else if (strcasecmp(prop->key, "remove_prefix") == 0) {
            ctx->prefix = flb_strdup(prop->val);
            ctx->prefix_len = strlen(prop->val);
            ctx->remove_prefix = true;
        } else {
            flb_error("[filter_nest] Invalid configuration key '%s'", prop->key);
            return -1;
        }
    }

    /* Sanity checks */
    if (ctx->remove_prefix && ctx->add_prefix) {
        flb_error("[filter_nest] Add_prefix and Remove_prefix are exclusive");
        return -1;
    }

    if ((ctx->operation != NEST) &&
            (ctx->operation != LIFT)) {
        flb_error("[filter_nest] Operation can only be NEST or LIFT");
        return -1;
    }

    if ((ctx->remove_prefix || ctx->add_prefix) && ctx->prefix == 0) {
        flb_error("[filter_nest] A prefix has to be specified for prefix add or remove operations");
        return -1;
    }

    return 0;

}

static void helper_pack_string(msgpack_packer * packer, const char *str,
                               int len)
{
    if (str == NULL) {
        msgpack_pack_nil(packer);
    }
    else {
        msgpack_pack_str(packer, len);
        msgpack_pack_str_body(packer, str, len);
    }
}

static void helper_pack_string_remove_prefix(msgpack_packer * packer,
        struct filter_nest_ctx *ctx,
        const char *str,
        int len)
{
    int size;

    if (strncmp(str, ctx->prefix, ctx->prefix_len) == 0) {
        size = len - ctx->prefix_len;
        msgpack_pack_str(packer, size);
        msgpack_pack_str_body(packer, (str + ctx->prefix_len), size);
    }
    else {
        /* Key does not contain specified prefix */
        msgpack_pack_str(packer, len);
        msgpack_pack_str_body(packer, str, len);
    }
}

static void helper_pack_string_add_prefix(msgpack_packer * packer,
        struct filter_nest_ctx *ctx,
        const char *str,
        int len)
{
    msgpack_pack_str(packer, ctx->prefix_len + len);
    msgpack_pack_str_body(packer, ctx->prefix, ctx->prefix_len);
    msgpack_pack_str_body(packer, str, len);
}

static inline void map_pack_each_fn(msgpack_packer * packer,
                                    msgpack_object * map,
                                    struct filter_nest_ctx *ctx,
                                    bool(*f) (msgpack_object_kv * kv,
                                              struct filter_nest_ctx * ctx)
    )
{
    int i;
    msgpack_object *key;

    for (i = 0; i < map->via.map.size; i++) {
        if ((*f) (&map->via.map.ptr[i], ctx)) {
            key = &map->via.map.ptr[i].key;
            msgpack_pack_object(packer, *key);
            msgpack_pack_object(packer, map->via.map.ptr[i].val);
        }
    }
}

static inline void map_transform_and_pack_each_fn(msgpack_packer * packer,
                                    msgpack_object * map,
                                    struct filter_nest_ctx *ctx,
                                    bool(*f) (msgpack_object_kv * kv,
                                              struct filter_nest_ctx * ctx)
    )
{
    int i;
    msgpack_object *key;

    for (i = 0; i < map->via.map.size; i++) {
        if ((*f) (&map->via.map.ptr[i], ctx)) {
            key = &map->via.map.ptr[i].key;
            if (ctx->add_prefix) {
                helper_pack_string_add_prefix(packer, ctx, key->via.str.ptr, key->via.str.size);
            }
            else if (ctx->remove_prefix) {
                helper_pack_string_remove_prefix(packer, ctx, key->via.str.ptr, key->via.str.size);
            }
            else {
                msgpack_pack_object(packer, *key);
            }

            msgpack_pack_object(packer, map->via.map.ptr[i].val);
        }
    }
}

static inline int map_count_fn(msgpack_object * map,
                               struct filter_nest_ctx *ctx,
                               bool(*f) (msgpack_object_kv * kv,
                                         struct filter_nest_ctx * ctx)
    )
{
    int i;
    int count = 0;

    for (i = 0; i < map->via.map.size; i++) {
        if ((*f) (&map->via.map.ptr[i], ctx)) {
            count++;
        }
    }
    return count;
}

static inline bool is_kv_to_nest(msgpack_object_kv * kv,
                                 struct filter_nest_ctx *ctx)
{

    char *key;
    int klen;

    msgpack_object *obj = &kv->key;

    struct mk_list *tmp;
    struct mk_list *head;
    struct filter_nest_wildcard *wildcard;

    if (obj->type == MSGPACK_OBJECT_BIN) {
        key = (char *) obj->via.bin.ptr;
        klen = obj->via.bin.size;
    }
    else if (obj->type == MSGPACK_OBJECT_STR) {
        key = (char *) obj->via.str.ptr;
        klen = obj->via.str.size;
    }
    else {
        /* If the key is not something we can match on, leave it alone */
        return false;
    }

    mk_list_foreach_safe(head, tmp, &ctx->wildcards) {
        wildcard = mk_list_entry(head, struct filter_nest_wildcard, _head);

        if (wildcard->key_is_dynamic) {
            /* This will positively match "ABC123" with prefix "ABC*" */
            if (strncmp(key, wildcard->key, wildcard->key_len) == 0) {
                return true;
            }
        }
        else {
            /* This will positively match "ABC" with prefix "ABC" */
            if ((wildcard->key_len == klen) &&
                    (strncmp(key, wildcard->key, klen) == 0)
              ) {
                return true;
            }
        }
    }

    return false;

}

static inline bool is_not_kv_to_nest(msgpack_object_kv * kv,
                                     struct filter_nest_ctx *ctx)
{
    return !is_kv_to_nest(kv, ctx);
}

static inline bool is_kv_to_lift(msgpack_object_kv * kv,
                                 struct filter_nest_ctx *ctx)
{

    char *key;
    int klen;
    bool match;

    msgpack_object *obj = &kv->key;

    if (obj->type == MSGPACK_OBJECT_BIN) {
        key = (char *) obj->via.bin.ptr;
        klen = obj->via.bin.size;
    }
    else if (obj->type == MSGPACK_OBJECT_STR) {
        key = (char *) obj->via.str.ptr;
        klen = obj->via.str.size;
    }
    else {
        /* If the key is not something we can match on, leave it alone */
        return false;
    }

    match = ((ctx->key_len == klen) &&
             (strncmp(key, ctx->key, klen) == 0));

    if (match && (kv->val.type != MSGPACK_OBJECT_MAP)) {
        flb_warn
            ("[filter_nest] Value of key '%s' is not a map. Will not attempt to lift from here",
             key);
        return false;
    }
    else {
        return match;
    }
}

static inline bool is_not_kv_to_lift(msgpack_object_kv * kv,
                                     struct filter_nest_ctx *ctx)
{
    return !is_kv_to_lift(kv, ctx);
}

static inline int count_items_to_lift(msgpack_object * map,
                                      struct filter_nest_ctx *ctx)
{
    int i;
    int count = 0;
    msgpack_object_kv *kv;

    for (i = 0; i < map->via.map.size; i++) {
        kv = &map->via.map.ptr[i];
        if (is_kv_to_lift(kv, ctx)) {
            count = count + kv->val.via.map.size;
        }
    }
    return count;
}

static inline void pack_map(msgpack_packer * packer, msgpack_object * map,
                            struct filter_nest_ctx *ctx)
{
    int i;

    msgpack_object *key;

    for (i = 0; i < map->via.map.size; i++) {
        key = &map->via.map.ptr[i].key;

        if (ctx->add_prefix) {
            helper_pack_string_add_prefix(packer, ctx, key->via.str.ptr, key->via.str.size);
        }
        else if (ctx->remove_prefix) {
            helper_pack_string_remove_prefix(packer, ctx, key->via.str.ptr, key->via.str.size);
        }
        else {
            msgpack_pack_object(packer, *key);
        }
        msgpack_pack_object(packer, map->via.map.ptr[i].val);
    }
}

static inline void map_lift_each_fn(msgpack_packer * packer,
                                    msgpack_object * map,
                                    struct filter_nest_ctx *ctx,
                                    bool(*f) (msgpack_object_kv * kv,
                                              struct filter_nest_ctx * ctx)
    )
{
    int i;
    msgpack_object_kv *kv;

    for (i = 0; i < map->via.map.size; i++) {
        kv = &map->via.map.ptr[i];
        if ((*f) (kv, ctx)) {
            pack_map(packer, &kv->val, ctx);
        }
    }
}

static inline int apply_lifting_rules(msgpack_packer * packer,
                                      msgpack_object * root,
                                      struct filter_nest_ctx *ctx)
{
    msgpack_object ts = root->via.array.ptr[0];
    msgpack_object map = root->via.array.ptr[1];

    int items_to_lift = map_count_fn(&map, ctx, &is_kv_to_lift);

    if (items_to_lift == 0) {
        flb_debug("[filter_nest] Lift : No match found for %s", ctx->key);
        return 0;
    }

    /*
     * New items at top level =
     *   current size
     *   - number of maps to lift
     *   + number of element inside maps to lift
     */
    int toplevel_items =
        (map.via.map.size - items_to_lift) + count_items_to_lift(&map, ctx);

    flb_debug
        ("[filter_nest] Lift : Outer map size is %d, will be %d, lifting %d record(s)",
         map.via.map.size, toplevel_items, items_to_lift);

    /* Record array init(2) */
    msgpack_pack_array(packer, 2);

    /* Record array item 1/2 */
    msgpack_pack_object(packer, ts);

    /*
     * Record array item 2/2
     * Create a new map with top-level number of items
     */
    msgpack_pack_map(packer, (size_t) toplevel_items);

    /* Pack all current top-level items excluding the key keys */
    map_pack_each_fn(packer, &map, ctx, &is_not_kv_to_lift);

    /* Lift and pack all elements in key keys */
    map_lift_each_fn(packer, &map, ctx, &is_kv_to_lift);

    return 1;
}

static inline int apply_nesting_rules(msgpack_packer * packer,
                                      msgpack_object * root,
                                      struct filter_nest_ctx *ctx)
{
    msgpack_object ts = root->via.array.ptr[0];
    msgpack_object map = root->via.array.ptr[1];

    size_t items_to_nest = map_count_fn(&map, ctx, &is_kv_to_nest);

    if (items_to_nest == 0) {
        flb_debug("[filter_nest] Nest : No match found for %s", ctx->prefix);
        return 0;
    }

    size_t toplevel_items = (map.via.map.size - items_to_nest + 1);

    flb_debug
        ("[filter_nest] Nest : Outer map size is %d, will be %d, nested map size will be %d",
         map.via.map.size, toplevel_items, items_to_nest);

    /* Record array init(2) */
    msgpack_pack_array(packer, 2);

    /* Record array item 1/2 */
    msgpack_pack_object(packer, ts);

    /*
     * Record array item 2/2
     * Create a new map with toplevel items +1 for nested map
     */
    msgpack_pack_map(packer, toplevel_items);
    map_pack_each_fn(packer, &map, ctx, &is_not_kv_to_nest);

    /* Pack the nested map key */
    helper_pack_string(packer, ctx->key, ctx->key_len);

    /* Create the nest map value */
    msgpack_pack_map(packer, items_to_nest);

    /* Pack the nested items */
    map_transform_and_pack_each_fn(packer, &map, ctx, &is_kv_to_nest);

    return 1;
}

static int cb_nest_init(struct flb_filter_instance *f_ins,
                        struct flb_config *config, void *data)
{
    struct filter_nest_ctx *ctx;

    ctx = flb_malloc(sizeof(struct filter_nest_ctx));

    if (!ctx) {
        flb_errno();
        return -1;
    }

    mk_list_init(&ctx->wildcards);
    ctx->wildcards_cnt = 0;

    if (configure(ctx, f_ins, config) < 0) {
        flb_free(ctx);
        return -1;
    }

    flb_filter_set_context(f_ins, ctx);
    return 0;
}

static int cb_nest_filter(void *data, size_t bytes,
                          char *tag, int tag_len,
                          void **out_buf, size_t * out_size,
                          struct flb_filter_instance *f_ins,
                          void *context, struct flb_config *config)
{
    msgpack_unpacked result;
    size_t off = 0;
    (void) f_ins;
    (void) config;

    struct filter_nest_ctx *ctx = context;
    int modified_records = 0;

    msgpack_sbuffer buffer;
    msgpack_sbuffer_init(&buffer);

    msgpack_packer packer;
    msgpack_packer_init(&packer, &buffer, msgpack_sbuffer_write);

    /*
     * Records come in the format,
     *
     * [ TIMESTAMP, { K1=>V1, K2=>V2, ...} ],
     * [ TIMESTAMP, { K1=>V1, K2=>V2, ...} ]
     *
     * Example record,
     * [1123123, {"Mem.total"=>4050908, "Mem.used"=>476, "Mem.free"=>3574332 }]
     */

    msgpack_unpacked_init(&result);
    while (msgpack_unpack_next(&result, data, bytes, &off) == MSGPACK_UNPACK_SUCCESS) {
        if (result.data.type == MSGPACK_OBJECT_ARRAY) {
            if (ctx->operation == NEST) {
                modified_records +=
                    apply_nesting_rules(&packer, &result.data, ctx);
            }
            else {
                modified_records +=
                    apply_lifting_rules(&packer, &result.data, ctx);
            }
        }
        else {
            flb_debug("[filter_nest] Record is NOT an array, skipping");
            msgpack_pack_object(&packer, result.data);
        }
    }
    msgpack_unpacked_destroy(&result);

    *out_buf = buffer.data;
    *out_size = buffer.size;

    if (modified_records == 0) {
        return FLB_FILTER_NOTOUCH;
    }
    else {
        return FLB_FILTER_MODIFIED;
    }
}

static int cb_nest_exit(void *data, struct flb_config *config)
{
    struct filter_nest_ctx *ctx = data;

    teardown(ctx);
    flb_free(ctx);
    return 0;
}

struct flb_filter_plugin filter_nest_plugin = {
    .name = "nest",
    .description = "nest events by specified field values",
    .cb_init = cb_nest_init,
    .cb_filter = cb_nest_filter,
    .cb_exit = cb_nest_exit,
    .flags = 0
};
