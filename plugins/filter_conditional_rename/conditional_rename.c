#include <stdio.h>

#include <fluent-bit/flb_filter.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_time.h>

#include <msgpack.h>

#include "conditional_rename.h"

#define PLUGIN_NAME "filter_conditional_rename"

static int configure(struct filter_conditional_rename_ctx *ctx,
                     struct flb_filter_instance *f_ins,
                     struct flb_config *config)
{
    char *tmp;

    struct mk_list *split;
    struct flb_split_entry *sentry;

    ctx->if_equal_key = NULL;
    ctx->if_equal_val = NULL;
    ctx->rename_field = NULL;
    ctx->rename_renamed_field = NULL;

    tmp = flb_filter_get_property("if_equal", f_ins);
    if (tmp) {

        split = flb_utils_split(tmp, ' ', 1);
        if (mk_list_size(split) != 2) {
            flb_error("[%s] invalid if_equal parameters, expects 'KEY VALUE'", PLUGIN_NAME);
            flb_free(ctx);
            flb_utils_split_free(split);
            return -1;
        }
        /* Get first value (field) */
        sentry = mk_list_entry_first(split, struct flb_split_entry, _head);
        ctx->if_equal_key = flb_strndup(sentry->value, sentry->len);
        ctx->if_equal_key_len = sentry->len;

        sentry = mk_list_entry_last(split, struct flb_split_entry, _head);
        ctx->if_equal_val = flb_strndup(sentry->value, sentry->len);
        ctx->if_equal_val_len = sentry->len;

        flb_utils_split_free(split);
    }
    else {
        flb_error("[%s] Key \"if_equal\" is missing\n", PLUGIN_NAME);
        return -1;
    }

    tmp = flb_filter_get_property("rename", f_ins);
    if (tmp) {

        split = flb_utils_split(tmp, ' ', 1);
        if (mk_list_size(split) != 2) {
            flb_error("[%s] invalid rename parameters, expects 'FIELD RENAMED_FIELD'", PLUGIN_NAME);
            flb_free(ctx);
            flb_utils_split_free(split);
            return -1;
        }
        /* Get first value (field) */
        sentry = mk_list_entry_first(split, struct flb_split_entry, _head);
        ctx->rename_field = flb_strndup(sentry->value, sentry->len);
        ctx->rename_field_len = sentry->len;

        sentry = mk_list_entry_last(split, struct flb_split_entry, _head);
        ctx->rename_renamed_field = flb_strndup(sentry->value, sentry->len);
        ctx->rename_renamed_field_len = sentry->len;

        flb_utils_split_free(split);
    }
    else {
        flb_error("[%s] Key \"rename\" is missing\n", PLUGIN_NAME);
        return -1;
    }

    return 0;
}

static int cb_conditional_rename_init(struct flb_filter_instance *f_ins,
                          struct flb_config *config,
                          void *data)
{
    struct filter_conditional_rename_ctx *ctx;

    ctx = flb_malloc(sizeof(struct filter_conditional_rename_ctx));
    if (!ctx) {
        flb_errno();
        return -1;
    }

    if (configure(ctx, f_ins, config) < 0) {
        flb_free(ctx);
        return -1;
    }

    flb_filter_set_context(f_ins, ctx);
    return 0;
}

static inline bool if_equal_match(msgpack_object_kv * kv, struct filter_conditional_rename_ctx *ctx)
{
    char *key;
    int klen;
    char *val;
    int vlen;

    msgpack_object *obj = &kv->key;
    msgpack_object *obj2 = &kv->val; //todo correct with -> val??

    if (obj->type == MSGPACK_OBJECT_BIN) {
        key = (char *) obj->via.bin.ptr;
        klen = obj->via.bin.size;
        val = (char *) obj2->via.bin.ptr;
        vlen = obj2->via.bin.size;
    }
    else if (obj->type == MSGPACK_OBJECT_STR) {
        key = (char *) obj->via.str.ptr;
        klen = obj->via.str.size;
        val = (char *) obj2->via.str.ptr;
        vlen = obj2->via.str.size;
    }
    else {
        // If the key is not something we can match on then we leave it alone
        return false;
    }

    // Exact match of key and value
    return ((ctx->if_equal_key_len == klen) && (strncmp(key, ctx->if_equal_key, klen)) &&
            (ctx->if_equal_val_len == vlen) && (strncmp(val, ctx->if_equal_val, vlen)) == 0);
}

static inline bool kv_key_matches(msgpack_object_kv * kv, struct filter_conditional_rename_ctx *ctx)
{

    char *key;
    int klen;

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
        return false;
    }

    return ((ctx->rename_field_len == klen) && (strncmp(ctx->rename_field, key, klen) == 0));
}

static void helper_pack_string(msgpack_packer * packer, const char *str, int len)
{
    if (str == NULL) {
        msgpack_pack_nil(packer);
    }
    else {
        msgpack_pack_str(packer, len);
        msgpack_pack_str_body(packer, str, len);
    }
}

static inline void pack_map_with_rename(msgpack_packer * packer,
                                        msgpack_object * map,
                                        struct filter_conditional_rename_ctx *ctx)
{
    bool matched;
    for (int i = 0; i < map->via.map.size; i++) {

        matched = false;

        if (kv_key_matches(&map->via.map.ptr[i], ctx)) {
            matched = true;
        }

        if (matched) {
            helper_pack_string(packer, ctx->rename_renamed_field, ctx->rename_renamed_field_len);
        }
        else {
            msgpack_pack_object(packer, map->via.map.ptr[i].key);
        }
        msgpack_pack_object(packer, map->via.map.ptr[i].val);

    }
}

static inline bool has_matching_kv(msgpack_object * map, struct filter_conditional_rename_ctx *ctx)
{
    for (int i = 0; i < map->via.map.size; i++) {
        if (if_equal_match(&map->via.map.ptr[i], ctx)) {
            return true;
        }
    }
    return false;
}

static inline void apply_modifying_rules(msgpack_packer * packer,
                                         msgpack_object * root,
                                         struct filter_conditional_rename_ctx *ctx)
{
    msgpack_object ts = root->via.array.ptr[0];
    msgpack_object map = root->via.array.ptr[1];

    // TODO: We can scan for both rules and if they both come back 0 we can
    // return without rewriting

    bool if_equal_matches = has_matching_kv(&map, ctx);

    //TODO if if_equal_matches == false -> return unmodified ELSE apply rename
    int total_records = map.via.map.size;

    // * Record array init(2)
    msgpack_pack_array(packer, 2);

    // * * Record array item 1/2
    msgpack_pack_object(packer, ts);

    // * * Record array item 2/2
    msgpack_pack_map(packer, total_records);

    // * * * Add from input map to new map with items renamed
    if (if_equal_matches) {
        pack_map_with_rename(packer, &map, ctx);
    }

    //todo else return unmodified
}

static int cb_conditional_rename_filter(void *data, size_t bytes,
                            char *tag, int tag_len,
                            void **out_buf, size_t *out_size,
                            struct flb_filter_instance *f_ins,
                            void *filter_context,
                            struct flb_config *config)
{
    msgpack_unpacked result;
    size_t off = 0;
    (void) f_ins;
    (void) config;

    struct filter_conditional_rename_ctx *ctx = filter_context;

    msgpack_sbuffer buffer;
    msgpack_sbuffer_init(&buffer);

    msgpack_packer packer;
    msgpack_packer_init(&packer, &buffer, msgpack_sbuffer_write);

    msgpack_unpacked_init(&result);
    while (msgpack_unpack_next(&result, data, bytes, &off)) {

    //todo 1. if if_equal matches
    //todo 2. then apply rename

            if (result.data.type == MSGPACK_OBJECT_ARRAY) {
                apply_modifying_rules(&packer, &result.data, ctx);
            }
            else {
                msgpack_pack_object(&packer, result.data);
            }
    }
    msgpack_unpacked_destroy(&result);

    *out_buf = buffer.data;
    *out_size = buffer.size;

    return FLB_FILTER_MODIFIED;
    //todo return FLB_FILTER_NOTOUCH;
}

static int cb_conditional_rename_exit(void *data, struct flb_config *config)
{
    struct filter_conditional_rename_ctx *ctx = data;

    flb_free(ctx->if_equal_key);
    flb_free(ctx->if_equal_val);
    flb_free(ctx->rename_field);
    flb_free(ctx->rename_renamed_field);
    flb_free(ctx);

    return 0;
}

struct flb_filter_plugin filter_conditional_rename_plugin = {
    .name         = "conditional_rename",
    .description  = "Conditionally rename fields",
    .cb_init      = cb_conditional_rename_init,
    .cb_filter    = cb_conditional_rename_filter,
    .cb_exit      = cb_conditional_rename_exit,
    .flags        = 0
};