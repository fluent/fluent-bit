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
#include <fluent-bit/flb_filter.h>
#include <fluent-bit/flb_filter_plugin.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_kv.h>
#include <fluent-bit/flb_str.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_log_event_decoder.h>
#include <fluent-bit/flb_log_event_encoder.h>
#include <msgpack.h>

#include "nest.h"

#include <stdio.h>
#include <sys/types.h>


static void teardown(struct filter_nest_ctx *ctx)
{
    struct mk_list *tmp;
    struct mk_list *head;

    struct filter_nest_wildcard *wildcard;
    struct filter_nest_wildcard *wildcard_excludes;

    flb_free(ctx->prefix);
    flb_free(ctx->key);

    mk_list_foreach_safe(head, tmp, &ctx->wildcards) {
        wildcard = mk_list_entry(head, struct filter_nest_wildcard, _head);
        flb_free(wildcard->key);
        mk_list_del(&wildcard->_head);
        flb_free(wildcard);
    }
    mk_list_foreach_safe(head, tmp, &ctx->wildcard_excludes) {
        wildcard_excludes = mk_list_entry(head, struct filter_nest_wildcard, _head);
        flb_free(wildcard_excludes->key);
        mk_list_del(&wildcard_excludes->_head);
        flb_free(wildcard_excludes);
    }

}

static int configure(struct filter_nest_ctx *ctx,
                     struct flb_filter_instance *f_ins,
                     struct flb_config *config)
{

    struct mk_list *head;
    struct flb_kv *kv;
    struct filter_nest_wildcard *wildcard;
    struct filter_nest_wildcard *wildcard_exclude;

    char *operation_nest = "nest";
    char *operation_lift = "lift";

    ctx->key = NULL;
    ctx->key_len = 0;
    ctx->prefix = NULL;
    ctx->prefix_len = 0;
    ctx->remove_prefix = false;
    ctx->add_prefix = false;

    if (flb_filter_config_map_set(f_ins, ctx) < 0) {
        flb_plg_error(f_ins, "unable to load configuration");
        return -1;
    }

    mk_list_foreach(head, &f_ins->properties) {
        kv = mk_list_entry(head, struct flb_kv, _head);

        if (strcasecmp(kv->key, "operation") == 0) {
            if (strncmp(kv->val, operation_nest, 4) == 0) {
                ctx->operation = NEST;
            }
            else if (strncmp(kv->val, operation_lift, 4) == 0) {
                ctx->operation = LIFT;
            }
            else {
                flb_plg_error(ctx->ins, "Key \"operation\" has invalid value "
                              "'%s'. Expected 'nest' or 'lift'\n",
                              kv->val);
                return -1;
            }
        }
        else if (strcasecmp(kv->key, "wildcard") == 0) {
            wildcard = flb_malloc(sizeof(struct filter_nest_wildcard));
            if (!wildcard) {
                flb_plg_error(ctx->ins, "Unable to allocate memory for "
                              "wildcard");
                flb_free(wildcard);
                return -1;
            }

            wildcard->key = flb_strndup(kv->val, flb_sds_len(kv->val));
            if (wildcard->key == NULL) {
                flb_errno();
                flb_free(wildcard);
                return -1;
            }
            wildcard->key_len = flb_sds_len(kv->val);

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
        else if (strcasecmp(kv->key, "wildcard_exclude") == 0) {
            wildcard_exclude = flb_malloc(sizeof(struct filter_nest_wildcard));
            if (!wildcard_exclude) {
                flb_plg_error(ctx->ins, "Unable to allocate memory for "
                              "wildcard_exclude");
                flb_free(wildcard_exclude);
                return -1;
            }

            wildcard_exclude->key = flb_strndup(kv->val, flb_sds_len(kv->val));
            if (wildcard_exclude->key == NULL) {
                flb_errno();
                flb_free(wildcard_exclude);
                return -1;
            }
            wildcard_exclude->key_len = flb_sds_len(kv->val);

            if (wildcard_exclude->key[wildcard_exclude->key_len - 1] == '*') {
                wildcard_exclude->key_is_dynamic = true;
                wildcard_exclude->key_len--;
            }
            else {
                wildcard_exclude->key_is_dynamic = false;
            }

            mk_list_add(&wildcard_exclude->_head, &ctx->wildcard_excludes);
            ctx->wildcard_excludes_cnt++;

        }
        else if (strcasecmp(kv->key, "nest_under") == 0) {
            ctx->key = flb_strdup(kv->val);
            ctx->key_len = flb_sds_len(kv->val);
        }
        else if (strcasecmp(kv->key, "nested_under") == 0) {
            ctx->key = flb_strdup(kv->val);
            ctx->key_len = flb_sds_len(kv->val);
        }
        else if (strcasecmp(kv->key, "prefix_with") == 0) {
            ctx->prefix = flb_strdup(kv->val);
            ctx->prefix_len = flb_sds_len(kv->val);
            ctx->add_prefix = true;
        }
        else if (strcasecmp(kv->key, "add_prefix") == 0) {
            ctx->prefix = flb_strdup(kv->val);
            ctx->prefix_len = flb_sds_len(kv->val);
            ctx->add_prefix = true;
        }
        else if (strcasecmp(kv->key, "remove_prefix") == 0) {
            ctx->prefix = flb_strdup(kv->val);
            ctx->prefix_len = flb_sds_len(kv->val);
            ctx->remove_prefix = true;
        } else {
            flb_plg_error(ctx->ins, "Invalid configuration key '%s'", kv->key);
            return -1;
        }
    }

    /* Sanity checks */
    if (ctx->remove_prefix && ctx->add_prefix) {
        flb_plg_error(ctx->ins, "Add_prefix and Remove_prefix are exclusive");
        return -1;
    }

    if ((ctx->operation != NEST) &&
            (ctx->operation != LIFT)) {
        flb_plg_error(ctx->ins, "Operation can only be NEST or LIFT");
        return -1;
    }

    if ((ctx->remove_prefix || ctx->add_prefix) && ctx->prefix == 0) {
        flb_plg_error(ctx->ins, "A prefix has to be specified for prefix add "
                      "or remove operations");
        return -1;
    }

    return 0;

}

static void helper_pack_string_remove_prefix(
        struct flb_log_event_encoder *log_encoder,
        struct filter_nest_ctx *ctx,
        const char *str,
        int len)
{
    if (strncmp(str, ctx->prefix, ctx->prefix_len) == 0) {
        flb_log_event_encoder_append_body_string(
            log_encoder,
            (char *) &str[ctx->prefix_len],
            len - ctx->prefix_len);
    }
    else {
        /* Key does not contain specified prefix */
        flb_log_event_encoder_append_body_string(
            log_encoder, (char *) str, len);
    }
}

static void helper_pack_string_add_prefix(struct flb_log_event_encoder *log_encoder,
        struct filter_nest_ctx *ctx,
        const char *str,
        int len)
{
    size_t new_size;

    /*
       An arg of FLB_LOG_EVENT_STRING_LENGTH_VALUE is a flb_log_event_encoder_size_t.
       flb_log_event_encoder_size_t is size_t* on Windows.
       It can cause pointer arithmetic and the output can be larger value.
       We use 'new_size' to prevent pointer arithmetic.
     */
    new_size = ctx->prefix_len + len;

    flb_log_event_encoder_append_body_values(
        log_encoder,
        FLB_LOG_EVENT_STRING_LENGTH_VALUE(new_size),
        FLB_LOG_EVENT_STRING_BODY_VALUE(ctx->prefix, ctx->prefix_len),
        FLB_LOG_EVENT_STRING_BODY_VALUE(str, len));
}

static inline void map_pack_each_fn(struct flb_log_event_encoder *log_encoder,
                                    msgpack_object * map,
                                    struct filter_nest_ctx *ctx,
                                    bool(*f) (msgpack_object_kv * kv,
                                              struct filter_nest_ctx * ctx))
{
    int i;
    int ret;

    ret = FLB_EVENT_ENCODER_SUCCESS;
    for (i = 0;
         i < map->via.map.size &&
         ret == FLB_EVENT_ENCODER_SUCCESS;
         i++) {
        if ((*f) (&map->via.map.ptr[i], ctx)) {
            ret = flb_log_event_encoder_append_body_values(
                    log_encoder,
                    FLB_LOG_EVENT_MSGPACK_OBJECT_VALUE(
                        &map->via.map.ptr[i].key),
                    FLB_LOG_EVENT_MSGPACK_OBJECT_VALUE(
                        &map->via.map.ptr[i].val));
        }
    }
}

static inline void map_transform_and_pack_each_fn(struct flb_log_event_encoder *log_encoder,
                                    msgpack_object * map,
                                    struct filter_nest_ctx *ctx,
                                    bool(*f) (msgpack_object_kv * kv,
                                              struct filter_nest_ctx * ctx)
    )
{
    int i;
    int ret;
    msgpack_object *key;

    ret = FLB_EVENT_ENCODER_SUCCESS;
    for (i = 0;
         i < map->via.map.size &&
         ret == FLB_EVENT_ENCODER_SUCCESS ;
         i++) {
        if ((*f) (&map->via.map.ptr[i], ctx)) {
            key = &map->via.map.ptr[i].key;

            if (ctx->add_prefix) {
                helper_pack_string_add_prefix(log_encoder, ctx, key->via.str.ptr, key->via.str.size);
            }
            else if (ctx->remove_prefix) {
                helper_pack_string_remove_prefix(log_encoder, ctx, key->via.str.ptr, key->via.str.size);
            }
            else {
                ret = flb_log_event_encoder_append_body_msgpack_object(
                        log_encoder, key);
            }

            if (ret == FLB_EVENT_ENCODER_SUCCESS) {
                ret = flb_log_event_encoder_append_body_msgpack_object(
                        log_encoder, &map->via.map.ptr[i].val);
            }
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

    const char *key;
    int klen;

    msgpack_object *obj = &kv->key;

    struct mk_list *tmp;
    struct mk_list *head;
    struct filter_nest_wildcard *wildcard;
    struct filter_nest_wildcard *wildcard_exclude;

    if (obj->type == MSGPACK_OBJECT_BIN) {
        key = obj->via.bin.ptr;
        klen = obj->via.bin.size;
    }
    else if (obj->type == MSGPACK_OBJECT_STR) {
        key = obj->via.str.ptr;
        klen = obj->via.str.size;
    }
    else {
        /* If the key is not something we can match on, leave it alone */
        return false;
    }

    mk_list_foreach_safe(head, tmp, &ctx->wildcard_excludes) {
        wildcard_exclude = mk_list_entry(head, struct filter_nest_wildcard, _head);

        if (wildcard_exclude->key_is_dynamic) {
            /* This will negatively match "ABC123" with prefix "ABC*" */
            if (strncmp(key, wildcard_exclude->key, wildcard_exclude->key_len) == 0) {
                return false;
            }
        }
        else {
            /* This will negatively match "ABC" with prefix "ABC" */
            if ((wildcard_exclude->key_len == klen) &&
                    (strncmp(key, wildcard_exclude->key, klen) == 0)
              ) {
                return false;
              }
        }
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

    const char *key;
    char *tmp;
    int klen;
    bool match;

    msgpack_object *obj = &kv->key;

    if (obj->type == MSGPACK_OBJECT_BIN) {
        key = obj->via.bin.ptr;
        klen = obj->via.bin.size;
    }
    else if (obj->type == MSGPACK_OBJECT_STR) {
        key = obj->via.str.ptr;
        klen = obj->via.str.size;
    }
    else {
        /* If the key is not something we can match on, leave it alone */
        return false;
    }

    match = ((ctx->key_len == klen) &&
             (strncmp(key, ctx->key, klen) == 0));

    if (match && (kv->val.type != MSGPACK_OBJECT_MAP)) {
        tmp = flb_malloc(klen + 1);
        if (!tmp) {
            flb_errno();
            return false;
        }
        memcpy(tmp, key, klen);
        tmp[klen] = '\0';
        flb_plg_warn(ctx->ins, "Value of key '%s' is not a map. "
                     "Will not attempt to lift from here",
                     tmp);
        flb_free(tmp);
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

static inline void pack_map(
    struct flb_log_event_encoder *log_encoder,
    msgpack_object * map,
    struct filter_nest_ctx *ctx)
{
    int i;
    int ret;
    msgpack_object *key;

    ret = FLB_EVENT_ENCODER_SUCCESS;

    for (i = 0;
         i < map->via.map.size &&
         ret == FLB_EVENT_ENCODER_SUCCESS ;
         i++) {
        key = &map->via.map.ptr[i].key;

        if (ctx->add_prefix) {
            helper_pack_string_add_prefix(log_encoder, ctx, key->via.str.ptr, key->via.str.size);
        }
        else if (ctx->remove_prefix) {
            helper_pack_string_remove_prefix(log_encoder, ctx, key->via.str.ptr, key->via.str.size);
        }
        else {
            ret = flb_log_event_encoder_append_body_msgpack_object(log_encoder, key);
        }

        if (ret == FLB_EVENT_ENCODER_SUCCESS) {
            ret = flb_log_event_encoder_append_body_msgpack_object(log_encoder,
                    &map->via.map.ptr[i].val);
        }
    }
}

static inline void map_lift_each_fn(struct flb_log_event_encoder *log_encoder,
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
            pack_map(log_encoder, &kv->val, ctx);
        }
    }
}

static inline int apply_lifting_rules(struct flb_log_event_encoder *log_encoder,
                                      struct flb_log_event *log_event,
                                      struct filter_nest_ctx *ctx)
{
    int ret;
    msgpack_object map = *log_event->body;

    int items_to_lift = map_count_fn(&map, ctx, &is_kv_to_lift);

    if (items_to_lift == 0) {
        flb_plg_debug(ctx->ins, "Lift : No match found for %s", ctx->key);
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

    flb_plg_debug(ctx->ins, "Lift : Outer map size is %d, will be %d, "
                  "lifting %d record(s)",
                  map.via.map.size, toplevel_items, items_to_lift);

    ret = flb_log_event_encoder_begin_record(log_encoder);

    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        return -1;
    }

    ret = flb_log_event_encoder_set_timestamp(
            log_encoder, &log_event->timestamp);

    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        return -2;
    }

    ret = flb_log_event_encoder_set_metadata_from_msgpack_object(
            log_encoder, log_event->metadata);

    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        return -3;
    }

    /* Pack all current top-level items excluding the key keys */
    map_pack_each_fn(log_encoder, &map, ctx, &is_not_kv_to_lift);

    /* Lift and pack all elements in key keys */
    map_lift_each_fn(log_encoder, &map, ctx, &is_kv_to_lift);

    ret = flb_log_event_encoder_commit_record(log_encoder);

    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        return -2;
    }

    return 1;
}

static inline int apply_nesting_rules(struct flb_log_event_encoder *log_encoder,
                                      struct flb_log_event *log_event,
                                      struct filter_nest_ctx *ctx)
{
    int ret;
    msgpack_object map = *log_event->body;

    size_t items_to_nest = map_count_fn(&map, ctx, &is_kv_to_nest);

    if (items_to_nest == 0) {
        flb_plg_debug(ctx->ins, "no match found for %s", ctx->prefix);
        return 0;
    }

    size_t toplevel_items = (map.via.map.size - items_to_nest + 1);

    flb_plg_trace(ctx->ins, "outer map size is %d, will be %lu, nested "
                  "map size will be %lu",
                  map.via.map.size, toplevel_items, items_to_nest);

    ret = flb_log_event_encoder_begin_record(log_encoder);

    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        return -1;
    }

    ret = flb_log_event_encoder_set_timestamp(
            log_encoder, &log_event->timestamp);

    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        return -2;
    }

    ret = flb_log_event_encoder_set_metadata_from_msgpack_object(
            log_encoder, log_event->metadata);

    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        return -3;
    }

    /*
     * Record array item 2/2
     * Create a new map with toplevel items +1 for nested map
     */
    map_pack_each_fn(log_encoder, &map, ctx, &is_not_kv_to_nest);

    /* Pack the nested map key */
    ret = flb_log_event_encoder_append_body_string(
            log_encoder, ctx->key, ctx->key_len);

    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        return -4;
    }

    /* Create the nest map value */
    ret = flb_log_event_encoder_body_begin_map(log_encoder);

    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        return -5;
    }

    /* Pack the nested items */
    map_transform_and_pack_each_fn(log_encoder, &map, ctx, &is_kv_to_nest);

    ret = flb_log_event_encoder_commit_record(log_encoder);

    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        return -6;
    }

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
    ctx->ins = f_ins;
    mk_list_init(&ctx->wildcards);
    ctx->wildcards_cnt = 0;
    mk_list_init(&ctx->wildcard_excludes);
    ctx->wildcard_excludes_cnt = 0;

    if (configure(ctx, f_ins, config) < 0) {
        flb_free(ctx);
        return -1;
    }

    flb_filter_set_context(f_ins, ctx);
    return 0;
}

static int cb_nest_filter(const void *data, size_t bytes,
                          const char *tag, int tag_len,
                          void **out_buf, size_t * out_size,
                          struct flb_filter_instance *f_ins,
                          struct flb_input_instance *i_ins,
                          void *context, struct flb_config *config)
{
    struct flb_log_event_encoder log_encoder;
    struct flb_log_event_decoder log_decoder;
    struct flb_log_event log_event;
    struct filter_nest_ctx *ctx = context;
    int modified_records = 0;
    int ret;

    (void) f_ins;
    (void) i_ins;
    (void) config;


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
        modified_records = 0;

        if (ctx->operation == NEST) {
            modified_records =
                apply_nesting_rules(&log_encoder, &log_event, ctx);
        }
        else {
            modified_records =
                apply_lifting_rules(&log_encoder, &log_event, ctx);
        }

        if (modified_records == 0) {
            ret = flb_log_event_encoder_emit_raw_record(
                    &log_encoder,
                    log_decoder.record_base,
                    log_decoder.record_length);
        }
    }

    if (ret == FLB_EVENT_DECODER_ERROR_INSUFFICIENT_DATA &&
        log_decoder.offset == bytes) {
        ret = FLB_EVENT_ENCODER_SUCCESS;
    }

    if (log_encoder.output_length > 0) {
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

static int cb_nest_exit(void *data, struct flb_config *config)
{
    struct filter_nest_ctx *ctx = data;

    teardown(ctx);
    flb_free(ctx);
    return 0;
}

/* Configuration properties map */
static struct flb_config_map config_map[] = {
   {
    FLB_CONFIG_MAP_STR, "Operation", NULL,
    0, FLB_FALSE, 0,
    "Select the operation nest or lift"
   },
   {
    FLB_CONFIG_MAP_STR, "Wildcard", NULL,
    FLB_CONFIG_MAP_MULT, FLB_FALSE, 0,
    "Nest records which field matches the wildcard"
   },
   {
    FLB_CONFIG_MAP_STR, "Wildcard_exclude", NULL,
    FLB_CONFIG_MAP_MULT, FLB_FALSE, 0,
    "Nest records which field doesn't matches the wildcard"
   },
   {
    FLB_CONFIG_MAP_STR, "Nest_under", NULL,
    0, FLB_FALSE, 0,
    "Nest records matching the Wildcard under this key"
   },
   {
    FLB_CONFIG_MAP_STR, "Nested_under", NULL,
    0, FLB_FALSE, 0,
    "Lift records nested under the Nested_under key"
   },
   {
    FLB_CONFIG_MAP_STR, "Add_prefix", NULL,
    0, FLB_FALSE, 0,
    "Prefix affected keys with this string"
   },
   {
    FLB_CONFIG_MAP_STR, "Remove_prefix", NULL,
    0, FLB_FALSE, 0,
    "Remove prefix from affected keys if it matches this string"
   },
   {0}
};

struct flb_filter_plugin filter_nest_plugin = {
    .name = "nest",
    .description = "nest events by specified field values",
    .cb_init = cb_nest_init,
    .cb_filter = cb_nest_filter,
    .cb_exit = cb_nest_exit,
    .config_map = config_map,
    .flags = 0
};
