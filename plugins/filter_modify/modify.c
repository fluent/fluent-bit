/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2024 The Fluent Bit Authors
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
#include <fluent-bit/flb_regex.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_record_accessor.h>
#include <fluent-bit/flb_ra_key.h>
#include <fluent-bit/flb_log_event_decoder.h>
#include <fluent-bit/flb_log_event_encoder.h>
#include <msgpack.h>

#include "modify.h"

#include <stdio.h>
#include <sys/types.h>

static void condition_free(struct modify_condition *condition)
{
    if (condition == NULL) {
        return;
    }

    if (condition->a) {
        flb_sds_destroy(condition->a);
    }
    if (condition->b) {
        flb_free(condition->b);
    }
    if (condition->raw_k) {
        flb_free(condition->raw_k);
    }
    if (condition->raw_v) {
        flb_free(condition->raw_v);
    }

    if (condition->a_regex) {
        flb_regex_destroy(condition->a_regex);
    }
    if (condition->b_regex) {
        flb_regex_destroy(condition->b_regex);
    }
    if (condition->ra_a) {
        flb_ra_destroy(condition->ra_a);
        condition->ra_a = NULL;
    }
    if (!mk_list_entry_is_orphan(&condition->_head)) {
        mk_list_del(&condition->_head);
    }
    flb_free(condition);
}

static void rule_free(struct modify_rule *rule)
{
    if (rule == NULL) {
        return;
    }

    if (rule->key) {
        flb_free(rule->key);
    }
    if (rule->val) {
        flb_free(rule->val);
    }
    if (rule->raw_k) {
        flb_free(rule->raw_k);
    }
    if (rule->raw_v) {
        flb_free(rule->raw_v);
    }
    if (rule->key_regex) {
        flb_regex_destroy(rule->key_regex);
    }
    if (rule->val_regex) {
        flb_regex_destroy(rule->val_regex);
    }
    if (!mk_list_entry_is_orphan(&rule->_head)) {
        mk_list_del(&rule->_head);
    }
    flb_free(rule);
}

static void teardown(struct filter_modify_ctx *ctx)
{
    struct mk_list *tmp;
    struct mk_list *head;

    struct modify_rule *rule;
    struct modify_condition *condition;

    mk_list_foreach_safe(head, tmp, &ctx->conditions) {
        condition = mk_list_entry(head, struct modify_condition, _head);
        condition_free(condition);
    }

    mk_list_foreach_safe(head, tmp, &ctx->rules) {
        rule = mk_list_entry(head, struct modify_rule, _head);
        rule_free(rule);
    }
}

static void helper_pack_string(struct filter_modify_ctx *ctx,
                               msgpack_packer *packer, const char *str,
                               int len)
{

    if (str == NULL) {
        flb_plg_error(ctx->ins, "helper_pack_string : NULL passed");
        msgpack_pack_nil(packer);
    }
    else {
        msgpack_pack_str(packer, len);
        msgpack_pack_str_body(packer, str, len);
    }
}

static int setup(struct filter_modify_ctx *ctx,
                 struct flb_filter_instance *f_ins, struct flb_config *config)
{
    struct mk_list *head;
    struct mk_list *split;
    struct flb_kv *kv;
    struct flb_split_entry *sentry;
    struct modify_rule *rule = NULL;
    struct modify_condition *condition;

    int list_size;

    // Split list
    // - Arg 1 is condition?
    // --> Setup Condition
    //   - Malloc Condition
    //   - Switch list size
    // --> Setup Rule
    //   - Malloc Rule
    //   - Switch list size

    if (flb_filter_config_map_set(f_ins, ctx) < 0) {
        flb_errno();
        flb_plg_error(f_ins, "configuration error");
        return -1;
    }

    mk_list_foreach(head, &f_ins->properties) {
        kv = mk_list_entry(head, struct flb_kv, _head);

        split = flb_utils_split_quoted(kv->val, ' ', 3);
        list_size = mk_list_size(split);

        // Conditions are,
        // CONDITION CONDITIONTYPE VAL_A VAL_B

        if (list_size == 0 || list_size > 3) {
            flb_plg_error(ctx->ins, "Invalid config for %s", kv->key);
            teardown(ctx);
            flb_utils_split_free(split);
            return -1;
        }
        else if (strcasecmp(kv->key, "condition") == 0) {

            //
            // Build a condition
            //

            condition = flb_calloc(1, sizeof(struct modify_condition));
            if (!condition) {
                flb_errno();
                flb_plg_error(ctx->ins, "Unable to allocate memory for "
                              "condition");
                teardown(ctx);
                flb_utils_split_free(split);
                return -1;
            }

            condition->a_is_regex = false;
            condition->b_is_regex = false;
            condition->ra_a = NULL;
            condition->raw_k = flb_strndup(kv->key, flb_sds_len(kv->key));
            if (condition->raw_k == NULL) {
                flb_errno();
                flb_plg_error(ctx->ins, "Unable to allocate memory for "
                              "condition->raw_k");
                teardown(ctx);
                condition_free(condition);
                flb_utils_split_free(split);
                return -1;
            }
            condition->raw_v = flb_strndup(kv->val, flb_sds_len(kv->val));
            if (condition->raw_v == NULL) {
                flb_errno();
                flb_plg_error(ctx->ins, "Unable to allocate memory for "
                              "condition->raw_v");
                teardown(ctx);
                condition_free(condition);
                flb_utils_split_free(split);
                return -1;
            }

            sentry =
                mk_list_entry_first(split, struct flb_split_entry, _head);

            if (strcasecmp(sentry->value, "key_exists") == 0) {
                condition->conditiontype = KEY_EXISTS;
            }
            else if (strcasecmp(sentry->value, "key_does_not_exist") == 0) {
                condition->conditiontype = KEY_DOES_NOT_EXIST;
            }
            else if (strcasecmp(sentry->value, "a_key_matches") == 0) {
                condition->conditiontype = A_KEY_MATCHES;
                condition->a_is_regex = true;
            }
            else if (strcasecmp(sentry->value, "no_key_matches") == 0) {
                condition->conditiontype = NO_KEY_MATCHES;
                condition->a_is_regex = true;
            }
            else if (strcasecmp(sentry->value, "key_value_equals") == 0) {
                condition->conditiontype = KEY_VALUE_EQUALS;
            }
            else if (strcasecmp(sentry->value, "key_value_does_not_equal") ==
                     0) {
                condition->conditiontype = KEY_VALUE_DOES_NOT_EQUAL;
            }
            else if (strcasecmp(sentry->value, "key_value_matches") == 0) {
                condition->conditiontype = KEY_VALUE_MATCHES;
                condition->b_is_regex = true;
            }
            else if (strcasecmp(sentry->value, "key_value_does_not_match") ==
                     0) {
                condition->conditiontype = KEY_VALUE_DOES_NOT_MATCH;
                condition->b_is_regex = true;
            }
            else if (strcasecmp
                     (sentry->value,
                      "matching_keys_have_matching_values") == 0) {
                condition->conditiontype = MATCHING_KEYS_HAVE_MATCHING_VALUES;
                condition->a_is_regex = true;
                condition->b_is_regex = true;
            }
            else if (strcasecmp
                     (sentry->value,
                      "matching_keys_do_not_have_matching_values") == 0) {
                condition->conditiontype =
                    MATCHING_KEYS_DO_NOT_HAVE_MATCHING_VALUES;
                condition->a_is_regex = true;
                condition->b_is_regex = true;
            }
            else {
                flb_plg_error(ctx->ins, "Invalid config for %s : %s",
                              kv->key, kv->val);
                teardown(ctx);
                condition_free(condition);
                flb_utils_split_free(split);
                return -1;
            }

            sentry =
                mk_list_entry_next(&sentry->_head, struct flb_split_entry,
                                   _head, split);
            condition->a = flb_sds_create_len(sentry->value, sentry->len);
            condition->a_len = sentry->len;
            condition->ra_a = flb_ra_create(condition->a, FLB_FALSE);
            if (list_size == 3) {
                sentry =
                    mk_list_entry_last(split, struct flb_split_entry, _head);
                condition->b = flb_strndup(sentry->value, sentry->len);
                if (condition->b == NULL) {
                    flb_errno();
                    flb_plg_error(ctx->ins, "Unable to allocate memory for "
                                  "condition->b");
                    teardown(ctx);
                    condition_free(condition);
                    flb_utils_split_free(split);
                    return -1;
                }
                condition->b_len = sentry->len;
            }
            else {
                condition->b = NULL;
                condition->b_len = 0;
            }

            if (condition->a_is_regex) {
                if (condition->a_len < 1) {
                    flb_plg_error(ctx->ins, "Unable to create regex for "
                                  "condition %s %s",
                                  condition->raw_k, condition->raw_v);
                    teardown(ctx);
                    condition_free(condition);
                    flb_utils_split_free(split);
                    return -1;
                }
                else {
                    flb_plg_debug(ctx->ins, "Creating regex for condition A : "
                                  "%s %s : %s",
                                  condition->raw_k, condition->raw_v,
                                  condition->a);
                    condition->a_regex =
                        flb_regex_create(condition->a);
                }
            }

            if (condition->b_is_regex) {
                if (condition->b_len < 1) {
                    flb_plg_error(ctx->ins, "Unable to create regex "
                                  "for condition %s %s",
                                  condition->raw_k, condition->raw_v);
                    teardown(ctx);
                    condition_free(condition);
                    flb_utils_split_free(split);
                    return -1;
                }
                else {
                    flb_plg_debug(ctx->ins, "Creating regex for condition B : %s "
                                  "%s : %s",
                                  condition->raw_k, condition->raw_v, condition->b);
                    condition->b_regex =
                        flb_regex_create(condition->b);
                }
            }

            flb_utils_split_free(split);

            mk_list_add(&condition->_head, &ctx->conditions);
            ctx->conditions_cnt++;
        }
        else {

            //
            // Build a rule
            //

            rule = flb_calloc(1, sizeof(struct modify_rule));
            if (!rule) {
                flb_plg_error(ctx->ins, "Unable to allocate memory for rule");
                teardown(ctx);
                flb_utils_split_free(split);
                return -1;
            }

            rule->key_is_regex = false;
            rule->val_is_regex = false;
            rule->raw_k = flb_strndup(kv->key, flb_sds_len(kv->key));
            if (rule->raw_k == NULL) {
                flb_errno();
                flb_plg_error(ctx->ins, "Unable to allocate memory for rule->raw_k");
                teardown(ctx);
                rule_free(rule);
                flb_utils_split_free(split);
                return -1;
            }
            rule->raw_v = flb_strndup(kv->val, flb_sds_len(kv->val));
            if (rule->raw_v == NULL) {
                flb_errno();
                flb_plg_error(ctx->ins, "Unable to allocate memory for rule->raw_v");
                teardown(ctx);
                rule_free(rule);
                flb_utils_split_free(split);
                return -1;
            }

            sentry =
                mk_list_entry_first(split, struct flb_split_entry, _head);
            rule->key = flb_strndup(sentry->value, sentry->len);
            if (rule->key == NULL) {
                flb_errno();
                flb_plg_error(ctx->ins, "Unable to allocate memory for rule->key");
                teardown(ctx);
                rule_free(rule);
                flb_utils_split_free(split);
                return -1;
            }
            rule->key_len = sentry->len;

            sentry = mk_list_entry_last(split, struct flb_split_entry, _head);
            rule->val = flb_strndup(sentry->value, sentry->len);
            if (rule->val == NULL) {
                flb_errno();
                flb_plg_error(ctx->ins, "Unable to allocate memory for rule->val");
                teardown(ctx);
                rule_free(rule);
                flb_utils_split_free(split);
                return -1;
            }
            rule->val_len = sentry->len;

            flb_utils_split_free(split);

            if (list_size == 1) {
                if (strcasecmp(kv->key, "remove") == 0) {
                    rule->ruletype = REMOVE;
                }
                else if (strcasecmp(kv->key, "remove_wildcard") == 0) {
                    rule->ruletype = REMOVE_WILDCARD;
                }
                else if (strcasecmp(kv->key, "remove_regex") == 0) {
                    rule->ruletype = REMOVE_REGEX;
                    rule->key_is_regex = true;
                }
                else if (strcasecmp(kv->key, "move_to_start") == 0) {
                    rule->ruletype = MOVE_TO_START;
                }
                else if (strcasecmp(kv->key, "move_to_end") == 0) {
                    rule->ruletype = MOVE_TO_END;
                }
                else {
                    flb_plg_error(ctx->ins, "Invalid operation %s : %s in "
                                  "configuration", kv->key, kv->val);
                    teardown(ctx);
                    rule_free(rule);
                    return -1;
                }
            }
            else if (list_size == 2) {
                if (strcasecmp(kv->key, "rename") == 0) {
                    rule->ruletype = RENAME;
                }
                else if (strcasecmp(kv->key, "hard_rename") == 0) {
                    rule->ruletype = HARD_RENAME;
                }
                else if (strcasecmp(kv->key, "add") == 0) {
                    rule->ruletype = ADD;
                }
                else if (strcasecmp(kv->key, "add_if_not_present") == 0) {
                    flb_plg_info(ctx->ins, "DEPRECATED : Operation "
                                 "'add_if_not_present' has been replaced "
                                 "by 'add'.");
                    rule->ruletype = ADD;
                }
                else if (strcasecmp(kv->key, "set") == 0) {
                    rule->ruletype = SET;
                }
                else if (strcasecmp(kv->key, "copy") == 0) {
                    rule->ruletype = COPY;
                }
                else if (strcasecmp(kv->key, "hard_copy") == 0) {
                    rule->ruletype = HARD_COPY;
                }
                else {
                    flb_plg_error(ctx->ins, "Invalid operation %s : %s in "
                                  "configuration", kv->key, kv->val);
                    teardown(ctx);
                    rule_free(rule);
                    return -1;
                }
            }

            if (rule->key_is_regex && rule->key_len == 0) {
                flb_plg_error(ctx->ins, "Unable to create regex for rule %s %s",
                              rule->raw_k, rule->raw_v);
                teardown(ctx);
                rule_free(rule);
                return -1;
            }
            else {
                rule->key_regex =
                    flb_regex_create(rule->key);
                if (rule->key_regex == NULL) {
                    flb_plg_error(ctx->ins, "Unable to create regex(key) from %s",
                                  rule->key);
                    teardown(ctx);
                    rule_free(rule);
                    return -1;
                }
            }

            if (rule->val_is_regex && rule->val_len == 0) {
                flb_plg_error(ctx->ins, "Unable to create regex for rule %s %s",
                              rule->raw_k, rule->raw_v);
                teardown(ctx);
                rule_free(rule);
                return -1;
            }
            else {
                rule->val_regex =
                    flb_regex_create(rule->val);
                if (rule->val_regex == NULL) {
                    flb_plg_error(ctx->ins, "Unable to create regex(val) from %s",
                                  rule->val);
                    teardown(ctx);
                    rule_free(rule);
                    return -1;
                }
            }

            mk_list_add(&rule->_head, &ctx->rules);
            ctx->rules_cnt++;
        }

    }

    flb_plg_debug(ctx->ins, "Initialized modify filter with %d conditions "
                  "and %d rules",
                  ctx->conditions_cnt, ctx->rules_cnt);
    return 0;
}


/* Regex matchers */
static inline bool helper_msgpack_object_matches_regex(msgpack_object * obj,
                                                       struct flb_regex
                                                       *regex)
{
    int len;
    const char *key;

    if (obj->type == MSGPACK_OBJECT_BIN) {
        return false;
    }
    else if (obj->type == MSGPACK_OBJECT_STR) {
        key = obj->via.str.ptr;
        len = obj->via.str.size;
    }
    else if (obj->type == MSGPACK_OBJECT_BOOLEAN) {
        if (obj->via.boolean) {
            key = "true";
            len = 4;
        }
        else {
            key = "false";
            len = 5;
        }
    }
    else {
        return false;
    }

    return flb_regex_match(regex, (unsigned char *) key, len) > 0;
}

static inline bool kv_key_matches_regex(msgpack_object_kv * kv,
                                        struct flb_regex *regex)
{
    return helper_msgpack_object_matches_regex(&kv->key, regex);
}

static inline bool kv_val_matches_regex(msgpack_object_kv * kv,
                                        struct flb_regex *regex)
{
    return helper_msgpack_object_matches_regex(&kv->val, regex);
}

static inline bool kv_key_matches_regex_rule_key(msgpack_object_kv * kv,
                                                 struct modify_rule *rule)
{
    return kv_key_matches_regex(kv, rule->key_regex);
}

static inline bool kv_key_does_not_match_regex_rule_key(msgpack_object_kv *
                                                        kv,
                                                        struct modify_rule
                                                        *rule)
{
    return !kv_key_matches_regex_rule_key(kv, rule);
}

static inline int map_count_keys_matching_regex(msgpack_object * map,
                                                struct flb_regex *regex)
{
    int i;
    int count = 0;

    for (i = 0; i < map->via.map.size; i++) {
        if (kv_key_matches_regex(&map->via.map.ptr[i], regex)) {
            count++;
        }
    }
    return count;
}


/*
 * Wildcard matchers
 */

static inline bool helper_msgpack_object_matches_wildcard(msgpack_object *
                                                          obj, char *str,
                                                          int len)
{
    const char *key;

    if (obj->type == MSGPACK_OBJECT_BIN) {
        key = obj->via.bin.ptr;
    }
    else if (obj->type == MSGPACK_OBJECT_STR) {
        key = obj->via.str.ptr;
    }
    else {
        return false;
    }

    return (strncmp(str, key, len) == 0);
}

static inline bool kv_key_matches_wildcard(msgpack_object_kv * kv,
                                           char *str, int len)
{
    return helper_msgpack_object_matches_wildcard(&kv->key, str, len);
}

static inline bool kv_key_matches_wildcard_rule_key(msgpack_object_kv * kv,
                                                    struct modify_rule *rule)
{
    return kv_key_matches_wildcard(kv, rule->key, rule->key_len);
}

static inline bool kv_key_does_not_match_wildcard_rule_key(msgpack_object_kv *
                                                           kv,
                                                           struct modify_rule
                                                           *rule)
{
    return !kv_key_matches_wildcard_rule_key(kv, rule);
}

static inline int map_count_keys_matching_wildcard(msgpack_object * map,
                                                   char *str, int len)
{
    int i;
    int count = 0;

    for (i = 0; i < map->via.map.size; i++) {
        if (kv_key_matches_wildcard(&map->via.map.ptr[i], str, len)) {
            count++;
        }
    }
    return count;
}

//
// String matchers
//

static inline bool helper_msgpack_object_matches_str(msgpack_object * obj,
                                                     char *str, int len)
{

    const char *key;
    int klen;

    if (obj->type == MSGPACK_OBJECT_BIN) {
        key = obj->via.bin.ptr;
        klen = obj->via.bin.size;
    }
    else if (obj->type == MSGPACK_OBJECT_STR) {
        key = obj->via.str.ptr;
        klen = obj->via.str.size;
    }
    else {
        return false;
    }

    return ((len == klen) && (strncmp(str, key, klen) == 0)
        );
}

static inline bool kv_key_matches_str(msgpack_object_kv * kv,
                                      char *str, int len)
{
    return helper_msgpack_object_matches_str(&kv->key, str, len);
}

static inline bool kv_key_matches_str_rule_key(msgpack_object_kv * kv,
                                               struct modify_rule *rule)
{
    return kv_key_matches_str(kv, rule->key, rule->key_len);
}

static inline bool kv_key_does_not_match_str_rule_key(msgpack_object_kv * kv,
                                                      struct modify_rule
                                                      *rule)
{
    return !kv_key_matches_str_rule_key(kv, rule);
}

static inline bool kv_key_matches_str_rule_val(msgpack_object_kv * kv,
                                               struct modify_rule *rule)
{
    return kv_key_matches_str(kv, rule->val, rule->val_len);
}

static inline int map_count_keys_matching_str(msgpack_object * map,
                                              char *str, int len)
{
    int i;
    int count = 0;

    for (i = 0; i < map->via.map.size; i++) {
        if (kv_key_matches_str(&map->via.map.ptr[i], str, len)) {
            count++;
        }
    }
    return count;
}

static inline void map_pack_each(msgpack_packer * packer,
                                 msgpack_object * map)
{
    int i;

    for (i = 0; i < map->via.map.size; i++) {
        msgpack_pack_object(packer, map->via.map.ptr[i].key);
        msgpack_pack_object(packer, map->via.map.ptr[i].val);
    }
}

static inline void map_pack_each_fn(msgpack_packer * packer,
                                    msgpack_object * map,
                                    struct modify_rule *rule,
                                    bool(*f) (msgpack_object_kv * kv,
                                              struct modify_rule * rule)
    )
{
    int i;

    for (i = 0; i < map->via.map.size; i++) {
        if ((*f) (&map->via.map.ptr[i], rule)) {
            msgpack_pack_object(packer, map->via.map.ptr[i].key);
            msgpack_pack_object(packer, map->via.map.ptr[i].val);
        }
    }
}

static inline bool evaluate_condition_KEY_EXISTS(msgpack_object * map,
                                                 struct modify_condition
                                                 *condition)
{
    msgpack_object *skey = NULL;
    msgpack_object *okey = NULL;
    msgpack_object *oval = NULL;

    flb_ra_get_kv_pair(condition->ra_a, *map, &skey, &okey, &oval);
    if (skey == NULL || okey == NULL || oval == NULL) {
        return false;
    }
    return true;
}

static inline bool evaluate_condition_KEY_DOES_NOT_EXIST(msgpack_object * map,
                                                         struct
                                                         modify_condition
                                                         *condition)
{
    return !evaluate_condition_KEY_EXISTS(map, condition);
}

static inline bool evaluate_condition_A_KEY_MATCHES(msgpack_object * map,
                                                    struct modify_condition
                                                    *condition)
{
    return (map_count_keys_matching_regex(map, condition->a_regex) > 0);
}

static inline bool evaluate_condition_NO_KEY_MATCHES(msgpack_object * map,
                                                     struct
                                                     modify_condition
                                                     *condition)
{
    return !evaluate_condition_A_KEY_MATCHES(map, condition);
}

static inline bool evaluate_condition_KEY_VALUE_EQUALS(struct filter_modify_ctx *ctx,
                                                       msgpack_object * map,
                                                       struct
                                                       modify_condition
                                                       *condition)
{
    msgpack_object *skey = NULL;
    msgpack_object *okey = NULL;
    msgpack_object *oval = NULL;
    bool ret = false;

    flb_ra_get_kv_pair(condition->ra_a, *map, &skey, &okey, &oval);
    if (skey == NULL || okey == NULL || oval == NULL) {
        return false;
    }
    ret = helper_msgpack_object_matches_str(oval, condition->b, condition->b_len);
    if (ret) {
        flb_plg_debug(ctx->ins, "Match for condition KEY_VALUE_EQUALS %s",
                      condition->b);
    }
    return ret;
}

static inline
bool evaluate_condition_KEY_VALUE_DOES_NOT_EQUAL(struct filter_modify_ctx *ctx,
                                                 msgpack_object
                                                 *map,
                                                 struct
                                                 modify_condition
                                                 *condition)
{
    if (!evaluate_condition_KEY_EXISTS(map, condition)) {
        return false;
    }
    return !evaluate_condition_KEY_VALUE_EQUALS(ctx, map, condition);
}

static inline bool evaluate_condition_KEY_VALUE_MATCHES(struct filter_modify_ctx *ctx,
                                                        msgpack_object *map,
                                                        struct
                                                        modify_condition
                                                        *condition)
{
    msgpack_object *skey = NULL;
    msgpack_object *okey = NULL;
    msgpack_object *oval = NULL;
    bool ret = false;

    flb_ra_get_kv_pair(condition->ra_a, *map, &skey, &okey, &oval);
    if (skey == NULL || okey == NULL || oval == NULL) {
        return false;
    }
    ret = helper_msgpack_object_matches_regex(oval, condition->b_regex);
    if (ret) {
        flb_plg_debug(ctx->ins, "Match for condition KEY_VALUE_MATCHES "
                      "%s", condition->b);
    }
    return ret;
}

static inline
bool evaluate_condition_KEY_VALUE_DOES_NOT_MATCH(struct filter_modify_ctx *ctx,
                                                 msgpack_object
                                                 * map,
                                                 struct
                                                 modify_condition
                                                 *condition)
{
    if (!evaluate_condition_KEY_EXISTS(map, condition)) {
        return false;
    }
    return !evaluate_condition_KEY_VALUE_MATCHES(ctx, map, condition);
}

static inline bool
evaluate_condition_MATCHING_KEYS_HAVE_MATCHING_VALUES(struct filter_modify_ctx *ctx,
                                                      msgpack_object *map,
                                                      struct modify_condition
                                                      *condition)
{
    int i;
    bool match = true;
    msgpack_object_kv *kv;

    for (i = 0; i < map->via.map.size; i++) {
        kv = &map->via.map.ptr[i];
        if (kv_key_matches_regex(kv, condition->a_regex)) {
            if (!kv_val_matches_regex(kv, condition->b_regex)) {
                flb_plg_debug(ctx->ins, "Match MISSED for condition "
                              "MATCHING_KEYS_HAVE_MATCHING_VALUES %s",
                              condition->b);
                match = false;
                break;
            }
        }
    }
    return match;
}

static inline bool
evaluate_condition_MATCHING_KEYS_DO_NOT_HAVE_MATCHING_VALUES(struct filter_modify_ctx *ctx,
                                                             msgpack_object *
                                                             map,
                                                             struct
                                                             modify_condition
                                                             *condition)
{
    return !evaluate_condition_MATCHING_KEYS_HAVE_MATCHING_VALUES(ctx,
                                                                  map,
                                                                  condition);
}

static inline bool evaluate_condition(struct filter_modify_ctx *ctx,
                                      msgpack_object * map,
                                      struct modify_condition *condition)
{
    switch (condition->conditiontype) {
    case KEY_EXISTS:
        return evaluate_condition_KEY_EXISTS(map, condition);
    case KEY_DOES_NOT_EXIST:
        return evaluate_condition_KEY_DOES_NOT_EXIST(map, condition);
    case A_KEY_MATCHES:
        return evaluate_condition_A_KEY_MATCHES(map, condition);
    case NO_KEY_MATCHES:
        return evaluate_condition_NO_KEY_MATCHES(map, condition);
    case KEY_VALUE_EQUALS:
        return evaluate_condition_KEY_VALUE_EQUALS(ctx, map, condition);
    case KEY_VALUE_DOES_NOT_EQUAL:
        return evaluate_condition_KEY_VALUE_DOES_NOT_EQUAL(ctx, map, condition);
    case KEY_VALUE_MATCHES:
        return evaluate_condition_KEY_VALUE_MATCHES(ctx, map, condition);
    case KEY_VALUE_DOES_NOT_MATCH:
        return evaluate_condition_KEY_VALUE_DOES_NOT_MATCH(ctx, map, condition);
    case MATCHING_KEYS_HAVE_MATCHING_VALUES:
        return evaluate_condition_MATCHING_KEYS_HAVE_MATCHING_VALUES(ctx,
                                                                     map,
                                                                     condition);
    case MATCHING_KEYS_DO_NOT_HAVE_MATCHING_VALUES:
        return
            evaluate_condition_MATCHING_KEYS_DO_NOT_HAVE_MATCHING_VALUES(ctx,
                                                                         map,
                                                                         condition);
    default:
        flb_plg_warn(ctx->ins, "Unknown conditiontype for condition %s : %s, "
                     "assuming result FAILED TO MEET CONDITION",
                     condition->raw_k, condition->raw_v);
    }
    return false;
}

static inline bool evaluate_conditions(msgpack_object * map,
                                       struct filter_modify_ctx *ctx)
{
    bool ok = true;

    struct mk_list *tmp;
    struct mk_list *head;
    struct modify_condition *condition;

    mk_list_foreach_safe(head, tmp, &ctx->conditions) {
        condition = mk_list_entry(head, struct modify_condition, _head);
        if (!evaluate_condition(ctx, map, condition)) {
            flb_plg_debug(ctx->ins, "Condition not met : %s",
                          condition->raw_v);
            ok = false;
        }
    }

    return ok;
}

static inline int apply_rule_RENAME(struct filter_modify_ctx *ctx,
                                    msgpack_packer *packer,
                                    msgpack_object *map,
                                    struct modify_rule *rule)
{
    int i;

    int match_keys =
        map_count_keys_matching_str(map, rule->key, rule->key_len);
    int conflict_keys =
        map_count_keys_matching_str(map, rule->val, rule->val_len);

    if (match_keys == 0) {
        flb_plg_debug(ctx->ins, "Rule RENAME %s TO %s : No keys matching %s "
                      "found, not applying rule",
                      rule->key, rule->val, rule->key);
        return FLB_FILTER_NOTOUCH;
    }
    else if (conflict_keys > 0) {
        flb_plg_debug(ctx->ins, "Rule RENAME %s TO %s : Existing key %s found, "
                      "not applying rule",
                      rule->key, rule->val, rule->key);
        return FLB_FILTER_NOTOUCH;
    }
    else {
        msgpack_pack_map(packer, map->via.map.size);
        for (i = 0; i < map->via.map.size; i++) {
            if (kv_key_matches_str_rule_key(&map->via.map.ptr[i], rule)) {
                helper_pack_string(ctx, packer, rule->val, rule->val_len);
            }
            else {
                msgpack_pack_object(packer, map->via.map.ptr[i].key);
            }
            msgpack_pack_object(packer, map->via.map.ptr[i].val);
        }
        return FLB_FILTER_MODIFIED;
    }
}

static inline int apply_rule_HARD_RENAME(struct filter_modify_ctx *ctx,
                                         msgpack_packer *packer,
                                         msgpack_object *map,
                                         struct modify_rule *rule)
{
    int i;

    int match_keys =
        map_count_keys_matching_str(map, rule->key, rule->key_len);
    int conflict_keys =
        map_count_keys_matching_str(map, rule->val, rule->val_len);
    msgpack_object_kv *kv;

    if (match_keys == 0) {
        flb_plg_debug(ctx->ins, "Rule HARD_RENAME %s TO %s : No keys matching "
                      "%s found, not applying rule",
                      rule->key, rule->val, rule->key);
        return FLB_FILTER_NOTOUCH;
    }
    else if (conflict_keys == 0) {
        msgpack_pack_map(packer, map->via.map.size);
        for (i = 0; i < map->via.map.size; i++) {
            kv = &map->via.map.ptr[i];
            if (kv_key_matches_str_rule_key(kv, rule)) {
                helper_pack_string(ctx, packer, rule->val, rule->val_len);
            }
            else {
                msgpack_pack_object(packer, kv->key);
            }
            msgpack_pack_object(packer, kv->val);
        }
        return FLB_FILTER_MODIFIED;
    }
    else {
        msgpack_pack_map(packer, map->via.map.size - conflict_keys);

        for (i = 0; i < map->via.map.size; i++) {
            kv = &map->via.map.ptr[i];
            // If this kv->key matches rule->val it's a conflict source key and
            // will be skipped
            if (!kv_key_matches_str_rule_val(kv, rule)) {
                if (kv_key_matches_str_rule_key(kv, rule)) {
                    helper_pack_string(ctx, packer, rule->val, rule->val_len);
                }
                else {
                    msgpack_pack_object(packer, kv->key);
                }

                msgpack_pack_object(packer, kv->val);
            }
        }
        return FLB_FILTER_MODIFIED;
    }
}

static inline int apply_rule_COPY(struct filter_modify_ctx *ctx,
                                  msgpack_packer *packer,
                                  msgpack_object *map,
                                  struct modify_rule *rule)
{
    int match_keys =
        map_count_keys_matching_str(map, rule->key, rule->key_len);
    int conflict_keys =
        map_count_keys_matching_str(map, rule->val, rule->val_len);
    int i;
    msgpack_object_kv *kv;

    if (match_keys < 1) {
        flb_plg_debug(ctx->ins, "Rule COPY %s TO %s : No keys matching %s "
                      "found, not applying rule",
                      rule->key, rule->val, rule->key);
        return FLB_FILTER_NOTOUCH;
    }
    else if (match_keys > 1) {
        flb_plg_debug(ctx->ins, "Rule COPY %s TO %s : Multiple keys matching "
                      "%s found, not applying rule",
                      rule->key, rule->val, rule->key);
        return FLB_FILTER_NOTOUCH;
    }
    else if (conflict_keys > 0) {
        flb_plg_debug(ctx->ins, "Rule COPY %s TO %s : Existing keys matching "
                      "target %s found, not applying rule",
                      rule->key, rule->val, rule->key);
        return FLB_FILTER_NOTOUCH;
    }
    else {
        msgpack_pack_map(packer, map->via.map.size + 1);
        for (i = 0; i < map->via.map.size; i++) {
            kv = &map->via.map.ptr[i];

            msgpack_pack_object(packer, kv->key);
            msgpack_pack_object(packer, kv->val);

            if (kv_key_matches_str_rule_key(kv, rule)) {
                helper_pack_string(ctx, packer, rule->val, rule->val_len);
                msgpack_pack_object(packer, kv->val);
            }
        }
        return FLB_FILTER_MODIFIED;
    }
}

static inline int apply_rule_HARD_COPY(struct filter_modify_ctx *ctx,
                                       msgpack_packer *packer,
                                       msgpack_object *map,
                                       struct modify_rule *rule)
{
    int i;

    int match_keys =
        map_count_keys_matching_str(map, rule->key, rule->key_len);
    int conflict_keys =
        map_count_keys_matching_str(map, rule->val, rule->val_len);
    msgpack_object_kv *kv;

    if (match_keys < 1) {
        flb_plg_debug(ctx->ins, "Rule HARD_COPY %s TO %s : No keys matching %s "
                      "found, not applying rule",
                      rule->key, rule->val, rule->key);
        return FLB_FILTER_NOTOUCH;
    }
    else if (match_keys > 1) {
        flb_plg_warn(ctx->ins, "Rule HARD_COPY %s TO %s : Multiple keys "
                     "matching %s found, not applying rule",
                     rule->key, rule->val, rule->key);
        return FLB_FILTER_NOTOUCH;
    }
    else if (conflict_keys > 1) {
        flb_plg_warn(ctx->ins, "Rule HARD_COPY %s TO %s : Multiple target keys "
                     "matching %s found, not applying rule",
                     rule->key, rule->val, rule->val);
        return FLB_FILTER_NOTOUCH;
    }
    else if (conflict_keys == 0) {
        msgpack_pack_map(packer, map->via.map.size + 1);
        for (i = 0; i < map->via.map.size; i++) {
            kv = &map->via.map.ptr[i];
            msgpack_pack_object(packer, kv->key);
            msgpack_pack_object(packer, kv->val);

            // This is our copy
            if (kv_key_matches_str_rule_key(kv, rule)) {
                helper_pack_string(ctx, packer, rule->val, rule->val_len);
                msgpack_pack_object(packer, kv->val);
            }
        }
        return FLB_FILTER_MODIFIED;
    }
    else {
        msgpack_pack_map(packer, map->via.map.size);

        for (i = 0; i < map->via.map.size; i++) {
            kv = &map->via.map.ptr[i];

            // Skip the conflict key, we will create a new one
            if (!kv_key_matches_str_rule_val(kv, rule)) {
                msgpack_pack_object(packer, kv->key);
                msgpack_pack_object(packer, kv->val);

                // This is our copy
                if (kv_key_matches_str_rule_key(kv, rule)) {
                    helper_pack_string(ctx, packer, rule->val, rule->val_len);
                    msgpack_pack_object(packer, kv->val);
                }
            }
        }

        return FLB_FILTER_MODIFIED;
    }
}

static inline int apply_rule_ADD(struct filter_modify_ctx *ctx,
                                 msgpack_packer *packer,
                                 msgpack_object *map,
                                 struct modify_rule *rule)
{
    if (map_count_keys_matching_str(map, rule->key, rule->key_len) == 0) {
        msgpack_pack_map(packer, map->via.map.size + 1);
        map_pack_each(packer, map);
        helper_pack_string(ctx, packer, rule->key, rule->key_len);
        helper_pack_string(ctx, packer, rule->val, rule->val_len);
        return FLB_FILTER_MODIFIED;
    }
    else {
        flb_plg_debug(ctx->ins, "Rule ADD %s : this key already exists, "
                      "skipping", rule->key);
        return FLB_FILTER_NOTOUCH;
    }
}

static inline int apply_rule_SET(struct filter_modify_ctx *ctx,
                                 msgpack_packer * packer,
                                 msgpack_object * map,
                                 struct modify_rule *rule)
{
    int matches = map_count_keys_matching_str(map, rule->key, rule->key_len);

    msgpack_pack_map(packer, map->via.map.size - matches + 1);

    if (matches == 0) {
        map_pack_each(packer, map);
        helper_pack_string(ctx, packer, rule->key, rule->key_len);
        helper_pack_string(ctx, packer, rule->val, rule->val_len);
    }
    else {
        map_pack_each_fn(packer, map, rule,
                         kv_key_does_not_match_str_rule_key);
        helper_pack_string(ctx, packer, rule->key, rule->key_len);
        helper_pack_string(ctx, packer, rule->val, rule->val_len);
    }

    return FLB_FILTER_MODIFIED;
}

static inline int apply_rule_REMOVE(msgpack_packer *packer,
                                    msgpack_object *map,
                                    struct modify_rule *rule)
{
    int matches = map_count_keys_matching_str(map, rule->key, rule->key_len);

    if (matches == 0) {
        return FLB_FILTER_NOTOUCH;
    }
    else {
        msgpack_pack_map(packer, map->via.map.size - matches);
        map_pack_each_fn(packer, map, rule,
                         kv_key_does_not_match_str_rule_key);
        return FLB_FILTER_MODIFIED;
    }
}

static inline int apply_rule_REMOVE_WILDCARD(msgpack_packer * packer,
                                             msgpack_object * map,
                                             struct modify_rule *rule)
{
    int matches =
        map_count_keys_matching_wildcard(map, rule->key, rule->key_len);

    if (matches == 0) {
        return FLB_FILTER_NOTOUCH;
    }
    else {
        msgpack_pack_map(packer, map->via.map.size - matches);
        map_pack_each_fn(packer, map, rule,
                         kv_key_does_not_match_wildcard_rule_key);
        return FLB_FILTER_MODIFIED;
    }
}

static inline int apply_rule_REMOVE_REGEX(msgpack_packer * packer,
                                          msgpack_object * map,
                                          struct modify_rule *rule)
{
    int matches = map_count_keys_matching_regex(map, rule->key_regex);

    if (matches == 0) {
        return FLB_FILTER_NOTOUCH;
    }
    else {
        msgpack_pack_map(packer, map->via.map.size - matches);
        map_pack_each_fn(packer, map, rule,
                         kv_key_does_not_match_regex_rule_key);
        return FLB_FILTER_MODIFIED;
    }
}

static inline int apply_rule_MOVE_TO_END(struct filter_modify_ctx *ctx,
                                         msgpack_packer *packer,
                                         msgpack_object *map,
                                         struct modify_rule *rule)
{

    int match_keys =
        map_count_keys_matching_wildcard(map, rule->key, rule->key_len);

    if (match_keys == 0) {
        return FLB_FILTER_NOTOUCH;
    }
    else {
        msgpack_pack_map(packer, map->via.map.size);
        map_pack_each_fn(packer, map, rule,
                         kv_key_does_not_match_wildcard_rule_key);
        map_pack_each_fn(packer, map, rule,
                         kv_key_matches_wildcard_rule_key);
        return FLB_FILTER_MODIFIED;
    }
}

static inline int apply_rule_MOVE_TO_START(struct filter_modify_ctx *ctx,
                                           msgpack_packer *packer,
                                           msgpack_object *map,
                                           struct modify_rule *rule)
{

    int match_keys =
        map_count_keys_matching_wildcard(map, rule->key, rule->key_len);

    if (match_keys == 0) {
        return FLB_FILTER_NOTOUCH;
    }
    else {
        msgpack_pack_map(packer, map->via.map.size);
        map_pack_each_fn(packer, map, rule,
                         kv_key_matches_wildcard_rule_key);
        map_pack_each_fn(packer, map, rule,
                         kv_key_does_not_match_wildcard_rule_key);
        return FLB_FILTER_MODIFIED;
    }
}

static inline int apply_modifying_rule(struct filter_modify_ctx *ctx,
                                       msgpack_packer *packer,
                                       msgpack_object *map,
                                       struct modify_rule *rule)
{
    switch (rule->ruletype) {
    case RENAME:
        return apply_rule_RENAME(ctx, packer, map, rule);
    case HARD_RENAME:
        return apply_rule_HARD_RENAME(ctx, packer, map, rule);
    case ADD:
        return apply_rule_ADD(ctx, packer, map, rule);
    case SET:
        return apply_rule_SET(ctx, packer, map, rule);
    case REMOVE:
        return apply_rule_REMOVE(packer, map, rule);
    case REMOVE_WILDCARD:
        return apply_rule_REMOVE_WILDCARD(packer, map, rule);
    case REMOVE_REGEX:
        return apply_rule_REMOVE_REGEX(packer, map, rule);
    case COPY:
        return apply_rule_COPY(ctx, packer, map, rule);
    case HARD_COPY:
        return apply_rule_HARD_COPY(ctx, packer, map, rule);
    case MOVE_TO_START:
        return apply_rule_MOVE_TO_START(ctx, packer, map, rule);
    case MOVE_TO_END:
        return apply_rule_MOVE_TO_END(ctx, packer, map, rule);
    default:
        flb_plg_warn(ctx->ins, "Unknown ruletype for rule with key %s, ignoring",
                     rule->key);
    }
    return FLB_FILTER_NOTOUCH;
}



static inline int apply_modifying_rules(
                    struct flb_log_event_encoder *log_encoder,
                    struct flb_log_event *log_event,
                    struct filter_modify_ctx *ctx)
{
    int ret;
    int records_in;
    msgpack_object map;
    struct modify_rule *rule;
    msgpack_sbuffer sbuffer;
    msgpack_packer in_packer;
    msgpack_unpacker unpacker;
    msgpack_unpacked unpacked;
    int initial_buffer_size = 1024 * 8;
    int new_buffer_size = 0;
    struct mk_list *tmp;
    struct mk_list *head;
    bool has_modifications = false;

    map = *log_event->body;
    records_in = map.via.map.size;

    if (!evaluate_conditions(&map, ctx)) {
        flb_plg_debug(ctx->ins, "Conditions not met, not touching record");
        return 0;
    }

    msgpack_sbuffer_init(&sbuffer);
    msgpack_packer_init(&in_packer, &sbuffer, msgpack_sbuffer_write);
    msgpack_unpacked_init(&unpacked);

    if (!msgpack_unpacker_init(&unpacker, initial_buffer_size)) {
        flb_plg_error(ctx->ins, "Unable to allocate memory for unpacker, aborting");
        return -1;
    }

    mk_list_foreach_safe(head, tmp, &ctx->rules) {
        rule = mk_list_entry(head, struct modify_rule, _head);

        msgpack_sbuffer_clear(&sbuffer);

        if (apply_modifying_rule(ctx, &in_packer, &map, rule) !=
            FLB_FILTER_NOTOUCH) {

            has_modifications = true;
            new_buffer_size = sbuffer.size * 2;

            if (msgpack_unpacker_buffer_capacity(&unpacker) < new_buffer_size) {
                if (!msgpack_unpacker_reserve_buffer
                    (&unpacker, new_buffer_size)) {
                    flb_plg_error(ctx->ins, "Unable to re-allocate memory for "
                                  "unpacker, aborting");
                    return -1;
                }
            }

            memcpy(msgpack_unpacker_buffer(&unpacker), sbuffer.data,
                   sbuffer.size);
            msgpack_unpacker_buffer_consumed(&unpacker, sbuffer.size);

            msgpack_unpacker_next(&unpacker, &unpacked);

            if (unpacked.data.type == MSGPACK_OBJECT_MAP) {
                map = unpacked.data;
            }
            else {
                flb_plg_error(ctx->ins, "Expected MSGPACK_MAP, this is not a "
                              "valid return value, skipping");
            }
        }
    }

    if (has_modifications) {
        ret = flb_log_event_encoder_begin_record(log_encoder);

        if (ret == FLB_EVENT_ENCODER_SUCCESS) {
            ret = flb_log_event_encoder_set_timestamp(
                    log_encoder, &log_event->timestamp);
        }

        if (ret == FLB_EVENT_ENCODER_SUCCESS) {
            ret = flb_log_event_encoder_set_metadata_from_msgpack_object(
                    log_encoder, log_event->metadata);
        }

        flb_plg_trace(ctx->ins, "Input map size %d elements, output map size "
                      "%d elements", records_in, map.via.map.size);

        if (ret == FLB_EVENT_ENCODER_SUCCESS) {
            ret = flb_log_event_encoder_set_body_from_msgpack_object(
                    log_encoder, &map);
        }

        if (ret == FLB_EVENT_ENCODER_SUCCESS) {
            ret = flb_log_event_encoder_commit_record(log_encoder);
        }

        if (ret != FLB_EVENT_ENCODER_SUCCESS) {
            flb_plg_error(ctx->ins, "log event encoding error : %d", ret);

            flb_log_event_encoder_rollback_record(log_encoder);

            has_modifications = FLB_FALSE;
        }
    }

    msgpack_unpacked_destroy(&unpacked);
    msgpack_unpacker_destroy(&unpacker);
    msgpack_sbuffer_destroy(&sbuffer);

    return has_modifications ? 1 : 0;

}

static int cb_modify_init(struct flb_filter_instance *f_ins,
                          struct flb_config *config, void *data)
{
    struct filter_modify_ctx *ctx;

    // Create context
    ctx = flb_malloc(sizeof(struct filter_modify_ctx));
    if (!ctx) {
        flb_errno();
        return -1;
    }
    mk_list_init(&ctx->conditions);
    mk_list_init(&ctx->rules);
    ctx->ins = f_ins;
    ctx->rules_cnt = 0;
    ctx->conditions_cnt = 0;

    if (setup(ctx, f_ins, config) < 0) {
        flb_free(ctx);
        return -1;
    }

    // Set context
    flb_filter_set_context(f_ins, ctx);
    return 0;
}

static int cb_modify_filter(const void *data, size_t bytes,
                            const char *tag, int tag_len,
                            void **out_buf, size_t * out_size,
                            struct flb_filter_instance *f_ins,
                            struct flb_input_instance *i_ins,
                            void *context, struct flb_config *config)
{
    struct flb_log_event_encoder log_encoder;
    struct flb_log_event_decoder log_decoder;
    struct flb_log_event log_event;
    struct filter_modify_ctx *ctx = context;
    int modifications = 0;
    int total_modifications = 0;
    int ret = FLB_FILTER_NOTOUCH;
    int dec_ret;
    int enc_ret;

    (void) f_ins;
    (void) i_ins;
    (void) config;

    dec_ret = flb_log_event_decoder_init(&log_decoder, (char *) data, bytes);
    if (dec_ret != FLB_EVENT_DECODER_SUCCESS) {
        flb_plg_error(ctx->ins,
                      "Log event decoder initialization error : %s",
                      flb_log_event_decoder_get_error_description(dec_ret));
        return FLB_FILTER_NOTOUCH;
    }

    enc_ret = flb_log_event_encoder_init(&log_encoder,
                                        FLB_LOG_EVENT_FORMAT_DEFAULT);
    if (enc_ret != FLB_EVENT_ENCODER_SUCCESS) {
        flb_plg_error(ctx->ins,
                      "Log event encoder initialization error : %s",
                      flb_log_event_encoder_get_error_description(enc_ret));
        flb_log_event_decoder_destroy(&log_decoder);
        return FLB_FILTER_NOTOUCH;
    }

    while ((dec_ret = flb_log_event_decoder_next(
                      &log_decoder,
                      &log_event)) == FLB_EVENT_DECODER_SUCCESS) {
        modifications =
            apply_modifying_rules(&log_encoder, &log_event, ctx);

        if (modifications == 0) {
            /* not matched, so copy original event. */
            enc_ret = flb_log_event_encoder_emit_raw_record(
                               &log_encoder,
                               log_decoder.record_base,
                               log_decoder.record_length);
        }

        total_modifications += modifications;
    }

    if (total_modifications <= 0) {
        ret = FLB_FILTER_NOTOUCH;
        goto cb_modify_filter_end;
    }

    dec_ret = flb_log_event_decoder_get_last_result(&log_decoder);
    if (dec_ret != FLB_EVENT_DECODER_SUCCESS) {
        flb_plg_error(ctx->ins,
                      "Log event decoder error : %s",
                      flb_log_event_decoder_get_error_description(dec_ret));
        ret = FLB_FILTER_NOTOUCH;
        goto cb_modify_filter_end;
    }

    if (enc_ret != FLB_EVENT_ENCODER_SUCCESS) {
        flb_plg_error(ctx->ins,
                      "Log event encoder error : %s",
                      flb_log_event_encoder_get_error_description(enc_ret));

        ret = FLB_FILTER_NOTOUCH;
        goto cb_modify_filter_end;
    }

    *out_buf  = log_encoder.output_buffer;
    *out_size = log_encoder.output_length;

    ret = FLB_FILTER_MODIFIED;

    flb_log_event_encoder_claim_internal_buffer_ownership(&log_encoder);

 cb_modify_filter_end:
    flb_log_event_decoder_destroy(&log_decoder);
    flb_log_event_encoder_destroy(&log_encoder);

    return ret;
}

static int cb_modify_exit(void *data, struct flb_config *config)
{
    struct filter_modify_ctx *ctx = data;

    teardown(ctx);
    flb_free(ctx);
    return 0;
}

static struct flb_config_map config_map[] = {
    {
     FLB_CONFIG_MAP_STR, "Set", NULL,
     FLB_CONFIG_MAP_MULT, FLB_FALSE, 0,
     "Add a key/value pair with key KEY and value VALUE. "
     "If KEY already exists, this field is overwritten."
    },
    {
     FLB_CONFIG_MAP_STR, "Add", NULL,
     FLB_CONFIG_MAP_MULT, FLB_FALSE, 0,
     "Add a key/value pair with key KEY and value VALUE if KEY does not exist"
    },
    {
     FLB_CONFIG_MAP_STR, "Remove", NULL,
     FLB_CONFIG_MAP_MULT, FLB_FALSE, 0,
     "Remove a key/value pair with key KEY if it exists"
    },
    {
     FLB_CONFIG_MAP_STR, "Remove_wildcard", NULL,
     FLB_CONFIG_MAP_MULT, FLB_FALSE, 0,
     "Remove all key/value pairs with key matching wildcard KEY"
    },
    {
     FLB_CONFIG_MAP_STR, "Remove_regex", NULL,
     FLB_CONFIG_MAP_MULT, FLB_FALSE, 0,
     "Remove all key/value pairs with key matching regexp KEY"
    },
    {
     FLB_CONFIG_MAP_STR, "Move_To_Start", NULL,
     FLB_CONFIG_MAP_MULT, FLB_FALSE, 0,
     "Move key/value pairs with keys matching KEY to the start of the message"
    },
    {
     FLB_CONFIG_MAP_STR, "Move_To_End", NULL,
     FLB_CONFIG_MAP_MULT, FLB_FALSE, 0,
     "Move key/value pairs with keys matching KEY to the end of the message"
    },
    {
     FLB_CONFIG_MAP_STR, "Rename", NULL,
     FLB_CONFIG_MAP_MULT, FLB_FALSE, 0,
     "Rename a key/value pair with key KEY to RENAMED_KEY "
     "if KEY exists AND RENAMED_KEY does not exist"
    },
    {
     FLB_CONFIG_MAP_STR, "Hard_Rename", NULL,
     FLB_CONFIG_MAP_MULT, FLB_FALSE, 0,
     "Rename a key/value pair with key KEY to RENAMED_KEY if KEY exists. "
     "If RENAMED_KEY already exists, this field is overwritten"
    },
    {
     FLB_CONFIG_MAP_STR, "Copy", NULL,
     FLB_CONFIG_MAP_MULT, FLB_FALSE, 0,
     "Copy a key/value pair with key KEY to COPIED_KEY "
     "if KEY exists AND COPIED_KEY does not exist"
    },
    {
     FLB_CONFIG_MAP_STR, "Hard_copy", NULL,
     FLB_CONFIG_MAP_MULT, FLB_FALSE, 0,
     "Copy a key/value pair with key KEY to COPIED_KEY if KEY exists. "
     "If COPIED_KEY already exists, this field is overwritten"
    },
    {
     FLB_CONFIG_MAP_STR, "Condition", NULL,
     FLB_CONFIG_MAP_MULT, FLB_FALSE, 0,
     "Set the condition to modify. Key_exists, Key_does_not_exist, A_key_matches, "
     "No_key_matches, Key_value_equals, Key_value_does_not_equal, Key_value_matches, "
     "Key_value_does_not_match, Matching_keys_have_matching_values "
     "and Matching_keys_do_not_have_matching_values are supported."
    },
    {0}
};

struct flb_filter_plugin filter_modify_plugin = {
    .name = "modify",
    .description = "modify records by applying rules",
    .cb_init = cb_modify_init,
    .cb_filter = cb_modify_filter,
    .cb_exit = cb_modify_exit,
    .config_map = config_map,
    .flags = 0
};
