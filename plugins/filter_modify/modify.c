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
#include <fluent-bit/flb_regex.h>
#include <msgpack.h>

#include "modify.h"

static void condition_free(struct modify_condition *condition)
{
    flb_free(condition->a);
    flb_free(condition->b);
    flb_free(condition->raw_k);
    flb_free(condition->raw_v);

    if (condition->a_is_regex) {
        flb_regex_destroy(condition->a_regex);
    }
    if (condition->b_is_regex) {
        flb_regex_destroy(condition->b_regex);
    }
}

static void teardown(struct filter_modify_ctx *ctx)
{
    struct mk_list *tmp;
    struct mk_list *head;

    struct modify_rule *rule;
    struct modify_condition *condition;

    mk_list_foreach_safe(head, tmp, &ctx->conditions) {
        condition = mk_list_entry(head, struct modify_condition, _head);
        mk_list_del(&condition->_head);
        condition_free(condition);
    }

    mk_list_foreach_safe(head, tmp, &ctx->rules) {
        rule = mk_list_entry(head, struct modify_rule, _head);
        flb_free(rule->key);
        flb_free(rule->val);
        flb_free(rule->raw_k);
        flb_free(rule->raw_v);
        flb_regex_destroy(rule->key_regex);
        flb_regex_destroy(rule->val_regex);
        mk_list_del(&rule->_head);
        flb_free(rule);
    }
}

static void helper_pack_string(msgpack_packer * packer, const char *str,
                               int len)
{

    if (str == NULL) {
        flb_error("[filter_modify] helper_pack_string : NULL passed");
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
    struct flb_split_entry *sentry;
    struct flb_config_prop *prop;
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

    mk_list_foreach(head, &f_ins->properties) {
        prop = mk_list_entry(head, struct flb_config_prop, _head);

        split = flb_utils_split(prop->val, ' ', 3);
        list_size = mk_list_size(split);

        // Conditions are,
        // CONDITION CONDITIONTYPE VAL_A VAL_B

        if (list_size == 0 || list_size > 3) {
            flb_error("[filter_modify] Invalid config for %s", prop->key);
            teardown(ctx);
            flb_utils_split_free(split);
            return -1;
        }
        else if (strcasecmp(prop->key, "condition") == 0) {

            //
            // Build a condition
            //

            condition = flb_calloc(1, sizeof(struct modify_condition));
            if (!condition) {
                flb_error("[filter_modify] Unable to allocate memory for "
                          "condition");
                teardown(ctx);
                flb_utils_split_free(split);
                return -1;
            }

            condition->a_is_regex = false;
            condition->b_is_regex = false;
            condition->raw_k = flb_strndup(prop->key, strlen(prop->key));
            condition->raw_v = flb_strndup(prop->val, strlen(prop->val));

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
                flb_error("[filter_modify] Invalid config for %s : %s",
                          prop->key, prop->val);
                teardown(ctx);
                condition_free(condition);
                flb_utils_split_free(split);
                return -1;
            }

            sentry =
                mk_list_entry_next(&sentry->_head, struct flb_split_entry,
                                   _head, split);
            condition->a = flb_strndup(sentry->value, sentry->len);
            condition->a_len = sentry->len;

            if (list_size == 3) {
                sentry =
                    mk_list_entry_last(split, struct flb_split_entry, _head);
                condition->b = flb_strndup(sentry->value, sentry->len);
                condition->b_len = sentry->len;
            }
            else {
                condition->b = NULL;
                condition->b_len = 0;
            }

            if (condition->a_is_regex) {
                if (condition->a_len < 1) {
                    flb_error
                        ("[filter_modify] Unable to create regex for condition %s %s",
                         condition->raw_k, condition->raw_v);
                    condition_free(condition);
                    flb_utils_split_free(split);
                    return -1;
                }
                else {
                    flb_debug
                        ("[filter_modify] Creating regex for condition A : %s %s : %s",
                         condition->raw_k, condition->raw_v, condition->a);
                    condition->a_regex =
                        flb_regex_create((unsigned char *) condition->a);
                }
            }

            if (condition->b_is_regex) {
                if (condition->b_len < 1) {
                    flb_error("[filter_modify] Unable to create regex "
                              "for condition %s %s",
                              condition->raw_k, condition->raw_v);
                    condition_free(condition);
                    flb_utils_split_free(split);
                    return -1;
                }
                else {
                    flb_debug
                        ("[filter_modify] Creating regex for condition B : %s %s : %s",
                         condition->raw_k, condition->raw_v, condition->b);
                    condition->b_regex =
                        flb_regex_create((unsigned char *) condition->b);
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

            rule = flb_malloc(sizeof(struct modify_rule));
            if (!rule) {
                flb_error
                    ("[filter_modify] Unable to allocate memory for rule");
                teardown(ctx);
                flb_utils_split_free(split);
                return -1;
            }

            rule->key_is_regex = false;
            rule->val_is_regex = false;
            rule->raw_k = flb_strndup(prop->key, strlen(prop->key));
            rule->raw_v = flb_strndup(prop->val, strlen(prop->val));

            sentry =
                mk_list_entry_first(split, struct flb_split_entry, _head);
            rule->key = flb_strndup(sentry->value, sentry->len);
            rule->key_len = sentry->len;

            sentry = mk_list_entry_last(split, struct flb_split_entry, _head);
            rule->val = flb_strndup(sentry->value, sentry->len);
            rule->val_len = sentry->len;

            flb_utils_split_free(split);

            if (list_size == 1) {
                if (strcasecmp(prop->key, "remove") == 0) {
                    rule->ruletype = REMOVE;
                }
                else if (strcasecmp(prop->key, "remove_wildcard") == 0) {
                    rule->ruletype = REMOVE_WILDCARD;
                }
                else if (strcasecmp(prop->key, "remove_regex") == 0) {
                    rule->ruletype = REMOVE_REGEX;
                    rule->key_is_regex = true;
                }
                else {
                    flb_error
                        ("[filter_modify] Invalid operation %s : %s in configuration",
                         prop->key, prop->val);
                    teardown(ctx);
                    flb_free(rule);
                    return -1;
                }
            }
            else if (list_size == 2) {
                if (strcasecmp(prop->key, "rename") == 0) {
                    rule->ruletype = RENAME;
                }
                else if (strcasecmp(prop->key, "hard_rename") == 0) {
                    rule->ruletype = HARD_RENAME;
                }
                else if (strcasecmp(prop->key, "add") == 0) {
                    rule->ruletype = ADD;
                }
                else if (strcasecmp(prop->key, "add_if_not_present") == 0) {
                    flb_info
                        ("[filter_modify] DEPRECATED : Operation 'add_if_not_present' has been replaced by 'add'.");
                    rule->ruletype = ADD;
                }
                else if (strcasecmp(prop->key, "set") == 0) {
                    rule->ruletype = SET;
                }
                else if (strcasecmp(prop->key, "copy") == 0) {
                    rule->ruletype = COPY;
                }
                else if (strcasecmp(prop->key, "hard_copy") == 0) {
                    rule->ruletype = HARD_COPY;
                }
                else {
                    flb_error
                        ("[filter_modify] Invalid operation %s : %s in configuration",
                         prop->key, prop->val);
                    teardown(ctx);
                    flb_free(rule);
                    return -1;
                }
            }

            if (rule->key_is_regex && rule->key_len == 0) {
                flb_error
                    ("[filter_modify] Unable to create regex for rule %s %s",
                     rule->raw_k, rule->raw_v);
                return -1;
            }
            else {
                rule->key_regex =
                    flb_regex_create((unsigned char *) rule->key);
            }

            if (rule->val_is_regex && rule->val_len == 0) {
                flb_error
                    ("[filter_modify] Unable to create regex for rule %s %s",
                     rule->raw_k, rule->raw_v);
                return -1;
            }
            else {
                rule->val_regex =
                    flb_regex_create((unsigned char *) rule->val);
            }

            mk_list_add(&rule->_head, &ctx->rules);
            ctx->rules_cnt++;
        }

    }

    flb_debug
        ("[filter_modify] Initialized modify filter with %d conditions and %d rules",
         ctx->conditions_cnt, ctx->rules_cnt);
    return 0;
}

//
// Regex matchers
//

static inline bool helper_msgpack_object_matches_regex(msgpack_object * obj,
                                                       struct flb_regex
                                                       *regex)
{
    char *key;
    int len;
    struct flb_regex_search result;

    if (obj->type == MSGPACK_OBJECT_BIN) {
        return false;
    }
    else if (obj->type == MSGPACK_OBJECT_STR) {
        key = (char *) obj->via.str.ptr;
        len = obj->via.str.size;
    }
    else {
        return false;
    }

    return (flb_regex_do(regex, (unsigned char *) key, len, &result) == 0);
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

static inline bool kv_key_does_not_match_regex(msgpack_object_kv * kv,
                                               struct flb_regex *regex)
{
    return !kv_key_matches_regex(kv, regex);
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

static inline bool kv_key_matches_regex_rule_val(msgpack_object_kv * kv,
                                                 struct modify_rule *rule)
{
    return kv_key_matches_regex(kv, rule->val_regex);
}

static inline bool kv_key_does_not_match_regex_rule_val(msgpack_object_kv *
                                                        kv,
                                                        struct modify_rule
                                                        *rule)
{
    return !kv_key_matches_regex_rule_val(kv, rule);
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

static inline int map_count_keys_not_matching_regex(msgpack_object * map,
                                                    struct flb_regex *regex)
{
    int i;
    int count = 0;

    for (i = 0; i < map->via.map.size; i++) {
        if (!kv_key_matches_regex(&map->via.map.ptr[i], regex)) {
            count++;
        }
    }
    return count;
}

//
// Wildcard matchers
//

static inline bool helper_msgpack_object_matches_wildcard(msgpack_object *
                                                          obj, char *str,
                                                          int len)
{
    char *key;

    if (obj->type == MSGPACK_OBJECT_BIN) {
        key = (char *) obj->via.bin.ptr;
    }
    else if (obj->type == MSGPACK_OBJECT_STR) {
        key = (char *) obj->via.str.ptr;
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

static inline bool kv_val_matches_wildcard(msgpack_object_kv * kv,
                                           char *str, int len)
{
    return helper_msgpack_object_matches_wildcard(&kv->val, str, len);
}

static inline bool kv_key_does_not_match_wildcard(msgpack_object_kv * kv,
                                                  char *str, int len)
{
    return !kv_key_matches_wildcard(kv, str, len);
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

static inline bool kv_key_matches_wildcard_rule_val(msgpack_object_kv * kv,
                                                    struct modify_rule *rule)
{
    return kv_key_matches_wildcard(kv, rule->val, rule->val_len);
}

static inline bool kv_key_does_not_match_wildcard_rule_val(msgpack_object_kv *
                                                           kv,
                                                           struct modify_rule
                                                           *rule)
{
    return !kv_key_matches_wildcard_rule_val(kv, rule);
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

static inline int map_count_keys_not_matching_wildcard(msgpack_object * map,
                                                       char *str, int len)
{
    int i;
    int count = 0;

    for (i = 0; i < map->via.map.size; i++) {
        if (!kv_key_matches_wildcard(&map->via.map.ptr[i], str, len)) {
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

    char *key;
    int klen;

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

    return ((len == klen) && (strncmp(str, key, klen) == 0)
        );
}

static inline bool kv_key_matches_str(msgpack_object_kv * kv,
                                      char *str, int len)
{
    return helper_msgpack_object_matches_str(&kv->key, str, len);
}

static inline bool kv_val_matches_str(msgpack_object_kv * kv,
                                      char *str, int len)
{
    return helper_msgpack_object_matches_str(&kv->val, str, len);
}

static inline bool kv_key_does_not_match_str(msgpack_object_kv * kv,
                                             char *str, int len)
{
    return !kv_key_matches_str(kv, str, len);
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

static inline bool kv_key_does_not_match_str_rule_val(msgpack_object_kv * kv,
                                                      struct modify_rule
                                                      *rule)
{
    return !kv_key_matches_str_rule_val(kv, rule);
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

static inline int map_count_keys_not_matching_str(msgpack_object * map,
                                                  char *str, int len)
{
    int i;
    int count = 0;

    for (i = 0; i < map->via.map.size; i++) {
        if (!kv_key_matches_str(&map->via.map.ptr[i], str, len)) {
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

static inline int map_count_fn(msgpack_object * map,
                               struct modify_rule *ctx,
                               bool(*f) (msgpack_object_kv * kv,
                                         struct modify_rule * ctx)
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

static inline bool evaluate_condition_KEY_EXISTS(msgpack_object * map,
                                                 struct modify_condition
                                                 *condition)
{
    return (map_count_keys_matching_str(map, condition->a, condition->a_len) >
            0);
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

static inline bool evaluate_condition_KEY_VALUE_EQUALS(msgpack_object * map,
                                                       struct
                                                       modify_condition
                                                       *condition)
{
    int i;
    bool match = false;
    msgpack_object_kv *kv;

    for (i = 0; i < map->via.map.size; i++) {
        kv = &map->via.map.ptr[i];
        if (kv_key_matches_str(kv, condition->a, condition->a_len)) {
            if (kv_val_matches_str(kv, condition->b, condition->b_len)) {
                flb_debug
                    ("[filter_modify] : Match for condition KEY_VALUE_EQUALS %s",
                     condition->b);
                match = true;
                break;
            }
        }
    }
    return match;
}

static inline bool evaluate_condition_KEY_VALUE_DOES_NOT_EQUAL(msgpack_object
                                                               * map,
                                                               struct
                                                               modify_condition
                                                               *condition)
{
    return !evaluate_condition_KEY_VALUE_EQUALS(map, condition);
}

static inline bool evaluate_condition_KEY_VALUE_MATCHES(msgpack_object * map,
                                                        struct
                                                        modify_condition
                                                        *condition)
{
    int i;
    bool match = false;
    msgpack_object_kv *kv;

    for (i = 0; i < map->via.map.size; i++) {
        kv = &map->via.map.ptr[i];
        if (kv_key_matches_str(kv, condition->a, condition->a_len)) {
            if (kv_val_matches_regex(kv, condition->b_regex)) {
                flb_debug
                    ("[filter_modify] : Match for condition KEY_VALUE_MATCHES %s",
                     condition->b);
                match = true;
                break;
            }
        }
    }
    return match;
}

static inline bool evaluate_condition_KEY_VALUE_DOES_NOT_MATCH(msgpack_object
                                                               * map,
                                                               struct
                                                               modify_condition
                                                               *condition)
{
    return !evaluate_condition_KEY_VALUE_MATCHES(map, condition);
}

static inline bool
evaluate_condition_MATCHING_KEYS_HAVE_MATCHING_VALUES(msgpack_object * map,
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
                flb_debug
                    ("[filter_modify] : Match MISSED for condition MATCHING_KEYS_HAVE_MATCHING_VALUES %s",
                     condition->b);
                match = false;
                break;
            }
        }
    }
    return match;
}

static inline bool
evaluate_condition_MATCHING_KEYS_DO_NOT_HAVE_MATCHING_VALUES(msgpack_object *
                                                             map,
                                                             struct
                                                             modify_condition
                                                             *condition)
{
    return !evaluate_condition_MATCHING_KEYS_HAVE_MATCHING_VALUES(map,
                                                                  condition);
}

static inline bool evaluate_condition(msgpack_object * map,
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
        return evaluate_condition_KEY_VALUE_EQUALS(map, condition);
    case KEY_VALUE_DOES_NOT_EQUAL:
        return evaluate_condition_KEY_VALUE_DOES_NOT_EQUAL(map, condition);
    case KEY_VALUE_MATCHES:
        return evaluate_condition_KEY_VALUE_MATCHES(map, condition);
    case KEY_VALUE_DOES_NOT_MATCH:
        return evaluate_condition_KEY_VALUE_DOES_NOT_MATCH(map, condition);
    case MATCHING_KEYS_HAVE_MATCHING_VALUES:
        return evaluate_condition_MATCHING_KEYS_HAVE_MATCHING_VALUES(map,
                                                                     condition);
    case MATCHING_KEYS_DO_NOT_HAVE_MATCHING_VALUES:
        return
            evaluate_condition_MATCHING_KEYS_DO_NOT_HAVE_MATCHING_VALUES(map,
                                                                         condition);
    default:
        flb_warn
            ("[filter_modify] Unknown conditiontype for condition %s : %s, assuming result FAILED TO MEET CONDITION",
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
        if (!evaluate_condition(map, condition)) {
            flb_debug("[filter_modify] : Condition not met : %s",
                      condition->raw_v);
            ok = false;
        }
    }

    return ok;
}

static inline int apply_rule_RENAME(msgpack_packer * packer,
                                    msgpack_object * map,
                                    struct modify_rule *rule)
{
    int i;

    int match_keys =
        map_count_keys_matching_str(map, rule->key, rule->key_len);
    int conflict_keys =
        map_count_keys_matching_str(map, rule->val, rule->val_len);

    if (match_keys == 0) {
        flb_debug
            ("[filter_modify] Rule RENAME %s TO %s : No keys matching %s found, not applying rule",
             rule->key, rule->val, rule->key);
        return FLB_FILTER_NOTOUCH;
    }
    else if (conflict_keys > 0) {
        flb_debug
            ("[filter_modify] Rule RENAME %s TO %s : Existing key %s found, not applying rule",
             rule->key, rule->val, rule->key);
        return FLB_FILTER_NOTOUCH;
    }
    else {
        msgpack_pack_map(packer, map->via.map.size);
        for (i = 0; i < map->via.map.size; i++) {
            if (kv_key_matches_str_rule_key(&map->via.map.ptr[i], rule)) {
                helper_pack_string(packer, rule->val, rule->val_len);
            }
            else {
                msgpack_pack_object(packer, map->via.map.ptr[i].key);
            }
            msgpack_pack_object(packer, map->via.map.ptr[i].val);
        }
        return FLB_FILTER_MODIFIED;
    }
}

static inline int apply_rule_HARD_RENAME(msgpack_packer * packer,
                                         msgpack_object * map,
                                         struct modify_rule *rule)
{
    int i;

    int match_keys =
        map_count_keys_matching_str(map, rule->key, rule->key_len);
    int conflict_keys =
        map_count_keys_matching_str(map, rule->val, rule->val_len);
    msgpack_object_kv *kv;

    if (match_keys == 0) {
        flb_debug
            ("[filter_modify] Rule HARD_RENAME %s TO %s : No keys matching %s found, not applying rule",
             rule->key, rule->val, rule->key);
        return FLB_FILTER_NOTOUCH;
    }
    else if (conflict_keys == 0) {
        msgpack_pack_map(packer, map->via.map.size);
        for (i = 0; i < map->via.map.size; i++) {
            kv = &map->via.map.ptr[i];
            if (kv_key_matches_str_rule_key(kv, rule)) {
                helper_pack_string(packer, rule->val, rule->val_len);
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
                    helper_pack_string(packer, rule->val, rule->val_len);
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

static inline int apply_rule_COPY(msgpack_packer * packer,
                                  msgpack_object * map,
                                  struct modify_rule *rule)
{
    int match_keys =
        map_count_keys_matching_str(map, rule->key, rule->key_len);
    int conflict_keys =
        map_count_keys_matching_str(map, rule->val, rule->val_len);
    int i;
    msgpack_object_kv *kv;

    if (match_keys < 1) {
        flb_debug
            ("[filter_modify] Rule COPY %s TO %s : No keys matching %s found, not applying rule",
             rule->key, rule->val, rule->key);
        return FLB_FILTER_NOTOUCH;
    }
    else if (match_keys > 1) {
        flb_debug
            ("[filter_modify] Rule COPY %s TO %s : Multiple keys matching %s found, not applying rule",
             rule->key, rule->val, rule->key);
        return FLB_FILTER_NOTOUCH;
    }
    else if (conflict_keys > 0) {
        flb_debug
            ("[filter_modify] Rule COPY %s TO %s : Existing keys matching target %s found, not applying rule",
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
                helper_pack_string(packer, rule->val, rule->val_len);
                msgpack_pack_object(packer, kv->val);
            }
        }
        return FLB_FILTER_MODIFIED;
    }
}

static inline int apply_rule_HARD_COPY(msgpack_packer * packer,
                                       msgpack_object * map,
                                       struct modify_rule *rule)
{
    int i;

    int match_keys =
        map_count_keys_matching_str(map, rule->key, rule->key_len);
    int conflict_keys =
        map_count_keys_matching_str(map, rule->val, rule->val_len);
    msgpack_object_kv *kv;

    if (match_keys < 1) {
        flb_debug
            ("[filter_modify] Rule HARD_COPY %s TO %s : No keys matching %s found, not applying rule",
             rule->key, rule->val, rule->key);
        return FLB_FILTER_NOTOUCH;
    }
    else if (match_keys > 1) {
        flb_warn
            ("[filter_modify] Rule HARD_COPY %s TO %s : Multiple keys matching %s found, not applying rule",
             rule->key, rule->val, rule->key);
        return FLB_FILTER_NOTOUCH;
    }
    else if (conflict_keys > 1) {
        flb_warn
            ("[filter_modify] Rule HARD_COPY %s TO %s : Multiple target keys matching %s found, not applying rule",
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
                helper_pack_string(packer, rule->val, rule->val_len);
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
                    helper_pack_string(packer, rule->val, rule->val_len);
                    msgpack_pack_object(packer, kv->val);
                }
            }
        }

        return FLB_FILTER_MODIFIED;
    }
}

static inline int apply_rule_ADD(msgpack_packer * packer,
                                 msgpack_object * map,
                                 struct modify_rule *rule)
{
    if (map_count_keys_matching_str(map, rule->key, rule->key_len) == 0) {
        msgpack_pack_map(packer, map->via.map.size + 1);
        map_pack_each(packer, map);
        helper_pack_string(packer, rule->key, rule->key_len);
        helper_pack_string(packer, rule->val, rule->val_len);
        return FLB_FILTER_MODIFIED;
    }
    else {
        flb_debug
            ("[filter_modify] Rule ADD %s : this key already exists, skipping",
             rule->key);
        return FLB_FILTER_NOTOUCH;
    }
}

static inline int apply_rule_SET(msgpack_packer * packer,
                                 msgpack_object * map,
                                 struct modify_rule *rule)
{
    int matches = map_count_keys_matching_str(map, rule->key, rule->key_len);

    msgpack_pack_map(packer, map->via.map.size - matches + 1);

    if (matches == 0) {
        map_pack_each(packer, map);
        helper_pack_string(packer, rule->key, rule->key_len);
        helper_pack_string(packer, rule->val, rule->val_len);
    }
    else {
        map_pack_each_fn(packer, map, rule,
                         kv_key_does_not_match_str_rule_key);
        helper_pack_string(packer, rule->key, rule->key_len);
        helper_pack_string(packer, rule->val, rule->val_len);
    }

    return FLB_FILTER_MODIFIED;
}

static inline int apply_rule_REMOVE(msgpack_packer * packer,
                                    msgpack_object * map,
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

static inline int apply_modifying_rule(msgpack_packer * packer,
                                       msgpack_object * map,
                                       struct modify_rule *rule)
{
    switch (rule->ruletype) {
    case RENAME:
        return apply_rule_RENAME(packer, map, rule);
    case HARD_RENAME:
        return apply_rule_HARD_RENAME(packer, map, rule);
    case ADD:
        return apply_rule_ADD(packer, map, rule);
    case SET:
        return apply_rule_SET(packer, map, rule);
    case REMOVE:
        return apply_rule_REMOVE(packer, map, rule);
    case REMOVE_WILDCARD:
        return apply_rule_REMOVE_WILDCARD(packer, map, rule);
    case REMOVE_REGEX:
        return apply_rule_REMOVE_REGEX(packer, map, rule);
    case COPY:
        return apply_rule_COPY(packer, map, rule);
    case HARD_COPY:
        return apply_rule_HARD_COPY(packer, map, rule);
    default:
        flb_warn
            ("[filter_modify] Unknown ruletype for rule with key %s, ignoring",
             rule->key);
    }
    return FLB_FILTER_NOTOUCH;
}

static inline int apply_modifying_rules(msgpack_packer * packer,
                                        msgpack_object * root,
                                        struct filter_modify_ctx *ctx)
{
    msgpack_object ts = root->via.array.ptr[0];
    msgpack_object map = root->via.array.ptr[1];

    if (!evaluate_conditions(&map, ctx)) {
        flb_debug
            ("[filter_modify] : Conditions not met, not touching record");
        return 0;
    }

    bool has_modifications = false;

    int records_in = map.via.map.size;

    struct modify_rule *rule;

    msgpack_sbuffer sbuffer;
    msgpack_packer in_packer;
    msgpack_unpacker unpacker;
    msgpack_unpacked unpacked;

    int initial_buffer_size = 1024 * 8;
    int new_buffer_size = 0;

    struct mk_list *tmp;
    struct mk_list *head;

    msgpack_sbuffer_init(&sbuffer);
    msgpack_packer_init(&in_packer, &sbuffer, msgpack_sbuffer_write);
    msgpack_unpacked_init(&unpacked);
    if (!msgpack_unpacker_init(&unpacker, initial_buffer_size)) {
        flb_error
            ("[filter_modify] Unable to allocate memory for unpacker, aborting");
        return -1;
    }

    mk_list_foreach_safe(head, tmp, &ctx->rules) {
        rule = mk_list_entry(head, struct modify_rule, _head);

        msgpack_sbuffer_clear(&sbuffer);

        if (apply_modifying_rule(&in_packer, &map, rule) !=
            FLB_FILTER_NOTOUCH) {

            has_modifications = true;
            new_buffer_size = sbuffer.size * 2;

            if (msgpack_unpacker_buffer_capacity(&unpacker) < new_buffer_size) {
                if (!msgpack_unpacker_reserve_buffer
                    (&unpacker, new_buffer_size)) {
                    flb_error
                        ("[filter_modify] Unable to re-allocate memory for unpacker, aborting");
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
                flb_error
                    ("[modify_filter] Expected MSGPACK_MAP, this is not a valid return value, skipping");
            }
        }
    }

    if (has_modifications) {
        // * Record array init(2)
        msgpack_pack_array(packer, 2);

        // * * Record array item 1/2
        msgpack_pack_object(packer, ts);

        flb_debug
            ("[filter_modify] Input map size %d elements, output map size %d elements",
             records_in, map.via.map.size);

        // * * Record array item 2/2
        msgpack_pack_map(packer, map.via.map.size);
        map_pack_each(packer, &map);

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

static int cb_modify_filter(void *data, size_t bytes,
                            char *tag, int tag_len,
                            void **out_buf, size_t * out_size,
                            struct flb_filter_instance *f_ins,
                            void *context, struct flb_config *config)
{
    msgpack_unpacked result;
    size_t off = 0;
    (void) f_ins;
    (void) config;

    struct filter_modify_ctx *ctx = context;

    int modifications = 0;

    msgpack_sbuffer buffer;
    msgpack_sbuffer_init(&buffer);

    msgpack_packer packer;
    msgpack_packer_init(&packer, &buffer, msgpack_sbuffer_write);

    // Records come in the format,
    //
    // [ TIMESTAMP, { K1:V1, K2:V2, ...} ],
    // [ TIMESTAMP, { K1:V1, K2:V2, ...} ]
    //
    // Example record,
    // [1123123, {"Mem.total"=>4050908, "Mem.used"=>476576, "Mem.free"=>3574332 } ]

    msgpack_unpacked_init(&result);
    while (msgpack_unpack_next(&result, data, bytes, &off) == MSGPACK_UNPACK_SUCCESS) {
        if (result.data.type == MSGPACK_OBJECT_ARRAY) {
            modifications +=
                apply_modifying_rules(&packer, &result.data, ctx);
        }
        else {
            msgpack_pack_object(&packer, result.data);
        }
    }
    msgpack_unpacked_destroy(&result);

    if(modifications == 0) {
        msgpack_sbuffer_destroy(&buffer);
        return FLB_FILTER_NOTOUCH;
    }

    *out_buf = buffer.data;
    *out_size = buffer.size;

    return FLB_FILTER_MODIFIED;
}

static int cb_modify_exit(void *data, struct flb_config *config)
{
    struct filter_modify_ctx *ctx = data;

    teardown(ctx);
    flb_free(ctx);
    return 0;
}

struct flb_filter_plugin filter_modify_plugin = {
    .name = "modify",
    .description = "modify records by applying rules",
    .cb_init = cb_modify_init,
    .cb_filter = cb_modify_filter,
    .cb_exit = cb_modify_exit,
    .flags = 0
};
