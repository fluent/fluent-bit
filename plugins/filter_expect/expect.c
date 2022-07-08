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

#include <fluent-bit/flb_filter_plugin.h>
#include <fluent-bit/flb_filter.h>
#include <fluent-bit/flb_ra_key.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_kv.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_utils.h>

#include "expect.h"
#include <msgpack.h>

static int key_to_type(char *key)
{
    if (strcasecmp(key, "key_exists") == 0) {
        return FLB_EXP_KEY_EXISTS;
    }
    else if (strcasecmp(key, "key_not_exists") == 0) {
        return FLB_EXP_KEY_NOT_EXISTS;
    }
    else if (strcasecmp(key, "key_val_is_null") == 0) {
        return FLB_EXP_KEY_VAL_NULL;
    }
    else if (strcasecmp(key, "key_val_is_not_null") == 0) {
        return FLB_EXP_KEY_VAL_NOT_NULL;
    }
    else if (strcasecmp(key, "key_val_eq") == 0) {
        return FLB_EXP_KEY_VAL_EQ;
    }

    return -1;
}

/* Create a rule */
static struct flb_expect_rule *rule_create(struct flb_expect *ctx,
                                           int type, char *value)
{
    int ret;
    struct mk_list *list;
    struct flb_slist_entry *key;
    struct flb_slist_entry *val;
    struct flb_expect_rule *rule;

    rule = flb_calloc(1, sizeof(struct flb_expect_rule));
    if (!rule) {
        flb_errno();
        return NULL;
    }
    rule->type = type;
    rule->value = value;
    rule->expect = NULL;

    /* Only the rule 'key_val_eq' expects two values from the configuration */
    if (type == FLB_EXP_KEY_VAL_EQ) {
        list = flb_malloc(sizeof(struct mk_list));
        if (!list) {
            flb_errno();
            flb_free(rule);
            return NULL;
        }
        mk_list_init(list);
        ret = flb_slist_split_string(list, value, ' ', 1);
        if (ret == -1) {
            flb_plg_error(ctx->ins, "error reading list of options '%s'",
                          value);
            flb_free(rule);
            return NULL;
        }

        /* Get the 'key' and the expected value */
        key = mk_list_entry_first(list, struct flb_slist_entry, _head);
        val = mk_list_entry_last(list, struct flb_slist_entry, _head);

        rule->ra = flb_ra_create(key->str, FLB_TRUE);
        if (!rule->ra) {
            flb_plg_error(ctx->ins, "error processing accessor key '%s'",
                          key->str);
            flb_slist_destroy(list);
            flb_free(list);
            flb_free(rule);
            return NULL;
        }
        rule->expect = flb_sds_create(val->str);
        flb_slist_destroy(list);
        flb_free(list);
    }
    else {
        rule->ra = flb_ra_create(value, FLB_TRUE);
        if (!rule->ra) {
            flb_plg_error(ctx->ins, "error processing accessor key '%s'",
                          value);
            flb_free(rule);
            return NULL;
        }
    }

    return rule;
}

static void rule_destroy(struct flb_expect_rule *rule)
{
    if (rule->expect) {
        flb_sds_destroy(rule->expect);
    }
    if (rule->ra) {
        flb_ra_destroy(rule->ra);
    }

    flb_free(rule);
}

static void context_destroy(struct flb_expect *ctx)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_expect_rule *rule;

    mk_list_foreach_safe(head, tmp, &ctx->rules) {
        rule = mk_list_entry(head, struct flb_expect_rule, _head);
        mk_list_del(&rule->_head);
        rule_destroy(rule);
    }
    flb_free(ctx);
}

static struct flb_expect *context_create(struct flb_filter_instance *ins,
                                         struct flb_config *config)
{
    int i = 0;
    int type;
    int ret;
    flb_sds_t tmp;
    struct flb_kv *kv;
    struct mk_list *head;
    struct flb_expect *ctx;
    struct flb_expect_rule *rule;

    ctx = flb_calloc(1, sizeof(struct flb_expect));
    if (!ctx) {
        flb_errno();
        return NULL;
    }
    ctx->ins = ins;
    ctx->action = FLB_EXP_WARN;
    mk_list_init(&ctx->rules);

    /* Get the action property */
    tmp = (char *) flb_filter_get_property("action", ins);
    if (tmp) {
        if (strcasecmp(tmp, "warn") == 0) {
            ctx->action = FLB_EXP_WARN;
        }
        else if (strcasecmp(tmp, "exit") == 0) {
            ctx->action = FLB_EXP_EXIT;
        }
        else if (strcasecmp(tmp, "result_key") == 0) {
            ctx->action = FLB_EXP_RESULT_KEY;
        }
        else {
            flb_plg_error(ctx->ins, "unexpected 'action' value '%s'", tmp);
            flb_free(ctx);
            return NULL;
        }
    }

    /* Load config map */
    ret = flb_filter_config_map_set(ins, ctx);
    if (ret == -1) {
        flb_free(ctx);
        return NULL;
    }

    /* Read the configuration properties */
    mk_list_foreach(head, &ins->properties) {
        kv = mk_list_entry(head, struct flb_kv, _head);

        /* Validate the type of the rule */
        type = key_to_type(kv->key);
        if (strcasecmp(kv->key, "result_key") == 0) {
            /* skip */
            continue;
        }

        if (type == -1 && strcasecmp(kv->key, "action") != 0) {
            flb_plg_error(ctx->ins, "unknown configuration rule '%s'", kv->key);
            context_destroy(ctx);
            return NULL;
        }

        rule = rule_create(ctx, type, kv->val);
        if (!rule) {
            context_destroy(ctx);
            return NULL;
        }
        mk_list_add(&rule->_head, &ctx->rules);

        /* Debug message */
        if (rule->type == -1) {
            flb_plg_debug(ctx->ins, "action : '%s'", kv->val);
        }
        else {
            flb_plg_debug(ctx->ins, "rule #%i: '%s', expects: '%s'",
                          i, kv->key, kv->val);
        }
        i++;
    }

    return ctx;

}

static int cb_expect_init(struct flb_filter_instance *ins,
                          struct flb_config *config,
                          void *data)
{
    struct flb_expect *ctx;

    /* Create the plugin context */
    ctx = context_create(ins, config);
    if (!ctx) {
        return -1;
    }

    /* Set filter context */
    flb_filter_set_context(ins, ctx);

    if (mk_list_size(&ctx->rules) == 0) {
        flb_plg_warn(ctx->ins, "no rules has been defined");
    }

    return 0;
}

static char *ra_value_type_to_str(struct flb_ra_value *val)
{
    if (val->type == FLB_RA_BOOL) {
        return "boolean";
    }
    else if (val->type == FLB_RA_INT) {
        return "integer";
    }
    else if (val->type == FLB_RA_FLOAT) {
        return "float / double";
    }
    else if (val->type == FLB_RA_STRING) {
        return "string";
    }
    else if (val->type == FLB_RA_NULL) {
        return "null";
    }

    return "UNKNOWN";
}

static int rule_apply(struct flb_expect *ctx, msgpack_object map)
{
    int n = 0;
    char *json;
    size_t size = 1024;
    struct mk_list *head;
    struct flb_expect_rule *rule;
    struct flb_ra_value *val;

    mk_list_foreach(head, &ctx->rules) {
        rule = mk_list_entry(head, struct flb_expect_rule, _head);

        val = flb_ra_get_value_object(rule->ra, map);
        if (rule->type == FLB_EXP_KEY_EXISTS) {
            if (val) {
                flb_ra_key_value_destroy(val);
                n++;
                continue;
            }

            json = flb_msgpack_to_json_str(size, &map);
            flb_plg_error(ctx->ins,
                          "exception on rule #%i 'key_exists', key '%s' "
                          "not found. Record content:\n%s",
                          n, rule->value, json);
            flb_free(json);
            return FLB_FALSE;
        }
        else if (rule->type == FLB_EXP_KEY_NOT_EXISTS) {
            if (!val) {
                n++;
                continue;
            }
            json = flb_msgpack_to_json_str(size, &map);
            flb_plg_error(ctx->ins,
                          "exception on rule #%i 'key_not_exists', key '%s' "
                          "exists. Record content:\n%s",
                          n, rule->value, json);
            flb_free(json);
            flb_ra_key_value_destroy(val);
            return FLB_FALSE;
        }
        else if (rule->type == FLB_EXP_KEY_VAL_NULL) {
            if (!val) {
                json = flb_msgpack_to_json_str(size, &map);
                flb_plg_error(ctx->ins,
                              "exception on rule #%i 'key_val_is_null', "
                              "key '%s' not found. Record content:\n%s",
                              n, rule->value, json);
                flb_free(json);
                return FLB_FALSE;
            }
            if (val->type != FLB_RA_NULL) {
                json = flb_msgpack_to_json_str(size, &map);
                flb_plg_error(ctx->ins,
                              "exception on rule #%i 'key_val_is_null', "
                              "key '%s' contains a value type '%s'. "
                              "Record content:\n%s",
                              n, rule->value,
                              ra_value_type_to_str(val), json);
                flb_free(json);
                flb_ra_key_value_destroy(val);
                return FLB_FALSE;
            }
            flb_ra_key_value_destroy(val);
        }
        else if (rule->type == FLB_EXP_KEY_VAL_NOT_NULL) {
            if (!val) {
                json = flb_msgpack_to_json_str(size, &map);
                flb_plg_error(ctx->ins,
                              "exception on rule #%i 'key_val_is_not_null', "
                              "key '%s' not found. Record content:\n%s",
                              n, rule->value, json);
                flb_free(json);
                return FLB_FALSE;
            }
            if (val->type == FLB_RA_NULL) {
                json = flb_msgpack_to_json_str(size, &map);
                flb_plg_error(ctx->ins,
                              "exception on rule #%i 'key_val_is_not_null', "
                              "key '%s' contains a value type '%s'. "
                              "Record content:\n%s",
                              n, rule->value,
                              ra_value_type_to_str(val), json);
                flb_free(json);
                flb_ra_key_value_destroy(val);
                return FLB_FALSE;
            }
            flb_ra_key_value_destroy(val);
        }
        else if (rule->type == FLB_EXP_KEY_VAL_EQ) {
            if (!val) {
                json = flb_msgpack_to_json_str(size, &map);
                flb_plg_error(ctx->ins,
                              "exception on rule #%i 'key_val_is_null', "
                              "key '%s' not found. Record content:\n%s",
                              n, rule->value, json);
                flb_free(json);
                return FLB_FALSE;
            }

            if (val->type == FLB_RA_STRING) {
                if (flb_sds_cmp(val->val.string, rule->expect,
                                flb_sds_len(rule->expect)) != 0) {
                    json = flb_msgpack_to_json_str(size, &map);
                    flb_plg_error(ctx->ins,
                                  "exception on rule #%i 'key_val_eq', "
                                  "key value '%s' is different than "
                                  "expected: '%s'. Record content:\n%s",
                                  n, val->val.string, rule->expect, json);
                    flb_free(json);
                    flb_ra_key_value_destroy(val);
                    return FLB_FALSE;
                }
            }
            flb_ra_key_value_destroy(val);
        }
        n++;
    }

    return FLB_TRUE;
}

static int cb_expect_filter(const void *data, size_t bytes,
                            const char *tag, int tag_len,
                            void **out_buf, size_t *out_bytes,
                            struct flb_filter_instance *f_ins,
                            struct flb_input_instance *i_ins,
                            void *filter_context,
                            struct flb_config *config)
{
    int ret;
    msgpack_unpacked result;
    size_t off = 0;
    (void) out_buf;
    (void) out_bytes;
    (void) f_ins;
    (void) i_ins;
    (void) config;
    msgpack_object map;
    msgpack_object root;
    struct flb_expect *ctx = filter_context;

    int i;
    int rule_matched = FLB_TRUE;
    struct flb_time tm;
    msgpack_object *obj;
    msgpack_sbuffer tmp_sbuf;
    msgpack_packer tmp_pck;
    msgpack_object_kv *kv;

    msgpack_unpacked_init(&result);
    while (msgpack_unpack_next(&result, data, bytes, &off) == MSGPACK_UNPACK_SUCCESS) {
        root = result.data;
        map = root.via.array.ptr[1];

        ret = rule_apply(ctx, map);
        if (ret == FLB_TRUE) {
            /* rule matches, we are good */
            continue;
        }
        else {
            if (ctx->action == FLB_EXP_WARN) {
                flb_plg_warn(ctx->ins, "expect check failed");
            }
            else if (ctx->action == FLB_EXP_EXIT) {
                flb_engine_exit_status(config, 255);
            }
            else if (ctx->action == FLB_EXP_RESULT_KEY) {
                rule_matched = FLB_FALSE;
            }
            break;
        }
    }
    msgpack_unpacked_destroy(&result);

    /* Append result key when action is "result_key"*/
    if (ctx->action == FLB_EXP_RESULT_KEY) {
        off = 0;
        msgpack_unpacked_init(&result);

        /* Create temporary msgpack buffer */
        msgpack_sbuffer_init(&tmp_sbuf);
        msgpack_packer_init(&tmp_pck, &tmp_sbuf, msgpack_sbuffer_write);

        while (msgpack_unpack_next(&result, data, bytes, &off) == MSGPACK_UNPACK_SUCCESS) {
            flb_time_pop_from_msgpack(&tm, &result, &obj);
            msgpack_pack_array(&tmp_pck, 2);
            flb_time_append_to_msgpack(&tm, &tmp_pck, 0);

            msgpack_pack_map(&tmp_pck, obj->via.map.size + 1);
            msgpack_pack_str(&tmp_pck, flb_sds_len(ctx->result_key));
            msgpack_pack_str_body(&tmp_pck, ctx->result_key,
                                  flb_sds_len(ctx->result_key));
            if (rule_matched) {
                msgpack_pack_true(&tmp_pck);
            }
            else {
                msgpack_pack_false(&tmp_pck);
            }

            kv = obj->via.map.ptr;
            for (i=0; i<map.via.map.size; i++) {
                msgpack_pack_object(&tmp_pck, (kv+i)->key);
                msgpack_pack_object(&tmp_pck, (kv+i)->val);
            }
        }
        msgpack_unpacked_destroy(&result);

        *out_buf   = tmp_sbuf.data;
        *out_bytes = tmp_sbuf.size;

        return FLB_FILTER_MODIFIED;
    }

    return FLB_FILTER_NOTOUCH;
}

static int cb_expect_exit(void *data, struct flb_config *config)
{
    struct flb_expect *ctx = data;
    (void) config;

    if (!ctx) {
        return 0;
    }

    context_destroy(ctx);
    return 0;
}

/* Configuration properties map */
static struct flb_config_map config_map[] =
{
    /* rule: the key exists in the record */
    {
      FLB_CONFIG_MAP_STR, "key_exists", NULL,
      FLB_CONFIG_MAP_MULT, FLB_FALSE, 0,
      "check that the given key name exists in the record"
    },

    /* rule: the key not exists in the record */
    {
      FLB_CONFIG_MAP_STR, "key_not_exists", NULL,
      FLB_CONFIG_MAP_MULT, FLB_FALSE, 0,
      "check that the given key name do not exists in the record"
    },

    /* rule: the value of the key is NULL */
    {
      FLB_CONFIG_MAP_STR, "key_val_is_null", NULL,
      FLB_CONFIG_MAP_MULT, FLB_FALSE, 0,
      "check that the value of the key is NULL"
    },

    /* rule: the value of the key is NOT NULL */
    {
      FLB_CONFIG_MAP_STR, "key_val_is_not_null", NULL,
      FLB_CONFIG_MAP_MULT, FLB_FALSE, 0,
      "check that the value of the key is NOT NULL"
    },

    /* rule: the value of the key is equal a given value */
    {
      FLB_CONFIG_MAP_SLIST_1, "key_val_eq", NULL,
      FLB_CONFIG_MAP_MULT, FLB_FALSE, 0,
      "check that the value of the key equals the given value"
    },

    /* rule action: the value of the key is equal a given value */
    {
      FLB_CONFIG_MAP_STR, "action", "warn",
      0, FLB_FALSE, 0,
      "action to take when a rule does not match: 'warn', 'exit' or 'result_key'."
    },
    {
      FLB_CONFIG_MAP_STR, "result_key", "matched",
      0, FLB_TRUE, offsetof(struct flb_expect, result_key),
      "specify the key name to append a boolean that indicates rule is matched or not. "
      "This key is to be used only when 'action' is 'result_key'."
    },

    /* EOF */
    {0}
};

struct flb_filter_plugin filter_expect_plugin = {
    .name         = "expect",
    .description  = "Validate expected keys and values",
    .cb_init      = cb_expect_init,
    .cb_filter    = cb_expect_filter,
    .cb_exit      = cb_expect_exit,
    .config_map   = config_map,
    .flags        = 0
};
