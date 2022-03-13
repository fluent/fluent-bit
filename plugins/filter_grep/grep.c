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

#include <stdio.h>
#include <sys/types.h>

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_kv.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_str.h>
#include <fluent-bit/flb_filter.h>
#include <fluent-bit/flb_filter_plugin.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_regex.h>
#include <fluent-bit/flb_record_accessor.h>
#include <msgpack.h>

#include "grep.h"

static void delete_rules(struct grep_ctx *ctx)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct grep_rule *rule;

    mk_list_foreach_safe(head, tmp, &ctx->rules) {
        rule = mk_list_entry(head, struct grep_rule, _head);
        flb_sds_destroy(rule->field);
        flb_free(rule->regex_pattern);
        flb_ra_destroy(rule->ra);
        flb_regex_destroy(rule->regex);
        mk_list_del(&rule->_head);
        flb_free(rule);
    }
}

static int set_rules(struct grep_ctx *ctx, struct flb_filter_instance *f_ins,
                     struct flb_config_map_val *mv, int type)
{
    flb_sds_t tmp;
    struct grep_rule *rule;
    struct flb_slist_entry *sentry;

    /* Create a new rule */
    rule = flb_malloc(sizeof(struct grep_rule));
    if (!rule) {
        flb_errno();
        return -1;
    }

    if (type != GREP_REGEX && type != GREP_EXCLUDE) {
        flb_plg_error(ctx->ins, "unknown rule type: %d", type);
        delete_rules(ctx);
        flb_free(rule);
        return -1;
    }
    rule->type = type;

    /* As a value we expect a pair of field name and a regular expression */
    if (mk_list_size(mv->val.list) != 2) {
        flb_plg_error(ctx->ins,
                      "invalid regex, expected field and regular expression");
        delete_rules(ctx);
        flb_free(rule);
        return -1;
    }

    /* Get first value (field) */
    sentry = mk_list_entry_first(mv->val.list, struct flb_slist_entry, _head);
    if (*sentry->str == '$') {
        rule->field = flb_sds_create_len(sentry->str, flb_sds_len(sentry->str));
    }
    else {
        rule->field = flb_sds_create_size(flb_sds_len(sentry->str) + 2);
        tmp = flb_sds_cat(rule->field, "$", 1);
        rule->field = tmp;

        tmp = flb_sds_cat(rule->field, sentry->str, flb_sds_len(sentry->str));
        rule->field = tmp;
    }

    /* Get remaining content (regular expression) */
    sentry = mk_list_entry_last(mv->val.list, struct flb_slist_entry, _head);
    rule->regex_pattern = flb_strndup(sentry->str, flb_sds_len(sentry->str));

    /* Create a record accessor context for this rule */
    rule->ra = flb_ra_create(rule->field, FLB_FALSE);
    if (!rule->ra) {
        flb_plg_error(ctx->ins, "invalid record accessor? '%s'", rule->field);
        delete_rules(ctx);
        flb_free(rule);
        return -1;
    }

    /* Convert string to regex pattern */
    rule->regex = flb_regex_create(rule->regex_pattern);
    if (!rule->regex) {
        flb_plg_error(ctx->ins, "could not compile regex pattern '%s'",
                      rule->regex_pattern);
        delete_rules(ctx);
        flb_free(rule);
        return -1;
    }

    /* Link to parent list */
    mk_list_add(&rule->_head, &ctx->rules);

    return 0;
}

/* Given a msgpack record, do some filter action based on the defined rules */
static inline int grep_filter_data(msgpack_object map, struct grep_ctx *ctx)
{
    ssize_t ret;
    struct mk_list *head;
    struct grep_rule *rule;

    /* For each rule, validate against map fields */
    mk_list_foreach(head, &ctx->rules) {
        rule = mk_list_entry(head, struct grep_rule, _head);

        ret = flb_ra_regex_match(rule->ra, map, rule->regex, NULL);
        if (ret <= 0) { /* no match */
            if (rule->type == GREP_REGEX) {
                return GREP_RET_EXCLUDE;
            }
        }
        else {
            if (rule->type == GREP_EXCLUDE) {
                return GREP_RET_EXCLUDE;
            }
            else {
                return GREP_RET_KEEP;
            }
        }
    }

    return GREP_RET_KEEP;
}

static int cb_grep_init(struct flb_filter_instance *f_ins,
                        struct flb_config *config,
                        void *data)
{
    int ret;
    struct grep_ctx *ctx;
    struct flb_config_map_val *mv = NULL;
    struct mk_list *head = NULL;

    /* Create context */
    ctx = flb_malloc(sizeof(struct grep_ctx));
    if (!ctx) {
        flb_errno();
        return -1;
    }
    if (flb_filter_config_map_set(f_ins, ctx) < 0) {
        flb_errno();
        flb_plg_error(f_ins, "configuration error");
        flb_free(ctx);
        return -1;
    }

    mk_list_init(&ctx->rules);
    ctx->ins = f_ins;

    /* Load rules */
    flb_config_map_foreach(head, mv, ctx->regex_map) {
        ret = set_rules(ctx, f_ins, mv, GREP_REGEX);
        if (ret == -1) {
            flb_free(ctx);
            return -1;
        }
    }
    flb_config_map_foreach(head, mv, ctx->exclude_map) {
        ret = set_rules(ctx, f_ins, mv, GREP_EXCLUDE);
        if (ret == -1) {
            flb_free(ctx);
            return -1;
        }
    }

    /* Set our context */
    flb_filter_set_context(f_ins, ctx);
    return 0;
}

static int cb_grep_filter(const void *data, size_t bytes,
                          const char *tag, int tag_len,
                          void **out_buf, size_t *out_size,
                          struct flb_filter_instance *f_ins,
                          void *context,
                          struct flb_config *config)
{
    int ret;
    int old_size = 0;
    int new_size = 0;
    msgpack_unpacked result;
    msgpack_object map;
    msgpack_object root;
    size_t off = 0;
    (void) f_ins;
    (void) config;
    msgpack_sbuffer tmp_sbuf;
    msgpack_packer tmp_pck;

    /* Create temporary msgpack buffer */
    msgpack_sbuffer_init(&tmp_sbuf);
    msgpack_packer_init(&tmp_pck, &tmp_sbuf, msgpack_sbuffer_write);

    /* Iterate each item array and apply rules */
    msgpack_unpacked_init(&result);
    while (msgpack_unpack_next(&result, data, bytes, &off) == MSGPACK_UNPACK_SUCCESS) {
        root = result.data;
        if (root.type != MSGPACK_OBJECT_ARRAY) {
            continue;
        }

        old_size++;

        /* get time and map */
        map  = root.via.array.ptr[1];

        ret = grep_filter_data(map, context);
        if (ret == GREP_RET_KEEP) {
            msgpack_pack_object(&tmp_pck, root);
            new_size++;
        }
        else if (ret == GREP_RET_EXCLUDE) {
            /* Do nothing */
        }
    }
    msgpack_unpacked_destroy(&result);

    /* we keep everything ? */
    if (old_size == new_size) {
        /* Destroy the buffer to avoid more overhead */
        msgpack_sbuffer_destroy(&tmp_sbuf);
        return FLB_FILTER_NOTOUCH;
    }

    /* link new buffers */
    *out_buf   = tmp_sbuf.data;
    *out_size = tmp_sbuf.size;

    return FLB_FILTER_MODIFIED;
}

static int cb_grep_exit(void *data, struct flb_config *config)
{
    struct grep_ctx *ctx = data;

    if (!ctx) {
        return 0;
    }

    delete_rules(ctx);
    flb_free(ctx);
    return 0;
}

static struct flb_config_map config_map[] = {
    {
     FLB_CONFIG_MAP_SLIST_2, "regex", NULL,
     FLB_CONFIG_MAP_MULT, FLB_TRUE, offsetof(struct grep_ctx, regex_map),
     "Keep records in which the content of KEY matches the regular expression."
    },
    {
     FLB_CONFIG_MAP_SLIST_2, "exclude", NULL,
     FLB_CONFIG_MAP_MULT, FLB_TRUE, offsetof(struct grep_ctx, exclude_map),
     "Exclude records in which the content of KEY matches the regular expression."
    },
    {0}
};

struct flb_filter_plugin filter_grep_plugin = {
    .name         = "grep",
    .description  = "grep events by specified field values",
    .cb_init      = cb_grep_init,
    .cb_filter    = cb_grep_filter,
    .cb_exit      = cb_grep_exit,
    .config_map   = config_map,
    .flags        = 0
};
