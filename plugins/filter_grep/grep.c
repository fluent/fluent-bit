/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2017 Treasure Data Inc.
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
#include <regex.h>

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_str.h>
#include <fluent-bit/flb_filter.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_pack.h>
#include <msgpack.h>

#include "grep.h"

static void delete_rules(struct grep_ctx *ctx)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct grep_rule *rule;

    mk_list_foreach_safe(head, tmp, &ctx->rules) {
        rule = mk_list_entry(head, struct grep_rule, _head);
        flb_free(rule->field);
        flb_free(rule->regex);
        regfree(&rule->match);
        mk_list_del(&rule->_head);
        flb_free(rule);
    }
}

static int str_to_regex(char *str, regex_t *reg)
{
    int ret;
    char tmp[80];
    char *p = str;

    while (*p) {
        if (*p == ' ') *p = '|';
        p++;
    }

    ret = regcomp(reg, str, REG_EXTENDED|REG_ICASE|REG_NOSUB);
    if (ret) {
        regerror(ret, reg, tmp, sizeof(tmp));
        flb_error("[filter_grep]: Failed to compile regex: %s", tmp);
        return -1;
    }

    return 0;
}

static int set_rules(struct grep_ctx *ctx, struct flb_filter_instance *f_ins)
{
    struct mk_list *head;
    struct mk_list *split;
    struct flb_split_entry *sentry;
    struct flb_config_prop *prop;
    struct grep_rule *rule;

    /* Iterate all filter properties */
    mk_list_foreach(head, &f_ins->properties) {
        prop = mk_list_entry(head, struct flb_config_prop, _head);

        /* Create a new rule */
        rule = flb_malloc(sizeof(struct grep_rule));
        if (!rule) {
            flb_errno();
            return -1;
        }

        /* Get the type */
        if (strcasecmp(prop->key, "regex") == 0) {
            rule->type = GREP_REGEX;
        }
        else if (strcasecmp(prop->key, "exclude") == 0) {
            rule->type = GREP_EXCLUDE;
        }
        else {
            delete_rules(ctx);
            flb_free(rule);
            return -1;
        }

        /* As a value we expect a pair of field name and a regular expression */
        split = flb_utils_split(prop->val, ' ', 1);
        if (mk_list_size(split) != 2) {
            flb_error("[filter_grep] invalid regex, expected field and regular expression");
            delete_rules(ctx);
            flb_free(rule);
            flb_utils_split_free(split);
            return -1;
        }

        /* Get first value (field) */
        sentry = mk_list_entry_first(split, struct flb_split_entry, _head);
        rule->field = flb_strndup(sentry->value, sentry->len);

        /* Get remaining content (regular expression) */
        sentry = mk_list_entry_last(split, struct flb_split_entry, _head);
        rule->regex = flb_strndup(sentry->value, sentry->len);

        /* Release split */
        flb_utils_split_free(split);

        /* Convert string to regex pattern */
        str_to_regex(rule->regex, &rule->match);

        /* Link to parent list */
        mk_list_add(&rule->_head, &ctx->rules);
    }

    return 0;
}

/* Given a msgpack record, do some filter action based on the defined rules */
static inline int grep_filter_data(msgpack_object map, struct grep_ctx *ctx)
{
    int i;
    int ret;
    int klen;
    int vlen;
    char *key;
    char *val;
    msgpack_object *k;
    msgpack_object *v;
    struct mk_list *head;
    struct grep_rule *rule;

    /* For each rule, validate against map fields */
    mk_list_foreach(head, &ctx->rules) {
        rule = mk_list_entry(head, struct grep_rule, _head);

        /* Lookup target key/value */
        for (i = 0; i < map.via.map.size; i++) {
            k = &map.via.map.ptr[i].key;

            if (k->type != MSGPACK_OBJECT_BIN &&
                k->type != MSGPACK_OBJECT_STR) {
                continue;
            }

            if (k->type == MSGPACK_OBJECT_STR) {
                key  = (char *) k->via.str.ptr;
                klen = k->via.str.size;
            }
            else {
                key = (char *) k->via.bin.ptr;
                klen = k->via.bin.size;
            }

            if (strncmp(key, rule->field, klen) == 0) {
                break;
            }

            k = NULL;
        }

        /* If the key don't exists, take an action */
        if (!k) {
            if (rule->type == GREP_REGEX) {
                return GREP_RET_EXCLUDE;
            }
            else if (rule->type == GREP_EXCLUDE) {
                return GREP_RET_KEEP;
            }
        }

        /* Based on the value of the key, do the regex */
        v = &map.via.map.ptr[i].val;

        /* a value must be a string */
        if (v->type == MSGPACK_OBJECT_STR) {
            val  = (char *)v->via.str.ptr;
            vlen = v->via.str.size;
        }
        else if(v->type == MSGPACK_OBJECT_BIN) {
            val  = (char *)v->via.bin.ptr;
            vlen = v->via.bin.size;
        }
        else {
            return GREP_RET_EXCLUDE;
        }

        /* FIXME: regexec() don't allow to set the length of the string
         * to match, we are forced to create a new temporal buffer.
         *
         * The fix is to move to the new flb_regex() interface.
         */
        char *tmp = flb_malloc(vlen + 1);
        memcpy(tmp, val, vlen );
        tmp[vlen] = '\0';

        ret = regexec(&rule->match, tmp, 0, NULL, 0);
        flb_free(tmp);

        if (ret != 0) { /* no match */
            if (rule->type == GREP_REGEX) {
                return GREP_RET_EXCLUDE;
            }
        }
        else {
            if (rule->type == GREP_EXCLUDE) {
                return GREP_RET_EXCLUDE;
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

    /* Create context */
    ctx = flb_malloc(sizeof(struct grep_ctx));
    if (!ctx) {
        flb_errno();
        return -1;
    }
    mk_list_init(&ctx->rules);

    /* Load rules */
    ret = set_rules(ctx, f_ins);
    if (ret == -1) {
        flb_free(ctx);
        return -1;
    }

    /* Set our context */
    flb_filter_set_context(f_ins, ctx);
    return 0;
}

static int cb_grep_filter(void *data, size_t bytes,
                          char *tag, int tag_len,
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

    /* Create temporal msgpack buffer */
    msgpack_sbuffer_init(&tmp_sbuf);
    msgpack_packer_init(&tmp_pck, &tmp_sbuf, msgpack_sbuffer_write);

    /* Iterate each item array and apply rules */
    msgpack_unpacked_init(&result);
    while (msgpack_unpack_next(&result, data, bytes, &off)) {
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

    delete_rules(ctx);
    flb_free(ctx);
    return 0;
}

struct flb_filter_plugin filter_grep_plugin = {
    .name         = "grep",
    .description  = "grep events by specified field values",
    .cb_init      = cb_grep_init,
    .cb_filter    = cb_grep_filter,
    .cb_exit      = cb_grep_exit,
    .flags        = 0
};
