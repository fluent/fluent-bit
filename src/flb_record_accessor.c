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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_env.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_slist.h>
#include <fluent-bit/flb_record_accessor.h>
#include <fluent-bit/flb_ra_key.h>
#include <fluent-bit/record_accessor/flb_ra_parser.h>
#include <monkey/mk_core.h>
#include <msgpack.h>

#include <ctype.h>

static struct flb_ra_parser *ra_parse_string(struct flb_record_accessor *ra,
                                             flb_sds_t buf, int start, int end)
{
    int len;
    struct flb_ra_parser *rp;

    len = end - start;
    rp = flb_ra_parser_string_create(buf + start, len);
    if (!rp) {
        return NULL;
    }

    return rp;
}

/* Create a parser context for a key map or function definition */
static struct flb_ra_parser *ra_parse_meta(struct flb_record_accessor *ra,
                                           flb_sds_t buf, int start, int end)
{
    int len;
    struct flb_ra_parser *rp;

    len = end - start;
    rp = flb_ra_parser_meta_create(buf + start, len);
    if (!rp) {
        return NULL;
    }

    return rp;
}

/*
 * Supported data
 *
 * ${X}                         => environment variable
 * $key, $key[x], $key[x][y][z] => record key value
 * $X()                         => built-in function
 */
static int ra_parse_buffer(struct flb_record_accessor *ra, flb_sds_t buf)
{
    int i;
    int n;
    int len;
    int pre = 0;
    int end = 0;
    struct flb_ra_parser *rp;
    struct flb_ra_parser *rp_str = NULL;

    len = flb_sds_len(buf);

    for (i = 0; i < len; i++) {
        if (buf[i] != '$') {
            continue;
        }

        n = i + 1;
        if (n >= len) {
            /* Finalize, nothing to do */
            break;
        }

        for (end = i + 1; end < len; end++) {
            if (buf[end] == ' ' || buf[end] == ',' || buf[end] == '"') {
                break;
            }
        }
        if (end > len) {
            end = len;
        }

        /* Parse the content, we use 'end' as the separator position  */
        rp = ra_parse_meta(ra, buf, i, end);
        if (!rp) {
            return -1;
        }

        /* Generate fixed length string */
        if (pre < i) {
            rp_str = ra_parse_string(ra, buf, pre, i);
            if (!rp_str) {
                flb_ra_parser_destroy(rp);
                return -1;
            }
        }
        else {
            rp_str = NULL;
        }

        if (rp_str) {
            mk_list_add(&rp_str->_head, &ra->list);
        }
        mk_list_add(&rp->_head, &ra->list);
        pre = end;
        i = end;
    }

    /* Append remaining string */
    if (i - 1 > end) {
        rp_str = ra_parse_string(ra, buf, pre, i);
        if (rp_str) {
            mk_list_add(&rp_str->_head, &ra->list);
        }
    }

    return 0;
}

void flb_ra_destroy(struct flb_record_accessor *ra)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_ra_parser *rp;

    mk_list_foreach_safe(head, tmp, &ra->list) {
        rp = mk_list_entry(head, struct flb_ra_parser, _head);
        mk_list_del(&rp->_head);
        flb_ra_parser_destroy(rp);
    }
    flb_free(ra);
}

struct flb_record_accessor *flb_ra_create(char *str)
{
    int ret;
    size_t hint = 0;
    flb_sds_t buf;
    struct flb_env *env;
    struct mk_list *head;
    struct flb_ra_parser *rp;
    struct flb_record_accessor *ra;

    /*
     * First step is to check if some environment variable has been created
     * as part of the string. Upon running the environment variable will be
     * pre-set in the string.
     */
    env = flb_env_create();
    if (!env) {
        flb_error("[record accessor] cannot create environment context");
        return NULL;
    }

    /* Translate string */
    buf = flb_env_var_translate(env, str);
    if (!buf) {
        flb_error("[record accessor] cannot translate string");
        flb_env_destroy(env);
        return NULL;
    }
    flb_env_destroy(env);

    /* Allocate context */
    ra = flb_malloc(sizeof(struct flb_record_accessor));
    if (!ra) {
        flb_errno();
        flb_error("[record accessor] cannot create context");
        flb_env_destroy(env);
        flb_sds_destroy(buf);
        return NULL;
    }
    mk_list_init(&ra->list);
    flb_slist_create(&ra->list);

    /*
     * The buffer needs to processed where we create a list of parts, basically
     * a linked list of sds using 'slist' api.
     */
    ret = ra_parse_buffer(ra, buf);
    flb_sds_destroy(buf);
    if (ret == -1) {
        flb_ra_destroy(ra);
        return NULL;
    }

    /* Calculate a hint of an outgoing size buffer */
    mk_list_foreach(head, &ra->list) {
        rp = mk_list_entry(head, struct flb_ra_parser, _head);
        if (rp->key) {
            hint += flb_sds_len(rp->key->name);
        }
    }
    ra->size_hint = hint + 128;
    return ra;
}

void flb_ra_dump(struct flb_record_accessor *ra)
{
    struct mk_list *head;
    struct flb_ra_parser *rp;

    mk_list_foreach(head, &ra->list) {
        rp = mk_list_entry(head, struct flb_ra_parser, _head);
        printf("\n");
        flb_ra_parser_dump(rp);
    }
}

static flb_sds_t ra_translate_string(struct flb_ra_parser *rp, flb_sds_t buf)
{
    flb_sds_t tmp;

    tmp = flb_sds_cat(buf, rp->key->name, flb_sds_len(rp->key->name));
    return tmp;
}

static flb_sds_t ra_translate_keymap(struct flb_ra_parser *rp, flb_sds_t buf,
                                     msgpack_object map, int *found)
{
    char str[32];
    int len;
    flb_sds_t tmp = NULL;
    struct flb_ra_value *v;

    /* Lookup key or subkey value */
    v = flb_ra_key_to_value(rp->key->name, map, rp->key->subkeys);
    if (!v) {
        *found = FLB_FALSE;
        return buf;
    }
    else {
        *found = FLB_TRUE;
    }

    /* Based on data type, convert to it string representation */
    if (v->type == FLB_RA_BOOL) {
        if (v->val.boolean) {
            tmp = flb_sds_cat(buf, "true", 4);
        }
        else {
            tmp = flb_sds_cat(buf, "false", 5);
        }
    }
    else if (v->type == FLB_RA_INT) {
        len = snprintf(str, sizeof(str) - 1, "%" PRId64, v->val.i64);
        tmp = flb_sds_cat(buf, str, len);
    }
    else if (v->type == FLB_RA_FLOAT) {
        len = snprintf(str, sizeof(str) - 1, "%f", v->val.f64);
        tmp = flb_sds_cat(buf, str, len);
    }
    else if (v->type == FLB_RA_STRING) {
        tmp = flb_sds_cat(buf, v->val.string, flb_sds_len(v->val.string));
    }
    else if (v->type == FLB_RA_NULL) {
        tmp = flb_sds_cat(buf, "null", 4);
    }

    flb_ra_key_value_destroy(v);
    return tmp;
}

/*
 * Translate a record accessor buffer, tag and records are optional
 * parameters.
 *
 * For safety, the function returns a newly created string that needs
 * to be destroyed by the caller.
 */
flb_sds_t flb_ra_translate(struct flb_record_accessor *ra,
                           char *tag, int tag_len,
                           msgpack_object map)
{
    int found;
    flb_sds_t tmp;
    flb_sds_t buf;
    struct mk_list *head;
    struct flb_ra_parser *rp;

    buf = flb_sds_create_size(ra->size_hint);
    if (!buf) {
        flb_error("[record accessor] cannot create outgoing buffer");
        return NULL;
    }

    mk_list_foreach(head, &ra->list) {
        rp = mk_list_entry(head, struct flb_ra_parser, _head);
        if (rp->type == FLB_RA_PARSER_STRING) {
            tmp = ra_translate_string(rp, buf);
        }
        else if (rp->type == FLB_RA_PARSER_KEYMAP) {
            tmp = ra_translate_keymap(rp, buf, map, &found);
        }
        //else if (rp->type == FLB_RA_PARSER_FUNC) {
            //tmp = ra_translate_func(rp, buf, tag, tag_len);
        //}

        if (!tmp) {
            flb_error("[record accessor] translation failed");
            flb_sds_destroy(buf);
            return NULL;
        }
        if (tmp != buf) {
            buf = tmp;
        }
    }

    return buf;
}
