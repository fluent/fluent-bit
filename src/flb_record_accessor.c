/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2020 The Fluent Bit Authors
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

static struct flb_ra_parser *ra_parse_regex_id(struct flb_record_accessor *ra,
                                               int c)
{
    struct flb_ra_parser *rp;

    rp = flb_ra_parser_regex_id_create(c);
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
 * $0, $1,..$9                  => regex id
 * $X()                         => built-in function
 */
static int ra_parse_buffer(struct flb_record_accessor *ra, flb_sds_t buf)
{
    int i;
    int n;
    int c;
    int t;
    int len;
    int pre = 0;
    int end = 0;
    int quote_cnt;
    struct flb_ra_parser *rp;
    struct flb_ra_parser *rp_str = NULL;

    len = flb_sds_len(buf);

    for (i = 0; i < len; i++) {
        if (buf[i] != '$') {
            continue;
        }

        /*
         * Before to add the number entry, add the previous text
         * before hitting this.
         */
        if (i > pre) {
            rp = ra_parse_string(ra, buf, pre, i);
            if (!rp) {
                return -1;
            }
            mk_list_add(&rp->_head, &ra->list);
        }
        pre = i;


        n = i + 1;
        if (n >= len) {
            /* Finalize, nothing to do */
            break;
        }

        /*
         * If the next character is a digit like $0,$1,$2..$9, means the user wants to use
         * the result of a regex capture.
         *
         * We support up to 10 regex ids [0-9]
         */
        if (isdigit(buf[n])) {
            /* Add REGEX_ID entry */
            c = atoi(buf + n);
            rp = ra_parse_regex_id(ra, c);
            if (!rp) {
                return -1;
            }

            mk_list_add(&rp->_head, &ra->list);
            i++;
            pre = i + 1;
            continue;
        }

        /*
         * If the next 3 character are 'TAG', the user might want to include the tag or
         * part of it (e.g: TAG[n]).
         */
        if (n + 2 < len && strncmp(buf + n, "TAG", 3) == 0) {
            /* Check if some [] was added */
            if (n + 4 < len) {
                end = -1;
                if (buf[n + 3] == '[') {
                    t = n + 3;

                    /* Look for the ending ']' */
                    end = mk_string_char_search(buf + t, ']', len - t);
                    if (end == 0) {
                        end = -1;
                    }

                    /* continue processsing */
                    c = atoi(buf + t + 1);

                    rp = flb_ra_parser_tag_part_create(c);
                    if (!rp) {
                        return -1;
                    }
                    mk_list_add(&rp->_head, &ra->list);

                    i = t + end + 1;
                    pre = i;
                    continue;
                }
            }

            /* Append full tag */
            rp = flb_ra_parser_tag_create();
            if (!rp) {
                return -1;
            }
            mk_list_add(&rp->_head, &ra->list);
            i = n + 3;
            pre = n + 3;
            continue;
        }

        quote_cnt = 0;
        for (end = i + 1; end < len; end++) {
            if (buf[end] == '\'') {
              ++quote_cnt;
            }
            else if (buf[end] == '.' && (quote_cnt & 0x01)) {
              // ignore '.' if it is inside a string/subkey
              continue;
            }
            else if (buf[end] == '.' || buf[end] == ' ' || buf[end] == ',' || buf[end] == '"') {
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
    if (i - 1 > end && pre < i) {
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

struct flb_record_accessor *flb_ra_create(char *str, int translate_env)
{
    int ret;
    size_t hint = 0;
    char *p;
    flb_sds_t buf = NULL;
    struct flb_env *env;
    struct mk_list *head;
    struct flb_ra_parser *rp;
    struct flb_record_accessor *ra;

    p = str;
    if (translate_env == FLB_TRUE) {
        /*
         * Check if some environment variable has been created as part of the
         * string. Upon running the environment variable will be pre-set in the
         * string.
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
        p = buf;
    }

    /* Allocate context */
    ra = flb_malloc(sizeof(struct flb_record_accessor));
    if (!ra) {
        flb_errno();
        flb_error("[record accessor] cannot create context");
        if (buf) {
            flb_sds_destroy(buf);
        }
        return NULL;
    }
    mk_list_init(&ra->list);
    flb_slist_create(&ra->list);

    /*
     * The buffer needs to processed where we create a list of parts, basically
     * a linked list of sds using 'slist' api.
     */
    ret = ra_parse_buffer(ra, p);
    if (buf) {
        flb_sds_destroy(buf);
    }
    if (ret == -1) {
        flb_ra_destroy(ra);
        return NULL;
    }

    /* Calculate a hint of an outgoing size buffer */
    mk_list_foreach(head, &ra->list) {
        rp = mk_list_entry(head, struct flb_ra_parser, _head);
        if (rp->key) {
            if (rp->type == FLB_RA_PARSER_REGEX_ID) {
                hint += 32;
            }
            else {
                hint += flb_sds_len(rp->key->name);
            }
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

static flb_sds_t ra_translate_regex_id(struct flb_ra_parser *rp,
                                       struct flb_regex_search *result,
                                       flb_sds_t buf)
{
    int ret;
    ptrdiff_t start;
    ptrdiff_t end;
    flb_sds_t tmp;

    ret = flb_regex_results_get(result, rp->id, &start, &end);
    if (ret == -1) {
        return buf;
    }

    tmp = flb_sds_cat(buf, result->str + start, end - start);
    return tmp;
}

static flb_sds_t ra_translate_tag(struct flb_ra_parser *rp, flb_sds_t buf,
                                  char *tag, int tag_len)
{
    flb_sds_t tmp;

    tmp = flb_sds_cat(buf, tag, tag_len);
    return tmp;
}

static flb_sds_t ra_translate_tag_part(struct flb_ra_parser *rp, flb_sds_t buf,
                                       char *tag, int tag_len)
{
    int i = 0;
    int id = -1;
    int end;
    flb_sds_t tmp = buf;

    while (i < tag_len) {
        end = mk_string_char_search(tag + i, '.', tag_len - i);
        if (end == -1) {
            if (i == 0) {
                break;
            }
            end = tag_len - i;
        }
        id++;
        if (rp->id == id) {
            tmp = flb_sds_cat(buf, tag + i, end);
            break;
        }

        i += end + 1;
    }

    /* No dots in the tag */
    if (rp->id == 0 && id == -1 && i < tag_len) {
        tmp = flb_sds_cat(buf, tag, tag_len);
        return tmp;
    }

    return tmp;
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
                           msgpack_object map, struct flb_regex_search *result)
{
    int found;
    flb_sds_t tmp = NULL;
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
        else if (rp->type == FLB_RA_PARSER_REGEX_ID && result) {
            tmp = ra_translate_regex_id(rp, result, buf);
        }
        else if (rp->type == FLB_RA_PARSER_TAG) {
            tmp = ra_translate_tag(rp, buf, tag, tag_len);
        }
        else if (rp->type == FLB_RA_PARSER_TAG_PART) {
            tmp = ra_translate_tag_part(rp, buf, tag, tag_len);
        }
        else {

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

/*
 * Compare a string value against the first entry of a record accessor component, used
 * specifically when the record accessor refers to a single key name.
 */
int flb_ra_strcmp(struct flb_record_accessor *ra, msgpack_object map,
                  char *str, int len)
{
    struct flb_ra_parser *rp;

    rp = mk_list_entry_first(&ra->list, struct flb_ra_parser, _head);
    return flb_ra_key_strcmp(rp->key->name, map, rp->key->subkeys,
                             rp->key->name, flb_sds_len(rp->key->name));
}

/*
 * Check if a regular expression matches a record accessor key in the
 * given map
 */
int flb_ra_regex_match(struct flb_record_accessor *ra, msgpack_object map,
                       struct flb_regex *regex, struct flb_regex_search *result)
{
    struct flb_ra_parser *rp;

    rp = mk_list_entry_first(&ra->list, struct flb_ra_parser, _head);
    return flb_ra_key_regex_match(rp->key->name, map, rp->key->subkeys,
                                  regex, result);
}

struct flb_ra_value *flb_ra_get_value_object(struct flb_record_accessor *ra,
                                             msgpack_object map)
{
    struct flb_ra_parser *rp;

    if (mk_list_size(&ra->list) == 0) {
        return NULL;
    }

    rp = mk_list_entry_first(&ra->list, struct flb_ra_parser, _head);
    return flb_ra_key_to_value(rp->key->name, map, rp->key->subkeys);
}
