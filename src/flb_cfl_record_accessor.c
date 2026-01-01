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
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_env.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_sds_list.h>
#include <fluent-bit/flb_cfl_record_accessor.h>
#include <fluent-bit/flb_cfl_ra_key.h>
#include <fluent-bit/record_accessor/flb_ra_parser.h>
#include <monkey/mk_core.h>

#include <ctype.h>

static struct flb_ra_parser *cfl_ra_parse_string(struct flb_cfl_record_accessor *cra,
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
static struct flb_ra_parser *cfl_ra_parse_meta(struct flb_cfl_record_accessor *cra,
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
 * ${X}                               => environment variable
 * $key, $key['x'], $key['x'][N]['z'] => record key value or array index
 * $0, $1,..$9                        => regex id
 * $X()                               => built-in function
 */
static int cfl_ra_parse_buffer(struct flb_cfl_record_accessor *cra, flb_sds_t buf)
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
            rp = cfl_ra_parse_string(cra, buf, pre, i);
            if (!rp) {
                return -1;
            }
            mk_list_add(&rp->_head, &cra->list);
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
            rp = flb_ra_parser_regex_id_create(c);
            if (!rp) {
                return -1;
            }

            mk_list_add(&rp->_head, &cra->list);
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
                    mk_list_add(&rp->_head, &cra->list);

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
            mk_list_add(&rp->_head, &cra->list);
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
                /* ignore '.' if it is inside a string/subkey */
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
        rp = cfl_ra_parse_meta(cra, buf, i, end);
        if (!rp) {
            return -1;
        }

        /* Generate fixed length string */
        if (pre < i) {
            rp_str = cfl_ra_parse_string(cra, buf, pre, i);
            if (!rp_str) {
                flb_ra_parser_destroy(rp);
                return -1;
            }
        }
        else {
            rp_str = NULL;
        }

        if (rp_str) {
            mk_list_add(&rp_str->_head, &cra->list);
        }
        mk_list_add(&rp->_head, &cra->list);
        pre = end;
        i = end;
    }

    /* Append remaining string */
    if ((i - 1 > end && pre < i) || i == 1 /*allow single character*/) {
        end = flb_sds_len(buf);
        rp_str = cfl_ra_parse_string(cra, buf, pre, end);
        if (rp_str) {
            mk_list_add(&rp_str->_head, &cra->list);
        }
    }

    return 0;
}

void flb_cfl_ra_destroy(struct flb_cfl_record_accessor *cra)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_ra_parser *rp;

    mk_list_foreach_safe(head, tmp, &cra->list) {
        rp = mk_list_entry(head, struct flb_ra_parser, _head);
        mk_list_del(&rp->_head);
        flb_ra_parser_destroy(rp);
    }

    if (cra->pattern) {
        flb_sds_destroy(cra->pattern);
    }
    flb_free(cra);
}

int flb_cfl_ra_subkey_count(struct flb_cfl_record_accessor *cra)
{
    struct mk_list *head;
    struct flb_ra_parser *rp;
    int ret = -1;
    int tmp;

    if (cra == NULL) {
        return -1;
    }
    mk_list_foreach(head, &cra->list) {
        rp = mk_list_entry(head, struct flb_ra_parser, _head);
        tmp = flb_ra_parser_subkey_count(rp);
        if (tmp > ret) {
            ret = tmp;
        }
    }

    return ret;
}

struct flb_cfl_record_accessor *flb_cfl_ra_create(char *str, int translate_env)
{
    int ret;
    size_t hint = 0;
    char *p;
    flb_sds_t buf = NULL;
    flb_sds_t tmp_str;
    struct flb_env *env;
    struct mk_list *head;
    struct flb_ra_parser *rp;
    struct flb_cfl_record_accessor *cra;

    /* temporary copy of 'str' to workaround potential issues literal parsing */
    tmp_str = flb_sds_create(str);
    if (!tmp_str) {
        flb_error("[cfl record accessor] cannot allocate temporary buffer");
        return NULL;
    }

    p = tmp_str;
    if (translate_env == FLB_TRUE) {
        /*
         * Check if some environment variable has been created as part of the
         * string. Upon running the environment variable will be pre-set in the
         * string.
         */
        env = flb_env_create();
        if (!env) {
            flb_error("[cfl record accessor] cannot create environment context");
            flb_sds_destroy(tmp_str);
            return NULL;
        }

        /* Translate string */
        buf = flb_env_var_translate(env, str);
        if (!buf) {
            flb_error("[cfl record accessor] cannot translate string");
            flb_env_destroy(env);
            flb_sds_destroy(tmp_str);
            return NULL;
        }
        flb_env_destroy(env);
        p = buf;
    }

    /* Allocate context */
    cra = flb_calloc(1, sizeof(struct flb_cfl_record_accessor));
    if (!cra) {
        flb_errno();
        flb_error("[cfl record accessor] cannot create context");
        if (buf) {
            flb_sds_destroy(buf);
        }
        flb_sds_destroy(tmp_str);
        return NULL;
    }

    cra->pattern = tmp_str;
    mk_list_init(&cra->list);

    /*
     * The buffer needs to processed where we create a list of parts, basically
     * a linked list of sds using 'slist' api.
     */
    ret = cfl_ra_parse_buffer(cra, p);
    if (buf) {
        flb_sds_destroy(buf);
    }
    if (ret == -1) {
        flb_cfl_ra_destroy(cra);
        return NULL;
    }

    /* Calculate a hint of an outgoing size buffer */
    mk_list_foreach(head, &cra->list) {
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
    cra->size_hint = hint + 128;
    return cra;
}

/*
  flb_ra_create_str_from_list returns record accessor string from string list.
  e.g. {"aa", "bb", "cc", NULL} -> "$aa['bb']['cc']"
  Return value should be freed using flb_sds_destroy after using.
*/
flb_sds_t flb_cfl_ra_create_str_from_list(struct flb_sds_list *str_list)
{
    int i = 0;
    int ret_i = 0;
    int offset = 0;

    char *fmt = NULL;
    char **strs = NULL;
    flb_sds_t str;
    flb_sds_t tmp_sds;

    if (str_list == NULL || flb_sds_list_size(str_list) == 0) {
        return NULL;
    }

    str = flb_sds_create_size(256);
    if (str == NULL) {
        flb_errno();
        return NULL;
    }

    strs = flb_sds_list_create_str_array(str_list);
    if (strs == NULL) {
        flb_error("%s flb_sds_list_create_str_array failed", __FUNCTION__);
        flb_sds_destroy(str);
        return NULL;
    }

    while(strs[i] != NULL) {
        if (i == 0) {
            fmt = "$%s";
        }
        else {
            fmt = "['%s']";
        }

        ret_i = snprintf(str+offset, flb_sds_alloc(str)-offset-1, fmt, strs[i]);
        if (ret_i > flb_sds_alloc(str)-offset-1) {
            tmp_sds = flb_sds_increase(str, ret_i);
            if (tmp_sds == NULL) {
                flb_errno();
                flb_sds_list_destroy_str_array(strs);
                flb_sds_destroy(str);
                return NULL;
            }
            str = tmp_sds;
            ret_i = snprintf(str+offset, flb_sds_alloc(str)-offset-1, fmt, strs[i]);
            if (ret_i > flb_sds_alloc(str)-offset-1) {
                flb_errno();
                flb_sds_list_destroy_str_array(strs);
                flb_sds_destroy(str);
                return NULL;
            }
        }
        offset += ret_i;
        i++;
    }
    flb_sds_list_destroy_str_array(strs);

    return str;
}

struct flb_cfl_record_accessor *flb_cfl_ra_create_from_list(struct flb_sds_list *str_list, int translate_env)
{
    flb_sds_t tmp = NULL;
    struct flb_cfl_record_accessor *ret = NULL;

    tmp = flb_cfl_ra_create_str_from_list(str_list);
    if (tmp == NULL) {
        flb_errno();
        return NULL;
    }

    ret = flb_cfl_ra_create(tmp, translate_env);
    flb_sds_destroy(tmp);

    return ret;
}

void flb_cfl_ra_dump(struct flb_cfl_record_accessor *cra)
{
    struct mk_list *head;
    struct flb_ra_parser *rp;

    mk_list_foreach(head, &cra->list) {
        rp = mk_list_entry(head, struct flb_ra_parser, _head);
        printf("\n");
        flb_ra_parser_dump(rp);
    }
}

static flb_sds_t cfl_ra_translate_regex_id(struct flb_ra_parser *rp,
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

static flb_sds_t cfl_ra_translate_tag(struct flb_ra_parser *rp, flb_sds_t buf,
                                      char *tag, int tag_len)
{
    flb_sds_t tmp;

    tmp = flb_sds_cat(buf, tag, tag_len);
    return tmp;
}

static flb_sds_t cfl_ra_translate_tag_part(struct flb_ra_parser *rp, flb_sds_t buf,
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

static flb_sds_t cfl_ra_translate_string(struct flb_ra_parser *rp, flb_sds_t buf)
{
    flb_sds_t tmp;

    tmp = flb_sds_cat(buf, rp->key->name, flb_sds_len(rp->key->name));
    return tmp;
}

static int cfl_to_json(struct cfl_variant *var, flb_sds_t buf)
{
    int i = 0;
    int ret;
    int loop = 0;
    struct cfl_list *head;
    struct cfl_kvpair *kv;
    struct cfl_kvlist *kvlist;

    switch (var->type) {
    case CFL_VARIANT_NULL:
        flb_sds_cat_safe(&buf, "null", 4);
        break;
    case CFL_VARIANT_BOOL:
        if (var->data.as_bool) {
            flb_sds_cat_safe(&buf, "true", 4);
        }
        else {
            flb_sds_cat_safe(&buf, "false", 5);
        }
        break;
    case CFL_VARIANT_INT: {
        char tmp[32] = {0};
        i = snprintf(tmp, sizeof(tmp)-1, "%"PRId64, var->data.as_int64);
        flb_sds_cat_safe(&buf, tmp, i);
        break;
    }
    case CFL_VARIANT_UINT: {
        char tmp[32] = {0};
        i = snprintf(tmp, sizeof(tmp)-1, "%"PRIu64, var->data.as_uint64);
        flb_sds_cat_safe(&buf, tmp, i);
        break;
    }
    case CFL_VARIANT_DOUBLE: {
        char tmp[512] = {0};
        i = snprintf(tmp, sizeof(tmp)-1, "%"PRIu64, var->data.as_uint64);
        flb_sds_cat_safe(&buf, tmp, i);
        break;
    }
    case CFL_VARIANT_STRING:
        flb_sds_cat_safe(&buf, "\"", 1);
        flb_sds_cat_safe(&buf, var->data.as_string, cfl_sds_len(var->data.as_string));
        flb_sds_cat_safe(&buf, "\"", 1);
        break;
    case CFL_VARIANT_BYTES:
        flb_sds_cat_safe(&buf, "\"", 1);
        flb_sds_cat_safe(&buf, var->data.as_string, cfl_sds_len(var->data.as_bytes));
        flb_sds_cat_safe(&buf, "\"", 1);
        break;
    case CFL_VARIANT_ARRAY: {
        struct cfl_array *array = var->data.as_array;
        loop = cfl_array_size(array);

        flb_sds_cat_safe(&buf, "[", 1);
        if (loop != 0) {
            for (i = 0; i < loop - 1; i++) {
                cfl_to_json(array->entries[i], buf);
                flb_sds_cat_safe(&buf, ",", 1);
            }
        }
        cfl_to_json(array->entries[loop-1], buf);
        flb_sds_cat_safe(&buf, "]", 1);
        break;
    }
    case CFL_VARIANT_KVLIST:
        kvlist = var->data.as_kvlist;
        flb_sds_cat_safe(&buf, "{", 1);
        cfl_list_foreach(head, &kvlist->list) {
            kv = cfl_list_entry(head, struct cfl_kvpair, _head);

            /* key */
            flb_sds_cat_safe(&buf, "\"", 1);
            flb_sds_cat_safe(&buf, kv->key, cfl_sds_len(kv->key));
            flb_sds_cat_safe(&buf, "\"", 1);

            /* separator */
            flb_sds_cat_safe(&buf, ":", 1);

            /* value */
            ret = cfl_to_json(kv->val, buf);
            if (ret == -1) {
                return -1;
            }
            break;
        }
        flb_sds_cat_safe(&buf, "}", 1);
    }

    return 0;
}

static flb_sds_t cfl_ra_translate_keymap(struct flb_ra_parser *rp, flb_sds_t buf,
                                         struct cfl_variant vobj, int *found)
{
    int ret;
    int len;
    char *js;
    char str[32];
    flb_sds_t tmp = NULL;
    struct flb_cfl_ra_value *crv;

    /* Lookup key or subkey value */
    if (rp->key == NULL) {
        *found = FLB_FALSE;
        return buf;
    }

    crv = flb_cfl_ra_key_to_value(rp->key->name, vobj, rp->key->subkeys);
    if (!crv) {
        *found = FLB_FALSE;
        return buf;
    }
    else {
        *found = FLB_TRUE;
    }

    /* Based on data type, convert to it string representation */
    if (crv->type == FLB_CFL_RA_BOOL) {
        /* Check if is a kvlist or a real bool */
        if (crv->v.type == CFL_VARIANT_KVLIST) {
            js = flb_sds_create_size(1024);
            /* Convert cfl_variant to JSON string */
            ret = cfl_to_json(&crv->v, js);
            if (ret == -1) {
                len = strlen(js);
                tmp = flb_sds_cat(buf, js, len);
                flb_free(js);
            }
        }
        else if (crv->v.type == CFL_VARIANT_BOOL) {
            if (crv->val.boolean) {
                tmp = flb_sds_cat(buf, "true", 4);
            }
            else {
                tmp = flb_sds_cat(buf, "false", 5);
            }
        }
    }
    else if (crv->type == FLB_CFL_RA_INT) {
        len = snprintf(str, sizeof(str) - 1, "%" PRId64, crv->val.i64);
        tmp = flb_sds_cat(buf, str, len);
    }
    else if (crv->type == FLB_CFL_RA_FLOAT) {
        len = snprintf(str, sizeof(str) - 1, "%f", crv->val.f64);
        if (len >= sizeof(str)) {
            tmp = flb_sds_cat(buf, str, sizeof(str)-1);
        }
        else {
            tmp = flb_sds_cat(buf, str, len);
        }
    }
    else if (crv->type == FLB_CFL_RA_STRING) {
        tmp = flb_sds_cat(buf, crv->val.string, crv->v.size);
    }
    else if (crv->type == FLB_CFL_RA_NULL) {
        tmp = flb_sds_cat(buf, "null", 4);
    }

    flb_cfl_ra_key_value_destroy(crv);
    return tmp;
}

/*
 * Translate a cfl record accessor buffer, tag and records are optional
 * parameters.
 *
 * For safety, the function returns a newly created string that needs
 * to be destroyed by the caller.
 */
flb_sds_t flb_cfl_ra_translate(struct flb_cfl_record_accessor *cra,
                               char *tag, int tag_len,
                               struct cfl_variant var, struct flb_regex_search *result)
{
    return flb_cfl_ra_translate_check(cra, tag, tag_len, var, result, FLB_FALSE);
}

/*
 * Translate a cfl record accessor buffer, tag and records are optional
 * parameters.
 *
 * For safety, the function returns a newly created string that needs
 * to be destroyed by the caller.
 *
 * Returns NULL if `check` is FLB_TRUE and any key lookup in the record failed
 */
flb_sds_t flb_cfl_ra_translate_check(struct flb_cfl_record_accessor *cra,
                                     char *tag, int tag_len,
                                     struct cfl_variant var, struct flb_regex_search *result,
                                     int check)
{
    flb_sds_t tmp = NULL;
    flb_sds_t buf;
    struct mk_list *head;
    struct flb_ra_parser *rp;
    int found = FLB_FALSE;

    buf = flb_sds_create_size(cra->size_hint);
    if (!buf) {
        flb_error("[cfl record accessor] cannot create outgoing buffer");
        return NULL;
    }

    mk_list_foreach(head, &cra->list) {
        rp = mk_list_entry(head, struct flb_ra_parser, _head);
        if (rp->type == FLB_RA_PARSER_STRING) {
            tmp = cfl_ra_translate_string(rp, buf);
        }
        else if (rp->type == FLB_RA_PARSER_KEYMAP) {
            tmp = cfl_ra_translate_keymap(rp, buf, var, &found);
            if (check == FLB_TRUE && found == FLB_FALSE) {
                flb_warn("[cfl record accessor] translation failed, root key=%s", rp->key->name);
                flb_sds_destroy(buf);
                return NULL;
            }
        }
        else if (rp->type == FLB_RA_PARSER_REGEX_ID && result) {
            tmp = cfl_ra_translate_regex_id(rp, result, buf);
        }
        else if (rp->type == FLB_RA_PARSER_TAG && tag) {
            tmp = cfl_ra_translate_tag(rp, buf, tag, tag_len);
        }
        else if (rp->type == FLB_RA_PARSER_TAG_PART && tag) {
            tmp = cfl_ra_translate_tag_part(rp, buf, tag, tag_len);
        }

        /* else if (rp->type == FLB_RA_PARSER_FUNC) { */
        /*     tmp = cfl_ra_translate_func(rp, buf, tag, tag_len); */
        /* } */

        if (!tmp) {
            flb_error("[cfl record accessor] translation failed");
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
 * If the cfl record accessor rules do not generate content based on a keymap or
 * regex, it's considered to be 'static', so the value returned will always be
 * the same.
 *
 * If the 'ra' is static, return FLB_TRUE, otherwise FLB_FALSE.
 */
int flb_cfl_ra_is_static(struct flb_cfl_record_accessor *cra)
{
    struct mk_list *head;
    struct flb_ra_parser *rp;

    mk_list_foreach(head, &cra->list) {
        rp = mk_list_entry(head, struct flb_ra_parser, _head);
        if (rp->type == FLB_RA_PARSER_STRING) {
            continue;
        }
        else if (rp->type == FLB_RA_PARSER_KEYMAP) {
            return FLB_FALSE;
        }
        else if (rp->type == FLB_RA_PARSER_REGEX_ID) {
            return FLB_FALSE;
        }
        else if (rp->type == FLB_RA_PARSER_TAG) {
            continue;
        }
        else if (rp->type == FLB_RA_PARSER_TAG_PART) {
            continue;
        }
    }

    return FLB_TRUE;
}

/*
 * Compare a string value against the first entry of a record accessor component, used
 * specifically when the record accessor refers to a single key name.
 */
int flb_cfl_ra_strcmp(struct flb_cfl_record_accessor *ra, struct cfl_variant var,
                      char *str, int len)
{
    struct flb_ra_parser *rp;

    rp = mk_list_entry_first(&ra->list, struct flb_ra_parser, _head);
    return flb_cfl_ra_key_strcmp(rp->key->name, var, rp->key->subkeys,
                                 rp->key->name, flb_sds_len(rp->key->name));
}

/*
 * Check if a regular expression matches a cfl record accessor key in the
 * given cfl_object
 */
int flb_cfl_ra_regex_match(struct flb_cfl_record_accessor *cra, struct cfl_variant var,
                           struct flb_regex *regex, struct flb_regex_search *result)
{
    struct flb_ra_parser *rp;

    rp = mk_list_entry_first(&cra->list, struct flb_ra_parser, _head);
    if (rp == NULL || rp->key == NULL) {
        return -1;
    }
    return flb_cfl_ra_key_regex_match(rp->key->name, var, rp->key->subkeys,
                                      regex, result);
}

static struct flb_ra_parser* get_ra_parser(struct flb_cfl_record_accessor *cra)
{
    struct flb_ra_parser *rp = NULL;

    if (mk_list_size(&cra->list) == 0) {
        return NULL;
    }
    rp = mk_list_entry_first(&cra->list, struct flb_ra_parser, _head);
    if (!rp->key) {
        return NULL;
    }
    return rp;
}

/*
 * If 'cfl record accessor' pattern matches an entry in the 'cfl', set the
 * reference in 'out_key' and 'out_val' for the entries in question.
 *
 * Returns FLB_TRUE if the pattern matched a kv pair, otherwise it returns
 * FLB_FALSE.
 */
int flb_cfl_ra_get_kv_pair(struct flb_cfl_record_accessor *cra,
                           struct cfl_variant var,
                           cfl_sds_t *start_key,
                           cfl_sds_t *out_key, struct cfl_variant **out_val)
{
    struct flb_ra_parser *rp;

    rp = get_ra_parser(cra);
    if (rp == NULL) {
        return FLB_FALSE;
    }

    return flb_cfl_ra_key_value_get(rp->key->name, var, rp->key->subkeys,
                                    start_key, out_key, out_val);
}


struct flb_cfl_ra_value *flb_cfl_ra_get_value_object(struct flb_cfl_record_accessor *cra,
                                                     struct cfl_variant var)
{
    struct flb_ra_parser *rp;

    rp = get_ra_parser(cra);
    if (rp == NULL) {
        return NULL;
    }

    return flb_cfl_ra_key_to_value(rp->key->name, var, rp->key->subkeys);
}

/**
 *  Update key and/or value of the map using record accessor.
 *
 *  @param cra   the record accessor to specify key/value pair
 *  @param cfl  the original cfl_object.
 *  @param in_key   the pointer to overwrite key. If NULL, key will not be updated.
 *  @param in_val   the pointer to overwrite val. If NULL, val will not be updated.
 *
 *  @return result of the API. 0:success, -1:fail
 */

int flb_cfl_ra_update_kv_pair(struct flb_cfl_record_accessor *cra, struct cfl_variant var,
                              cfl_sds_t in_key, struct cfl_variant *in_val)
{
    struct flb_ra_parser *rp;
    int ret;

    cfl_sds_t s_key = NULL;
    cfl_sds_t o_key = NULL;
    struct cfl_variant *o_val = NULL;

    if (in_key == NULL && in_val == NULL) {
        /* no key and value. nothing to do */
        flb_error("%s: no inputs", __FUNCTION__);
        return -1;
    }
    else if (cra == NULL) {
        /* invalid input */
        flb_error("%s: invalid input", __FUNCTION__);
        return -1;
    }
    else if (flb_cfl_ra_get_kv_pair(cra, var, &s_key, &o_key, &o_val) != 0) {
        /* key and value are not found */
        flb_error("%s: no value", __FUNCTION__);
        return -1;
    }

    rp = get_ra_parser(cra);
    if (rp == NULL) {
        return -1;
    }

    ret = flb_cfl_ra_key_value_update(rp, &var, in_key, in_val);
    if (ret < 0) {
        return -1;
    }

    return 0;
}

/**
 *  Add key and/or value of the map using record accessor.
 *  If key already exists, the API fails.
 *
 *  @param cra  the record accessor to specify key.
 *  @param vobj the original cfl_object.
 *  @param in_val   the pointer to add val.
 *
 *  @return result of the API. 0:success, -1:fail
 */

int flb_cfl_ra_append_kv_pair(struct flb_cfl_record_accessor *cra, struct cfl_variant var,
                              struct cfl_variant *in_val)
{
    struct flb_ra_parser *rp;
    int ret;

    cfl_sds_t s_key = NULL;
    cfl_sds_t o_key = NULL;
    struct cfl_variant *o_val = NULL;

    if (in_val == NULL) {
        /* no key and value. nothing to do */
        flb_error("%s: no value", __FUNCTION__);
        return -1;
    }
    else if (cra == NULL) {
        /* invalid input */
        flb_error("%s: invalid input", __FUNCTION__);
        return -1;
    }

    flb_cfl_ra_get_kv_pair(cra, var, &s_key, &o_key, &o_val);
    if (o_key != NULL && o_val != NULL) {
        /* key and value already exist */
        flb_error("%s: already exist", __FUNCTION__);
        return -1;
    }

    rp = get_ra_parser(cra);
    if (rp == NULL || rp->key == NULL) {
        return -1;
    }

    ret = flb_cfl_ra_key_value_append(rp, &var, in_val);
    if (ret < 0) {
        return -1;
    }

    return 0;
}
