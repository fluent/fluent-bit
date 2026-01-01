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
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_regex.h>
#include <fluent-bit/flb_cfl_ra_key.h>
#include <fluent-bit/record_accessor/flb_ra_parser.h>
#include <cfl/cfl.h>
#include <limits.h>

/* Map cfl variant into flb_cfl_ra_value representation */
static int cfl_variant_to_ra_value(struct cfl_variant v,
                                   struct flb_cfl_ra_value *result)
{
    result->v = v;

    /* Compose result with found value */
    if (v.type == CFL_VARIANT_BOOL) {
        result->type = FLB_CFL_RA_BOOL;
        result->val.boolean = v.data.as_bool;
        return 0;
    }
    else if (v.type == CFL_VARIANT_INT) {
        result->type = FLB_CFL_RA_INT;
        result->val.i64 = v.data.as_int64;
        return 0;
    }
    else if (v.type == CFL_VARIANT_UINT) {
        result->type = FLB_CFL_RA_INT;
        result->val.i64 = v.data.as_uint64;
        return 0;
    }
    else if (v.type == CFL_VARIANT_DOUBLE) {
        result->type = FLB_CFL_RA_FLOAT;
        result->val.f64 = v.data.as_double;
        return 0;
    }
    else if (v.type == CFL_VARIANT_NULL) {
        result->type = FLB_CFL_RA_NULL;
        return 0;
    }
    else if (v.type == CFL_VARIANT_STRING) {
        result->type = FLB_CFL_RA_STRING;
        result->val.string = v.data.as_string;
        return 0;
    }
    else if (v.type == CFL_VARIANT_BYTES) {
        result->type = FLB_CFL_RA_STRING;
        result->val.string = v.data.as_bytes;
        return 0;
    }
    else if (v.type == CFL_VARIANT_ARRAY) {
        /* return boolean 'true', just denoting the existence of the key */
        result->type = FLB_CFL_RA_BOOL;
        result->val.boolean = true;
        return 0;
    }
    else if (v.type == CFL_VARIANT_KVLIST) {
        /* return boolean 'true', just denoting the existence of the key */
        result->type = FLB_CFL_RA_BOOL;
        result->val.boolean = true;
        return 0;
    }

    return -1;
}

static struct cfl_kvpair *cfl_variant_kvpair_get(struct cfl_variant *vobj, cfl_sds_t key)
{
    struct cfl_list *head;
    struct cfl_kvlist *kvlist;
    struct cfl_kvpair *kvpair;

    if (!vobj) {
        return NULL;
    }

    switch (vobj->type) {
    case CFL_VARIANT_BOOL:
    case CFL_VARIANT_INT:
    case CFL_VARIANT_UINT:
    case CFL_VARIANT_DOUBLE:
    case CFL_VARIANT_NULL:
    case CFL_VARIANT_REFERENCE:
    case CFL_VARIANT_STRING:
    case CFL_VARIANT_BYTES:
    case CFL_VARIANT_ARRAY:
        return NULL;
    case CFL_VARIANT_KVLIST:
        break;
    }

    kvlist = vobj->data.as_kvlist;
    cfl_list_foreach_r(head, &kvlist->list) {
        kvpair = cfl_list_entry(head, struct cfl_kvpair, _head);

        if (cfl_sds_len(key) != cfl_sds_len(kvpair->key)) {
            continue;
        }

        if (strncmp(key, kvpair->key, cfl_sds_len(key)) == 0) {
            return kvpair;
        }
    }

    return NULL;
}

/* Lookup perfect match of sub-keys and cfl_variant content */
static int subkey_to_variant(struct cfl_variant *vobj, struct mk_list *subkeys,
                             cfl_sds_t *out_key, struct cfl_variant **out_val)
{
    int levels;
    int matched = 0;
    cfl_sds_t key = NULL;
    struct cfl_variant *val = NULL;
    struct cfl_kvpair *kvpair = NULL;
    struct mk_list *head;
    struct cfl_variant cur;
    struct flb_ra_subentry *entry = NULL;

    /* Expected number of map levels in the map */
    levels = mk_list_size(subkeys);

    /* Early return if no subkeys */
    if (levels == 0) {
        return -1;
    }

    cur = *vobj;

    mk_list_foreach(head, subkeys) {
        /* expected entry */
        entry = mk_list_entry(head, struct flb_ra_subentry, _head);

        /* Array Handling */
        if (entry->type == FLB_RA_PARSER_ARRAY_ID) {
            /* check the current cfl_variant is a kvlist */
            if (cur.type != CFL_VARIANT_ARRAY) {
                return -1;
            }

            /* Index limit and ensure no overflow */
            if (entry->array_id == INT_MAX ||
                entry->array_id >= cfl_array_size(cur.data.as_array)) {
                return -1;
            }

            val = cur.data.as_array->entries[entry->array_id];
            cur = *val;
            key = NULL; /* fill NULL since the type is array. */
            matched++;

            if (levels == matched) {
                break;
            }

            continue;
        }

        if (cur.type != CFL_VARIANT_KVLIST) {
            break;
        }

        kvpair = cfl_variant_kvpair_get(&cur, entry->str);
        if (kvpair == NULL) {
            continue;  /* Try next entry */
        }

        key = kvpair->key;
        val = kvpair->val;

        cur = *val;
        matched++;

        if (levels == matched) {
            break;
        }
    }

    /* No matches */
    if (matched == 0 || (matched > 0 && levels != matched)) {
        return -1;
    }

    *out_key = key;
    *out_val = val;

    return 0;
}

struct flb_cfl_ra_value *flb_cfl_ra_key_to_value(flb_sds_t ckey,
                                                 struct cfl_variant vobj,
                                                 struct mk_list *subkeys)
{
    int ret;
    struct cfl_variant *out_val = NULL;
    struct cfl_kvpair *kvpair = NULL;
    struct cfl_variant *val = NULL;
    cfl_sds_t out_key = NULL;
    struct flb_cfl_ra_value *result = NULL;

    /* Get the kvpair in the variant */
    kvpair = cfl_variant_kvpair_get(&vobj, ckey);
    if (kvpair == NULL) {
        return NULL;
    }

    /* Reference entries */
    val = kvpair->val;

    /* Create the result context */
    result = flb_calloc(1, sizeof(struct flb_cfl_ra_value));
    if (!result) {
        flb_errno();
        return NULL;
    }
    result->v = *val;

    if ((val->type == CFL_VARIANT_ARRAY || val->type == CFL_VARIANT_KVLIST)
        && subkeys != NULL && mk_list_size(subkeys) > 0) {
        ret = subkey_to_variant(val, subkeys, &out_key, &out_val);
        if (ret == 0) {
            ret = cfl_variant_to_ra_value(*out_val, result);
            if (ret == -1) {
                flb_free(result);
                return NULL;
            }
            return result;
        }
        else {
            flb_free(result);
            return NULL;
        }
    }
    else {
        ret = cfl_variant_to_ra_value(*val, result);
        if (ret == -1) {
            flb_error("[ra key] cannot process key value");
            flb_free(result);
            return NULL;
        }
    }

    return result;
}

int flb_cfl_ra_key_value_get(flb_sds_t ckey, struct cfl_variant vobj,
                             struct mk_list *subkeys,
                             cfl_sds_t *start_key,
                             cfl_sds_t *out_key, struct cfl_variant **out_val)
{
    int ret;
    struct cfl_kvpair *kvpair = NULL;
    struct cfl_variant *val = NULL;
    cfl_sds_t o_key = NULL;
    struct cfl_variant *o_val = NULL;

    /* Get the kvpair in the variant */
    kvpair = cfl_variant_kvpair_get(&vobj, ckey);
    if (kvpair == NULL) {
        return -1;
    }

    /* Reference entries */
    *start_key = kvpair->key;
    val = kvpair->val;

    if ((val->type == CFL_VARIANT_ARRAY || val->type == CFL_VARIANT_KVLIST)
        && subkeys != NULL && mk_list_size(subkeys) > 0) {
        ret = subkey_to_variant(val, subkeys, &o_key, &o_val);
        if (ret == 0) {
            *out_key = o_key;
            *out_val = o_val;
            return 0;
        }
    }
    else {
        *out_key = kvpair->key;
        *out_val = kvpair->val;
        return 0;
    }

    return -1;
}

void flb_cfl_ra_key_value_destroy(struct flb_cfl_ra_value *v)
{
    flb_free(v);
}

static int cfl_variant_strcmp(struct cfl_variant v, char *str, int len)
{
    if (v.type != CFL_VARIANT_STRING) {
        return -1;
    }

    if (cfl_sds_len(v.data.as_string) != len) {
        return -1;
    }

    return strncmp(v.data.as_string, str, len);
}

int flb_cfl_ra_key_strcmp(flb_sds_t ckey, struct cfl_variant vobj,
                          struct mk_list *subkeys, char *str, int len)
{
    int ret;
    struct cfl_kvpair *kvpair = NULL;
    struct cfl_variant *val;
    cfl_sds_t out_key;
    struct cfl_variant *out_val;

    /* Get the kvpair in the variant */
    kvpair = cfl_variant_kvpair_get(&vobj, ckey);
    if (kvpair == NULL) {
        return -1;
    }

    val = kvpair->val;

    if ((val->type == CFL_VARIANT_ARRAY || val->type == CFL_VARIANT_KVLIST)
        && subkeys != NULL && mk_list_size(subkeys) > 0) {
        ret = subkey_to_variant(val, subkeys, &out_key, &out_val);
        if (ret == 0) {
            return cfl_variant_strcmp(*out_val, str, len);
        }
        else {
            return -1;
        }
    }

    return cfl_variant_strcmp(*val, str, len);
}

int flb_cfl_ra_key_regex_match(flb_sds_t ckey, struct cfl_variant vobj,
                               struct mk_list *subkeys, struct flb_regex *regex,
                               struct flb_regex_search *result)
{
    int ret;
    struct cfl_kvpair *kvpair = NULL;
    struct cfl_variant *val;
    cfl_sds_t out_key;
    struct cfl_variant *out_val;

    /* Get the key position in the map */
    kvpair = cfl_variant_kvpair_get(&vobj, ckey);
    if (kvpair == NULL) {
        return -1;
    }

    val = kvpair->val;

    if ((val->type == CFL_VARIANT_ARRAY || val->type == CFL_VARIANT_KVLIST)
        && subkeys != NULL && mk_list_size(subkeys) > 0) {
        ret = subkey_to_variant(val, subkeys, &out_key, &out_val);
        if (ret == 0) {
            if (out_val->type != CFL_VARIANT_STRING) {
                return -1;
            }

            if (result) {
                /* Regex + capture mode */
                return flb_regex_do(regex,
                                    (char *) out_val->data.as_string,
                                    cfl_sds_len(out_val->data.as_string),
                                    result);
            }
            else {
                /* No capture */
                return flb_regex_match(regex,
                                       (unsigned char *) out_val->data.as_string,
                                       cfl_sds_len(out_val->data.as_string));
            }
        }
        return -1;
    }

    if (val->type != CFL_VARIANT_STRING) {
        return -1;
    }

    if (result) {
        /* Regex + capture mode */
        return flb_regex_do(regex,
                            (char *) out_val->data.as_string,
                            cfl_sds_len(out_val->data.as_string),
                            result);
    }
    else {
        /* No capture */
        return flb_regex_match(regex, (unsigned char *) out_val->data.as_string,
                               cfl_sds_len(out_val->data.as_string));
    }

    return -1;
}

static int update_subkey(struct cfl_variant *vobj, struct mk_list *subkeys,
                         int levels, int *matched,
                         flb_sds_t in_key, struct cfl_variant *in_val);

static int update_subkey_array(struct cfl_variant *vobj, struct mk_list *subkeys,
                               int levels, int *matched,
                               flb_sds_t in_key, struct cfl_variant *in_val)
{
    struct flb_ra_subentry *entry;
    struct cfl_array *array;
    int i;
    int ret;
    int size;

    entry = mk_list_entry_first(subkeys, struct flb_ra_subentry, _head);

    /* check the current msgpack object is an array */
    if (vobj->type != CFL_VARIANT_ARRAY) {
        flb_error("%s: object is not array", __FUNCTION__);
        return -1;
    }
    array = vobj->data.as_array;

    size = cfl_array_size(array);
    /* Index limit and ensure no overflow */
    if (entry->array_id == INT_MAX ||
        size < entry->array_id + 1) {
        flb_trace("%s: out of index", __FUNCTION__);
            return -1;
    }

    for (i=0; i<size; i++) {
        if (i != entry->array_id) {
            continue;
        }
        *matched += 1;
        if (levels == *matched) {
            flb_trace("%s: update val matched=%d", __FUNCTION__, *matched);
            /* update value */
            continue;
        }

        if (subkeys->next == NULL) {
            flb_trace("%s: end of subkey", __FUNCTION__);
            return -1;
        }
        ret = update_subkey(array->entries[i], subkeys->next,
                            levels, matched,
                            in_key, in_val);
        if (ret < 0) {
            return ret;
        }
    }
    return 0;
}

static int update_subkey_kvlist(struct cfl_variant *vobj, struct mk_list *subkeys,
                                int levels, int *matched,
                                cfl_sds_t in_key, struct cfl_variant *in_val)
{
    struct flb_ra_subentry *entry;
    int ret;
    flb_sds_t key = NULL;
    flb_sds_t tmp = NULL;
    struct cfl_kvlist *kvlist = NULL;
    struct cfl_kvpair *kvpair = NULL;
    struct cfl_kvpair *pair = NULL;
    struct cfl_variant *val = NULL;
    struct cfl_list *head = NULL;

    entry = mk_list_entry_first(subkeys, struct flb_ra_subentry, _head);
    /* check the current msgpack object is a map */
    if (vobj->type != CFL_VARIANT_KVLIST) {
        flb_trace("%s: variant is not cfl_kvlist", __FUNCTION__);
        return -1;
    }

    kvlist = vobj->data.as_kvlist;
    if (kvlist == NULL) {
        return -1;
    }

    /* Get the kvpair in the variant */
    kvpair = cfl_variant_kvpair_get(vobj, entry->str);
    if (kvpair == NULL) {
        return -1;
    }

    cfl_list_foreach(head, &kvlist->list) {
        pair = cfl_list_entry(head,
                              struct cfl_kvpair, _head);

        if (cfl_sds_len(kvpair->key) != cfl_sds_len(pair->key)) {
            continue;
        }
        if (strcasecmp(pair->key, kvpair->key) != 0) {
            continue;
        }
        *matched += 1;
        if (levels == *matched) {
            flb_trace("%s update key/val matched=%d", __FUNCTION__, *matched);
            if (in_key != NULL && in_val != NULL) {
                cfl_kvlist_insert(kvlist, in_key, in_val);
                if (pair) {
                    cfl_kvpair_destroy(pair);
                }
            }
            else if (in_key != NULL) {
                tmp = kvpair->key;
                kvpair->key = cfl_sds_create_len(in_key, cfl_sds_len(in_key));
                if (!kvpair->key) {
                    kvpair->key = tmp;
                    return 0;
                }
                flb_sds_destroy(tmp);
            }
            else if (in_val != NULL) {
                key = cfl_sds_create_len(pair->key, cfl_sds_len(pair->key));
                if (key == NULL) {
                    return -1;
                }
                cfl_kvlist_insert(kvlist, key, in_val);
                cfl_sds_destroy(key);
                if (pair) {
                    cfl_kvpair_destroy(pair);
                }
            }
            return 0;
        }
        /* No need to dig into further elements */
        if (*matched > levels) {
            return 0;
        }
        if (subkeys->next == NULL) {
            flb_trace("%s: end of subkey", __FUNCTION__);
            return -1;
        }

        val = pair->val;
        ret = update_subkey(val, subkeys->next,
                            levels, matched,
                            in_key, in_val);
        if (ret < 0) {
            return -1;
        }
    }
    return 0;
}

static int update_subkey(struct cfl_variant *vobj, struct mk_list *subkeys,
                         int levels, int *matched,
                         cfl_sds_t in_key, struct cfl_variant *in_val)
{
    struct flb_ra_subentry *entry;

    entry = mk_list_entry_first(subkeys, struct flb_ra_subentry, _head);

    if (entry->type == FLB_RA_PARSER_ARRAY_ID) {
        return update_subkey_array(vobj, subkeys,
                                   levels, matched,
                                   in_key, in_val);
    }
    return update_subkey_kvlist(vobj, subkeys, levels, matched, in_key, in_val);
}

int flb_cfl_ra_key_value_update(struct flb_ra_parser *rp,  struct cfl_variant *vobj,
                                cfl_sds_t in_key, struct cfl_variant *in_val)
{
    int i;
    int kv_size;
    int ret;
    int levels;
    int matched = 0;
    struct cfl_kvpair *kvpair = NULL;
    struct cfl_kvlist *kvlist = NULL;
    struct cfl_variant *val;
    cfl_sds_t p_key;
    flb_sds_t tmp = NULL;

    /* Get the kvpair in the cfl_variant */
    kvpair = cfl_variant_kvpair_get(vobj, rp->key->name);
    if (kvpair == NULL) {
        return -1;
    }

    if (vobj->type != CFL_VARIANT_KVLIST) {
        return -1;
    }
    kvlist = vobj->data.as_kvlist;

    levels = mk_list_size(rp->key->subkeys);

    kv_size = cfl_kvlist_count(kvlist);

    if (levels == 0) {
        /* update key/val */
        if (in_key != NULL && in_val != NULL) {
            cfl_kvlist_insert(kvlist, in_key, in_val);
        }
        else if (in_key != NULL) {
            tmp = kvpair->key;
            kvpair->key = cfl_sds_create_len(in_key, cfl_sds_len(in_key));
            if (!kvpair->key) {
                kvpair->key = tmp;
                return 0;
            }
            flb_sds_destroy(tmp);
        }
        else if (in_val != NULL) {
            p_key = cfl_sds_create_len(kvpair->key, cfl_sds_len(kvpair->key));
            if (!p_key) {
                return -1;
            }
            cfl_kvlist_insert(kvlist, p_key, in_val);
            cfl_sds_destroy(p_key);
        }

        return 0;
    }

    for (i=0; i<kv_size; i++) {
        val = kvpair->val;
        ret = update_subkey(val, rp->key->subkeys,
                            levels, &matched,
                            in_key, in_val);
        if (ret < 0) {
            return -1;
        }
    }

    return 0;
}

static int append_subkey(struct cfl_variant *vobj, struct mk_list *subkeys,
                         int levels, int *matched,
                         struct cfl_variant *in_val);

static int append_subkey_array(struct cfl_variant *vobj, struct mk_list *subkeys,
                               int levels, int *matched,
                               struct cfl_variant *in_val)
{
    struct flb_ra_subentry *entry;
    struct cfl_array *array;
    int i;
    int ret;
    int size;

    /* check the current msgpack object is an array */
    if (vobj->type != CFL_VARIANT_ARRAY) {
        flb_trace("%s: object is not array", __FUNCTION__);
        return -1;
    }

    array = vobj->data.as_array;
    size = cfl_array_size(array);

    entry = mk_list_entry_first(subkeys, struct flb_ra_subentry, _head);

    if (levels == *matched) {
        /* append val */
        cfl_array_append(array, in_val);

        *matched = -1;
        return 0;
    }

    /* Index limit and ensure no overflow */
    if (entry->array_id == INT_MAX ||
        size < entry->array_id + 1) {
        flb_trace("%s: out of index", __FUNCTION__);
            return -1;
    }

    for (i=0; i<size; i++) {
        if (i != entry->array_id) {
            continue;
        }
        if (*matched >= 0) {
            *matched += 1;
        }
        if (subkeys->next == NULL) {
            flb_trace("%s: end of subkey", __FUNCTION__);
            return -1;
        }
        ret = append_subkey(array->entries[i], subkeys->next,
                            levels, matched,
                            in_val);
        if (ret < 0) {
            return -1;
        }
    }
    return 0;
}

static int append_subkey_kvlist(struct cfl_variant *vobj, struct mk_list *subkeys,
                                int levels, int *matched,
                                struct cfl_variant *in_val)
{
    struct flb_ra_subentry *entry;
    struct cfl_kvlist *kvlist = NULL;
    struct cfl_kvpair *kvpair = NULL;
    struct cfl_kvpair *pair = NULL;
    struct cfl_variant *val = NULL;
    struct cfl_list *head = NULL;
    int ret;

    /* check the current cfl_variant is a kvlist */
    if (vobj->type != CFL_VARIANT_KVLIST) {
        flb_trace("%s: object is not kvlist", __FUNCTION__);
        return -1;
    }

    kvlist = vobj->data.as_kvlist;
    if (kvlist == NULL) {
        return -1;
    }

    entry = mk_list_entry_first(subkeys, struct flb_ra_subentry, _head);

    if (levels == *matched) {
        /* append val */
        cfl_kvlist_insert(kvlist, entry->str, in_val);

        *matched = -1;
        return 0;
    }

    /* Get the kvpair in the variant */
    kvpair = cfl_variant_kvpair_get(vobj, entry->str);
    if (kvpair == NULL) {
        return -1;
    }

    cfl_list_foreach(head, &kvlist->list) {
        pair = cfl_list_entry(head,
                              struct cfl_kvpair, _head);

        if (strcasecmp(kvpair->key, pair->key) != 0) {
            continue;
        }

        if (*matched >= 0) {
            *matched += 1;
        }
        if (*matched > levels) {
            return 0;
        }

        if (subkeys->next == NULL) {
            flb_trace("%s: end of subkey", __FUNCTION__);
            return -1;
        }

        val = pair->val;
        ret = append_subkey(val, subkeys->next,
                            levels, matched,
                            in_val);
        if (ret < 0) {
            return -1;
        }
    }

    return 0;
}

static int append_subkey(struct cfl_variant *vobj, struct mk_list *subkeys,
                         int levels, int *matched,
                         struct cfl_variant *in_val)
{
    struct flb_ra_subentry *entry;

    entry = mk_list_entry_first(subkeys, struct flb_ra_subentry, _head);

    if (entry->type == FLB_RA_PARSER_ARRAY_ID) {
        return append_subkey_array(vobj, subkeys,
                                   levels, matched,
                                   in_val);
    }
    return append_subkey_kvlist(vobj, subkeys, levels, matched, in_val);
}

int flb_cfl_ra_key_value_append(struct flb_ra_parser *rp, struct cfl_variant *vobj,
                                struct cfl_variant *in_val)
{
    struct cfl_kvlist *kvlist;
    struct cfl_kvpair *kvpair;
    struct cfl_variant *val;
    int ref_level;
    int ret;
    int matched = 0;

    if (vobj->type != CFL_VARIANT_KVLIST) {
        return -1;
    }

    kvlist = vobj->data.as_kvlist;

    /* Decrement since the last key doesn't exist */
    ref_level = mk_list_size(rp->key->subkeys) - 1;
    if (ref_level < 0) {
        /* no subkeys */
        cfl_kvlist_insert(kvlist, rp->key->name, in_val);
        return 0;
    }

    /* Get the kvpair in the cfl_variant */
    kvpair = cfl_variant_kvpair_get(vobj, rp->key->name);
    if (kvpair == NULL) {
        return -1;
    }

    val = kvpair->val;
    ret = append_subkey(val, rp->key->subkeys,
                        ref_level, &matched,
                        in_val);
    if (ret < 0) {
        return -1;
    }

    return 0;
}
