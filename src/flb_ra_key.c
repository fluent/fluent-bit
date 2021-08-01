/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2021 The Fluent Bit Authors
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
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_regex.h>
#include <fluent-bit/flb_ra_key.h>
#include <fluent-bit/record_accessor/flb_ra_parser.h>
#include <msgpack.h>
#include <limits.h>

/* Map msgpack object into flb_ra_value representation */
static int msgpack_object_to_ra_value(msgpack_object o,
                                      struct flb_ra_value *result)
{
    result->o = o;

    /* Compose result with found value */
    if (o.type == MSGPACK_OBJECT_BOOLEAN) {
        result->type = FLB_RA_BOOL;
        result->val.boolean = o.via.boolean;
        return 0;
    }
    else if (o.type == MSGPACK_OBJECT_POSITIVE_INTEGER ||
             o.type == MSGPACK_OBJECT_NEGATIVE_INTEGER) {
        result->type = FLB_RA_INT;
        result->val.i64 = o.via.i64;
        return 0;
    }
    else if (o.type == MSGPACK_OBJECT_FLOAT32 ||
             o.type == MSGPACK_OBJECT_FLOAT) {
        result->type = FLB_RA_FLOAT;
        result->val.f64 = o.via.f64;
        return 0;
    }
    else if (o.type == MSGPACK_OBJECT_STR) {
        result->type = FLB_RA_STRING;
        result->val.string = flb_sds_create_len((char *) o.via.str.ptr,
                                                o.via.str.size);
        return 0;
    }
    else if (o.type == MSGPACK_OBJECT_MAP) {
        /* return boolean 'true', just denoting the existence of the key */
        result->type = FLB_RA_BOOL;
        result->val.boolean = true;
        return 0;
    }
    else if (o.type == MSGPACK_OBJECT_NIL) {
        result->type = FLB_RA_NULL;
        return 0;
    }

    return -1;
}

/* Return the entry position of key/val in the map */
static int ra_key_val_id(flb_sds_t ckey, msgpack_object map)
{
    int i;
    int map_size;
    msgpack_object key;

    if (map.type != MSGPACK_OBJECT_MAP) {
        return -1;
    }

    map_size = map.via.map.size;
    for (i = 0; i < map_size; i++) {
        key = map.via.map.ptr[i].key;

        if (key.type != MSGPACK_OBJECT_STR) {
            continue;
        }

        /* Compare by length and by key name */
        if (flb_sds_cmp(ckey, key.via.str.ptr, key.via.str.size) != 0) {
            continue;
        }

        return i;
    }

    return -1;
}

static int msgpack_object_strcmp(msgpack_object o, char *str, int len)
{
    if (o.type != MSGPACK_OBJECT_STR) {
        return -1;
    }

    if (o.via.str.size != len) {
        return -1;
    }

    return strncmp(o.via.str.ptr, str, len);
}

/* Lookup perfect match of sub-keys and map content */
static int subkey_to_object(msgpack_object *map, struct mk_list *subkeys,
                            msgpack_object **out_key, msgpack_object **out_val)
{
    int i = 0;
    int levels;
    int matched = 0;
    msgpack_object *found = NULL;
    msgpack_object *key = NULL;
    msgpack_object *val = NULL;
    msgpack_object cur;
    struct mk_list *head;
    struct flb_ra_subentry *entry;

    /* Expected number of map levels in the map */
    levels = mk_list_size(subkeys);

    cur = *map;

    mk_list_foreach(head, subkeys) {
        /* expected entry */
        entry = mk_list_entry(head, struct flb_ra_subentry, _head);

        /* Array Handling */
        if (entry->type == FLB_RA_PARSER_ARRAY_ID) {
            /* check the current msgpack object is an array */
            if (cur.type != MSGPACK_OBJECT_ARRAY) {
                return -1;
            }

            /* Index limit and ensure no overflow */
            if (entry->array_id == INT_MAX ||
                cur.via.array.size < entry->array_id + 1) {
                return -1;
            }

            cur = cur.via.array.ptr[entry->array_id];
            goto next;
        }

        if (cur.type != MSGPACK_OBJECT_MAP) {
            break;
        }

        i = ra_key_val_id(entry->str, cur);
        if (i == -1) {
            found = NULL;
            continue;
        }

        key = &cur.via.map.ptr[i].key;
        val = &cur.via.map.ptr[i].val;

        /* A bit obvious, but it's better to validate data type */
        if (key->type != MSGPACK_OBJECT_STR) {
            found = NULL;
            continue;
        }

        found = key;
        cur = cur.via.map.ptr[i].val;

    next:
        matched++;

        if (levels == matched) {
            break;
        }
    }

    /* No matches */
    if (!found || (matched > 0 && levels != matched)) {
        return -1;
    }

    *out_key = (msgpack_object *) key;
    *out_val = (msgpack_object *) val;

    return 0;
}

struct flb_ra_value *flb_ra_key_to_value(flb_sds_t ckey,
                                         msgpack_object map,
                                         struct mk_list *subkeys)
{
    int i;
    int ret;
    msgpack_object val;
    msgpack_object *out_key;
    msgpack_object *out_val;
    struct flb_ra_value *result;

    /* Get the key position in the map */
    i = ra_key_val_id(ckey, map);
    if (i == -1) {
        return NULL;
    }

    /* Reference entries */
    val = map.via.map.ptr[i].val;

    /* Create the result context */
    result = flb_calloc(1, sizeof(struct flb_ra_value));
    if (!result) {
        flb_errno();
        return NULL;
    }
    result->o = val;

    if ((val.type == MSGPACK_OBJECT_MAP || val.type == MSGPACK_OBJECT_ARRAY)
        && subkeys != NULL && mk_list_size(subkeys) > 0) {

        ret = subkey_to_object(&val, subkeys, &out_key, &out_val);
        if (ret == 0) {
            ret = msgpack_object_to_ra_value(*out_val, result);
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
        ret = msgpack_object_to_ra_value(val, result);
        if (ret == -1) {
            flb_error("[ra key] cannot process key value");
            flb_free(result);
            return NULL;
        }
    }

    return result;
}

int flb_ra_key_value_get(flb_sds_t ckey, msgpack_object map,
                         struct mk_list *subkeys,
                         msgpack_object **start_key,
                         msgpack_object **out_key, msgpack_object **out_val)
{
    int i;
    int ret;
    msgpack_object val;
    msgpack_object *o_key;
    msgpack_object *o_val;

    /* Get the key position in the map */
    i = ra_key_val_id(ckey, map);
    if (i == -1) {
        return -1;
    }

    /* Reference entries */
    *start_key = &map.via.map.ptr[i].key;
    val = map.via.map.ptr[i].val;

    if ((val.type == MSGPACK_OBJECT_MAP || val.type == MSGPACK_OBJECT_ARRAY)
        && subkeys != NULL && mk_list_size(subkeys) > 0) {
        ret = subkey_to_object(&val, subkeys, &o_key, &o_val);
        if (ret == 0) {
            *out_key = o_key;
            *out_val = o_val;
            return 0;
        }
    }
    else {
        *out_key = &map.via.map.ptr[i].key;
        *out_val = &map.via.map.ptr[i].val;
        return 0;
    }

    return -1;
}

int flb_ra_key_strcmp(flb_sds_t ckey, msgpack_object map,
                      struct mk_list *subkeys, char *str, int len)
{
    int i;
    int ret;
    msgpack_object val;
    msgpack_object *out_key;
    msgpack_object *out_val;

    /* Get the key position in the map */
    i = ra_key_val_id(ckey, map);
    if (i == -1) {
        return -1;
    }

    /* Reference map value */
    val = map.via.map.ptr[i].val;

    if ((val.type == MSGPACK_OBJECT_MAP || val.type == MSGPACK_OBJECT_ARRAY)
        && subkeys != NULL && mk_list_size(subkeys) > 0) {
        ret = subkey_to_object(&val, subkeys, &out_key, &out_val);
        if (ret == 0) {
            return msgpack_object_strcmp(*out_val, str, len);
        }
        else {
            return -1;
        }
    }

    return msgpack_object_strcmp(val, str, len);
}

int flb_ra_key_regex_match(flb_sds_t ckey, msgpack_object map,
                           struct mk_list *subkeys, struct flb_regex *regex,
                           struct flb_regex_search *result)
{
    int i;
    int ret;
    msgpack_object val;
    msgpack_object *out_key;
    msgpack_object *out_val;

    /* Get the key position in the map */
    i = ra_key_val_id(ckey, map);
    if (i == -1) {
        return -1;
    }

    /* Reference map value */
    val = map.via.map.ptr[i].val;

    if ((val.type == MSGPACK_OBJECT_MAP || val.type == MSGPACK_OBJECT_ARRAY)
        && subkeys != NULL && mk_list_size(subkeys) > 0) {
        ret = subkey_to_object(&val, subkeys, &out_key, &out_val);
        if (ret == 0) {
            if (out_val->type != MSGPACK_OBJECT_STR) {
                return -1;
            }

            if (result) {
                /* Regex + capture mode */
                return flb_regex_do(regex,
                                    (char *) out_val->via.str.ptr,
                                    out_val->via.str.size,
                                    result);
            }
            else {
                /* No capture */
                return flb_regex_match(regex,
                                       (unsigned char *) out_val->via.str.ptr,
                                       out_val->via.str.size);
            }
        }
        return -1;
    }

    if (val.type != MSGPACK_OBJECT_STR) {
        return -1;
    }

    if (result) {
        /* Regex + capture mode */
        return flb_regex_do(regex, (char *) val.via.str.ptr, val.via.str.size,
                            result);
    }
    else {
        /* No capture */
        return flb_regex_match(regex, (unsigned char *) val.via.str.ptr,
                               val.via.str.size);
    }

    return -1;
}

void flb_ra_key_value_destroy(struct flb_ra_value *v)
{
    if (v->type == FLB_RA_STRING) {
        flb_sds_destroy(v->val.string);
    }
    flb_free(v);
}
