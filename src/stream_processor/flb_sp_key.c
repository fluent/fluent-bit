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
#include <fluent-bit/flb_slist.h>

#include <fluent-bit/stream_processor/flb_sp.h>
#include <fluent-bit/stream_processor/flb_sp_parser.h>

void flb_sp_key_value_print(struct flb_sp_value *v)
{
    if (v->type == FLB_EXP_BOOL) {
        if (v->val.boolean) {
            printf("true");
        }
        else {
            printf("false");
        }
    }
    else if (v->type == FLB_EXP_INT) {
        printf("%" PRId64, v->val.i64);
    }
    else if (v->type == FLB_EXP_FLOAT) {
        printf("%f", v->val.f64);
    }
    else if (v->type == FLB_EXP_STRING) {
        printf("%s", v->val.string);
    }
    else if (v->type == FLB_EXP_NULL) {
        printf("NULL");
    }
}

/* Map msgpack object intp flb_sp_value representation */
static int msgpack_object_to_sp_value(msgpack_object o,
                                      struct flb_sp_value *result)
{
    result->o = o;

    /* Compose result with found value */
    if (o.type == MSGPACK_OBJECT_BOOLEAN) {
        result->type = FLB_EXP_BOOL;
        result->val.boolean = o.via.boolean;
        return 0;
    }
    else if (o.type == MSGPACK_OBJECT_POSITIVE_INTEGER ||
             o.type == MSGPACK_OBJECT_NEGATIVE_INTEGER) {
        result->type = FLB_EXP_INT;
        result->val.i64 = o.via.i64;
        return 0;
    }
    else if (o.type == MSGPACK_OBJECT_FLOAT32 ||
             o.type == MSGPACK_OBJECT_FLOAT) {
        result->type = FLB_EXP_FLOAT;
        result->val.f64 = o.via.f64;
        return 0;
    }
    else if (o.type == MSGPACK_OBJECT_STR) {
        result->type = FLB_EXP_STRING;
        result->val.string = flb_sds_create_len((char *) o.via.str.ptr,
                                                o.via.str.size);
        return 0;
    }
    else if (o.type == MSGPACK_OBJECT_MAP) {
        /* return boolean 'true', just denoting the existence of the key */
        result->type = FLB_EXP_BOOL;
        result->val.boolean = true;
        return 0;
    }
    else if (o.type == MSGPACK_OBJECT_NIL) {
        result->type = FLB_EXP_NULL;
        return 0;
    }

    return -1;
}

/* Lookup perfect match of sub-keys and map content */
static int subkey_to_value(msgpack_object *map, struct mk_list *subkeys,
                           struct flb_sp_value *result)
{
    int i = 0;
    int ret;
    int levels;
    int matched = 0;
    msgpack_object *key_found = NULL;
    msgpack_object key;
    msgpack_object val;
    msgpack_object cur_map;
    struct mk_list *head;
    struct flb_slist_entry *entry;

    /* Expected number of map levels in the map */
    levels = mk_list_size(subkeys);

    cur_map = *map;

    mk_list_foreach(head, subkeys) {
        /* Key expected key entry */
        entry = mk_list_entry(head, struct flb_slist_entry, _head);

        if (cur_map.type != MSGPACK_OBJECT_MAP) {
            break;
        }

        /* Get map entry that matches entry name */
        for (i = 0; i < cur_map.via.map.size; i++) {
            key = cur_map.via.map.ptr[i].key;
            val = cur_map.via.map.ptr[i].val;

            /* A bit obvious, but it's better to validate data type */
            if (key.type != MSGPACK_OBJECT_STR) {
                continue;
            }

            /* Compare strings by length and content */
            if (flb_sds_cmp(entry->str,
                            (char *) key.via.str.ptr,
                            key.via.str.size) != 0) {
                key_found = NULL;
                continue;
            }

            key_found = &key;
            cur_map = val;
            matched++;
            break;
        }

        if (levels == matched) {
            break;
        }
    }

    /* No matches */
    if (!key_found || (matched > 0 && levels != matched)) {
        return -1;
    }

    ret = msgpack_object_to_sp_value(val, result);
    if (ret == -1) {
        //flb_error("[sp key] cannot process key value");
        return -1;
    }

    return 0;
}

struct flb_sp_value *flb_sp_key_to_value(flb_sds_t ckey,
                                         msgpack_object map,
                                         struct mk_list *subkeys)
{
    int i;
    int ret;
    int map_size;
    msgpack_object key;
    msgpack_object val;
    struct flb_sp_value *result;

    map_size = map.via.map.size;
    for (i = 0; i < map_size; i++) {
        key = map.via.map.ptr[i].key;
        val = map.via.map.ptr[i].val;

        /* Compare by length and by key name */
        if (flb_sds_cmp(ckey, key.via.str.ptr, key.via.str.size) != 0) {
            continue;
        }

        result = flb_calloc(1, sizeof(struct flb_sp_value));
        if (!result) {
            flb_errno();
            return NULL;
        }
        result->o = val;

        if (val.type == MSGPACK_OBJECT_MAP && subkeys != NULL) {
            ret = subkey_to_value(&val, subkeys, result);
            if (ret == 0) {
                return result;
            }
            else {
                flb_free(result);
                return NULL;
            }
        }
        else {
            ret = msgpack_object_to_sp_value(val, result);
            if (ret == -1) {
                flb_error("[sp key] cannot process key value");
                flb_free(result);
                return NULL;
            }
        }

        return result;
    }

    /*
     * NULL return means: failed memory allocation, an invalid value,
     * or non-existing key.
     */
    return NULL;
}

void flb_sp_key_value_destroy(struct flb_sp_value *v)
{
    if (v->type == FLB_EXP_STRING) {
        flb_sds_destroy(v->val.string);
    }
    flb_free(v);
}
