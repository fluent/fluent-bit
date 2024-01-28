/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2024 The Fluent Bit Authors
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

#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_sds.h>
#include <string.h>
#include <msgpack.h>

/* Return 0 if string of msgpack object and str is same. */
int flb_msgpack_strcmp_str_len(msgpack_object *o, char *str, size_t str_len)
{
    if (o == NULL || str == NULL || o->type != MSGPACK_OBJECT_STR) {
        return -1;
    }

    if (o->via.str.size != str_len) {
        return -1;
    }

    return strncmp(o->via.str.ptr, str, str_len);
}

int flb_msgpack_strcmp_str(msgpack_object *o, char *str)
{
    if (str == NULL) {
        return -1;
    }
    return flb_msgpack_strcmp_str_len(o, str, strlen(str));
}

int flb_msgpack_strcmp_sds(msgpack_object *o, flb_sds_t str)
{
    return flb_msgpack_strcmp_str_len(o, str, flb_sds_len(str));
}

int flb_msgpack_strcmp_msgpack_str(msgpack_object *o1, msgpack_object *o2)
{
    if (o2 == NULL || o2->type != MSGPACK_OBJECT_STR) {
        return -1;
    }

    return flb_msgpack_strcmp_str_len(o1, (char *)o2->via.str.ptr, o2->via.str.size);
}



msgpack_object *flb_msgpack_get_value_from_map(msgpack_object *o, char *str, size_t str_len)
{
    size_t i;
    int ret;

    if (o == NULL || str == NULL || str_len == 0 || o->type != MSGPACK_OBJECT_MAP) {
        return NULL;
    }

    for (i=0; i<o->via.map.size; i++) {
        ret = flb_msgpack_strcmp_str_len(&o->via.map.ptr[i].key, str, str_len);
        if (ret == 0) {
            return &o->via.map.ptr[i].val;
        }
    }

    return NULL;
}

/* e.g. strs is {"nested", "key"} and strs_len is 2. */
msgpack_object *flb_msgpack_get_value_from_nested_map(msgpack_object *o, char **strs, size_t strs_len)
{
    size_t i_strs;
    msgpack_object *obj;
    msgpack_object *ret = NULL;

    if (o == NULL || strs == NULL || strs_len == 0 || o->type != MSGPACK_OBJECT_MAP) {
        return NULL;
    }

    obj = o;
    for (i_strs=0; i_strs<strs_len; i_strs++) {
        ret = flb_msgpack_get_value_from_map(obj, strs[i_strs], strlen(strs[i_strs]));
        if (ret == NULL) {
            return NULL;
        }
        obj = ret;
    }

    return obj;
}

