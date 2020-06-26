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


#include "stackdriver.h"

int cmp_helper(msgpack_object key, const char* str, const int size) {
    if (size != key.via.str.size 
        || strncmp(str, key.via.str.ptr, key.via.str.size) != 0) {
        return FLB_FALSE;
    }
    return FLB_TRUE;
}

int assign_subfield_str(msgpack_object_kv *tmp_p, const char* str, 
                        const int size, flb_sds_t *subfield) {
    if (cmp_helper(tmp_p->key, str, size)) {
        if (tmp_p->val.type != MSGPACK_OBJECT_STR) {
            return 0;
        }
        *subfield = flb_sds_copy(*subfield, tmp_p->val.via.str.ptr, 
                                 tmp_p->val.via.str.size);
        return 0;
    }
    return -1;
}

int assign_subfield_bool(msgpack_object_kv *tmp_p, const char* str, 
                         const int size, int *subfield) {
    if (cmp_helper(tmp_p->key, str, size)) {
        if (tmp_p->val.type != MSGPACK_OBJECT_BOOLEAN) {
            return 0;
        }
        if (tmp_p->val.via.boolean) {
            *subfield = FLB_TRUE;
        }
        return 0;
    }
    return -1;
}

int assign_subfield_int(msgpack_object_kv *tmp_p, const char* str, 
                        const int size, int *subfield) {
    if (cmp_helper(tmp_p->key, str, size)) {
        if (tmp_p->val.type == MSGPACK_OBJECT_STR) {
            *subfield = atoll(tmp_p->val.via.str.ptr);
        }
        else if (tmp_p->val.type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
            *subfield = tmp_p->val.via.i64;
        }
        return 0;
    }
    return -1;
}
