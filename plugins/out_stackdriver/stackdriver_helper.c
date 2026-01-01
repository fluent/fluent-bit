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


#include "stackdriver.h"

int equal_obj_str(msgpack_object obj, const char *str, const int size) {
    if (obj.type != MSGPACK_OBJECT_STR) {
        return FLB_FALSE;
    }
    if (size != obj.via.str.size
        || strncmp(str, obj.via.str.ptr, obj.via.str.size) != 0) {
        return FLB_FALSE;
    }
    return FLB_TRUE;
}

int validate_key(msgpack_object obj, const char *str, const int size) {
    return equal_obj_str(obj, str, size);
}

void try_assign_subfield_str(msgpack_object obj, flb_sds_t *subfield) {
    if (obj.type == MSGPACK_OBJECT_STR) {
        *subfield = flb_sds_copy(*subfield, obj.via.str.ptr,
                                 obj.via.str.size);
    }
}

void try_assign_subfield_bool(msgpack_object obj, int *subfield) {
    if (obj.type == MSGPACK_OBJECT_BOOLEAN) {
        if (obj.via.boolean) {
            *subfield = FLB_TRUE;
        }
        else {
            *subfield = FLB_FALSE;
        }
    }
}

void try_assign_subfield_int(msgpack_object obj, int64_t *subfield) {
    if (obj.type == MSGPACK_OBJECT_STR) {
        *subfield = atoll(obj.via.str.ptr);
    }
    else if (obj.type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
        *subfield = obj.via.i64;
    }
}
