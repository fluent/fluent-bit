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


#include <errno.h>

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
        if (!*subfield) {
            *subfield = flb_sds_create_len(obj.via.str.ptr, obj.via.str.size);
        }
        else {
            *subfield = flb_sds_copy(*subfield, obj.via.str.ptr,
                                     obj.via.str.size);
        }
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
        char buf[32];
        char *end;
        long long val;
        size_t len = obj.via.str.size;

        /*
         * Reject empty or oversized strings: no valid int64 has more than 20
         * characters (19 digits plus an optional sign), so anything that does
         * not fit the buffer cannot be a complete integer.
         */
        if (len == 0 || len > sizeof(buf) - 1) {
            return;
        }

        memcpy(buf, obj.via.str.ptr, len);
        buf[len] = '\0';

        errno = 0;
        val = strtoll(buf, &end, 10);

        /*
         * Only assign when the whole string parsed as a single complete
         * integer (no leftover characters) and the value did not overflow;
         * otherwise leave the field at its previous value.
         */
        if (errno == 0 && end != buf && *end == '\0') {
            *subfield = val;
        }
    }
    else if (obj.type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
        *subfield = obj.via.i64;
    }
}

void pack_sds_safe(msgpack_packer *mp_pck, flb_sds_t s) {
    if (s) {
        msgpack_pack_str(mp_pck, flb_sds_len(s));
        msgpack_pack_str_body(mp_pck, s, flb_sds_len(s));
    }
    else {
        msgpack_pack_str(mp_pck, 0);
        msgpack_pack_str_body(mp_pck, "", 0);
    }
}

