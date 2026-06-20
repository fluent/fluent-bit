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

#include <fluent-bit/flb_output_plugin.h>

#include "stackdriver.h"
#include "stackdriver_helper.h"
#include "stackdriver_timestamp.h"
#include <fluent-bit/flb_regex.h>

#include <ctype.h>

static int is_integer(char *str, int size) {
    int i;
    for (i = 0; i < size; ++ i) {
        if (!isdigit(str[i])) {
            return FLB_FALSE;
        }
    }
    return FLB_TRUE;
}

static void try_assign_time(long long seconds, long long nanos,
                            struct flb_time *tms)
{
    if (seconds != 0) {
        tms->tm.tv_sec = seconds;
        tms->tm.tv_nsec = nanos;
    }
}

static long long get_integer(msgpack_object obj)
{
    char tmp[32];

    if (obj.type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
        return obj.via.i64;
    }
    else if (obj.type == MSGPACK_OBJECT_STR
             && is_integer((char *) obj.via.str.ptr,
                           obj.via.str.size)) {

        /*
         * use an intermediary buffer to perform the conversion to avoid any
         * overflow by atoll. LLONG_MAX value is +9,223,372,036,854,775,807,
         * so using a 32 bytes buffer is enough.
         */
        if (obj.via.str.size > sizeof(tmp) - 1) {
            return 0;
        }

        memcpy(tmp, obj.via.str.ptr, obj.via.str.size);
        tmp[obj.via.str.size] = '\0';

        return atoll(tmp);
    }

    return 0;
}

static int extract_format_timestamp_object(msgpack_object *obj,
                                           struct flb_time *tms)
{
    int seconds_found = FLB_FALSE;
    int nanos_found = FLB_FALSE;
    long long seconds = 0;
    long long nanos = 0;

    msgpack_object_kv *p;
    msgpack_object_kv *pend;
    msgpack_object_kv *tmp_p;
    msgpack_object_kv *tmp_pend;

    if (obj->via.map.size == 0) {
        return FLB_FALSE;
    }
    p = obj->via.map.ptr;
    pend = obj->via.map.ptr + obj->via.map.size;

    for (; p < pend; ++p) {
        if (!validate_key(p->key, "timestamp", 9)
            || p->val.type != MSGPACK_OBJECT_MAP) {
            continue;
        }

        tmp_p = p->val.via.map.ptr;
        tmp_pend = p->val.via.map.ptr + p->val.via.map.size;

        for (; tmp_p < tmp_pend; ++tmp_p) {
            if (validate_key(tmp_p->key, "seconds", 7)) {
                seconds_found = FLB_TRUE;
                seconds = get_integer(tmp_p->val);

                if (nanos_found == FLB_TRUE) {
                    try_assign_time(seconds, nanos, tms);
                    return FLB_TRUE;
                }
            }
            else if (validate_key(tmp_p->key, "nanos", 5)) {
                nanos_found = FLB_TRUE;
                nanos = get_integer(tmp_p->val);

                if (seconds_found == FLB_TRUE) {
                    try_assign_time(seconds, nanos, tms);
                    return FLB_TRUE;
                }
            }
        }
    }
    return FLB_FALSE;
}

static int extract_format_timestamp_duo_fields(msgpack_object *obj,
                                               struct flb_time *tms)
{
    int seconds_found = FLB_FALSE;
    int nanos_found = FLB_FALSE;
    long long seconds = 0;
    long long nanos = 0;

    msgpack_object_kv *p;
    msgpack_object_kv *pend;

    if (obj->via.map.size == 0) {
        return FLB_FALSE;
    }
    p = obj->via.map.ptr;
    pend = obj->via.map.ptr + obj->via.map.size;

    for (; p < pend; ++p) {
        if (validate_key(p->key, "timestampSeconds", 16)) {
            seconds_found = FLB_TRUE;
            seconds = get_integer(p->val);

            if (nanos_found == FLB_TRUE) {
                try_assign_time(seconds, nanos, tms);
                return FLB_TRUE;
            }
        }
        else if (validate_key(p->key, "timestampNanos", 14)) {
            nanos_found = FLB_TRUE;
            nanos = get_integer(p->val);

            if (seconds_found == FLB_TRUE) {
                try_assign_time(seconds, nanos, tms);
                return FLB_TRUE;
            }
        }
    }

    return FLB_FALSE;
}

timestamp_status extract_timestamp(msgpack_object *obj,
                                   struct flb_time *tms)
{
    if (extract_format_timestamp_object(obj, tms)) {
        return FORMAT_TIMESTAMP_OBJECT;
    }
    if (extract_format_timestamp_duo_fields(obj, tms)) {
        return FORMAT_TIMESTAMP_DUO_FIELDS;
    }
    return TIMESTAMP_NOT_PRESENT;
}
