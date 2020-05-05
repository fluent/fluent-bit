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

/*
 * The following SDS interface is a clone/strip-down version of the original
 * SDS library created by Antirez at https://github.com/antirez/sds.
 */

#ifndef FLB_SDS_H
#define FLB_SDS_H

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_macros.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

#define FLB_SDS_HEADER_SIZE (sizeof(uint64_t) + sizeof(uint64_t))

typedef char *flb_sds_t;

#pragma pack(push, 1)
struct flb_sds {
    uint64_t len;        /* used */
    uint64_t alloc;      /* excluding the header and null terminator */
    char buf[];
};
#pragma pack(pop)

#define FLB_SDS_HEADER(s)  ((struct flb_sds *) (s - FLB_SDS_HEADER_SIZE))

static inline size_t flb_sds_len(flb_sds_t s)
{
    return (size_t) FLB_SDS_HEADER(s)->len;
}

static inline int flb_sds_is_empty(flb_sds_t s)
{
    if (flb_sds_len(s) == 0) {
        return FLB_TRUE;
    }

    return FLB_FALSE;
}

static inline void flb_sds_len_set(flb_sds_t s, size_t len)
{
    FLB_SDS_HEADER(s)->len = len;
}

static inline size_t flb_sds_alloc(flb_sds_t s)
{
    return (size_t) FLB_SDS_HEADER(s)->alloc;
}

static inline size_t flb_sds_avail(flb_sds_t s)
{
    struct flb_sds *h;

    h = FLB_SDS_HEADER(s);
    return (size_t) (h->alloc - h->len);
}

static inline int flb_sds_cmp(flb_sds_t s, const char *str, int len)
{
    if (flb_sds_len(s) != len) {
        return -1;
    }

    return strncmp(s, str, len);
}

flb_sds_t flb_sds_create(const char *str);
flb_sds_t flb_sds_create_len(const char *str, int len);
flb_sds_t flb_sds_create_size(size_t size);
flb_sds_t flb_sds_cat(flb_sds_t s, const char *str, int len);
flb_sds_t flb_sds_cat_esc(flb_sds_t s, const char *str, int len,
                                       char *esc, size_t esc_size);
flb_sds_t flb_sds_cat_utf8(flb_sds_t *sds, const char *str, int len);
flb_sds_t flb_sds_increase(flb_sds_t s, size_t len);
flb_sds_t flb_sds_copy(flb_sds_t s, const char *str, int len);
void flb_sds_destroy(flb_sds_t s);
flb_sds_t flb_sds_printf(flb_sds_t *sds, const char *fmt, ...);

#endif
