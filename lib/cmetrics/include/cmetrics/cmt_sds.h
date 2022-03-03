/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  CMetrics
 *  ========
 *  Copyright 2021 Eduardo Silva <eduardo@calyptia.com>
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

#ifndef CMT_SDS_H
#define CMT_SDS_H

/*
 * This interface is a minimized version of Fluent Bit SDS just for easily
 * string storage
 */

#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

#include <cmetrics/cmt_log.h>

#define CMT_SDS_HEADER_SIZE (sizeof(uint64_t) + sizeof(uint64_t))

typedef char *cmt_sds_t;

#pragma pack(push, 1)
struct cmt_sds {
    uint64_t len;        /* used */
    uint64_t alloc;      /* excluding the header and null terminator */
    char buf[];
};
#pragma pack(pop)

#define CMT_SDS_HEADER(s)  ((struct cmt_sds *) (s - CMT_SDS_HEADER_SIZE))

static inline void cmt_sds_len_set(cmt_sds_t s, size_t len)
{
    CMT_SDS_HEADER(s)->len = len;
}

size_t cmt_sds_avail(cmt_sds_t s);
cmt_sds_t sds_alloc(size_t size);
size_t cmt_sds_alloc(cmt_sds_t s);
cmt_sds_t cmt_sds_increase(cmt_sds_t s, size_t len);
size_t cmt_sds_len(cmt_sds_t s);
cmt_sds_t cmt_sds_create_len(const char *str, int len);
cmt_sds_t cmt_sds_create(const char *str);
void cmt_sds_destroy(cmt_sds_t s);
cmt_sds_t cmt_sds_cat(cmt_sds_t s, const char *str, int len);
cmt_sds_t cmt_sds_create_size(size_t size);
void cmt_sds_set_len(cmt_sds_t s, size_t len);
void cmt_sds_cat_safe(cmt_sds_t *buf, const char *str, int len);

#endif