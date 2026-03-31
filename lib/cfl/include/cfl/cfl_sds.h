/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  CFL
 *  ===
 *  Copyright (C) 2022 The CFL Authors
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

#ifndef CFL_SDS_H
#define CFL_SDS_H

/*
 * This interface is a minimized version of Fluent Bit SDS just for easily
 * string storage
 */

#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

#define CFL_SDS_HEADER_SIZE (sizeof(uint64_t) + sizeof(uint64_t))

typedef char *cfl_sds_t;

#pragma pack(push, 1)
struct cfl_sds {
    uint64_t len;        /* used */
    uint64_t alloc;      /* excluding the header and null terminator */
    char buf[];
};
#pragma pack(pop)

#define CFL_SDS_HEADER(s)  ((struct cfl_sds *) (s - CFL_SDS_HEADER_SIZE))

static inline void cfl_sds_len_set(cfl_sds_t s, size_t len)
{
    CFL_SDS_HEADER(s)->len = len;
}

size_t cfl_sds_avail(cfl_sds_t s);
size_t cfl_sds_alloc(cfl_sds_t s);
cfl_sds_t cfl_sds_increase(cfl_sds_t s, size_t len);
size_t cfl_sds_len(cfl_sds_t s);
cfl_sds_t cfl_sds_create_len(const char *str, int len);
cfl_sds_t cfl_sds_create(const char *str);
void cfl_sds_destroy(cfl_sds_t s);
cfl_sds_t cfl_sds_cat(cfl_sds_t s, const char *str, int len);
cfl_sds_t cfl_sds_create_size(size_t size);
void cfl_sds_set_len(cfl_sds_t s, size_t len);
void cfl_sds_cat_safe(cfl_sds_t *buf, const char *str, int len);
cfl_sds_t cfl_sds_printf(cfl_sds_t *sds, const char *fmt, ...);

#endif
