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

/*
 * This interface is a minimized version of Fluent Bit SDS just for easily
 * string storage
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <inttypes.h>

#include <cfl/cfl_sds.h>

size_t cfl_sds_avail(cfl_sds_t s)
{
    struct cfl_sds *h;

    h = CFL_SDS_HEADER(s);
    return (size_t) (h->alloc - h->len);
}

static cfl_sds_t sds_alloc(size_t size)
{
    void *buf;
    cfl_sds_t s;
    struct cfl_sds *head;

    buf = malloc(CFL_SDS_HEADER_SIZE + size + 1);
    if (!buf) {
        return NULL;
    }

    head = buf;
    head->len = 0;
    head->alloc = size;

    s = head->buf;
    *s = '\0';

    return s;
}

size_t cfl_sds_alloc(cfl_sds_t s)
{
    return (size_t) CFL_SDS_HEADER(s)->alloc;
}

cfl_sds_t cfl_sds_increase(cfl_sds_t s, size_t len)
{
    size_t new_size;
    struct cfl_sds *head;
    cfl_sds_t out;
    void *tmp;

    out = s;
    new_size = (CFL_SDS_HEADER_SIZE + cfl_sds_alloc(s) + len + 1);
    head = CFL_SDS_HEADER(s);
    tmp = realloc(head, new_size);
    if (!tmp) {
        return NULL;
    }
    head = (struct cfl_sds *) tmp;
    head->alloc += len;
    out = head->buf;

    return out;
}

size_t cfl_sds_len(cfl_sds_t s)
{
    return (size_t) CFL_SDS_HEADER(s)->len;
}

cfl_sds_t cfl_sds_create_len(const char *str, int len)
{
    cfl_sds_t s;
    struct cfl_sds *head;

    s = sds_alloc(len);
    if (!s) {
        return NULL;
    }

    if (str) {
        memcpy(s, str, len);
        s[len] = '\0';

        head = CFL_SDS_HEADER(s);
        head->len = len;
    }
    return s;
}

cfl_sds_t cfl_sds_create(const char *str)
{
    size_t len;

    if (!str) {
        len = 0;
    }
    else {
        len = strlen(str);
    }

    return cfl_sds_create_len(str, len);
}

void cfl_sds_destroy(cfl_sds_t s)
{
    struct cfl_sds *head;

    if (!s) {
        return;
    }

    head = CFL_SDS_HEADER(s);
    free(head);
}

cfl_sds_t cfl_sds_cat(cfl_sds_t s, const char *str, int len)
{
    size_t avail;
    struct cfl_sds *head;
    cfl_sds_t tmp = NULL;

    avail = cfl_sds_avail(s);
    if (avail < len) {
        tmp = cfl_sds_increase(s, len);
        if (!tmp) {
            return NULL;
        }
        s = tmp;
    }
    memcpy((char *) (s + cfl_sds_len(s)), str, len);

    head = CFL_SDS_HEADER(s);
    head->len += len;
    s[head->len] = '\0';

    return s;
}

cfl_sds_t cfl_sds_create_size(size_t size)
{
    return sds_alloc(size);
}

void cfl_sds_set_len(cfl_sds_t s, size_t len)
{
    struct cfl_sds *head;

    head = CFL_SDS_HEADER(s);
    head->len = len;
}

void cfl_sds_cat_safe(cfl_sds_t *buf, const char *str, int len)
{
    cfl_sds_t tmp;

    tmp = cfl_sds_cat(*buf, str, len);
    if (!tmp) {
        return;
    }
    *buf = tmp;
}

cfl_sds_t cfl_sds_printf(cfl_sds_t *sds, const char *fmt, ...)
{
    va_list ap;
    int len = strlen(fmt)*2;
    int size;
    cfl_sds_t tmp = NULL;
    cfl_sds_t s;
    struct cfl_sds *head;

    if (len < 64) len = 64;

    s = *sds;
    if (cfl_sds_avail(s)< len) {
        tmp = cfl_sds_increase(s, len);
        if (!tmp) {
            return NULL;
        }
        *sds = s = tmp;
    }

    va_start(ap, fmt);
    size = vsnprintf((char *) (s + cfl_sds_len(s)), cfl_sds_avail(s), fmt, ap);
    if (size < 0) {
        va_end(ap);
        return NULL;
    }
    va_end(ap);

    if (size >= cfl_sds_avail(s)) {
        tmp = cfl_sds_increase(s, size - cfl_sds_avail(s) + 1);
        if (!tmp) {
            return NULL;
        }
        *sds = s = tmp;

        va_start(ap, fmt);
        size = vsnprintf((char *) (s + cfl_sds_len(s)), cfl_sds_avail(s), fmt, ap);
        if (size > cfl_sds_avail(s)) {
            va_end(ap);
            return NULL;
        }
        va_end(ap);
    }

    head = CFL_SDS_HEADER(s);
    head->len += size;
    s[head->len] = '\0';

    return s;
}

