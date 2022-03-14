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

/*
 * This interface is a minimized version of Fluent Bit SDS just for easily
 * string storage
 */

#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

#include <cmetrics/cmt_sds.h>
#include <cmetrics/cmt_log.h>

size_t cmt_sds_avail(cmt_sds_t s)
{
    struct cmt_sds *h;

    h = CMT_SDS_HEADER(s);
    return (size_t) (h->alloc - h->len);
}

cmt_sds_t sds_alloc(size_t size)
{
    void *buf;
    cmt_sds_t s;
    struct cmt_sds *head;

    buf = malloc(CMT_SDS_HEADER_SIZE + size + 1);
    if (!buf) {
        cmt_errno();
        return NULL;
    }

    head = buf;
    head->len = 0;
    head->alloc = size;

    s = head->buf;
    *s = '\0';

    return s;
}

size_t cmt_sds_alloc(cmt_sds_t s)
{
    return (size_t) CMT_SDS_HEADER(s)->alloc;
}

cmt_sds_t cmt_sds_increase(cmt_sds_t s, size_t len)
{
    size_t new_size;
    struct cmt_sds *head;
    cmt_sds_t out;
    void *tmp;

    out = s;
    new_size = (CMT_SDS_HEADER_SIZE + cmt_sds_alloc(s) + len + 1);
    head = CMT_SDS_HEADER(s);
    tmp = realloc(head, new_size);
    if (!tmp) {
        cmt_errno();
        return NULL;
    }
    head = (struct cmt_sds *) tmp;
    head->alloc += len;
    out = head->buf;

    return out;
}

size_t cmt_sds_len(cmt_sds_t s)
{
    return (size_t) CMT_SDS_HEADER(s)->len;
}

cmt_sds_t cmt_sds_create_len(const char *str, int len)
{
    cmt_sds_t s;
    struct cmt_sds *head;

    s = sds_alloc(len);
    if (!s) {
        return NULL;
    }

    if (str) {
        memcpy(s, str, len);
        s[len] = '\0';

        head = CMT_SDS_HEADER(s);
        head->len = len;
    }
    return s;
}

cmt_sds_t cmt_sds_create(const char *str)
{
    size_t len;

    if (!str) {
        len = 0;
    }
    else {
        len = strlen(str);
    }

    return cmt_sds_create_len(str, len);
}

void cmt_sds_destroy(cmt_sds_t s)
{
    struct cmt_sds *head;

    if (!s) {
        return;
    }

    head = CMT_SDS_HEADER(s);
    free(head);
}

cmt_sds_t cmt_sds_cat(cmt_sds_t s, const char *str, int len)
{
    size_t avail;
    struct cmt_sds *head;
    cmt_sds_t tmp = NULL;

    avail = cmt_sds_avail(s);
    if (avail < len) {
        tmp = cmt_sds_increase(s, len);
        if (!tmp) {
            return NULL;
        }
        s = tmp;
    }
    memcpy((char *) (s + cmt_sds_len(s)), str, len);

    head = CMT_SDS_HEADER(s);
    head->len += len;
    s[head->len] = '\0';

    return s;
}

cmt_sds_t cmt_sds_create_size(size_t size)
{
    return sds_alloc(size);
}

void cmt_sds_set_len(cmt_sds_t s, size_t len)
{
    struct cmt_sds *head;

    head = CMT_SDS_HEADER(s);
    head->len = len;
}

void cmt_sds_cat_safe(cmt_sds_t *buf, const char *str, int len)
{
    cmt_sds_t tmp;

    tmp = cmt_sds_cat(*buf, str, len);
    if (!tmp) {
        return;
    }
    *buf = tmp;
}

