/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_sds.h>

static flb_sds_t sds_alloc(size_t size)
{
    void *buf;
    flb_sds_t s;
    struct flb_sds *head;

    buf = flb_malloc(FLB_SDS_HEADER_SIZE + size + 1);
    if (!buf) {
        flb_errno();
        return NULL;
    }

    head = buf;
    head->len = 0;
    head->alloc = size;

    s = head->buf;
    *s = '\0';

    return s;
}

flb_sds_t flb_sds_create_len(char *str, int len)
{
    flb_sds_t s;
    struct flb_sds *head;

    s = sds_alloc(len);
    if (str) {
        memcpy(s, str, len);
        s[len] = '\0';

        head = FLB_SDS_HEADER(s);
        head->len = len;
    }
    return s;
}

flb_sds_t flb_sds_create(char *str)
{
    size_t len;

    if (!str) {
        len = 0;
    }
    else {
        len = strlen(str);
    }

    return flb_sds_create_len(str, len);
}

flb_sds_t flb_sds_create_size(size_t size)
{
    return sds_alloc(size);
}

/* Increase SDS buffer size 'len' bytes */
flb_sds_t flb_sds_increase(flb_sds_t s, size_t len)
{
    size_t new_size;
    struct flb_sds *head;
    flb_sds_t out;
    void *tmp;

    out = s;
    new_size = (FLB_SDS_HEADER_SIZE + flb_sds_alloc(s) + len + 1);
    head = FLB_SDS_HEADER(s);
    tmp = flb_realloc(head, new_size);
    if (!tmp) {
        flb_errno();
        return NULL;
    }

    if (tmp != head) {
        head = tmp;
    }

    head->alloc += len;
    out = head->buf;

    return out;
}

flb_sds_t flb_sds_cat(flb_sds_t s, char *str, int len)
{
    size_t avail;
    struct flb_sds *head;
    flb_sds_t tmp = NULL;

    avail = flb_sds_avail(s);
    if (avail < len) {
        tmp = flb_sds_increase(s, len);
        if (!tmp) {
            return NULL;
        }
        s = tmp;
    }
    memcpy((char *) (s + flb_sds_len(s)), str, len);

    head = FLB_SDS_HEADER(s);
    head->len += len;
    s[head->len] = '\0';

    return s;
}

flb_sds_t flb_sds_copy(flb_sds_t s, char *str, int len)
{
    size_t avail;
    struct flb_sds *head;
    flb_sds_t tmp = NULL;

    avail = flb_sds_alloc(s);
    if (avail < len) {
        tmp = flb_sds_increase(s, len);
        if (!tmp) {
            return NULL;
        }
        s = tmp;
    }
    memcpy((char *) s, str, len);

    head = FLB_SDS_HEADER(s);
    head->len = len;
    s[head->len] = '\0';

    return s;
}

int flb_sds_destroy(flb_sds_t s)
{
    struct flb_sds *head;

    head = FLB_SDS_HEADER(s);
    flb_free(head);

    return 0;
}
