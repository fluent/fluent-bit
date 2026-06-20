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

/*
 * The following SDS interface is a clone/strip-down version of the original
 * SDS library created by Antirez at https://github.com/antirez/sds.
 */

#include <fluent-bit/flb_compat.h>
#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_utf8.h>
#include <fluent-bit/flb_utils.h>

#include <stdarg.h>
#include <ctype.h>

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

flb_sds_t flb_sds_create_len(const char *str, int len)
{
    flb_sds_t s;
    struct flb_sds *head;

    s = sds_alloc(len);
    if (!s) {
        return NULL;
    }

    if (str) {
        memcpy(s, str, len);
        s[len] = '\0';

        head = FLB_SDS_HEADER(s);
        head->len = len;
    }
    return s;
}

flb_sds_t flb_sds_create(const char *str)
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
    head = (struct flb_sds *) tmp;
    head->alloc += len;
    out = head->buf;

    return out;
}

flb_sds_t flb_sds_cat(flb_sds_t s, const char *str, int len)
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


/*
 * remove empty spaces on left/right from sds buffer 's' and return the new length
 * of the content.
 */
int flb_sds_trim(flb_sds_t s)
{
    unsigned int i;
    unsigned int len;
    char *left = 0, *right = 0;
    char *buf;

    if (!s) {
        return -1;
    }

    len = flb_sds_len(s);
    if (len == 0) {
        return 0;
    }

    buf = s;
    left = buf;

    /* left spaces */
    while (left) {
        if (isspace(*left)) {
            left++;
        }
        else {
            break;
        }
    }

    right = buf + (len - 1);
    /* Validate right v/s left */
    if (right < left) {
        buf[0] = '\0';
        return -1;
    }

    /* Move back */
    while (right != buf){
        if (isspace(*right)) {
            right--;
        }
        else {
            break;
        }
    }

    len = (right - left) + 1;
    for (i=0; i<len; i++) {
        buf[i] = (char) left[i];
    }
    buf[i] = '\0';
    flb_sds_len_set(buf, i);

    return i;
}

int flb_sds_cat_safe(flb_sds_t *buf, const char *str, int len)
{
    flb_sds_t tmp;

    tmp = flb_sds_cat(*buf, str, len);
    if (!tmp) {
        return -1;
    }
    *buf = tmp;
    return 0;
}

flb_sds_t flb_sds_cat_esc(flb_sds_t s, const char *str, int len,
                                       char *esc, size_t esc_size)
{
    size_t avail;
    struct flb_sds *head;
    flb_sds_t tmp = NULL;
    uint32_t c;
    int i;

    avail = flb_sds_avail(s);
    if (avail < len) {
        tmp = flb_sds_increase(s, len);
        if (!tmp) {
            return NULL;
        }
        s = tmp;
    }
    head = FLB_SDS_HEADER(s);

    for (i = 0; i < len; i++) {
        if (flb_sds_avail(s) < 8) {
            tmp = flb_sds_increase(s, 8);
            if (tmp == NULL) {
                return NULL;
            }
            s = tmp;
            head = FLB_SDS_HEADER(s);
        }
        c = (unsigned char) str[i];
        if (esc != NULL && c < esc_size && esc[c] != 0) {
            s[head->len++] = '\\';
            s[head->len++] = esc[c];
        }
        else {
            s[head->len++] = c;
        }
    }

    s[head->len] = '\0';

    return s;
}


flb_sds_t flb_sds_copy(flb_sds_t s, const char *str, int len)
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

flb_sds_t flb_sds_cat_utf8(flb_sds_t *sds, const char *str, int str_len)
{
    int ret;
    int offset;
    size_t size;
    struct flb_sds *head;
    flb_sds_t tmp;
    flb_sds_t s;

    s = *sds;
    head = FLB_SDS_HEADER(s);

    /* make sure we have at least str_len extra bytes available */
    if (flb_sds_avail(s) <= str_len) {
        tmp = flb_sds_increase(s, str_len);
        if (tmp == NULL) {
            return NULL;
        }
        *sds = s = tmp;
        head = FLB_SDS_HEADER(s);
    }

    while (1) {
        offset = head->len;
        ret = flb_utils_write_str(s, &offset, flb_sds_alloc(s), str, str_len, FLB_TRUE);
        if (ret == FLB_FALSE) {
            /* realloc */
            size = flb_sds_alloc(s) * 2;
            tmp = flb_sds_increase(s, size);
            if (tmp == NULL) {
                return NULL;
            }
            *sds = s = tmp;
            head = FLB_SDS_HEADER(s);
        }
        else {
            break;
        }
    }

    flb_sds_len_set(s, offset);
    s[head->len] = '\0';
    return s;
}

flb_sds_t flb_sds_printf(flb_sds_t *sds, const char *fmt, ...)
{
    va_list ap;
    int len = strlen(fmt)*2;
    int size;
    flb_sds_t tmp = NULL;
    flb_sds_t s;
    struct flb_sds *head;

    if (len < 64) len = 64;

    s = *sds;
    if (flb_sds_avail(s) < len) {
        tmp = flb_sds_increase(s, len - flb_sds_avail(s));
        if (!tmp) {
            return NULL;
        }
        *sds = s = tmp;
    }

    va_start(ap, fmt);
    size = vsnprintf((char *) (s + flb_sds_len(s)), flb_sds_avail(s), fmt, ap);
    if (size < 0) {
        flb_warn("[%s] buggy vsnprintf return %d", __FUNCTION__, size);
        va_end(ap);
        return NULL;
    }
    va_end(ap);

    if (size >= flb_sds_avail(s)) {
        tmp = flb_sds_increase(s, size - flb_sds_avail(s) + 1);
        if (!tmp) {
            return NULL;
        }
        *sds = s = tmp;

        va_start(ap, fmt);
        size = vsnprintf((char *) (s + flb_sds_len(s)), flb_sds_avail(s), fmt, ap);
        if (size > flb_sds_avail(s)) {
            flb_warn("[%s] vsnprintf is insatiable ", __FUNCTION__);
            va_end(ap);
            return NULL;
        }
        va_end(ap);
    }

    head = FLB_SDS_HEADER(s);
    head->len += size;
    s[head->len] = '\0';

    return s;
}

void flb_sds_destroy(flb_sds_t s)
{
    struct flb_sds *head;

    if (!s) {
        return;
    }

    head = FLB_SDS_HEADER(s);
    flb_free(head);
}

/*
 * flb_sds_snprintf is a wrapper of snprintf.
 * The difference is that this function can increase the buffer of flb_sds_t.
 */
int flb_sds_snprintf(flb_sds_t *str, size_t size, const char *fmt, ...)
{
    va_list va;
    flb_sds_t tmp;
    int ret;

 retry_snprintf:
    va_start(va, fmt);
    ret = vsnprintf(*str, size, fmt, va);
    if (ret > size) {
        tmp = flb_sds_increase(*str, ret-size);
        if (tmp == NULL) {
            return -1;
        }
        *str = tmp;
        size = ret;
        va_end(va);
        goto retry_snprintf;
    }
    va_end(va);

    flb_sds_len_set(*str, ret);
    return ret;
}
