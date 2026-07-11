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
#include <limits.h>
#include <stdint.h>

#include <cfl/cfl_sds.h>
#include "cfl_arena_internal.h"

#define CFL_SDS_ARENA_FLAG (UINT64_C(1) << 63)
#define CFL_SDS_ALLOC_MASK (~CFL_SDS_ARENA_FLAG)

struct cfl_sds_arena_header {
    struct cfl_arena *arena;
    uint8_t external;
    uint8_t allocation_class;
};

static struct cfl_sds_arena_header *sds_arena_header(struct cfl_sds *head)
{
    return (struct cfl_sds_arena_header *)
           ((char *) head - sizeof(struct cfl_sds_arena_header));
}

size_t cfl_sds_avail(cfl_sds_t s)
{
    struct cfl_sds *h;

    if (s == NULL) {
        return 0;
    }

    h = CFL_SDS_HEADER(s);
    return (size_t) ((h->alloc & CFL_SDS_ALLOC_MASK) - h->len);
}

static cfl_sds_t sds_alloc(struct cfl_arena *arena, size_t size)
{
    void *buf;
    cfl_sds_t s;
    struct cfl_sds *head;
    struct cfl_sds_arena_header *arena_head;
    size_t allocation_size;
    size_t external_threshold;
    size_t payload_capacity;
    uint8_t allocation_class;

    if (size > SIZE_MAX - CFL_SDS_HEADER_SIZE -
                         sizeof(struct cfl_sds_arena_header) - 1) {
        return NULL;
    }

    payload_capacity = size;
    allocation_class = 0;
    allocation_size = CFL_SDS_HEADER_SIZE + size + 1;
    if (arena == NULL) {
        buf = malloc(allocation_size);
    }
    else if (size <= 1024) {
        external_threshold = cfl_arena_large_object_threshold(arena);
        buf = cfl_arena_alloc_sds(arena, size,
                                          CFL_SDS_HEADER_SIZE +
                                          sizeof(struct cfl_sds_arena_header),
                                          &allocation_class,
                                          &payload_capacity);
        allocation_size = sizeof(struct cfl_sds_arena_header) +
                          CFL_SDS_HEADER_SIZE + payload_capacity + 1;
    }
    else {
        external_threshold = cfl_arena_large_object_threshold(arena);
        allocation_size += sizeof(struct cfl_sds_arena_header);
        if (allocation_size >= external_threshold) {
            buf = cfl_arena_alloc_external(arena, allocation_size);
        }
        else {
            buf = cfl_arena_alloc(arena, allocation_size);
        }
    }
    if (!buf) {
        return NULL;
    }

    if (arena == NULL) {
        head = buf;
    }
    else {
        arena_head = buf;
        arena_head->arena = arena;
        arena_head->external = allocation_class == 0 &&
                               allocation_size >= external_threshold;
        arena_head->allocation_class = allocation_class;
        head = (struct cfl_sds *) (arena_head + 1);
    }
    head->len = 0;
    head->alloc = payload_capacity;
    if (arena != NULL) {
        head->alloc |= CFL_SDS_ARENA_FLAG;
    }

    s = head->buf;
    *s = '\0';

    return s;
}

size_t cfl_sds_alloc(cfl_sds_t s)
{
    if (s == NULL) {
        return 0;
    }

    return (size_t) (CFL_SDS_HEADER(s)->alloc & CFL_SDS_ALLOC_MASK);
}

cfl_sds_t cfl_sds_increase(cfl_sds_t s, size_t len)
{
    size_t new_size;
    struct cfl_sds *head;
    struct cfl_sds *new_head;
    cfl_sds_t out;
    cfl_sds_t arena_out;
    void *tmp;

    if (s == NULL) {
        return NULL;
    }

    out = s;
    head = CFL_SDS_HEADER(s);

    if (len == 0) {
        return s;
    }

    if (cfl_sds_alloc(s) > SIZE_MAX - len) {
        return NULL;
    }

    new_size = cfl_sds_alloc(s) + len;
    if (new_size > SIZE_MAX - CFL_SDS_HEADER_SIZE - 1) {
        return NULL;
    }
    if ((head->alloc & CFL_SDS_ARENA_FLAG) != 0) {
        arena_out = sds_alloc(sds_arena_header(head)->arena, new_size);
        if (arena_out == NULL) {
            return NULL;
        }
        memcpy(arena_out, s, head->len + 1);
        new_head = CFL_SDS_HEADER(arena_out);
        new_head->len = head->len;
        cfl_sds_destroy(s);
        return arena_out;
    }

    new_size += CFL_SDS_HEADER_SIZE + 1;
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
    if (s == NULL) {
        return 0;
    }

    return (size_t) CFL_SDS_HEADER(s)->len;
}

cfl_sds_t cfl_sds_create_len(const char *str, int len)
{
    return cfl_sds_create_len_in(NULL, str, len);
}

cfl_sds_t cfl_sds_create_len_in(struct cfl_arena *arena,
                                const char *str, int len)
{
    cfl_sds_t s;
    struct cfl_sds *head;

    if (len < 0) {
        return NULL;
    }

    s = sds_alloc(arena, len);
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
        if (len > INT_MAX) {
            return NULL;
        }
    }

    return cfl_sds_create_len(str, (int) len);
}

void cfl_sds_destroy(cfl_sds_t s)
{
    struct cfl_sds *head;
    struct cfl_sds_arena_header *arena_head;

    if (!s) {
        return;
    }

    head = CFL_SDS_HEADER(s);
    if ((head->alloc & CFL_SDS_ARENA_FLAG) == 0) {
        free(head);
    }
    else {
        arena_head = sds_arena_header(head);
        if (arena_head->external) {
            cfl_arena_free_external(arena_head->arena, arena_head);
        }
        else if (arena_head->allocation_class != 0) {
            cfl_arena_free_sds(
                arena_head->arena, arena_head,
                arena_head->allocation_class,
                sizeof(struct cfl_sds_arena_header) + CFL_SDS_HEADER_SIZE +
                cfl_sds_alloc(s) + 1);
        }
    }
}

cfl_sds_t cfl_sds_cat(cfl_sds_t s, const char *str, int len)
{
    size_t avail;
    size_t append_len;
    size_t source_offset;
    uintptr_t buffer_addr;
    uintptr_t source_addr;
    struct cfl_sds *head;
    cfl_sds_t tmp = NULL;
    const char *source;
    int source_in_buffer;
    size_t allocation_size;

    if (s == NULL || str == NULL || len < 0) {
        return NULL;
    }

    if (len == 0) {
        return s;
    }

    append_len = (size_t) len;
    head = CFL_SDS_HEADER(s);
    allocation_size = cfl_sds_alloc(s);
    if (head->len > allocation_size ||
        head->len > SIZE_MAX - append_len - 1) {
        return NULL;
    }

    source = str;
    source_in_buffer = 0;
    source_offset = 0;

    /*
     * This flat-address check lets self-appends survive realloc. If the
     * source starts inside the SDS buffer, the whole source slice must also
     * fit in that allocation.
     */
    buffer_addr = (uintptr_t) s;
    source_addr = (uintptr_t) str;
    if (source_addr >= buffer_addr &&
        (source_addr - buffer_addr) <= allocation_size) {
        source_offset = (size_t) (source_addr - buffer_addr);

        if (append_len - 1 >= allocation_size - source_offset) {
            return NULL;
        }

        source_in_buffer = 1;
    }

    avail = cfl_sds_avail(s);
    if (avail < append_len) {
        tmp = cfl_sds_increase(s, append_len - avail);
        if (!tmp) {
            return NULL;
        }
        s = tmp;
    }

    if (source_in_buffer) {
        source = s + source_offset;
    }

    head = CFL_SDS_HEADER(s);
    if (head->len > UINT64_MAX - append_len) {
        return NULL;
    }

    memmove((char *) (s + head->len), source, append_len);

    head->len += append_len;
    s[head->len] = '\0';

    return s;
}

cfl_sds_t cfl_sds_create_size(size_t size)
{
    return sds_alloc(NULL, size);
}

void cfl_sds_set_len(cfl_sds_t s, size_t len)
{
    struct cfl_sds *head;

    if (s == NULL) {
        return;
    }

    head = CFL_SDS_HEADER(s);
    if (len > cfl_sds_alloc(s)) {
        return;
    }

    head->len = len;
    s[len] = '\0';
}

void cfl_sds_cat_safe(cfl_sds_t *buf, const char *str, int len)
{
    cfl_sds_t tmp;

    if (buf == NULL || *buf == NULL) {
        return;
    }

    tmp = cfl_sds_cat(*buf, str, len);
    if (!tmp) {
        return;
    }
    *buf = tmp;
}

cfl_sds_t cfl_sds_printf(cfl_sds_t *sds, const char *fmt, ...)
{
    va_list ap;
    size_t avail;
    size_t growth;
    size_t base_len;
    int size;
    cfl_sds_t tmp = NULL;
    cfl_sds_t s;
    struct cfl_sds *head;

    if (sds == NULL || *sds == NULL || fmt == NULL) {
        return NULL;
    }

    s = *sds;
    base_len = cfl_sds_len(s);
    if (base_len > cfl_sds_alloc(s)) {
        return NULL;
    }

    while (1) {
        avail = cfl_sds_avail(s);
        va_start(ap, fmt);
        size = vsnprintf((char *) (s + base_len), avail + 1, fmt, ap);
        va_end(ap);

        if (size < 0) {
            s[base_len] = '\0';
            return NULL;
        }

        if ((size_t) size <= avail) {
            break;
        }

        /*
         * vsnprintf() writes a truncated result when the available space is
         * insufficient. Restore the original SDS terminator before growing
         * so an allocation failure leaves the input unchanged.
         */
        s[base_len] = '\0';

        growth = (size_t) size - avail;
        tmp = cfl_sds_increase(s, growth);
        if (!tmp) {
            return NULL;
        }

        *sds = s = tmp;
    }

    head = CFL_SDS_HEADER(s);
    if (head->len > UINT64_MAX - (size_t) size) {
        return NULL;
    }

    head->len += (size_t) size;
    s[head->len] = '\0';

    return s;
}
