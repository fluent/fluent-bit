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

#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_mp_preflight.h>
#include <msgpack.h>
#include <msgpack/unpack_define.h>
#include <msgpack/util.h>

/* The bundled allocator uses a single pointer as its chunk header. */
typedef char preflight_zone_alignment_check[
    MSGPACK_ZONE_ALIGN == sizeof(void *) ? 1 : -1];

struct preflight_budget {
    size_t limit;
    size_t used;
    size_t free_bytes;
    int has_zone;
};

static int preflight_charge(struct preflight_budget *budget, size_t bytes)
{
    if (bytes > budget->limit - budget->used) {
        return -1;
    }
    budget->used += bytes;
    return 0;
}

/* Mirror the bundled zone's geometric growth without allocating it. Charge
 * alignment and chunk linkage, including the initial empty zone.
 * Keep this in sync with msgpack-c's zone allocator when updating the library.
 */
static int preflight_zone(struct preflight_budget *budget, size_t bytes, int allocate)
{
    size_t capacity;
    size_t aligned_bytes;

    if (!budget->has_zone) {
        if (preflight_charge(budget, sizeof(msgpack_zone) + MSGPACK_ZONE_CHUNK_SIZE +
                             sizeof(void *)) != 0) {
            return -1;
        }
        budget->has_zone = 1;
        budget->free_bytes = MSGPACK_ZONE_CHUNK_SIZE;
    }
    if (!allocate) {
        return 0;
    }
    if (bytes > SIZE_MAX - (MSGPACK_ZONE_ALIGN - 1)) {
        return -1;
    }
    /* Chunk ends are pointer-aligned, so the free-byte remainder is the
     * padding needed to align the next allocation. */
    aligned_bytes = bytes + budget->free_bytes % MSGPACK_ZONE_ALIGN;
    if (aligned_bytes <= budget->free_bytes) {
        budget->free_bytes -= aligned_bytes;
        return 0;
    }
    bytes += MSGPACK_ZONE_ALIGN - 1;
    capacity = MSGPACK_ZONE_CHUNK_SIZE;
    while (capacity < bytes) {
        if (capacity > SIZE_MAX / 2) {
            return -1;
        }
        capacity *= 2;
    }
    if (capacity > SIZE_MAX - sizeof(void *) ||
        preflight_charge(budget, capacity + sizeof(void *)) != 0) {
        return -1;
    }
    budget->free_bytes = capacity - bytes;
    return 0;
}

static int preflight_root(struct preflight_budget *budget)
{
    return 0;
}

static int preflight_nil(struct preflight_budget *budget, int *object)
{
    *object = 0;
    return 0;
}

static int preflight_true(struct preflight_budget *budget, int *object)
{
    *object = 0;
    return 0;
}

static int preflight_false(struct preflight_budget *budget, int *object)
{
    *object = 0;
    return 0;
}

static int preflight_uint8(struct preflight_budget *budget, uint8_t value, int *object)
{
    *object = 0;
    return 0;
}

static int preflight_uint16(struct preflight_budget *budget, uint16_t value, int *object)
{
    *object = 0;
    return 0;
}

static int preflight_uint32(struct preflight_budget *budget, uint32_t value, int *object)
{
    *object = 0;
    return 0;
}

static int preflight_uint64(struct preflight_budget *budget, uint64_t value, int *object)
{
    *object = 0;
    return 0;
}

static int preflight_int8(struct preflight_budget *budget, int8_t value, int *object)
{
    *object = 0;
    return 0;
}

static int preflight_int16(struct preflight_budget *budget, int16_t value, int *object)
{
    *object = 0;
    return 0;
}

static int preflight_int32(struct preflight_budget *budget, int32_t value, int *object)
{
    *object = 0;
    return 0;
}

static int preflight_int64(struct preflight_budget *budget, int64_t value, int *object)
{
    *object = 0;
    return 0;
}

static int preflight_float(struct preflight_budget *budget, float value, int *object)
{
    *object = 0;
    return 0;
}

static int preflight_double(struct preflight_budget *budget, double value, int *object)
{
    *object = 0;
    return 0;
}

static int preflight_str(struct preflight_budget *budget, const char *base,
                          const char *data, unsigned int length, int *object)
{
    *object = 0;
    return preflight_zone(budget, 0, 0);
}

static int preflight_bin(struct preflight_budget *budget, const char *base,
                          const char *data, unsigned int length, int *object)
{
    *object = 0;
    return preflight_zone(budget, 0, 0);
}

static int preflight_ext(struct preflight_budget *budget, const char *base,
                          const char *data, unsigned int length, int *object)
{
    *object = 0;
    if (length == 0) {
        return -1;
    }
    return preflight_zone(budget, 0, 0);
}

static int preflight_array(struct preflight_budget *budget, unsigned int count, int *object)
{
    *object = 0;
    if (count > budget->limit / sizeof(msgpack_object)) {
        return -1;
    }
    return preflight_zone(budget, count * sizeof(msgpack_object), 1);
}

static int preflight_map(struct preflight_budget *budget, unsigned int count, int *object)
{
    *object = 0;
    if (count > budget->limit / sizeof(msgpack_object_kv)) {
        return -1;
    }
    return preflight_zone(budget, count * sizeof(msgpack_object_kv), 1);
}

static int preflight_array_item(struct preflight_budget *budget, int *container, int object)
{
    return 0;
}

static int preflight_map_item(struct preflight_budget *budget, int *container, int key, int value)
{
    return 0;
}

/* Reuse exactly the decoder's wire grammar and fixed nesting limit. */
#define msgpack_unpack_struct(name) struct preflight ## name
#define msgpack_unpack_func(ret, name) static inline ret preflight ## name
#define msgpack_unpack_callback(name) preflight ## name
#define msgpack_unpack_object int
#define msgpack_unpack_user struct preflight_budget
#include <msgpack/unpack_template.h>

struct flb_mp_preflight {
    struct preflight_context parser;
    size_t offset;
    size_t wire_limit;
};

void flb_mp_preflight_reset(struct flb_mp_preflight *scan, size_t limit, size_t wire_limit)
{
    memset(scan, 0, sizeof(*scan));
    scan->parser.user.limit = limit;
    scan->wire_limit = wire_limit;
    preflight_init(&scan->parser);
}

struct flb_mp_preflight *flb_mp_preflight_create(size_t limit, size_t wire_limit)
{
    struct flb_mp_preflight *scan;

    scan = flb_malloc(sizeof(*scan));
    if (scan != NULL) {
        flb_mp_preflight_reset(scan, limit, wire_limit);
    }
    return scan;
}

void flb_mp_preflight_destroy(struct flb_mp_preflight *scan)
{
    flb_free(scan);
}

int flb_mp_preflight_scan(struct flb_mp_preflight *scan, const char *data,
                         size_t len, size_t *consumed, size_t *cost)
{
    int ret;

    *consumed = 0;
    *cost = 0;
    if (scan->offset > len) {
        return -1;
    }
    if (len == scan->offset) {
        return 0;
    }
    ret = preflight_execute(&scan->parser, data, len, &scan->offset);
    if (ret < 0 || scan->offset > scan->wire_limit) {
        return -1;
    }
    if (ret == 0 && scan->parser.cs != MSGPACK_CS_HEADER &&
        scan->parser.trail > scan->wire_limit - scan->offset) {
        return -1;
    }
    if (ret == 1) {
        *consumed = scan->offset;
        *cost = scan->parser.user.used;
    }
    return ret;
}

int flb_mp_preflight_sequence(const char *data, size_t len, size_t limit)
{
    struct flb_mp_preflight scan;
    size_t offset;
    size_t consumed;
    size_t cost;
    int ret;

    offset = 0;
    while (offset < len) {
        flb_mp_preflight_reset(&scan, limit, len - offset);
        ret = flb_mp_preflight_scan(&scan, data + offset, len - offset, &consumed, &cost);
        if (ret != 1 || consumed == 0) {
            return -1;
        }
        offset += consumed;
        /* A decoder may retain a group-start zone across subsequent events. */
        limit -= cost;
    }
    return 0;
}
