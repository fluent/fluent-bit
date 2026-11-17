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

#ifndef FLB_MP_H
#define FLB_MP_H

#include <msgpack.h>
#include <cfl/cfl.h>

#include <stddef.h>
#include <stdint.h>

#define FLB_MP_MAP        MSGPACK_OBJECT_MAP
#define FLB_MP_ARRAY      MSGPACK_OBJECT_ARRAY

int flb_mp_count(const void *data, size_t bytes);

/*
 * Count log records without building msgpack objects; allocation-free in
 * non-tracking builds. Rejects unsupported or deep shapes, so callers can fall
 * back to the event decoder.
 */
int flb_mp_scan_log_records(const void *data, size_t bytes, int *records);
int flb_mp_scan_log_events(const void *data, size_t bytes,
                           int *records, int *group_markers);
int flb_mp_count_log_records(const void *data, size_t bytes);
int flb_mp_log_window_next(const void *data, size_t bytes, size_t offset,
                           size_t limit_bytes, int limit_records,
                           size_t *window_end, int *window_records);
/* group markers that belong to neighbouring appends, see flb_mp_log_group_boundaries() */
#define FLB_MP_GROUPS_KEEP_LEADING_END   1
#define FLB_MP_GROUPS_KEEP_TRAILING_OPEN 2

int flb_mp_log_group_boundaries(const void *data, size_t bytes);
int flb_mp_log_group_starts(const void *data, size_t bytes);
int flb_mp_normalize_log_buffer_groups_msgpack(const void *in_buf, size_t in_size,
                                               char **out_buf, size_t *out_size);
int flb_mp_normalize_log_buffer_groups_msgpack_ex(const void *in_buf, size_t in_size,
                                                  char **out_buf, size_t *out_size,
                                                  int flags);
int flb_mp_normalize_log_buffer_groups(const void *in_buf, size_t in_size,
                                       char **out_buf, size_t *out_size);
int flb_mp_count_remaining(const void *data, size_t bytes, size_t *remaining_bytes);
int flb_mp_validate_log_chunk(const void *data, size_t bytes,
                              int *out_records, size_t *processed_bytes);
int flb_mp_validate_metric_chunk(const void *data, size_t bytes,
                                 int *out_series, size_t *processed_bytes);
int flb_mp_validate_trace_chunk(const void *data, size_t bytes,
                                int *out_contexts, size_t *processed_bytes);

void flb_mp_set_map_header_size(char *buf, int arr_size);


/*
 * Map header handling functions
 */
struct flb_mp_map_header {
    off_t offset;
    size_t entries;
    void *data;
};

/* */
struct flb_mp_accessor_match {
    int matched;
    msgpack_object *start_key;
    msgpack_object *key;
    msgpack_object *val;
    struct flb_record_accessor *ra;
};

/* wrapper to hold a list of record_accessor contexts */
struct flb_mp_accessor_ra {
    int is_active;
    struct flb_record_accessor *ra;
    struct mk_list _head;
};

/* A context to abstract usage of record accessor when multiple patterns exists */
struct flb_mp_accessor {
    int matches_size;
    struct flb_mp_accessor_match *matches;
    struct mk_list ra_list;
};


int flb_mp_map_header_init(struct flb_mp_map_header *mh, msgpack_packer *mp_pck);
int flb_mp_map_header_append(struct flb_mp_map_header *mh);
void flb_mp_map_header_end(struct flb_mp_map_header *mh);

int flb_mp_array_header_init(struct flb_mp_map_header *mh, msgpack_packer *mp_pck);
int flb_mp_array_header_append(struct flb_mp_map_header *mh);
void flb_mp_array_header_end(struct flb_mp_map_header *mh);

/* mp accessor api */
struct flb_mp_accessor *flb_mp_accessor_create(struct mk_list *slist_patterns);
void flb_mp_accessor_destroy(struct flb_mp_accessor *mpa);
int flb_mp_accessor_keys_remove(struct flb_mp_accessor *mpa,
                                msgpack_object *map,
                                void **out_buf, size_t *out_size);
void flb_mp_accessor_set_active(struct flb_mp_accessor *mpa, int status);
int flb_mp_accessor_set_active_by_pattern(struct flb_mp_accessor *mpa,
                                          const char *pattern, int status);

struct cfl_object *flb_mp_object_to_cfl(msgpack_object *o);
int flb_mp_cfl_to_msgpack(struct cfl_object *obj, char **out_buf, size_t *out_size);




/*
 * Serialized MessagePack helpers
 * ------------------------------
 * Read-only functions that work on the serialized bytes: no msgpack object
 * tree is built and no memory is allocated. Every format of the MessagePack
 * specification is recognized, every read is bounds checked, and the type
 * 0xc1 (never used) is reported as an error.
 */

/* Nesting levels that can be enforced by a 'max_depth' argument */
#define FLB_MP_RAW_MAX_DEPTH  64

/*
 * Skip one complete object, including its children. On success returns 0 and
 * moves the cursor to the first byte after the object, otherwise returns -1
 * and the cursor is not modified.
 *
 * 'max_depth' is the number of nesting levels accepted, the object itself is
 * the first one. Zero means no limit, as in the specification; a value above
 * FLB_MP_RAW_MAX_DEPTH is handled as FLB_MP_RAW_MAX_DEPTH.
 */
int flb_mp_raw_skip(const unsigned char **cursor, const unsigned char *end,
                    int max_depth);

/*
 * Same as flb_mp_raw_skip(), but it also fails if any value is not stored
 * the way msgpack_pack_object() writes it: shortest integer, length and
 * count formats, no NaN. An accepted object can be copied as is where the
 * regular code path would unpack it and pack it again.
 */
int flb_mp_raw_skip_minimal(const unsigned char **cursor,
                            const unsigned char *end, int max_depth);

/* Size in bytes of the first object stored in a buffer, zero on error */
size_t flb_mp_raw_object_size(const char *buf, size_t size, int max_depth);

static inline uint16_t flb_mp_raw_be16(const unsigned char *p)
{
    return (uint16_t) (((uint16_t) p[0] << 8) | (uint16_t) p[1]);
}

static inline uint32_t flb_mp_raw_be32(const unsigned char *p)
{
    return ((uint32_t) p[0] << 24) | ((uint32_t) p[1] << 16) |
           ((uint32_t) p[2] << 8) | (uint32_t) p[3];
}

/*
 * Read a map header. On success returns 0, sets the number of key/value
 * pairs and moves the cursor to the first key.
 */
static inline int flb_mp_raw_map_header(const unsigned char **cursor,
                                        const unsigned char *end,
                                        uint32_t *count)
{
    const unsigned char *p = *cursor;

    if (p >= end) {
        return -1;
    }

    if ((p[0] & 0xf0) == 0x80) {
        *count = p[0] & 0x0f;
        *cursor = p + 1;
        return 0;
    }
    else if (p[0] == 0xde && end - p >= 3) {
        *count = flb_mp_raw_be16(p + 1);
        *cursor = p + 3;
        return 0;
    }
    else if (p[0] == 0xdf && end - p >= 5) {
        *count = flb_mp_raw_be32(p + 1);
        *cursor = p + 5;
        return 0;
    }

    return -1;
}

/*
 * Read a string header. On success returns 0, sets the string length and
 * moves the cursor to the first byte of the string. The string body is
 * guaranteed to be inside the buffer.
 */
static inline int flb_mp_raw_str_header(const unsigned char **cursor,
                                        const unsigned char *end,
                                        uint32_t *length)
{
    uint32_t len;
    const unsigned char *p = *cursor;

    if (p >= end) {
        return -1;
    }

    if ((p[0] & 0xe0) == 0xa0) {
        len = p[0] & 0x1f;
        p += 1;
    }
    else if (p[0] == 0xd9 && end - p >= 2) {
        len = p[1];
        p += 2;
    }
    else if (p[0] == 0xda && end - p >= 3) {
        len = flb_mp_raw_be16(p + 1);
        p += 3;
    }
    else if (p[0] == 0xdb && end - p >= 5) {
        len = flb_mp_raw_be32(p + 1);
        p += 5;
    }
    else {
        return -1;
    }

    if ((size_t) (end - p) < len) {
        return -1;
    }

    *length = len;
    *cursor = p;

    return 0;
}

/*
 * Same as flb_mp_raw_str_header(), but it also fails if the header is not the
 * shortest one for the string length.
 */
static inline int flb_mp_raw_str_header_minimal(const unsigned char **cursor,
                                                const unsigned char *end,
                                                uint32_t *length)
{
    uint32_t len;
    const unsigned char *p = *cursor;

    if (flb_mp_raw_str_header(&p, end, &len) != 0) {
        return -1;
    }

    if (((*cursor)[0] == 0xd9 && len < 32) ||
        ((*cursor)[0] == 0xda && len < 256) ||
        ((*cursor)[0] == 0xdb && len < 65536)) {
        return -1;
    }

    *length = len;
    *cursor = p;

    return 0;
}

#endif
