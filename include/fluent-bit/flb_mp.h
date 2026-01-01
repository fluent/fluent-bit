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

#define FLB_MP_MAP        MSGPACK_OBJECT_MAP
#define FLB_MP_ARRAY      MSGPACK_OBJECT_ARRAY

int flb_mp_count(const void *data, size_t bytes);
int flb_mp_count_remaining(const void *data, size_t bytes, size_t *remaining_bytes);
int flb_mp_validate_log_chunk(const void *data, size_t bytes,
                              int *out_records, size_t *processed_bytes);
int flb_mp_validate_metric_chunk(const void *data, size_t bytes,
                                 int *out_series, size_t *processed_bytes);

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




#endif
