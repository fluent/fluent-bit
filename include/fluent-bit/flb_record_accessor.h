/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2024 The Fluent Bit Authors
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

#ifndef FLB_RECORD_ACCESSOR_H
#define FLB_RECORD_ACCESSOR_H

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_regex.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_sds_list.h>
#include <monkey/mk_core.h>
#include <msgpack.h>

struct flb_record_accessor {
    size_t size_hint;
    flb_sds_t pattern;
    struct mk_list list;         /* List of parsed strings */
    struct mk_list _head;        /* Head to custom list (only used by flb_mp.h) */
};

int flb_ra_subkey_count(struct flb_record_accessor *ra);
struct flb_record_accessor *flb_ra_create(char *str, int translate_env);
void flb_ra_destroy(struct flb_record_accessor *ra);
void flb_ra_dump(struct flb_record_accessor *ra);
flb_sds_t flb_ra_translate(struct flb_record_accessor *ra,
                           char *tag, int tag_len,
                           msgpack_object map, struct flb_regex_search *result);
flb_sds_t flb_ra_translate_check(struct flb_record_accessor *ra,
                                 char *tag, int tag_len,
                                 msgpack_object map, struct flb_regex_search *result,
                                 int check);
int flb_ra_is_static(struct flb_record_accessor *ra);
int flb_ra_strcmp(struct flb_record_accessor *ra, msgpack_object map,
                  char *str, int len);
int flb_ra_regex_match(struct flb_record_accessor *ra, msgpack_object map,
                       struct flb_regex *regex,
                       struct flb_regex_search *result);

int flb_ra_get_kv_pair(struct flb_record_accessor *ra, msgpack_object map,
                       msgpack_object **start_key,
                       msgpack_object **out_key, msgpack_object **out_val);

struct flb_ra_value *flb_ra_get_value_object(struct flb_record_accessor *ra,
                                             msgpack_object map);
struct flb_ra_value *flb_ra_get_value_object_ref(struct flb_record_accessor *ra,
                                                 msgpack_object map);
int flb_ra_append_kv_pair(struct flb_record_accessor *ra, msgpack_object map,
                          void **out_map, size_t *out_size, msgpack_object *in_val);
int flb_ra_update_kv_pair(struct flb_record_accessor *ra, msgpack_object map,
                          void **out_map, size_t *out_size,
                          msgpack_object *in_key, msgpack_object *in_val);
flb_sds_t flb_ra_create_str_from_list(struct flb_sds_list *str_list);
struct flb_record_accessor *flb_ra_create_from_list(struct flb_sds_list *str_list, int translate_env);
#endif
