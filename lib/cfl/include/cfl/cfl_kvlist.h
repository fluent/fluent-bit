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

#ifndef CFL_KVLIST_H
#define CFL_KVLIST_H

#include <stdio.h>
#include <stddef.h>
#include <stdint.h>

#include <cfl/cfl_sds.h>
#include <cfl/cfl_list.h>
#include <cfl/cfl_variant.h>

struct cfl_array;
struct cfl_arena;

enum cfl_kvlist_match_mode {
    CFL_KVLIST_MATCH_CASE_INSENSITIVE = 0,
    CFL_KVLIST_MATCH_CASE_SENSITIVE
};

struct cfl_kvpair {
    cfl_sds_t            key;    /* Key */
    struct cfl_variant   *val;   /* Value */
    struct cfl_list      _head;  /* Link to list cfl_kvlist->list */
    struct cfl_arena *arena;
};

struct cfl_kvlist {
    struct cfl_list     list;
    struct cfl_variant *owner;
    struct cfl_array   *parent_array;
    struct cfl_kvlist  *parent_kvlist;
    struct cfl_arena *arena;
};

struct cfl_kvlist *cfl_kvlist_create();
struct cfl_kvlist *cfl_kvlist_create_in(struct cfl_arena *arena);
struct cfl_kvlist *cfl_kvlist_create_like(struct cfl_kvlist *parent);
void cfl_kvlist_destroy(struct cfl_kvlist *list);

/*
 * Insert APIs take ownership of array, kvlist, and variant values on success.
 * A raw array or kvlist must have one owning variant at a time. To move an
 * existing kvpair value, detach it with cfl_kvpair_take_value() before
 * reinserting it. Do not leave the same variant pointer attached to multiple
 * live containers.
 */
int cfl_kvlist_insert_string(struct cfl_kvlist *list,
                             char *key, char *value);

int cfl_kvlist_insert_bytes(struct cfl_kvlist *list,
                             char *key, char *value,
                             size_t value_length,
                             int referenced);

int cfl_kvlist_insert_reference(struct cfl_kvlist *list,
                                char *key, void *value);

int cfl_kvlist_insert_bool(struct cfl_kvlist *list,
                           char *key, int value);

int cfl_kvlist_insert_int64(struct cfl_kvlist *list,
                            char *key, int64_t value);

int cfl_kvlist_insert_uint64(struct cfl_kvlist *list,
                            char *key, uint64_t value);

int cfl_kvlist_insert_double(struct cfl_kvlist *list,
                             char *key, double value);

int cfl_kvlist_insert_array(struct cfl_kvlist *list,
                            char *key, struct cfl_array *value);

int cfl_kvlist_insert_new_array(struct cfl_kvlist *list,
                                char *key, size_t size);

int cfl_kvlist_insert_kvlist(struct cfl_kvlist *list,
                             char *key, struct cfl_kvlist *value);

int cfl_kvlist_insert(struct cfl_kvlist *list,
                      char *key, struct cfl_variant *value);

int cfl_kvlist_count(struct cfl_kvlist *list);
struct cfl_variant *cfl_kvlist_fetch(struct cfl_kvlist *list, char *key);
int cfl_kvlist_print(FILE *fp, struct cfl_kvlist *list);

int cfl_kvlist_insert_string_s(struct cfl_kvlist *list,
                               char *key, size_t key_size,
                               char *value, size_t value_size,
                               int referenced);

int cfl_kvlist_insert_bytes_s(struct cfl_kvlist *list,
                              char *key, size_t key_size,
                              char *value,
                              size_t value_length,
                              int referenced);

int cfl_kvlist_insert_reference_s(struct cfl_kvlist *list,
                                  char *key, size_t key_size,
                                  void *value);

int cfl_kvlist_insert_bool_s(struct cfl_kvlist *list,
                             char *key, size_t key_size, int value);

int cfl_kvlist_insert_int64_s(struct cfl_kvlist *list,
                              char *key, size_t key_size,
                              int64_t value);

int cfl_kvlist_insert_uint64_s(struct cfl_kvlist *list,
                               char *key, size_t key_size,
                               uint64_t value);

int cfl_kvlist_insert_double_s(struct cfl_kvlist *list,
                               char *key, size_t key_size,
                               double value);

int cfl_kvlist_insert_array_s(struct cfl_kvlist *list,
                              char *key, size_t key_size,
                              struct cfl_array *value);

int cfl_kvlist_insert_new_array_s(struct cfl_kvlist *list,
                                  char *key, size_t key_size,
                                  size_t size);

int cfl_kvlist_insert_kvlist_s(struct cfl_kvlist *list,
                               char *key, size_t key_size,
                               struct cfl_kvlist *value);

int cfl_kvlist_insert_s(struct cfl_kvlist *list,
                        char *key, size_t key_size,
                        struct cfl_variant *value);

struct cfl_variant *cfl_kvlist_fetch_s(struct cfl_kvlist *list,
                                       char *key, size_t key_size);
/* The existing fetch, contains, and remove APIs match case-insensitively. */
struct cfl_variant *cfl_kvlist_fetch_ex(struct cfl_kvlist *list,
                                        char *key,
                                        enum cfl_kvlist_match_mode mode);
struct cfl_variant *cfl_kvlist_fetch_s_ex(struct cfl_kvlist *list,
                                          char *key, size_t key_size,
                                          enum cfl_kvlist_match_mode mode);
struct cfl_variant *cfl_kvlist_fetch_case_s(struct cfl_kvlist *list,
                                            char *key, size_t key_size);

int cfl_kvlist_contains(struct cfl_kvlist *kvlist, char *name);
int cfl_kvlist_contains_ex(struct cfl_kvlist *kvlist, char *name,
                           enum cfl_kvlist_match_mode mode);
int cfl_kvlist_remove(struct cfl_kvlist *kvlist, char *name);
int cfl_kvlist_remove_ex(struct cfl_kvlist *kvlist, char *name,
                         enum cfl_kvlist_match_mode mode);
void cfl_kvpair_destroy(struct cfl_kvpair *pair);
struct cfl_variant *cfl_kvpair_take_value(struct cfl_kvpair *pair);
int cfl_kvpair_key_set_s(struct cfl_kvpair *pair,
                         char *key, size_t key_size);
int cfl_kvlist_rename_s(struct cfl_kvlist *list,
                        char *old_key, size_t old_key_size,
                        char *new_key, size_t new_key_size);


#endif
