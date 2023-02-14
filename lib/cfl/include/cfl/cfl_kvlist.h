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
#include <cfl/cfl_sds.h>
#include <cfl/cfl_list.h>
#include <cfl/cfl_variant.h>

struct cfl_kvpair {
    cfl_sds_t            key;    /* Key */
    struct cfl_variant   *val;   /* Value */
    struct cfl_list      _head;  /* Link to list cfl_kvlist->list */
};

struct cfl_kvlist {
    struct cfl_list list;
};

struct cfl_kvlist *cfl_kvlist_create();
void cfl_kvlist_destroy(struct cfl_kvlist *list);

int cfl_kvlist_insert_string(struct cfl_kvlist *list,
                             char *key, char *value);

int cfl_kvlist_insert_bytes(struct cfl_kvlist *list,
                             char *key, char *value,
                             size_t value_length);

int cfl_kvlist_insert_reference(struct cfl_kvlist *list,
                                char *key, void *value);

int cfl_kvlist_insert_bool(struct cfl_kvlist *list,
                           char *key, int value);

int cfl_kvlist_insert_int64(struct cfl_kvlist *list,
                            char *key, int64_t value);

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

#endif
