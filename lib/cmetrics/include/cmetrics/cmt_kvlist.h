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

#ifndef CMT_KVLIST_H
#define CMT_KVLIST_H

#include <cmetrics/cmt_sds.h>
#include <cmetrics/cmt_variant.h>

struct cmt_kvpair {
    cmt_sds_t           key;    /* Key */
    struct cmt_variant *val;    /* Value */
    struct mk_list      _head;  /* Link to list cmt_kvlist->list */
};

struct cmt_kvlist {
    struct mk_list list;
};

struct cmt_kvlist *cmt_kvlist_create();
void cmt_kvlist_destroy(struct cmt_kvlist *list);

int cmt_kvlist_insert_string(struct cmt_kvlist *list,
                             char *key, char *value);

int cmt_kvlist_insert_bytes(struct cmt_kvlist *list,
                             char *key, char *value,
                             size_t value_length);

int cmt_kvlist_insert_reference(struct cmt_kvlist *list,
                                char *key, void *value);

int cmt_kvlist_insert_bool(struct cmt_kvlist *list,
                           char *key, int value);

int cmt_kvlist_insert_int(struct cmt_kvlist *list,
                          char *key, int value);

int cmt_kvlist_insert_double(struct cmt_kvlist *list,
                             char *key, double value);

int cmt_kvlist_insert_array(struct cmt_kvlist *list,
                            char *key, struct cmt_array *value);

int cmt_kvlist_insert_new_array(struct cmt_kvlist *list,
                                char *key, size_t size);

int cmt_kvlist_insert_kvlist(struct cmt_kvlist *list,
                             char *key, struct cmt_kvlist *value);

int cmt_kvlist_insert(struct cmt_kvlist *list,
                      char *key, struct cmt_variant *value);

int cmt_kvlist_count(struct cmt_kvlist *list);
struct cmt_variant *cmt_kvlist_fetch(struct cmt_kvlist *list, char *key);

#endif
