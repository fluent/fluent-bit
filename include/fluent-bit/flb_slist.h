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

#ifndef FLB_SLIST_H
#define FLB_SLIST_H

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_sds.h>
#include <monkey/mk_core.h>

struct flb_slist_entry {
    flb_sds_t str;
    struct mk_list _head;
};

int flb_slist_create(struct mk_list *list);
int flb_slist_add(struct mk_list *head, const char *str);
int flb_slist_add_n(struct mk_list *head, const char *str, int len);
int flb_slist_add_sds(struct mk_list *head, flb_sds_t str);

void flb_slist_destroy(struct mk_list *list);
int flb_slist_split_string(struct mk_list *list, const char *str,
                           int separator, int max_split);
int flb_slist_split_tokens(struct mk_list *list, const char *str, int max_split);

void flb_slist_dump(struct mk_list *list);
struct flb_slist_entry *flb_slist_entry_get(struct mk_list *list, int n);

#endif
