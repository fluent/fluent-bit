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

#ifndef FLB_CALLBACK_H
#define FLB_CALLBACK_H

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_hash_table.h>
#include <fluent-bit/flb_sds.h>

struct flb_callback_entry {
    flb_sds_t name;
    void (*cb)(char *, void *, void *);
    struct mk_list _head;
};

struct flb_callback {
    flb_sds_t name;             /* Context name */
    struct flb_hash_table *ht;  /* Hash table */
    struct mk_list entries;     /* List for callback entries */
    struct flb_config *config;  /* Fluent Bit context */
};

struct flb_callback *flb_callback_create(char *name);
void flb_callback_destroy(struct flb_callback *ctx);
int flb_callback_set(struct flb_callback *ctx, char *name,
                     void (*cb)(char *, void *, void *));

int flb_callback_do(struct flb_callback *ctx, char *name, void *p1, void *p2);
int flb_callback_exists(struct flb_callback *ctx, char *name);

#endif
