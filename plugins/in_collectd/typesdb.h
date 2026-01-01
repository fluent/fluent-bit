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

#include "in_collectd.h"

struct typesdb_node {
    char *type;
    int alloc;
    int count;
    char **fields;
    struct mk_list _head;
};

/* Load and destroy TypesDB */
struct mk_list *typesdb_load_all(struct flb_in_collectd_config *ctx,
                                 const char *paths);
void typesdb_destroy(struct mk_list *tdb);

/* Find a node in TypesDB */
struct typesdb_node *typesdb_find_node(struct mk_list *tdb, const char *type);
struct typesdb_node *typesdb_last_node(struct mk_list *tdb);

/* Modify a TypesDB instance (used in typesdb_parser.c) */
int typesdb_add_node(struct mk_list *tdb, const char *type);
void typesdb_destroy_node(struct typesdb_node *node);
int typesdb_add_field(struct typesdb_node *node, const char *field);

/* For debugging */
void typesdb_dump(struct mk_list *tdb);
