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

#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_compat.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_str.h>

#include "in_collectd.h"
#include "typesdb.h"
#include "typesdb_parser.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>


/* Internal function to load from a single TypesDB */
static int typesdb_load(struct flb_in_collectd_config *ctx,
                        struct mk_list *tdb, const char *path)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        flb_errno();
        flb_plg_error(ctx->ins, "failed to open '%s'", path);
        return -1;
    }

    if (typesdb_parse(tdb, fd)) {
        flb_plg_error(ctx->ins, "failed to parse '%s'", path);
        close(fd);
        return -1;
    }
    close(fd);
    return 0;
}

/*
 * Load multiple TypesDB files at once. The return value is
 * a linked list of typesdb_node objects.
 *
 * "paths" is a comma-separated list of file names.
 */
struct mk_list *typesdb_load_all(struct flb_in_collectd_config *ctx,
                                 const char *paths)
{
    char *buf;
    char *state;
    char *path;
    struct mk_list *tdb;

    buf = flb_strdup(paths);
    if (!buf) {
        flb_errno();
        return NULL;
    }

    tdb = flb_malloc(sizeof(struct mk_list));
    if (!tdb) {
        flb_errno();
        flb_free(buf);
        return NULL;
    }
    mk_list_init(tdb);

    path = strtok_r(buf, ",", &state);
    while (path) {
        if (typesdb_load(ctx, tdb, path)) {
            typesdb_destroy(tdb);
            flb_free(buf);
            return NULL;
        }
        path = strtok_r(NULL, ",", &state);
    }
    flb_free(buf);
    return tdb;
}

void typesdb_destroy(struct mk_list *tdb)
{
    struct typesdb_node *node;
    struct mk_list *head;
    struct mk_list *tmp;

    mk_list_foreach_safe(head, tmp, tdb) {
        node = mk_list_entry(head, struct typesdb_node, _head);
        typesdb_destroy_node(node);
    }
    flb_free(tdb);
}

struct typesdb_node *typesdb_find_node(struct mk_list *tdb, const char *type)
{
    struct typesdb_node *node;
    struct mk_list *head;

    if (type == NULL) {
        return NULL;
    }

    /*
     * Search the linked list from the tail so that later entries
     * take precedence over earlier ones.
     */
    mk_list_foreach_r(head, tdb) {
        node = mk_list_entry(head, struct typesdb_node, _head);
        if (strcmp(node->type, type) == 0) {
            return node;
        }
    }
    return NULL;
}

struct typesdb_node *typesdb_last_node(struct mk_list *tdb)
{
    return mk_list_entry_last(tdb, struct typesdb_node, _head);
}

/*
 * The folloings are API functions to modify a TypesDB instance.
 */
int typesdb_add_node(struct mk_list *tdb, const char *type)
{
    struct typesdb_node *node;

    node = flb_calloc(1, sizeof(struct typesdb_node));
    if (!node) {
        flb_errno();
        return -1;
    }

    node->type = flb_strdup(type);
    if (!node->type) {
        flb_errno();
        flb_free(node);
        return -1;
    }

    mk_list_add(&node->_head, tdb);
    return 0;
}

void typesdb_destroy_node(struct typesdb_node *node)
{
    int i;

    flb_free(node->type);

    if (node->fields) {
        for (i = 0; i < node->count; i++) {
            flb_free(node->fields[i]);
        }
        flb_free(node->fields);
    }
    mk_list_del(&node->_head);
    flb_free(node);
}

int typesdb_add_field(struct typesdb_node *node, const char *field)
{
    char *end;
    int alloc;
    char **fields;

    end = strchr(field, ':');
    if (!end) {
        return -1;
    }

    if (node->count >= node->alloc) {
        alloc = node->alloc > 0 ? node->alloc * 2 : 1;
        fields = flb_realloc(node->fields, alloc * sizeof(char *));
        if (!fields) {
            flb_errno();
            return -1;
        }
        node->alloc = alloc;
        node->fields = fields;
    }

    node->fields[node->count] = flb_strndup(field, end - field);
    if (!node->fields[node->count]) {
        flb_errno();
        return -1;
    }
    node->count++;
    return 0;
}

/* A debug function to see the content of TypesDB */
void typesdb_dump(struct mk_list *tdb)
{
    struct mk_list *head;
    struct typesdb_node *node;
    int i;

    mk_list_foreach(head, tdb) {
        node = mk_list_entry(head, struct typesdb_node, _head);

        printf("%s", node->type);
        for (i = 0; i < node->count; i++) {
            printf("\t%s", node->fields[i]);
        }
        putchar('\n');
    }
}
