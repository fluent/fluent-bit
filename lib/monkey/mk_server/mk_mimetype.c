/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Monkey HTTP Server
 *  ==================
 *  Copyright 2001-2017 Eduardo Silva <eduardo@monkey.io>
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

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <string.h>
#include <ctype.h>

#include <mk_core/mk_unistd.h>

#include <monkey/monkey.h>
#include <monkey/mk_mimetype.h>
#include <monkey/mk_utils.h>
#include <monkey/mk_config.h>
#include <monkey/mk_core.h>
#include <monkey/mk_http.h>

struct mk_mimetype *mimetype_default;

static int rbtree_compare(const void *lhs, const void *rhs)
{
    return strcmp((const char *)lhs, (const char *)rhs);
}

/* Match mime type for requested resource */
struct mk_mimetype *mk_mimetype_lookup(struct mk_server *server, char *name)
{
    int cmp;
    struct rb_tree_node *node = server->mimetype_rb_head.root;

    while (node) {
        struct mk_mimetype *entry = container_of(node, struct mk_mimetype, _rb_head);
        cmp = strcmp(name, entry->name);
        if (cmp < 0)
            node = node->left;
        else if (cmp > 0)
            node = node->right;
        else {
            return entry;
        }
    }
    return NULL;
}

int mk_mimetype_add(struct mk_server *server, char *name, const char *type)
{
    int len = strlen(type) + 3;
    char *p;
    struct mk_mimetype *new_mime;

    /* make sure we register the extension in lower case */
    p = name;
    for ( ; *p; ++p) *p = tolower(*p);

    new_mime = mk_mem_alloc_z(sizeof(struct mk_mimetype));
    new_mime->name = mk_string_dup(name);
    new_mime->type.data = mk_mem_alloc(len);
    new_mime->type.len = len - 1;
    new_mime->header_type.data = mk_mem_alloc(len + 32);
    new_mime->header_type.len = snprintf(new_mime->header_type.data,
                                         len + 32,
                                         "Content-Type: %s\r\n",
                                         type);
    strcpy(new_mime->type.data, type);
    strcat(new_mime->type.data, MK_CRLF);
    new_mime->type.data[len-1] = '\0';

    /* Insert the node into the RBT */
    rb_tree_insert(&server->mimetype_rb_head,
                   new_mime->name, &new_mime->_rb_head);

    /* Add to linked list head */
    mk_list_add(&new_mime->_head, &server->mimetype_list);

    return 0;
}

int mk_mimetype_init(struct mk_server *server)
{
    char *name;

    /* Initialize the heads */
    mk_list_init(&server->mimetype_list);
    rb_tree_new(&server->mimetype_rb_head, rbtree_compare);

    name = mk_string_dup(MIMETYPE_DEFAULT_NAME);
    if (server->mimetype_default_str) {
        mk_mimetype_add(server, name, server->mimetype_default_str);
    }
    else {
        mk_mimetype_add(server, name, MIMETYPE_DEFAULT_TYPE);
    }
    server->mimetype_default = mk_list_entry_first(&server->mimetype_list,
                                                   struct mk_mimetype,
                                                   _head);
    mk_mem_free(name);
    return 0;
}

/* Load the two mime arrays into memory */
int mk_mimetype_read_config(struct mk_server *server)
{
    char path[MK_MAX_PATH];
    struct mk_rconf *cnf;
    struct mk_rconf_section *section;
    struct mk_rconf_entry *entry;
    struct mk_list *head;
    struct file_info f_info;
    int ret;

    if (!server->conf_mimetype) {
        return -1;
    }

    /* Read mime types configuration file */
    snprintf(path, MK_MAX_PATH, "%s/%s",
             server->path_conf_root,
             server->conf_mimetype);

    ret = mk_file_get_info(path, &f_info, MK_FILE_EXISTS);
    if (ret == -1 || f_info.is_file == MK_FALSE) {
        snprintf(path, MK_MAX_PATH, "%s", server->conf_mimetype);
    }
    cnf = mk_rconf_open(path);
    if (!cnf) {
        mk_warn("[mime] skipping mimetype configuration file");
        return -1;
    }

    /* Get MimeTypes tag */
    section = mk_rconf_section_get(cnf, "MIMETYPES");
    if (!section) {
        mk_err("[mime] Invalid mime type file");
        return -1;
    }

    mk_list_foreach(head, &section->entries) {
        entry = mk_list_entry(head, struct mk_rconf_entry, _head);
        if (!entry->key || !entry->val) {
            continue;
        }

        if (mk_mimetype_add(server, entry->key, entry->val) != 0) {
            mk_err("[mime] Error loading Mime Types");
            return -1;
        }
    }

    mk_rconf_free(cnf);

    return 0;
}

struct mk_mimetype *mk_mimetype_find(struct mk_server *server, mk_ptr_t *filename)
{
    int j, len;

    j = len = filename->len;

    /* looking for extension */
    while (j >= 0 && filename->data[j] != '.') {
        j--;
    }

    if (j <= 0) {
        return NULL;
    }

    return mk_mimetype_lookup(server, filename->data + j + 1);
}

void mk_mimetype_free_all(struct mk_server *server)
{
    struct mk_list *head;
    struct mk_list *tmp;
    struct mk_mimetype *mime;

    mk_list_foreach_safe(head, tmp, &server->mimetype_list) {
        mime = mk_list_entry(head, struct mk_mimetype, _head);
        mk_ptr_free(&mime->type);
        mk_mem_free(mime->name);
        mk_mem_free(mime->header_type.data);
        mk_mem_free(mime);
    }
}
