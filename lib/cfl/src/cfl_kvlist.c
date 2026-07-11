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

#include <cfl/cfl.h>
#include <cfl/cfl_kvlist.h>
#include <cfl/cfl_array.h>
#include <cfl/cfl_variant.h>
#include "cfl_arena_internal.h"
#include <cfl/cfl_compat.h>

#include <ctype.h>
#include <limits.h>

#include <cfl/cfl_container.h>

static int print_json_string(FILE *fp, const char *str, size_t len)
{
    size_t i;
    unsigned char c;
    int ret;

    if (fputc('"', fp) == EOF) {
        return -1;
    }

    for (i = 0; i < len; i++) {
        c = (unsigned char) str[i];

        switch (c) {
        case '"':
            ret = fputs("\\\"", fp);
            break;
        case '\\':
            ret = fputs("\\\\", fp);
            break;
        case '\b':
            ret = fputs("\\b", fp);
            break;
        case '\f':
            ret = fputs("\\f", fp);
            break;
        case '\n':
            ret = fputs("\\n", fp);
            break;
        case '\r':
            ret = fputs("\\r", fp);
            break;
        case '\t':
            ret = fputs("\\t", fp);
            break;
        default:
            if (c < 0x20) {
                ret = fprintf(fp, "\\u%04x", c);
            }
            else {
                ret = fputc(c, fp);
            }
            break;
        }

        if (ret < 0) {
            return -1;
        }
    }

    if (fputc('"', fp) == EOF) {
        return -1;
    }

    return 0;
}

struct cfl_kvlist *cfl_kvlist_create()
{
    return cfl_kvlist_create_in(NULL);
}

struct cfl_kvlist *cfl_kvlist_create_in(struct cfl_arena *arena)
{
    struct cfl_kvlist *list;

    if (arena == NULL) {
        list = malloc(sizeof(struct cfl_kvlist));
    }
    else {
        list = cfl_arena_alloc(arena, sizeof(struct cfl_kvlist));
    }
    if (list == NULL) {
        cfl_report_runtime_error();
        return NULL;
    }

    cfl_list_init(&list->list);
    list->owner = NULL;
    list->parent_array = NULL;
    list->parent_kvlist = NULL;
    list->arena = arena;

    return list;
}

struct cfl_kvlist *cfl_kvlist_create_like(struct cfl_kvlist *parent)
{
    if (parent == NULL) {
        return NULL;
    }

    return cfl_kvlist_create_in(parent->arena);
}

void cfl_kvlist_destroy(struct cfl_kvlist *list)
{
    struct cfl_list *tmp;
    struct cfl_list *head;
    struct cfl_kvpair *pair;

    if (list == NULL) {
        return;
    }

    cfl_list_foreach_safe(head, tmp, &list->list) {
        pair = cfl_list_entry(head, struct cfl_kvpair, _head);

        if (pair->key) {
            cfl_sds_destroy(pair->key);
        }

        if (pair->val) {
            cfl_variant_destroy(pair->val);
        }
        cfl_list_del(&pair->_head);
        if (pair->arena == NULL) {
            free(pair);
        }
        else {
            cfl_arena_free_kvpair(pair->arena, pair,
                                          sizeof(struct cfl_kvpair));
        }
    }

    if (list->arena == NULL) {
        free(list);
    }
}

int cfl_kvlist_insert_string_s(struct cfl_kvlist *list,
                               char *key, size_t key_size,
                               char *value, size_t value_size,
                               int referenced)
{
    struct cfl_variant *value_instance;
    int                 result;

    if (list == NULL || key == NULL || key_size > INT_MAX) {
        return -1;
    }

    value_instance = cfl_variant_create_from_string_s_in(list->arena, value,
                                                          value_size, referenced);
    if (value_instance == NULL) {
        return -1;
    }

    result = cfl_kvlist_insert_s(list, key, key_size, value_instance);
    if (result) {
        cfl_variant_destroy(value_instance);

        return -2;
    }

    return 0;
}

int cfl_kvlist_insert_bytes_s(struct cfl_kvlist *list,
                              char *key, size_t key_size,
                              char *value,
                              size_t length, int referenced)
{
    struct cfl_variant *value_instance;
    int                 result;

    if (list == NULL || key == NULL || key_size > INT_MAX) {
        return -1;
    }

    value_instance = cfl_variant_create_from_bytes_in(list->arena, value,
                                                       length, referenced);
    if (value_instance == NULL) {
        return -1;
    }

    result = cfl_kvlist_insert_s(list, key, key_size, value_instance);

    if (result) {
        cfl_variant_destroy(value_instance);
        return -2;
    }

    return 0;
}

int cfl_kvlist_insert_reference_s(struct cfl_kvlist *list,
                                  char *key, size_t key_size, void *value)
{
    struct cfl_variant *value_instance;
    int                 result;

    if (list == NULL || key == NULL || key_size > INT_MAX) {
        return -1;
    }

    value_instance = cfl_variant_create_from_reference_in(list->arena, value);

    if (value_instance == NULL) {
        return -1;
    }

    result = cfl_kvlist_insert_s(list, key, key_size, value_instance);

    if (result) {
        cfl_variant_destroy(value_instance);

        return -2;
    }

    return 0;
}

int cfl_kvlist_insert_bool_s(struct cfl_kvlist *list,
                             char *key, size_t key_size, int value)
{
    struct cfl_variant *value_instance;
    int                 result;

    if (list == NULL || key == NULL || key_size > INT_MAX) {
        return -1;
    }

    value_instance = cfl_variant_create_from_bool_in(list->arena, value);

    if (value_instance == NULL) {
        return -1;
    }

    result = cfl_kvlist_insert_s(list, key, key_size, value_instance);

    if (result) {
        cfl_variant_destroy(value_instance);

        return -2;
    }

    return 0;
}

int cfl_kvlist_insert_int64_s(struct cfl_kvlist *list,
                              char *key, size_t key_size, int64_t value)
{
    struct cfl_variant *value_instance;
    int                 result;

    if (list == NULL || key == NULL || key_size > INT_MAX) {
        return -1;
    }

    value_instance = cfl_variant_create_from_int64_in(list->arena, value);

    if (value_instance == NULL) {
        return -1;
    }

    result = cfl_kvlist_insert_s(list, key, key_size, value_instance);

    if (result) {
        cfl_variant_destroy(value_instance);

        return -2;
    }

    return 0;
}

int cfl_kvlist_insert_uint64_s(struct cfl_kvlist *list,
                               char *key, size_t key_size, uint64_t value)
{
    struct cfl_variant *value_instance;
    int                 result;

    if (list == NULL || key == NULL || key_size > INT_MAX) {
        return -1;
    }

    value_instance = cfl_variant_create_from_uint64_in(list->arena, value);

    if (value_instance == NULL) {
        return -1;
    }

    result = cfl_kvlist_insert_s(list, key, key_size, value_instance);

    if (result) {
        cfl_variant_destroy(value_instance);

        return -2;
    }

    return 0;
}

int cfl_kvlist_insert_double_s(struct cfl_kvlist *list,
                               char *key, size_t key_size, double value)
{
    struct cfl_variant *value_instance;
    int                 result;

    if (list == NULL || key == NULL || key_size > INT_MAX) {
        return -1;
    }

    value_instance = cfl_variant_create_from_double_in(list->arena, value);

    if (value_instance == NULL) {
        return -1;
    }

    result = cfl_kvlist_insert_s(list, key, key_size, value_instance);

    if (result) {
        cfl_variant_destroy(value_instance);

        return -2;
    }

    return 0;
}

int cfl_kvlist_insert_array_s(struct cfl_kvlist *list,
                              char *key, size_t key_size, struct cfl_array *value)
{
    struct cfl_variant *value_instance;
    int                 result;

    if (list == NULL || key == NULL || key_size > INT_MAX || value == NULL) {
        return -1;
    }

    value_instance = cfl_variant_create_from_array_in(list->arena, value);

    if (value_instance == NULL) {
        return -1;
    }

    result = cfl_kvlist_insert_s(list, key, key_size, value_instance);

    if (result) {
        cfl_container_release_variant(value_instance);
        value_instance->data.as_array = NULL;
        cfl_variant_destroy(value_instance);

        return -2;
    }

    return 0;
}


int cfl_kvlist_insert_new_array_s(struct cfl_kvlist *list,
                                  char *key, size_t key_size, size_t size)
{
    int               result;
    struct cfl_array *value;

    if (list == NULL || key == NULL || key_size > INT_MAX) {
        return -1;
    }

    value = cfl_array_create_in(list->arena, size);

    if (value == NULL) {
        return -1;
    }

    result = cfl_kvlist_insert_array_s(list, key, key_size, value);
    if (result < 0) {
        cfl_array_destroy(value);
    }

    return result;
}

int cfl_kvlist_insert_kvlist_s(struct cfl_kvlist *list,
                               char *key, size_t key_size, struct cfl_kvlist *value)
{
    struct cfl_variant *value_instance;
    int                 result;

    if (list == NULL || key == NULL || key_size > INT_MAX || value == NULL) {
        return -1;
    }

    if (list == value) {
        return -1;
    }

    value_instance = cfl_variant_create_from_kvlist_in(list->arena, value);
    if (value_instance == NULL) {
        return -1;
    }

    result = cfl_kvlist_insert_s(list, key, key_size, value_instance);

    if (result) {
        cfl_container_release_variant(value_instance);
        value_instance->data.as_kvlist = NULL;
        cfl_variant_destroy(value_instance);

        return -2;
    }

    return 0;
}

int cfl_kvlist_insert_s(struct cfl_kvlist *list,
                        char *key, size_t key_size,
                        struct cfl_variant *value)
{
    struct cfl_kvpair *pair;

    if (list == NULL || key == NULL || value == NULL || key_size > INT_MAX) {
        return -1;
    }

    if (list->arena != value->arena) {
        return -1;
    }

    if (list->arena == NULL) {
        pair = malloc(sizeof(struct cfl_kvpair));
    }
    else {
        pair = cfl_arena_alloc_kvpair(list->arena,
                                              sizeof(struct cfl_kvpair));
    }
    if (pair == NULL) {
        cfl_report_runtime_error();
        return -1;
    }

    pair->key = cfl_sds_create_len_in(list->arena, key, (int) key_size);
    if (pair->key == NULL) {
        if (list->arena == NULL) {
            free(pair);
        }
        else {
            cfl_arena_free_kvpair(list->arena, pair,
                                          sizeof(struct cfl_kvpair));
        }

        return -2;
    }

    if (cfl_container_move_variant_to_kvlist(list, value) != 0) {
        cfl_sds_destroy(pair->key);
        if (list->arena == NULL) {
            free(pair);
        }
        else {
            cfl_arena_free_kvpair(list->arena, pair,
                                          sizeof(struct cfl_kvpair));
        }

        return -1;
    }

    pair->val = value;
    pair->arena = list->arena;

    cfl_list_add(&pair->_head, &list->list);
    return 0;
}

static int key_matches(cfl_sds_t candidate, char *key, size_t key_size,
                       enum cfl_kvlist_match_mode mode)
{
    size_t index;

    if (cfl_sds_len(candidate) != key_size) {
        return CFL_FALSE;
    }

    if (mode == CFL_KVLIST_MATCH_CASE_SENSITIVE) {
        return memcmp(candidate, key, key_size) == 0;
    }

    if (mode == CFL_KVLIST_MATCH_CASE_INSENSITIVE) {
        for (index = 0; index < key_size; index++) {
            if (tolower((unsigned char) candidate[index]) !=
                tolower((unsigned char) key[index])) {
                return CFL_FALSE;
            }
        }

        return CFL_TRUE;
    }

    return CFL_FALSE;
}

struct cfl_variant *cfl_kvlist_fetch_s_ex(
    struct cfl_kvlist *list, char *key, size_t key_size,
    enum cfl_kvlist_match_mode mode)
{
    struct cfl_list *head;
    struct cfl_kvpair *pair;

    if (list == NULL || key == NULL) {
        return NULL;
    }

    cfl_list_foreach(head, &list->list) {
        pair = cfl_list_entry(head, struct cfl_kvpair, _head);

        if (key_matches(pair->key, key, key_size, mode) == CFL_TRUE) {
            return pair->val;
        }
    }

    return NULL;
}

struct cfl_variant *cfl_kvlist_fetch_s(struct cfl_kvlist *list,
                                       char *key, size_t key_size)
{
    return cfl_kvlist_fetch_s_ex(list, key, key_size,
                                 CFL_KVLIST_MATCH_CASE_INSENSITIVE);
}

struct cfl_variant *cfl_kvlist_fetch_case_s(struct cfl_kvlist *list,
                                            char *key, size_t key_size)
{
    return cfl_kvlist_fetch_s_ex(list, key, key_size,
                                 CFL_KVLIST_MATCH_CASE_SENSITIVE);
}

int cfl_kvlist_insert_string(struct cfl_kvlist *list,
                             char *key, char *value)
{
    size_t key_len;
    size_t val_len;

    if (!list || !key || !value) {
        return -1;
    }

    key_len = strlen(key);
    val_len = strlen(value);
    if (key_len > INT_MAX || val_len > INT_MAX) {
        return -1;
    }

    return cfl_kvlist_insert_string_s(list, key, key_len, value, val_len, CFL_FALSE);
}

int cfl_kvlist_insert_bytes(struct cfl_kvlist *list,
                            char *key, char *value,
                            size_t length, int referenced)
{
    if (!list || !key || (value == NULL && length > 0)) {
        return -1;
    }

    return cfl_kvlist_insert_bytes_s(list, key, strlen(key), value, length, referenced);
}

int cfl_kvlist_insert_reference(struct cfl_kvlist *list,
                                char *key, void *value)
{
    if (!list || !key) {
        return -1;
    }

    return cfl_kvlist_insert_reference_s(list, key, strlen(key), value);
}

int cfl_kvlist_insert_bool(struct cfl_kvlist *list,
                           char *key, int value)
{
    if (!list || !key) {
        return -1;
    }

    return cfl_kvlist_insert_bool_s(list, key, strlen(key), value);
}

int cfl_kvlist_insert_int64(struct cfl_kvlist *list,
                            char *key, int64_t value)
{
    if (!list || !key) {
        return -1;
    }

    return cfl_kvlist_insert_int64_s(list, key, strlen(key), value);
}

int cfl_kvlist_insert_uint64(struct cfl_kvlist *list,
                            char *key, uint64_t value)
{
    if (!list || !key) {
        return -1;
    }

    return cfl_kvlist_insert_uint64_s(list, key, strlen(key), value);
}

int cfl_kvlist_insert_double(struct cfl_kvlist *list,
                             char *key, double value)
{
    if (!list || !key) {
        return -1;
    }

    return cfl_kvlist_insert_double_s(list, key, strlen(key), value);
}

int cfl_kvlist_insert_array(struct cfl_kvlist *list,
                            char *key, struct cfl_array *value)
{
    if (!list || !key || !value) {
        return -1;
    }

    return cfl_kvlist_insert_array_s(list, key, strlen(key), value);
}

int cfl_kvlist_insert_new_array(struct cfl_kvlist *list,
                                char *key, size_t size)
{
    if (!list || !key) {
        return -1;
    }

    return cfl_kvlist_insert_new_array_s(list, key, strlen(key), size);
}

int cfl_kvlist_insert_kvlist(struct cfl_kvlist *list,
                             char *key, struct cfl_kvlist *value)
{
    if (!list || !key || !value) {
        return -1;
    }

    return cfl_kvlist_insert_kvlist_s(list, key, strlen(key), value);
}

int cfl_kvlist_insert(struct cfl_kvlist *list,
                      char *key, struct cfl_variant *value)
{
    if (!list || !key || !value) {
        return -1;
    }

    return cfl_kvlist_insert_s(list, key, strlen(key), value);
}

struct cfl_variant *cfl_kvlist_fetch(struct cfl_kvlist *list, char *key)
{
    return cfl_kvlist_fetch_ex(list, key,
                               CFL_KVLIST_MATCH_CASE_INSENSITIVE);
}

struct cfl_variant *cfl_kvlist_fetch_ex(
    struct cfl_kvlist *list, char *key,
    enum cfl_kvlist_match_mode mode)
{
    if (list == NULL || key == NULL) {
        return NULL;
    }

    return cfl_kvlist_fetch_s_ex(list, key, strlen(key), mode);
}

int cfl_kvlist_count(struct cfl_kvlist *list)
{
    if (list == NULL) {
        return 0;
    }

    return cfl_list_size(&list->list);
}

int cfl_kvlist_print(FILE *fp, struct cfl_kvlist *list)
{
    size_t key_size;
    int printed;
    int ret = 0;

    struct cfl_list *head = NULL;
    struct cfl_kvpair *pair = NULL;

    if (fp == NULL || list == NULL) {
        return -1;
    }

    printed = CFL_FALSE;
    if (fputc('{', fp) == EOF) {
        return -1;
    }

    cfl_list_foreach(head, &list->list) {
        pair = cfl_list_entry(head, struct cfl_kvpair, _head);
        if (pair == NULL || pair->key == NULL || pair->val == NULL) {
            continue;
        }

        if (printed) {
            if (fputc(',', fp) == EOF) {
                return -1;
            }
        }

        key_size = cfl_sds_len(pair->key);
        ret = print_json_string(fp, pair->key, key_size);
        if (ret < 0) {
            return -1;
        }

        if (fputc(':', fp) == EOF) {
            return -1;
        }

        ret = cfl_variant_print(fp, pair->val);
        if (ret < 0) {
            return -1;
        }

        printed = CFL_TRUE;
    }

    if (fputc('}', fp) == EOF) {
        return -1;
    }

    return ret;
}

int cfl_kvlist_contains(struct cfl_kvlist *kvlist, char *name)
{
    return cfl_kvlist_contains_ex(kvlist, name,
                                  CFL_KVLIST_MATCH_CASE_INSENSITIVE);
}

int cfl_kvlist_contains_ex(struct cfl_kvlist *kvlist, char *name,
                           enum cfl_kvlist_match_mode mode)
{
    struct cfl_list   *iterator;
    struct cfl_kvpair *pair;
    size_t             name_len;

    if (kvlist == NULL || name == NULL) {
        return CFL_FALSE;
    }

    name_len = strlen(name);

    cfl_list_foreach(iterator, &kvlist->list) {
        pair = cfl_list_entry(iterator,
                              struct cfl_kvpair, _head);

        if (key_matches(pair->key, name, name_len, mode) == CFL_TRUE) {
            return CFL_TRUE;
        }
    }

    return CFL_FALSE;
}


int cfl_kvlist_remove(struct cfl_kvlist *kvlist, char *name)
{
    return cfl_kvlist_remove_ex(kvlist, name,
                                CFL_KVLIST_MATCH_CASE_INSENSITIVE);
}

int cfl_kvlist_remove_ex(struct cfl_kvlist *kvlist, char *name,
                         enum cfl_kvlist_match_mode mode)
{
    struct cfl_list   *iterator_backup;
    struct cfl_list   *iterator;
    struct cfl_kvpair *pair;
    size_t             name_len;
    int                removed;

    if (kvlist == NULL || name == NULL) {
        return CFL_FALSE;
    }

    name_len = strlen(name);
    removed = CFL_FALSE;

    cfl_list_foreach_safe(iterator, iterator_backup, &kvlist->list) {
        pair = cfl_list_entry(iterator,
                              struct cfl_kvpair, _head);

        if (key_matches(pair->key, name, name_len, mode) == CFL_TRUE) {
            cfl_kvpair_destroy(pair);
            removed = CFL_TRUE;
        }
    }

    return removed;
}


void cfl_kvpair_destroy(struct cfl_kvpair *pair)
{
    if (pair != NULL) {
        if (!cfl_list_entry_is_orphan(&pair->_head)) {
            cfl_list_del(&pair->_head);
        }

        if (pair->key != NULL) {
            cfl_sds_destroy(pair->key);
        }

        if (pair->val != NULL) {
            cfl_variant_destroy(pair->val);
        }

        if (pair->arena == NULL) {
            free(pair);
        }
        else {
            cfl_arena_free_kvpair(pair->arena, pair,
                                          sizeof(struct cfl_kvpair));
        }
    }
}

struct cfl_variant *cfl_kvpair_take_value(struct cfl_kvpair *pair)
{
    struct cfl_variant *value;

    if (pair == NULL) {
        return NULL;
    }

    value = pair->val;
    pair->val = NULL;

    cfl_container_release_variant(value);

    return value;
}

int cfl_kvpair_key_set_s(struct cfl_kvpair *pair,
                         char *key, size_t key_size)
{
    cfl_sds_t replacement;

    if (pair == NULL || key == NULL || key_size > INT_MAX) {
        return -1;
    }

    replacement = cfl_sds_create_len_in(pair->arena, key, (int) key_size);
    if (replacement == NULL) {
        return -1;
    }

    cfl_sds_destroy(pair->key);
    pair->key = replacement;
    return 0;
}

int cfl_kvlist_rename_s(struct cfl_kvlist *list,
                        char *old_key, size_t old_key_size,
                        char *new_key, size_t new_key_size)
{
    struct cfl_list *head;
    struct cfl_kvpair *pair;
    struct cfl_kvpair *source;

    if (list == NULL || old_key == NULL || new_key == NULL ||
        old_key_size > INT_MAX || new_key_size > INT_MAX) {
        return -1;
    }

    source = NULL;
    cfl_list_foreach(head, &list->list) {
        pair = cfl_list_entry(head, struct cfl_kvpair, _head);
        if (cfl_sds_len(pair->key) == old_key_size &&
            memcmp(pair->key, old_key, old_key_size) == 0) {
            source = pair;
        }
        if (cfl_sds_len(pair->key) == new_key_size &&
            memcmp(pair->key, new_key, new_key_size) == 0 &&
            !(old_key_size == new_key_size &&
              memcmp(old_key, new_key, old_key_size) == 0)) {
            return -1;
        }
    }

    if (source == NULL) {
        return -1;
    }

    return cfl_kvpair_key_set_s(source, new_key, new_key_size);
}
