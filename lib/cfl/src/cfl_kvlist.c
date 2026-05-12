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
#include <cfl/cfl_compat.h>

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
    struct cfl_kvlist *list;

    list = malloc(sizeof(struct cfl_kvlist));
    if (list == NULL) {
        cfl_report_runtime_error();
        return NULL;
    }

    cfl_list_init(&list->list);
    return list;
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
        free(pair);
    }

    free(list);
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

    value_instance = cfl_variant_create_from_string_s(value, value_size, referenced);
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

    value_instance = cfl_variant_create_from_bytes(value, length, referenced);
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

    value_instance = cfl_variant_create_from_reference(value);

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

    value_instance = cfl_variant_create_from_bool(value);

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

    value_instance = cfl_variant_create_from_int64(value);

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

    value_instance = cfl_variant_create_from_uint64(value);

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

    value_instance = cfl_variant_create_from_double(value);

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

    if (cfl_container_kvlist_contains_array(list, value) ||
        cfl_container_array_contains_kvlist(value, list)) {
        return -1;
    }

    value_instance = cfl_variant_create_from_array(value);

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


int cfl_kvlist_insert_new_array_s(struct cfl_kvlist *list,
                                  char *key, size_t key_size, size_t size)
{
    int               result;
    struct cfl_array *value;

    if (list == NULL || key == NULL || key_size > INT_MAX) {
        return -1;
    }

    value = cfl_array_create(size);

    if (value == NULL) {
        return -1;
    }

    result = cfl_kvlist_insert_array_s(list, key, key_size, value);
    if (result == -1) {
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

    if (cfl_container_kvlist_contains_kvlist(list, value) ||
        cfl_container_kvlist_contains_kvlist(value, list)) {
        return -1;
    }

    value_instance = cfl_variant_create_from_kvlist(value);
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

int cfl_kvlist_insert_s(struct cfl_kvlist *list,
                        char *key, size_t key_size,
                        struct cfl_variant *value)
{
    struct cfl_kvpair *pair;

    if (list == NULL || key == NULL || value == NULL || key_size > INT_MAX) {
        return -1;
    }

    if (cfl_container_kvlist_contains_variant(list, value)) {
        return -1;
    }

    /* Only container-valued variants can participate in container cycles. */
    if (value->type == CFL_VARIANT_ARRAY || value->type == CFL_VARIANT_KVLIST) {
        if (cfl_container_variant_contains_kvlist(value, list)) {
            return -1;
        }

        if (value->type == CFL_VARIANT_ARRAY &&
            cfl_container_kvlist_contains_array(list, value->data.as_array)) {
            return -1;
        }

        if (value->type == CFL_VARIANT_KVLIST &&
            cfl_container_kvlist_contains_kvlist(list, value->data.as_kvlist)) {
            return -1;
        }
    }

    pair = malloc(sizeof(struct cfl_kvpair));
    if (pair == NULL) {
        cfl_report_runtime_error();
        return -1;
    }

    pair->key = cfl_sds_create_len(key, (int) key_size);
    if (pair->key == NULL) {
        free(pair);

        return -2;
    }

    pair->val = value;

    cfl_list_add(&pair->_head, &list->list);
    return 0;
}

struct cfl_variant *cfl_kvlist_fetch_s(struct cfl_kvlist *list, char *key, size_t key_size)
{
    struct cfl_list *head;
    struct cfl_kvpair *pair;

    if (list == NULL || key == NULL) {
        return NULL;
    }

    cfl_list_foreach(head, &list->list) {
        pair = cfl_list_entry(head, struct cfl_kvpair, _head);

        if (cfl_sds_len(pair->key) != key_size) {
            continue;
        }

        if (strncasecmp(pair->key, key, key_size) == 0) {
            return pair->val;
        }
    }

    return NULL;
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
    if (!list || !key) {
        return NULL;
    }

    return cfl_kvlist_fetch_s(list, key, strlen(key));
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
    struct cfl_list   *iterator;
    struct cfl_kvpair *pair;
    size_t             name_len;
    size_t             key_len;

    if (kvlist == NULL || name == NULL) {
        return CFL_FALSE;
    }

    name_len = strlen(name);

    cfl_list_foreach(iterator, &kvlist->list) {
        pair = cfl_list_entry(iterator,
                              struct cfl_kvpair, _head);

        key_len = cfl_sds_len(pair->key);
        if (key_len != name_len) {
            continue;
        }

        if (strncasecmp(pair->key, name, name_len) == 0) {
            return CFL_TRUE;
        }
    }

    return CFL_FALSE;
}


int cfl_kvlist_remove(struct cfl_kvlist *kvlist, char *name)
{
    struct cfl_list   *iterator_backup;
    struct cfl_list   *iterator;
    struct cfl_kvpair *pair;
    size_t             name_len;
    size_t             key_len;
    int                removed;

    if (kvlist == NULL || name == NULL) {
        return CFL_FALSE;
    }

    name_len = strlen(name);
    removed = CFL_FALSE;

    cfl_list_foreach_safe(iterator, iterator_backup, &kvlist->list) {
        pair = cfl_list_entry(iterator,
                              struct cfl_kvpair, _head);

        key_len = cfl_sds_len(pair->key);
        if (key_len != name_len) {
            continue;
        }

        if (strncasecmp(pair->key, name, name_len) == 0) {
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

        free(pair);
    }
}
