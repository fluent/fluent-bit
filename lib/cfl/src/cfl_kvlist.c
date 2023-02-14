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

/*
int cfl_kvlist_insert(struct cfl_kvlist *list,
                      char *key, void *value,
                      size_t value_length,
                      int value_type)
{
    struct cfl_kvpair *pair;

    pair = malloc(sizeof(struct cfl_kvpair));

    if (pair == NULL) {
        cfl_errno();

        return -1;
    }

    pair->key = cfl_sds_create(key);

    if (pair->key == NULL) {
        free(pair);

        return -2;
    }

    pair->val = cfl_variant_create(value, value_length, value_type);

    if (pair->val == NULL) {
        cfl_sds_destroy(pair->key);
        free(pair);

        return -3;
    }

    cfl_list_add(&pair->_head, &list->list);

    return 0;
}
*/

int cfl_kvlist_insert_string(struct cfl_kvlist *list,
                             char *key, char *value)
{
    struct cfl_variant *value_instance;
    int                 result;

    value_instance = cfl_variant_create_from_string(value);
    if (value_instance == NULL) {
        return -1;
    }

    result = cfl_kvlist_insert(list, key, value_instance);
    if (result) {
        cfl_variant_destroy(value_instance);

        return -2;
    }

    return 0;
}

int cfl_kvlist_insert_bytes(struct cfl_kvlist *list,
                             char *key, char *value,
                             size_t length)
{
    struct cfl_variant *value_instance;
    int                 result;

    value_instance = cfl_variant_create_from_bytes(value, length);

    if (value_instance == NULL) {
        return -1;
    }

    result = cfl_kvlist_insert(list, key, value_instance);

    if (result) {
        cfl_variant_destroy(value_instance);

        return -2;
    }

    return 0;
}

int cfl_kvlist_insert_reference(struct cfl_kvlist *list,
                                char *key, void *value)
{
    struct cfl_variant *value_instance;
    int                 result;

    value_instance = cfl_variant_create_from_reference(value);

    if (value_instance == NULL) {
        return -1;
    }

    result = cfl_kvlist_insert(list, key, value_instance);

    if (result) {
        cfl_variant_destroy(value_instance);

        return -2;
    }

    return 0;
}

int cfl_kvlist_insert_bool(struct cfl_kvlist *list,
                           char *key, int value)
{
    struct cfl_variant *value_instance;
    int                 result;

    value_instance = cfl_variant_create_from_bool(value);

    if (value_instance == NULL) {
        return -1;
    }

    result = cfl_kvlist_insert(list, key, value_instance);

    if (result) {
        cfl_variant_destroy(value_instance);

        return -2;
    }

    return 0;
}

int cfl_kvlist_insert_int64(struct cfl_kvlist *list,
                            char *key, int64_t value)
{
    struct cfl_variant *value_instance;
    int                 result;

    value_instance = cfl_variant_create_from_int64(value);

    if (value_instance == NULL) {
        return -1;
    }

    result = cfl_kvlist_insert(list, key, value_instance);

    if (result) {
        cfl_variant_destroy(value_instance);

        return -2;
    }

    return 0;
}

int cfl_kvlist_insert_double(struct cfl_kvlist *list,
                             char *key, double value)
{
    struct cfl_variant *value_instance;
    int                 result;

    value_instance = cfl_variant_create_from_double(value);

    if (value_instance == NULL) {
        return -1;
    }

    result = cfl_kvlist_insert(list, key, value_instance);

    if (result) {
        cfl_variant_destroy(value_instance);

        return -2;
    }

    return 0;
}

int cfl_kvlist_insert_array(struct cfl_kvlist *list,
                            char *key, struct cfl_array *value)
{
    struct cfl_variant *value_instance;
    int                 result;

    value_instance = cfl_variant_create_from_array(value);

    if (value_instance == NULL) {
        return -1;
    }

    result = cfl_kvlist_insert(list, key, value_instance);

    if (result) {
        cfl_variant_destroy(value_instance);

        return -2;
    }

    return 0;
}

int cfl_kvlist_insert_new_array(struct cfl_kvlist *list,
                                char *key, size_t size)
{
    int               result;
    struct cfl_array *value;

    value = cfl_array_create(size);

    if (value == NULL) {
        return -1;
    }

    result = cfl_kvlist_insert_array(list, key, value);

    if (result) {
        cfl_array_destroy(value);
    }

    return result;
}

int cfl_kvlist_insert_kvlist(struct cfl_kvlist *list,
                             char *key, struct cfl_kvlist *value)
{
    struct cfl_variant *value_instance;
    int                 result;

    value_instance = cfl_variant_create_from_kvlist(value);
    if (value_instance == NULL) {
        return -1;
    }

    result = cfl_kvlist_insert(list, key, value_instance);

    if (result) {
        cfl_variant_destroy(value_instance);

        return -2;
    }

    return 0;
}

int cfl_kvlist_insert(struct cfl_kvlist *list,
                      char *key, struct cfl_variant *value)
{
    struct cfl_kvpair *pair;

    pair = malloc(sizeof(struct cfl_kvpair));
    if (pair == NULL) {
        cfl_report_runtime_error();
        return -1;
    }

    pair->key = cfl_sds_create(key);

    if (pair->key == NULL) {
        free(pair);

        return -2;
    }

    pair->val = value;

    cfl_list_add(&pair->_head, &list->list);
    return 0;
}

int cfl_kvlist_count(struct cfl_kvlist *list)
{
    return cfl_list_size(&list->list);
}

struct cfl_variant *cfl_kvlist_fetch(struct cfl_kvlist *list, char *key)
{
    int len;
    struct cfl_list *head;
    struct cfl_kvpair *pair;

    len = strlen(key);

    cfl_list_foreach(head, &list->list) {
        pair = cfl_list_entry(head, struct cfl_kvpair, _head);

        if (cfl_sds_len(pair->key) != len) {
            continue;
        }

        if (strcmp(pair->key, key) == 0) {
            return pair->val;
        }
    }

    return NULL;
}

int cfl_kvlist_print(FILE *fp, struct cfl_kvlist *list)
{
    size_t size;
    size_t i;
    int ret = -1;

    struct cfl_list *head = NULL;
    struct cfl_kvpair *pair = NULL;

    if (fp == NULL || list == NULL) {
        return -1;
    }

    size = (size_t)cfl_kvlist_count(list);
    i = 0;
    fputs("{", fp);
    cfl_list_foreach(head, &list->list) {
        pair = cfl_list_entry(head, struct cfl_kvpair, _head);
        if (pair == NULL || pair->key == NULL || pair->val == NULL) {
            continue;
        }

        fprintf(fp, "\"%s\":", pair->key);
        ret = cfl_variant_print(fp, pair->val);

        i++;
        if (i != size) {
            fputs(",", fp);
        }
    }
    fputs("}", fp);

    return ret;
}
