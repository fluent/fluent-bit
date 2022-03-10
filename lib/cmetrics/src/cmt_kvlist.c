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

#include <cmetrics/cmetrics.h>
#include <cmetrics/cmt_sds.h>
#include <cmetrics/cmt_kvlist.h>

struct cmt_kvlist *cmt_kvlist_create()
{
    struct cmt_kvlist *list;

    list = malloc(sizeof(struct cmt_kvlist));

    if (list == NULL) {
        cmt_errno();

        return NULL;
    }

    mk_list_init(&list->list);

    return list;
}

void cmt_kvlist_destroy(struct cmt_kvlist *list)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct cmt_kvpair *pair;

    mk_list_foreach_safe(head, tmp, &list->list) {
        pair = mk_list_entry(head, struct cmt_kvpair, _head);

        if (pair->key) {
            cmt_sds_destroy(pair->key);
        }

        if (pair->val) {
            cmt_variant_destroy(pair->val);
        }

        mk_list_del(&pair->_head);

        free(pair);
    }

    free(list);
}

/*
int cmt_kvlist_insert(struct cmt_kvlist *list,
                      char *key, void *value,
                      size_t value_length,
                      int value_type)
{
    struct cmt_kvpair *pair;

    pair = malloc(sizeof(struct cmt_kvpair));

    if (pair == NULL) {
        cmt_errno();

        return -1;
    }

    pair->key = cmt_sds_create(key);

    if (pair->key == NULL) {
        free(pair);

        return -2;
    }

    pair->val = cmt_variant_create(value, value_length, value_type);

    if (pair->val == NULL) {
        cmt_sds_destroy(pair->key);
        free(pair);

        return -3;
    }

    mk_list_add(&pair->_head, &list->list);

    return 0;
}
*/

int cmt_kvlist_insert_string(struct cmt_kvlist *list,
                             char *key, char *value)
{
    struct cmt_variant *value_instance;
    int                 result;

    value_instance = cmt_variant_create_from_string(value);

    if (value_instance == NULL) {
        return -1;
    }

    result = cmt_kvlist_insert(list, key, value_instance);

    if (result) {
        cmt_variant_destroy(value_instance);

        return -2;
    }

    return 0;
}

int cmt_kvlist_insert_bytes(struct cmt_kvlist *list,
                             char *key, char *value,
                             size_t length)
{
    struct cmt_variant *value_instance;
    int                 result;

    value_instance = cmt_variant_create_from_bytes(value, length);

    if (value_instance == NULL) {
        return -1;
    }

    result = cmt_kvlist_insert(list, key, value_instance);

    if (result) {
        cmt_variant_destroy(value_instance);

        return -2;
    }

    return 0;
}

int cmt_kvlist_insert_reference(struct cmt_kvlist *list,
                                char *key, void *value)
{
    struct cmt_variant *value_instance;
    int                 result;

    value_instance = cmt_variant_create_from_reference(value);

    if (value_instance == NULL) {
        return -1;
    }

    result = cmt_kvlist_insert(list, key, value_instance);

    if (result) {
        cmt_variant_destroy(value_instance);

        return -2;
    }

    return 0;
}

int cmt_kvlist_insert_bool(struct cmt_kvlist *list,
                           char *key, int value)
{
    struct cmt_variant *value_instance;
    int                 result;

    value_instance = cmt_variant_create_from_bool(value);

    if (value_instance == NULL) {
        return -1;
    }

    result = cmt_kvlist_insert(list, key, value_instance);

    if (result) {
        cmt_variant_destroy(value_instance);

        return -2;
    }

    return 0;
}

int cmt_kvlist_insert_int(struct cmt_kvlist *list,
                          char *key, int value)
{
    struct cmt_variant *value_instance;
    int                 result;

    value_instance = cmt_variant_create_from_int(value);

    if (value_instance == NULL) {
        return -1;
    }

    result = cmt_kvlist_insert(list, key, value_instance);

    if (result) {
        cmt_variant_destroy(value_instance);

        return -2;
    }

    return 0;
}

int cmt_kvlist_insert_double(struct cmt_kvlist *list,
                             char *key, double value)
{
    struct cmt_variant *value_instance;
    int                 result;

    value_instance = cmt_variant_create_from_double(value);

    if (value_instance == NULL) {
        return -1;
    }

    result = cmt_kvlist_insert(list, key, value_instance);

    if (result) {
        cmt_variant_destroy(value_instance);

        return -2;
    }

    return 0;
}

int cmt_kvlist_insert_array(struct cmt_kvlist *list,
                            char *key, struct cmt_array *value)
{
    struct cmt_variant *value_instance;
    int                 result;

    value_instance = cmt_variant_create_from_array(value);

    if (value_instance == NULL) {
        return -1;
    }

    result = cmt_kvlist_insert(list, key, value_instance);

    if (result) {
        cmt_variant_destroy(value_instance);

        return -2;
    }

    return 0;
}

int cmt_kvlist_insert_new_array(struct cmt_kvlist *list,
                                char *key, size_t size)
{
    int               result;
    struct cmt_array *value;

    value = cmt_array_create(size);

    if (value == NULL) {
        return -1;
    }

    result = cmt_kvlist_insert_array(list, key, value);

    if (result) {
        cmt_array_destroy(value);
    }

    return result;
}

int cmt_kvlist_insert_kvlist(struct cmt_kvlist *list,
                             char *key, struct cmt_kvlist *value)
{
    struct cmt_variant *value_instance;
    int                 result;

    value_instance = cmt_variant_create_from_kvlist(value);

    if (value_instance == NULL) {
        return -1;
    }

    result = cmt_kvlist_insert(list, key, value_instance);

    if (result) {
        cmt_variant_destroy(value_instance);

        return -2;
    }

    return 0;
}

int cmt_kvlist_insert(struct cmt_kvlist *list,
                      char *key, struct cmt_variant *value)
{
    struct cmt_kvpair *pair;

    pair = malloc(sizeof(struct cmt_kvpair));

    if (pair == NULL) {
        cmt_errno();

        return -1;
    }

    pair->key = cmt_sds_create(key);

    if (pair->key == NULL) {
        free(pair);

        return -2;
    }

    pair->val = value;

    mk_list_add(&pair->_head, &list->list);

    return 0;
}

int cmt_kvlist_count(struct cmt_kvlist *list)
{
    int c = 0;
    struct mk_list *head;

    mk_list_foreach(head, &list->list) {
        c++;
    }

    return c;
}

struct cmt_variant *cmt_kvlist_fetch(struct cmt_kvlist *list, char *key)
{
    struct mk_list *head;
    struct cmt_kvpair *pair;

    mk_list_foreach(head, &list->list) {
        pair = mk_list_entry(head, struct cmt_kvpair, _head);

        if (strcmp(pair->key, key) == 0) {
            return pair->val;
        }
    }

    return NULL;
}

