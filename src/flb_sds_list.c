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

#include <fluent-bit.h>
#include <fluent-bit/flb_sds_list.h>

size_t flb_sds_list_size(struct flb_sds_list *list)
{
    if (list == NULL) {
        return 0;
    }
    return mk_list_size(&list->strs);
}

struct flb_sds_list *flb_sds_list_create()
{
    struct flb_sds_list *ret = NULL;

    ret = flb_calloc(1, sizeof(struct flb_sds_list));
    if (ret == NULL) {
        return NULL;
    }

    mk_list_init(&ret->strs);

    return ret;
}

int flb_sds_list_del(struct flb_sds_list_entry* entry)
{
    if (entry == NULL) {
        return -1;
    }
    if (entry->str != NULL) {
        flb_sds_destroy(entry->str);
    }
    mk_list_del(&entry->_head);
    flb_free(entry);

    return 0;
}


int flb_sds_list_destroy(struct flb_sds_list *list)
{
    struct mk_list *tmp = NULL;
    struct mk_list *head = NULL;
    struct flb_sds_list_entry *entry = NULL;

    if (list == NULL) {
        return -1;
    }

    mk_list_foreach_safe(head, tmp, &list->strs) {
        entry = mk_list_entry(head, struct flb_sds_list_entry, _head);
        flb_sds_list_del(entry);
    }
    flb_free(list);

    return 0;
}

int flb_sds_list_add(struct flb_sds_list* list, char *in_str, size_t in_size)
{
    flb_sds_t str;
    struct flb_sds_list_entry *entry = NULL;

    if (list == NULL || in_str == NULL || in_size == 0) {
        return -1;
    }

    str = flb_sds_create_len(in_str, in_size);
    if (str == NULL) {
        return -1;
    }

    entry = flb_malloc(sizeof(struct flb_sds_list_entry));
    if (entry == NULL) {
        flb_errno();
        flb_sds_destroy(str);
        return -1;
    }
    entry->str = str;

    mk_list_add(&entry->_head, &list->strs);

    return 0;
}

int flb_sds_list_destroy_str_array(char **array)
{
    char **str = array;
    int i = 0;

    if (array == NULL) {
        return -1;
    }
    while(str[i] != NULL) {
        flb_free(str[i]);
        i++;
    }
    flb_free(array);

    return 0;
}


/*
  This function allocates NULL terminated string array from list. 
  The array should be destroyed by flb_sds_list_destroy_str_array.
*/
char **flb_sds_list_create_str_array(struct flb_sds_list *list)
{
    int i = 0;
    size_t size;
    char **ret = NULL;
    struct mk_list *tmp = NULL;
    struct mk_list *head = NULL;
    struct flb_sds_list_entry *entry = NULL;

    if (list == NULL) {
        return NULL;
    }

    size = flb_sds_list_size(list);
    if (size == 0) {
        return NULL;
    }

    ret = flb_malloc(sizeof(char*) * (size + 1));
    if (ret == NULL) {
        flb_errno();
        return NULL;
    }

    mk_list_foreach_safe(head, tmp, &list->strs) {
        entry = mk_list_entry(head, struct flb_sds_list_entry, _head);
        if (entry == NULL) {
            flb_free(ret);
            return NULL;
        }
        ret[i] = flb_malloc(flb_sds_len(entry->str)+1);
        if (ret[i] == NULL) {
            flb_free(ret);
            return NULL;
        }
        strncpy(ret[i], entry->str, flb_sds_len(entry->str));
        ret[i][flb_sds_len(entry->str)] = '\0';
        i++;
    }
    ret[i] = NULL;

    return ret;
}

int flb_sds_list_del_last_entry(struct flb_sds_list* list)
{
    struct flb_sds_list_entry *entry = NULL;

    if (list == NULL || flb_sds_list_size(list) == 0) {
        return -1;
    }

    entry = mk_list_entry_last(&list->strs, struct flb_sds_list_entry, _head);
    if (entry == NULL) {
        return -1;
    }
    return flb_sds_list_del(entry);
}
