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
#include <cmetrics/cmt_array.h>

struct cmt_array *cmt_array_create(size_t slot_count)
{
    struct cmt_array *array;

    array = malloc(sizeof(struct cmt_array));

    if (array == NULL) {
        cmt_errno();

        return NULL;
    }

    array->entries = calloc(slot_count, sizeof(void *));

    if (array->entries == NULL) {
        cmt_errno();

        free(array);

        return NULL;
    }

    array->entry_count = 0;
    array->slot_count = slot_count;

    return array;
}

void cmt_array_destroy(struct cmt_array *array)
{
    size_t index;

    if (array != NULL) {
        if (array->entries != NULL) {
            for (index = 0 ; index < array->entry_count ; index++) {
                if(array->entries[index] != NULL) {
                    cmt_variant_destroy(array->entries[index]);
                }
            }

            free(array->entries);
        }

        free(array);
    }
}

int cmt_array_remove_by_index(struct cmt_array *array,
                              size_t position)
{
    if (position >= array->entry_count) {
        return -1;
    }

    cmt_variant_destroy(array->entries[position]);

    if (position != array->entry_count - 1) {
        memcpy(&array->entries[position],
               &array->entries[position + 1],
               sizeof(void *) * (array->entry_count - (position + 1)));
    }
    else
    {
        array->entries[position] = NULL;
    }

    array->entry_count--;

    return 0;
}

int cmt_array_remove_by_reference(struct cmt_array *array,
                                  struct cmt_variant *value)
{
    size_t index;

    for (index = 0 ; index < array->entry_count ; index++) {
        if (array->entries[index] == value) {
            return cmt_array_remove_by_index(array, index);
        }
    }

    return 0;
}

int cmt_array_append(struct cmt_array *array,
                     struct cmt_variant *value)
{
    if (array->entry_count >= array->slot_count) {
        return -1;
    }

    array->entries[array->entry_count++] = value;

    return 0;
}

int cmt_array_append_string(struct cmt_array *array,
                             char *value)
{
    struct cmt_variant *value_instance;
    int                 result;

    value_instance = cmt_variant_create_from_string(value);

    if (value_instance == NULL) {
        return -1;
    }

    result = cmt_array_append(array, value_instance);

    if (result) {
        cmt_variant_destroy(value_instance);

        return -2;
    }

    return 0;
}

int cmt_array_append_bytes(struct cmt_array *array,
                             char *value,
                             size_t length)
{
    struct cmt_variant *value_instance;
    int                 result;

    value_instance = cmt_variant_create_from_bytes(value, length);

    if (value_instance == NULL) {
        return -1;
    }

    result = cmt_array_append(array, value_instance);

    if (result) {
        cmt_variant_destroy(value_instance);

        return -2;
    }

    return 0;
}

int cmt_array_append_reference(struct cmt_array *array,
                                void *value)
{
    struct cmt_variant *value_instance;
    int                 result;

    value_instance = cmt_variant_create_from_reference(value);

    if (value_instance == NULL) {
        return -1;
    }

    result = cmt_array_append(array, value_instance);

    if (result) {
        cmt_variant_destroy(value_instance);

        return -2;
    }

    return 0;
}

int cmt_array_append_bool(struct cmt_array *array,
                           int value)
{
    struct cmt_variant *value_instance;
    int                 result;

    value_instance = cmt_variant_create_from_bool(value);

    if (value_instance == NULL) {
        return -1;
    }

    result = cmt_array_append(array, value_instance);

    if (result) {
        cmt_variant_destroy(value_instance);

        return -2;
    }

    return 0;
}

int cmt_array_append_int(struct cmt_array *array,
                          int value)
{
    struct cmt_variant *value_instance;
    int                 result;

    value_instance = cmt_variant_create_from_int(value);

    if (value_instance == NULL) {
        return -1;
    }

    result = cmt_array_append(array, value_instance);

    if (result) {
        cmt_variant_destroy(value_instance);

        return -2;
    }

    return 0;
}


int cmt_array_append_double(struct cmt_array *array,
                             double value)
{
    struct cmt_variant *value_instance;
    int                 result;

    value_instance = cmt_variant_create_from_double(value);

    if (value_instance == NULL) {
        return -1;
    }

    result = cmt_array_append(array, value_instance);

    if (result) {
        cmt_variant_destroy(value_instance);

        return -2;
    }

    return 0;
}


int cmt_array_append_array(struct cmt_array *array,
                            struct cmt_array *value)
{
    struct cmt_variant *value_instance;
    int                 result;

    value_instance = cmt_variant_create_from_array(value);

    if (value_instance == NULL) {
        return -1;
    }

    result = cmt_array_append(array, value_instance);

    if (result) {
        cmt_variant_destroy(value_instance);

        return -2;
    }

    return 0;
}


int cmt_array_append_new_array(struct cmt_array *array,
                                size_t size)
{
    int               result;
    struct cmt_array *value;

    value = cmt_array_create(size);

    if (value == NULL) {
        return -1;
    }

    result = cmt_array_append_array(array, value);

    if (result) {
        cmt_array_destroy(value);
    }

    return result;
}


int cmt_array_append_kvlist(struct cmt_array *array,
                             struct cmt_kvlist *value)
{
    struct cmt_variant *value_instance;
    int                 result;

    value_instance = cmt_variant_create_from_kvlist(value);

    if (value_instance == NULL) {
        return -1;
    }

    result = cmt_array_append(array, value_instance);

    if (result) {
        cmt_variant_destroy(value_instance);

        return -2;
    }

    return 0;
}
