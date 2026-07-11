/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  CFL
 *  ===
 *  Copyright (C) 2022-2024 The CFL Authors
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
#include <cfl/cfl_array.h>
#include <cfl/cfl_variant.h>

#include <stdint.h>

#include <cfl/cfl_container.h>
#include "cfl_arena_internal.h"

struct cfl_array *cfl_array_create(size_t slot_count)
{
    return cfl_array_create_in(NULL, slot_count);
}

struct cfl_array *cfl_array_create_in(struct cfl_arena *arena,
                                      size_t slot_count)
{
    struct cfl_array *array;
    size_t alloc_count;

    alloc_count = slot_count;
    if (alloc_count == 0) {
        alloc_count = 1;
    }
    if (alloc_count > SIZE_MAX / sizeof(void *)) {
        return NULL;
    }

    if (arena == NULL) {
        array = malloc(sizeof(struct cfl_array));
    }
    else {
        array = cfl_arena_alloc(arena, sizeof(struct cfl_array));
    }
    if (array == NULL) {
        cfl_errno();
        return NULL;
    }

    /* by default arrays are not resizable */
    array->resizable = CFL_FALSE;

    /* allocate fixed number of entries */
    if (arena == NULL) {
        array->entries = calloc(alloc_count, sizeof(void *));
    }
    else {
        array->entries = cfl_arena_calloc(arena, alloc_count,
                                                  sizeof(void *));
    }
    if (array->entries == NULL) {
        cfl_errno();
        if (arena == NULL) {
            free(array);
        }
        return NULL;
    }

    array->entry_count = 0;
    array->slot_count = slot_count;
    array->owner = NULL;
    array->parent_array = NULL;
    array->parent_kvlist = NULL;
    array->arena = arena;

    return array;
}

struct cfl_array *cfl_array_create_like(struct cfl_array *parent,
                                        size_t slot_count)
{
    if (parent == NULL) {
        return NULL;
    }

    return cfl_array_create_in(parent->arena, slot_count);
}

void cfl_array_destroy(struct cfl_array *array)
{
    size_t index;

    if (!array) {
        return;
    }

    if (array->entries != NULL) {
        for (index = 0 ; index < array->entry_count ; index++) {
            if(array->entries[index] != NULL) {
                cfl_variant_destroy(array->entries[index]);
            }
        }

        if (array->arena == NULL) {
            free(array->entries);
        }
    }
    if (array->arena == NULL) {
        free(array);
    }
}

int cfl_array_resizable(struct cfl_array *array, int v)
{
    if (array == NULL) {
        return -1;
    }

    if (v != CFL_TRUE && v != CFL_FALSE) {
        return -1;
    }

    array->resizable = v;
    return 0;
}

int cfl_array_remove_by_index(struct cfl_array *array,
                              size_t position)
{
    if (array == NULL) {
        return -1;
    }

    if (position >= array->entry_count) {
        return -1;
    }

    cfl_variant_destroy(array->entries[position]);

    if (position != array->entry_count - 1) {
        memmove(&array->entries[position],
                &array->entries[position + 1],
                sizeof(void *) * (array->entry_count - (position + 1)));
    }
    else {
        array->entries[position] = NULL;
    }
    array->entry_count--;

    return 0;
}

int cfl_array_remove_by_reference(struct cfl_array *array,
                                  struct cfl_variant *value)
{
    size_t index;

    if (array == NULL || value == NULL) {
        return -1;
    }

    for (index = 0 ; index < array->entry_count ; index++) {
        if (array->entries[index] == value) {
            return cfl_array_remove_by_index(array, index);
        }
    }

    return -1;
}

int cfl_array_append(struct cfl_array *array,
                     struct cfl_variant *value)
{
    void *tmp;
    size_t new_slot_count;
    size_t new_size;
    size_t base_slot_count;

    if (array == NULL || value == NULL) {
        return -1;
    }

    if (array->arena != value->arena) {
        return -1;
    }

    if (array->entry_count >= array->slot_count) {
        /*
         * if there is no more space but the caller allowed to resize
         * the array, just double the size. Yeah, this is scary and should
         * be used only when the caller 'knows this is safe to do' because
         * it controls the input data.
         */
        if (array->resizable) {
            base_slot_count = array->slot_count;
            if (base_slot_count == 0) {
                base_slot_count = 1;
            }

            /* set new number of slots and total size */
            if (base_slot_count > SIZE_MAX / 2) {
                return -1;
            }

            new_slot_count = (base_slot_count * 2);
            if (new_slot_count > SIZE_MAX / sizeof(void *)) {
                return -1;
            }

            new_size = (new_slot_count * sizeof(void *));

            if (array->arena == NULL) {
                tmp = realloc(array->entries, new_size);
            }
            else {
                tmp = cfl_arena_alloc(array->arena, new_size);
                if (tmp != NULL) {
                    memcpy(tmp, array->entries,
                           array->entry_count * sizeof(void *));
                }
            }
            if (!tmp) {
                cfl_report_runtime_error();
                return -1;
            }
            array->slot_count = new_slot_count;
            array->entries = tmp;
        }
        else {
            return -1;
        }
    }

    /* this is just a double check to make sure the slot is really available */
    if (array->entry_count >= array->slot_count) {
        return -1;
    }

    if (cfl_container_move_variant_to_array(array, value) != 0) {
        return -1;
    }

    array->entries[array->entry_count++] = value;
    return 0;
}

int cfl_array_append_string(struct cfl_array *array, char *value)
{
    struct cfl_variant *value_instance;
    int                 result;

    value_instance = cfl_variant_create_from_string_in(
                         array == NULL ? NULL : array->arena, value);

    if (value_instance == NULL) {
        return -1;
    }

    result = cfl_array_append(array, value_instance);
    if (result) {
        cfl_variant_destroy(value_instance);
        return -2;
    }

    return 0;
}

int cfl_array_append_string_s(struct cfl_array *array, char *str, size_t str_len, int referenced)
{
    struct cfl_variant *value_instance;
    int                 result;

    value_instance = cfl_variant_create_from_string_s_in(
                         array == NULL ? NULL : array->arena, str,
                                                          str_len, referenced);
    if (value_instance == NULL) {
        return -1;
    }

    result = cfl_array_append(array, value_instance);
    if (result) {
        cfl_variant_destroy(value_instance);
        return -2;
    }

    return 0;
}

int cfl_array_append_bytes(struct cfl_array *array,
                           char *value,
                           size_t length,
                           int referenced)
{
    struct cfl_variant *value_instance;
    int                 result;

    value_instance = cfl_variant_create_from_bytes_in(
                         array == NULL ? NULL : array->arena, value,
                                                       length, referenced);
    if (value_instance == NULL) {
        return -1;
    }

    result = cfl_array_append(array, value_instance);

    if (result) {
        cfl_variant_destroy(value_instance);

        return -2;
    }

    return 0;
}

int cfl_array_append_reference(struct cfl_array *array, void *value)
{
    struct cfl_variant *value_instance;
    int                 result;

    value_instance = cfl_variant_create_from_reference_in(
                         array == NULL ? NULL : array->arena, value);

    if (value_instance == NULL) {
        return -1;
    }

    result = cfl_array_append(array, value_instance);

    if (result) {
        cfl_variant_destroy(value_instance);

        return -2;
    }

    return 0;
}

int cfl_array_append_bool(struct cfl_array *array, int value)
{
    struct cfl_variant *value_instance;
    int                 result;

    value_instance = cfl_variant_create_from_bool_in(
                         array == NULL ? NULL : array->arena, value);

    if (value_instance == NULL) {
        return -1;
    }

    result = cfl_array_append(array, value_instance);

    if (result) {
        cfl_variant_destroy(value_instance);

        return -2;
    }

    return 0;
}

int cfl_array_append_int64(struct cfl_array *array, int64_t value)
{
    struct cfl_variant *value_instance;
    int                 result;

    value_instance = cfl_variant_create_from_int64_in(
                         array == NULL ? NULL : array->arena, value);

    if (value_instance == NULL) {
        return -1;
    }

    result = cfl_array_append(array, value_instance);

    if (result) {
        cfl_variant_destroy(value_instance);
        return -2;
    }

    return 0;
}

int cfl_array_append_uint64(struct cfl_array *array, uint64_t value)
{
    struct cfl_variant *value_instance;
    int                 result;

    value_instance = cfl_variant_create_from_uint64_in(
                         array == NULL ? NULL : array->arena, value);

    if (value_instance == NULL) {
        return -1;
    }

    result = cfl_array_append(array, value_instance);

    if (result) {
        cfl_variant_destroy(value_instance);
        return -2;
    }

    return 0;
}


int cfl_array_append_double(struct cfl_array *array, double value)
{
    struct cfl_variant *value_instance;
    int                 result;

    value_instance = cfl_variant_create_from_double_in(
                         array == NULL ? NULL : array->arena, value);

    if (value_instance == NULL) {
        return -1;
    }

    result = cfl_array_append(array, value_instance);

    if (result) {
        cfl_variant_destroy(value_instance);

        return -2;
    }

    return 0;
}

int cfl_array_append_null(struct cfl_array *array)
{
    struct cfl_variant *value_instance;
    int                 result;

    value_instance = cfl_variant_create_from_null_in(
                         array == NULL ? NULL : array->arena);
    if (value_instance == NULL) {
        return -1;
    }

    result = cfl_array_append(array, value_instance);
    if (result) {
        cfl_variant_destroy(value_instance);
        return -2;
    }

    return 0;
}

int cfl_array_append_array(struct cfl_array *array, struct cfl_array *value)
{
    struct cfl_variant *value_instance;
    int                 result;

    if (array == NULL || value == NULL) {
        return -1;
    }

    if (array == value) {
        return -1;
    }

    value_instance = cfl_variant_create_from_array_in(array->arena, value);

    if (value_instance == NULL) {
        return -1;
    }

    result = cfl_array_append(array, value_instance);
    if (result) {
        cfl_container_release_variant(value_instance);
        value_instance->data.as_array = NULL;
        cfl_variant_destroy(value_instance);
        return -2;
    }

    return 0;
}


int cfl_array_append_new_array(struct cfl_array *array, size_t size)
{
    int               result;
    struct cfl_array *value;

    if (array == NULL) {
        return -1;
    }

    value = cfl_array_create_in(array->arena, size);

    if (value == NULL) {
        return -1;
    }

    result = cfl_array_append_array(array, value);
    if (result < 0) {
        cfl_array_destroy(value);
    }

    return result;
}

int cfl_array_append_kvlist(struct cfl_array *array, struct cfl_kvlist *value)
{
    struct cfl_variant *value_instance;
    int                 result;

    if (array == NULL || value == NULL) {
        return -1;
    }

    value_instance = cfl_variant_create_from_kvlist_in(array->arena, value);
    if (value_instance == NULL) {
        return -1;
    }
    result = cfl_array_append(array, value_instance);

    if (result) {
        cfl_container_release_variant(value_instance);
        value_instance->data.as_kvlist = NULL;
        cfl_variant_destroy(value_instance);

        return -2;
    }

    return 0;
}


int cfl_array_print(FILE *fp, struct cfl_array *array)
{
    size_t size;
    size_t i;
    int ret;

    if (fp == NULL || array == NULL) {
        return -1;
    }

    size = array->entry_count;
    if (size == 0) {
        if (fputs("[]", fp) == EOF) {
            return -1;
        }

        return 0;
    }

    if (fputc('[', fp) == EOF) {
        return -1;
    }

    for (i=0; i<size-1; i++) {
        ret = cfl_variant_print(fp, array->entries[i]);
        if (ret < 0) {
            return -1;
        }

        if (fputc(',', fp) == EOF) {
            return -1;
        }
    }

    ret = cfl_variant_print(fp, array->entries[size-1]);
    if (ret < 0) {
        return -1;
    }

    if (fputc(']', fp) == EOF) {
        return -1;
    }

    return ret;
}
