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
#include <cfl/cfl_array.h>
#include <cfl/cfl_variant.h>

struct cfl_array *cfl_array_create(size_t slot_count)
{
    struct cfl_array *array;

    array = malloc(sizeof(struct cfl_array));
    if (array == NULL) {
        cfl_errno();
        return NULL;
    }

    /* by default arrays are not resizable */
    array->resizable = CFL_FALSE;

    /* allocate fixed number of entries */
    array->entries = calloc(slot_count, sizeof(void *));
    if (array->entries == NULL) {
        cfl_errno();
        free(array);
        return NULL;
    }

    array->entry_count = 0;
    array->slot_count = slot_count;

    return array;
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

        free(array->entries);
    }
    free(array);
}

int cfl_array_resizable(struct cfl_array *array, int v)
{
    if (v != CFL_TRUE && v != CFL_FALSE) {
        return -1;
    }

    array->resizable = v;
    return 0;
}

int cfl_array_remove_by_index(struct cfl_array *array,
                              size_t position)
{
    if (position >= array->entry_count) {
        return -1;
    }

    cfl_variant_destroy(array->entries[position]);

    if (position != array->entry_count - 1) {
        memcpy(&array->entries[position],
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

    for (index = 0 ; index < array->entry_count ; index++) {
        if (array->entries[index] == value) {
            return cfl_array_remove_by_index(array, index);
        }
    }

    return 0;
}

int cfl_array_append(struct cfl_array *array,
                     struct cfl_variant *value)
{
    void *tmp;
    size_t new_slot_count;
    size_t new_size;

    if (array->entry_count >= array->slot_count) {
        /*
         * if there is no more space but the caller allowed to resize
         * the array, just double the size. Yeah, this is scary and should
         * be used only when the caller 'knows this is safe to do' because
         * it controls the input data.
         */
        if (array->resizable) {
            /* set new number of slots and total size */
            new_slot_count = (array->slot_count * 2);
            new_size = (new_slot_count * sizeof(void *));

            tmp = realloc(array->entries, new_size);
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
    array->entries[array->entry_count++] = value;

    return 0;
}

int cfl_array_append_string(struct cfl_array *array,
                            char *value)
{
    struct cfl_variant *value_instance;
    int                 result;

    value_instance = cfl_variant_create_from_string(value);

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
                           size_t length)
{
    struct cfl_variant *value_instance;
    int                 result;

    value_instance = cfl_variant_create_from_bytes(value, length);

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

    value_instance = cfl_variant_create_from_reference(value);

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

    value_instance = cfl_variant_create_from_bool(value);

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

    value_instance = cfl_variant_create_from_int64(value);

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

    value_instance = cfl_variant_create_from_double(value);

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

    value_instance = cfl_variant_create_from_array(value);

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


int cfl_array_append_new_array(struct cfl_array *array, size_t size)
{
    int               result;
    struct cfl_array *value;

    value = cfl_array_create(size);

    if (value == NULL) {
        return -1;
    }

    result = cfl_array_append_array(array, value);

    if (result) {
        cfl_array_destroy(value);
    }

    return result;
}

int cfl_array_append_kvlist(struct cfl_array *array, struct 
cfl_kvlist *value)
{
    struct cfl_variant *value_instance;
    int                 result;

    value_instance = cfl_variant_create_from_kvlist(value);
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
        fputs("[]", fp);
        return 0;
    }

    fputs("[", fp);
    for (i=0; i<size-1; i++) {
        ret = cfl_variant_print(fp, array->entries[i]);
        fputs(",", fp);
    }
    ret = cfl_variant_print(fp, array->entries[size-1]);
    fputs("]", fp);

    return ret;
}
