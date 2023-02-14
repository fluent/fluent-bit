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

#ifndef CFL_ARRAY_H
#define CFL_ARRAY_H

#include <stdio.h>
#include <cfl/cfl_variant.h>

struct cfl_array {
    int                  resizable;
    struct cfl_variant **entries;
    size_t               slot_count;
    size_t               entry_count;
};

struct cfl_array *cfl_array_create(size_t slot_count);
void cfl_array_destroy(struct cfl_array *array);

static inline struct cfl_variant *cfl_array_fetch_by_index(struct cfl_array *array,
                                                           size_t position)
{
    if (position >= array->entry_count) {
        return NULL;
    }

    return array->entries[position];
}

int cfl_array_resizable(struct cfl_array *array, int v);
int cfl_array_remove_by_index(struct cfl_array *array, size_t position);
int cfl_array_remove_by_reference(struct cfl_array *array, struct cfl_variant *value);
int cfl_array_append(struct cfl_array *array, struct cfl_variant *value);
int cfl_array_append_string(struct cfl_array *array, char *value);
int cfl_array_append_bytes(struct cfl_array *array, char *value, size_t length);
int cfl_array_append_reference(struct cfl_array *array, void *value);
int cfl_array_append_bool(struct cfl_array *array, int value);
int cfl_array_append_int64(struct cfl_array *array, int64_t value);
int cfl_array_append_double(struct cfl_array *array, double value);
int cfl_array_append_array(struct cfl_array *array, struct cfl_array *value);
int cfl_array_append_new_array(struct cfl_array *array, size_t size);
int cfl_array_append_kvlist(struct cfl_array *array, struct 
cfl_kvlist *value);
int cfl_array_print(FILE *fp, struct cfl_array *array);

#endif
