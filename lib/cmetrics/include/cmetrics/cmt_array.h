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

#ifndef CMT_ARRAY_H
#define CMT_ARRAY_H

#include <cmetrics/cmt_variant.h>

struct cmt_array {
    struct cmt_variant **entries;
    size_t               slot_count;
    size_t               entry_count;
};

struct cmt_array *cmt_array_create(size_t slot_count);
void cmt_array_destroy(struct cmt_array *array);

static inline struct cmt_variant *cmt_array_fetch_by_index(struct cmt_array *array,
                                                    size_t position)
{
    if (position >= array->entry_count) {
        return NULL;
    }

    return array->entries[position];
}

int cmt_array_remove_by_index(struct cmt_array *array,
                              size_t position);

int cmt_array_remove_by_reference(struct cmt_array *array,
                                  struct cmt_variant *value);

int cmt_array_append(struct cmt_array *array,
                     struct cmt_variant *value);


int cmt_array_append_string(struct cmt_array *array,
                            char *value);

int cmt_array_append_bytes(struct cmt_array *array,
                           char *value,
                           size_t length);

int cmt_array_append_reference(struct cmt_array *array,
                               void *value);

int cmt_array_append_bool(struct cmt_array *array,
                          int value);

int cmt_array_append_int(struct cmt_array *array,
                         int value);

int cmt_array_append_double(struct cmt_array *array,
                            double value);

int cmt_array_append_array(struct cmt_array *array,
                           struct cmt_array *value);

int cmt_array_append_new_array(struct cmt_array *array,
                               size_t size);

int cmt_array_append_kvlist(struct cmt_array *array,
                            struct cmt_kvlist *value);

#endif
