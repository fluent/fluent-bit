/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  CTraces
 *  =======
 *  Copyright 2022 The CTraces Authors
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

#include <ctraces/ctraces.h>

struct ctrace_attributes *ctr_attributes_create()
{
    struct ctrace_attributes *attr;

    attr = malloc(sizeof(struct ctrace_attributes));
    if (!attr) {
        ctr_errno();
        return NULL;
    }

    attr->kv = cfl_kvlist_create();
    if (!attr->kv) {
        free(attr);
        return NULL;
    }

    attr->ref_count = 1;

    return attr;
}

void ctr_attributes_destroy(struct ctrace_attributes *attr)
{
    if (!attr) {
        return;
    }

    if (attr->ref_count > 1) {
        attr->ref_count--;
        return;
    }

    if (attr->kv) {
        cfl_kvlist_destroy(attr->kv);
    }
    free(attr);
}

struct ctrace_attributes *ctr_attributes_acquire(struct ctrace_attributes *attr)
{
    if (!attr) {
        return NULL;
    }

    attr->ref_count++;
    return attr;
}

int ctr_attributes_count(struct ctrace_attributes *attr)
{
    return cfl_kvlist_count(attr->kv);
}

int ctr_attributes_set_string(struct ctrace_attributes *attr, char *key, char *value)
{
    return cfl_kvlist_insert_string(attr->kv, key, value);
}

int ctr_attributes_set_bool(struct ctrace_attributes *attr, char *key, int b)
{
    if (b != CTR_TRUE && b != CTR_FALSE) {
        return -1;
    }

    return cfl_kvlist_insert_bool(attr->kv, key, b);
}

int ctr_attributes_set_int64(struct ctrace_attributes *attr, char *key, int64_t value)
{
    return cfl_kvlist_insert_int64(attr->kv, key, value);
}

int ctr_attributes_set_double(struct ctrace_attributes *attr, char *key, double value)
{
    return cfl_kvlist_insert_double(attr->kv, key, value);
}

int ctr_attributes_set_array(struct ctrace_attributes *attr, char *key,
                             struct cfl_array *value)
{
    return cfl_kvlist_insert_array(attr->kv, key, value);
}

int ctr_attributes_set_kvlist(struct ctrace_attributes *attr, char *key,
                              struct cfl_kvlist *value)
{
    return cfl_kvlist_insert_kvlist(attr->kv, key, value);
}
