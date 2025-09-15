/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  CProfiles
 *  =========
 *  Copyright (C) 2024 The CProfiles Authors
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


#include <cprofiles/cprofiles.h>

struct cprof_instrumentation_scope *cprof_instrumentation_scope_create(
                                        char *name,
                                        char *version,
                                        struct cfl_kvlist *attributes,
                                        uint32_t dropped_attributes_count)

    {
    struct cprof_instrumentation_scope *instance;

    instance = calloc(1, sizeof(struct cprof_instrumentation_scope));

    if (instance == NULL) {
        return NULL;
    }

    if (name != NULL) {
        instance->name = cfl_sds_create(name);

        if (instance->name == NULL) {
            cprof_instrumentation_scope_destroy(instance);

            return NULL;
        }
    }

    if (version != NULL) {
        instance->version = cfl_sds_create(version);

        if (instance->version == NULL) {
            cprof_instrumentation_scope_destroy(instance);

            return NULL;
        }
    }

    if (attributes != NULL) {
        instance->attributes = attributes;
    }
    else {
        instance->attributes = cfl_kvlist_create();

        if (instance->attributes == NULL) {
            cprof_instrumentation_scope_destroy(instance);

            return NULL;
        }
    }

    instance->dropped_attributes_count = dropped_attributes_count;

    return instance;
}

void cprof_instrumentation_scope_destroy(
            struct cprof_instrumentation_scope *instance)
{
    if (instance != NULL) {
        if (instance->name != NULL) {
            cfl_sds_destroy(instance->name);
        }

        if (instance->version != NULL) {
            cfl_sds_destroy(instance->version);
        }

        if (instance->attributes != NULL) {
            cfl_kvlist_destroy(instance->attributes);
        }

        free(instance);
    }
}
