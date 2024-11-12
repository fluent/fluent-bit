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

struct cprof_resource *cprof_resource_create(struct cfl_kvlist *attributes)
{
    struct cprof_resource *resource;

    resource = calloc(1, sizeof(struct cprof_resource));

    if (resource == NULL) {
        return NULL;
    }

    if (attributes == NULL) {
        resource->attributes = cfl_kvlist_create();

        if (resource->attributes == NULL) {
            free(resource);

            return NULL;
        }
    }
    else {
        resource->attributes = attributes;
    }

    return resource;
}

void cprof_resource_destroy(struct cprof_resource *resource)
{
    if (resource->attributes != NULL) {
        cfl_kvlist_destroy(resource->attributes);
    }

    free(resource);
}

int cprof_resource_profiles_add(struct cprof *context,
                                struct cprof_resource_profiles *resource_profiles)
{
    cfl_list_add(&resource_profiles->_head, &context->profiles);

    return 0;
}
