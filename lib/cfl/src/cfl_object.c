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

#include "cfl/cfl.h"
#include <cfl/cfl_container.h>

/* CFL Object
 * ==========
 * the CFL Object interface is a generic object that can hold a cfl_kvlist, cfl_array
 * or a cfl_variant. It's used as a wrapper to link different objects and/or provide
 * a common interface to the user.
 */


/* Create CFL Object context */
struct cfl_object *cfl_object_create()
{
    struct cfl_object *o;

    o = calloc(1, sizeof(struct cfl_object));
    if (!o) {
        cfl_errno();
        return NULL;
    }

    /* mark it as not initialized */
    o->type = CFL_OBJECT_NONE;
    return o;
}

static int reuses_current_root(struct cfl_object *o, int type, void *ptr)
{
    if (o->variant == NULL) {
        return CFL_FALSE;
    }

    if (type == CFL_OBJECT_KVLIST &&
        o->variant->type == CFL_VARIANT_KVLIST &&
        o->variant->data.as_kvlist == ptr) {
        return CFL_TRUE;
    }

    if (type == CFL_OBJECT_ARRAY &&
        o->variant->type == CFL_VARIANT_ARRAY &&
        o->variant->data.as_array == ptr) {
        return CFL_TRUE;
    }

    if (type == CFL_OBJECT_VARIANT && o->variant == ptr) {
        return CFL_TRUE;
    }

    return CFL_FALSE;
}

/*
 * Associate a CFL data type to the object. We only support kvlist, array and variant. Note
 * that everything is held as a variant internally.
 */
int cfl_object_set(struct cfl_object *o, int type, void *ptr)
{
    struct cfl_variant *variant;
    int                 variant_created;

    if (!o || !ptr) {
        return -1;
    }

    if (o->variant != NULL) {
        if (reuses_current_root(o, type, ptr)) {
            o->type = type;
            return 0;
        }
    }

    variant_created = CFL_FALSE;

    if (type == CFL_OBJECT_KVLIST) {
        variant = cfl_variant_create_from_kvlist(ptr);
        variant_created = CFL_TRUE;
    }
    else if (type == CFL_OBJECT_VARIANT) {
        variant = ptr;
    }
    else if (type == CFL_OBJECT_ARRAY) {
        variant = cfl_variant_create_from_array(ptr);
        variant_created = CFL_TRUE;
    }
    else {
        return -1;
    }

    if (variant == NULL) {
        return -1;
    }

    if (cfl_container_adopt_variant(variant) != 0) {
        if (variant_created) {
            cfl_variant_destroy(variant);
        }

        return -1;
    }

    if (o->variant != NULL && o->variant != variant) {
        cfl_variant_destroy(o->variant);
    }

    o->type = type;
    o->variant = variant;

    return 0;
}

int cfl_object_print(FILE *stream, struct cfl_object *o)
{
    int ret;

    if (stream == NULL || o == NULL) {
        return -1;
    }

    if (!o->variant) {
        return -1;
    }

    ret = cfl_variant_print(stream, o->variant);
    if (ret < 0) {
        return -1;
    }

    if (fputc('\n', stream) == EOF) {
        return -1;
    }

    return 0;
}

/*
 * Destroy the object, note that if a CFL data type is linked
 * it will be destroyed as well
 */
void cfl_object_destroy(struct cfl_object *o)
{
    if (!o) {
        return;
    }

    if (o->variant) {
        cfl_variant_destroy(o->variant);
    }

    free(o);
}
